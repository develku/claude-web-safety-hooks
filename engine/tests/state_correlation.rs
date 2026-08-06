//! Cross-call correlation and the 3-strike escalation, against Bash's
//! `record_session_hit` semantics.
//!
//! The rules being pinned, all of them load-bearing:
//!
//! * an `H` row counts once per genuine delivered hit;
//! * a `C` row (Layer 5 cleared it) counts for nothing;
//! * `Q` rows collapse by content hash, because a subagent re-running an
//!   identical query gets byte-identical results and a retry loop must not
//!   manufacture strikes;
//! * a `Q` row that somehow has no hash counts *once* — fail toward counting;
//! * escalation needs **three** fresh strikes **and** at least one real `H`,
//!   so a pure-quarantine fan-out never escalates;
//! * the append and the recount are one critical section, so N parallel
//!   scanners cannot all read the same pre-third-hit total.

use std::path::PathBuf;
use std::sync::Arc;
use web_safety_engine::state::clock::TestClock;
use web_safety_engine::state::correlation::HitStatus;
use web_safety_engine::state::{StateConfig, StateContext, StateMode, StateStore};

/// `std::env::temp_dir()` is `/var/folders/...` on macOS and `/var` is a
/// symlink; the store requires a symlink-free absolute root, so the base is
/// resolved once here.
fn temp_root() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).expect("the temp dir resolves")
}

fn scratch(tag: &str) -> PathBuf {
    let base = temp_root().join(format!(
        "ws-corr-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    base.join("state")
}

fn config(dir: PathBuf) -> StateConfig {
    StateConfig {
        mode: StateMode::Report,
        dir,
        ..StateConfig::default()
    }
}

fn open(dir: PathBuf, clock: Arc<TestClock>) -> StateStore {
    StateStore::open_with_clock(config(dir), clock)
        .expect("open")
        .expect("store")
}

fn ctx(session: &str) -> StateContext {
    let mut c = StateContext::new("claude", "profile-a", session);
    c.tool_name = "WebFetch".into();
    c.url = Some("https://example.test/a".into());
    c
}

/// Three delivered hits: the THIRD escalates, and it escalates inside the same
/// call that recorded it.
#[test]
fn the_third_delivered_hit_escalates() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("three"), clock.clone());
    let c = ctx("s1");

    let a = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    let b = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    let d = s.record_hit(&c, HitStatus::Delivered, None).unwrap();

    assert_eq!((a.strikes, a.real_strikes), (1, 1));
    assert_eq!((b.strikes, b.real_strikes), (2, 2));
    assert_eq!((d.strikes, d.real_strikes), (3, 3));
    assert!(!a.escalates() && !b.escalates());
    assert!(d.escalates(), "the third strike escalates");
}

#[test]
fn cleared_rows_never_count_toward_escalation() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("cleared"), clock.clone());
    let c = ctx("s1");

    for _ in 0..5 {
        let n = s.record_hit(&c, HitStatus::Cleared, None).unwrap();
        assert_eq!((n.strikes, n.real_strikes), (0, 0));
        assert!(!n.escalates());
    }
    let after = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    assert_eq!(after.strikes, 1, "five cleared rows contributed nothing");
}

#[test]
fn quarantined_rows_collapse_by_content_hash() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("q-collapse"), clock.clone());
    let c = ctx("s1");

    for _ in 0..3 {
        s.record_hit(&c, HitStatus::Quarantined, Some("hash-aaa"))
            .unwrap();
    }
    let n = s
        .record_hit(&c, HitStatus::Quarantined, Some("hash-aaa"))
        .unwrap();
    assert_eq!(n.strikes, 1, "identical quarantined content counts once");

    // ...and the real hit that joins them is a plain MEDIUM, not an escalation:
    // 1 collapsed Q + 1 H = 2 strikes. This is Bash's q9 case.
    let real = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    assert_eq!((real.strikes, real.real_strikes), (2, 1));
    assert!(!real.escalates());
}

#[test]
fn a_quarantined_row_without_a_hash_still_counts_once() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("q-nohash"), clock.clone());
    let c = ctx("s1");

    let a = s.record_hit(&c, HitStatus::Quarantined, None).unwrap();
    let b = s.record_hit(&c, HitStatus::Quarantined, None).unwrap();
    assert_eq!(a.strikes, 1);
    assert_eq!(
        b.strikes, 2,
        "hashless quarantines fail TOWARD counting rather than vanishing"
    );
    assert_eq!(b.real_strikes, 0);
}

#[test]
fn three_distinct_quarantines_alone_never_escalate() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("q-only"), clock.clone());
    let c = ctx("s1");

    let mut last = None;
    for h in ["h1", "h2", "h3", "h4"] {
        last = Some(s.record_hit(&c, HitStatus::Quarantined, Some(h)).unwrap());
    }
    let n = last.unwrap();
    assert_eq!((n.strikes, n.real_strikes), (4, 0));
    assert!(
        !n.escalates(),
        "a window that exposed the model to zero bytes must not escalate"
    );
}

#[test]
fn two_quarantines_plus_one_real_hit_escalates() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("q-plus-real"), clock.clone());
    let c = ctx("s1");

    s.record_hit(&c, HitStatus::Quarantined, Some("h1"))
        .unwrap();
    s.record_hit(&c, HitStatus::Quarantined, Some("h2"))
        .unwrap();
    let n = s.record_hit(&c, HitStatus::Delivered, None).unwrap();

    assert_eq!((n.strikes, n.real_strikes), (3, 1));
    assert!(
        n.escalates(),
        "the model WAS exposed; the strike count is load-bearing again"
    );
}

/// `$1 >= cutoff` where `cutoff = now - SESSION_WINDOW`: a row exactly at the
/// boundary is still inside the window; one second older is not.
#[test]
fn the_ttl_boundary_is_inclusive_at_exactly_the_window() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("ttl"), clock.clone());
    let c = ctx("s1");

    s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    clock.advance(300);
    let at_boundary = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    assert_eq!(at_boundary.strikes, 2, "ts == now-300 is still fresh");

    clock.advance(1);
    let past = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
    assert_eq!(
        past.strikes, 2,
        "the t=1000 row expired; only the t=1300 and t=1301 rows remain"
    );
}

#[test]
fn strikes_are_scoped_per_agent_with_the_main_session_as_its_own_bucket() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("per-agent"), clock.clone());

    let main = ctx("s1");
    let mut a1 = ctx("s1");
    a1.agent_id = Some("agent-1".into());
    let mut a2 = ctx("s1");
    a2.agent_id = Some("agent-2".into());

    for _ in 0..2 {
        s.record_hit(&a1, HitStatus::Delivered, None).unwrap();
    }
    let other = s.record_hit(&a2, HitStatus::Delivered, None).unwrap();
    let m = s.record_hit(&main, HitStatus::Delivered, None).unwrap();

    assert_eq!(other.strikes, 1, "a sibling agent starts at zero");
    assert_eq!(m.strikes, 1, "the main session is its own bucket");
}

#[test]
fn no_strike_crosses_a_session_namespace_or_runtime() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("isolation"), clock.clone());

    let base = ctx("s1");
    for _ in 0..2 {
        s.record_hit(&base, HitStatus::Delivered, None).unwrap();
    }

    let other_session = ctx("s2");
    let mut other_ns = ctx("s1");
    other_ns.namespace = "profile-b".into();
    let mut other_runtime = ctx("s1");
    other_runtime.runtime = "codex".into();

    for c in [&other_session, &other_ns, &other_runtime] {
        let n = s.record_hit(c, HitStatus::Delivered, None).unwrap();
        assert_eq!(
            n.strikes, 1,
            "{}/{}/{} must not inherit strikes",
            c.runtime, c.namespace, c.session_id
        );
    }
}

/// The pre-append read Bash uses for the E8 store gate and the flagged-tools
/// message: same window, same "not C" filter, but NO hash collapse.
#[test]
fn the_pre_append_read_matches_bashs_early_session_hits() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("prior"), clock.clone());
    let c = ctx("s1");

    assert_eq!(s.prior_hits(&c).unwrap(), 0);
    s.record_hit(&c, HitStatus::Cleared, None).unwrap();
    assert_eq!(
        s.prior_hits(&c).unwrap(),
        0,
        "cleared rows are invisible here too"
    );

    s.record_hit(&c, HitStatus::Quarantined, Some("dup"))
        .unwrap();
    s.record_hit(&c, HitStatus::Quarantined, Some("dup"))
        .unwrap();
    assert_eq!(
        s.prior_hits(&c).unwrap(),
        2,
        "the early read counts rows, it does not collapse by hash"
    );
}

#[test]
fn flagged_tools_are_the_sorted_unique_non_cleared_tools_in_the_window() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("tools"), clock.clone());

    let mut fetch = ctx("s1");
    fetch.tool_name = "WebFetch".into();
    let mut search = ctx("s1");
    search.tool_name = "WebSearch".into();
    let mut cleared = ctx("s1");
    cleared.tool_name = "ZOnlyCleared".into();

    s.record_hit(&search, HitStatus::Delivered, None).unwrap();
    s.record_hit(&fetch, HitStatus::Delivered, None).unwrap();
    s.record_hit(&search, HitStatus::Delivered, None).unwrap();
    s.record_hit(&cleared, HitStatus::Cleared, None).unwrap();

    assert_eq!(
        s.flagged_tools(&fetch).unwrap(),
        vec!["WebFetch".to_string(), "WebSearch".to_string()]
    );
}

#[test]
fn expired_rows_are_pruned_without_touching_another_scope() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("prune"), clock.clone());

    let old = ctx("s-old");
    let fresh = ctx("s-fresh");
    s.record_hit(&old, HitStatus::Delivered, None).unwrap();
    clock.advance(301);
    s.record_hit(&fresh, HitStatus::Delivered, None).unwrap();

    let removed = s.prune().unwrap();
    assert_eq!(removed, 1, "exactly the expired row went");
    assert_eq!(
        s.prior_hits(&fresh).unwrap(),
        1,
        "the fresh scope is untouched"
    );
    assert_eq!(s.prior_hits(&old).unwrap(), 0);
}

/// The race the locked recount exists to close: with N parallel scanners each
/// appending one strike, every call must observe a DISTINCT running total. If
/// any two saw the same number, one append was invisible to the other's read —
/// which is exactly how the pre-v8 code let three parallel scanners all miss
/// the third strike.
/// Fifty simultaneous writers is far past anything a real fan-out produces —
/// a hook process makes one or two transactions — so this one runs with the
/// documented maximum lock budget rather than the production default. The
/// property under test is *correctness under contention*; the production
/// default's latency is measured separately, by
/// [`an_eight_way_fan_out_stays_inside_the_per_call_ceiling`] and by
/// `engine/tools/bench.pl`.
#[test]
fn fifty_concurrent_transitions_never_lose_a_strike() {
    const N: usize = 50;
    let dir = scratch("concurrent");
    let clock = Arc::new(TestClock::new(1_000));
    // Prime the schema once so the workers only contend on the hit append.
    let _primer = open(dir.clone(), clock.clone());

    let started = std::time::Instant::now();
    let mut handles = Vec::new();
    for _ in 0..N {
        let dir = dir.clone();
        let clock = clock.clone();
        handles.push(std::thread::spawn(move || {
            let s = StateStore::open_with_clock(
                StateConfig {
                    busy_timeout_ms: 2_000,
                    ..config(dir)
                },
                clock,
            )
            .expect("open")
            .expect("store");
            let c = ctx("s1");
            let t0 = std::time::Instant::now();
            let n = s.record_hit(&c, HitStatus::Delivered, None).unwrap();
            (n.strikes, n.escalates(), t0.elapsed().as_millis())
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let wall = started.elapsed();

    let mut seen: Vec<u32> = results.iter().map(|r| r.0).collect();
    seen.sort_unstable();
    assert_eq!(
        seen,
        (1..=N as u32).collect::<Vec<_>>(),
        "every concurrent transition must see its own distinct total"
    );
    assert_eq!(
        results.iter().filter(|r| r.1).count(),
        N - 2,
        "everything from the third strike on escalates"
    );

    let slowest = results.iter().map(|r| r.2).max().unwrap();
    assert!(
        slowest <= 2_000,
        "slowest single transition {slowest}ms exceeded even the maximum lock budget"
    );
    assert!(
        wall.as_millis() < 10_000,
        "50 contended transitions took {wall:?}"
    );
}

/// The realistic shape — a subagent fan-out of eight concurrent scanners, on the
/// PRODUCTION lock budget. Every call must succeed, see a distinct total, and
/// land inside the hard per-call ceiling.
#[test]
fn an_eight_way_fan_out_stays_inside_the_per_call_ceiling() {
    const N: usize = 8;
    let dir = scratch("fanout");
    let clock = Arc::new(TestClock::new(1_000));
    let _primer = open(dir.clone(), clock.clone());

    let mut handles = Vec::new();
    for i in 0..N {
        let dir = dir.clone();
        let clock = clock.clone();
        handles.push(std::thread::spawn(move || {
            // Each subagent is its own scanner process in production.
            let s = open(dir, clock);
            let mut c = ctx("s1");
            c.agent_id = Some(format!("agent-{i}"));
            let t0 = std::time::Instant::now();
            // All eight write to the SAME session scope's fragment/arm tables,
            // so they contend even though their strike buckets are per-agent.
            s.arm_egress(&c).expect("arm");
            let n = s
                .record_hit(&c, HitStatus::Delivered, None)
                .expect("record");
            (n.strikes, t0.elapsed().as_millis())
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for (strikes, _) in &results {
        assert_eq!(*strikes, 1, "each agent has its own bucket");
    }
    let slowest = results.iter().map(|r| r.1).max().unwrap();
    assert!(
        slowest < 500,
        "slowest fan-out transition {slowest}ms exceeded the hard per-call ceiling"
    );
}
