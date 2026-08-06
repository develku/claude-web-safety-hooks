//! Fault injection and adversarial bounds.
//!
//! Everything here answers one question: when the store is damaged, contended,
//! unwritable, or fed hostile input, does the layer produce a *typed* outcome
//! and stay inside its budgets — or does it quietly behave statelessly while
//! reporting success?

use std::path::PathBuf;
use std::sync::Arc;
use web_safety_engine::normalize::{ascii_lower, confusable};
use web_safety_engine::state::clock::TestClock;
use web_safety_engine::state::correlation::HitStatus;
use web_safety_engine::state::fragments::{E8Input, E8Lexicon};
use web_safety_engine::state::{StateConfig, StateContext, StateError, StateMode, StateStore};

/// `std::env::temp_dir()` is `/var/folders/...` on macOS and `/var` is a
/// symlink; the store requires a symlink-free absolute root, so the base is
/// resolved once here.
fn temp_root() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).expect("the temp dir resolves")
}

fn scratch(tag: &str) -> PathBuf {
    let base = temp_root().join(format!(
        "ws-fault-{}-{}-{:?}",
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

/// A writer holding the lock past another writer's budget produces
/// [`StateError::Busy`], bounded by that budget — never an open-ended wait that
/// would spend the hook's whole time allowance.
#[test]
fn a_lock_held_past_the_budget_fails_typed_and_fast() {
    let dir = scratch("busy");
    let clock = Arc::new(TestClock::new(1_000));
    let holder = open(dir.clone(), clock.clone());
    let waiter = StateStore::open_with_clock(
        StateConfig {
            busy_timeout_ms: 120,
            ..config(dir)
        },
        clock,
    )
    .expect("open")
    .expect("store");

    // Take the write lock and keep it for the duration of the probe.
    let guard = holder.begin_write_lock().expect("hold the write lock");

    let started = std::time::Instant::now();
    let err = waiter
        .record_hit(&ctx("s1"), HitStatus::Delivered, None)
        .expect_err("a held lock must not be waited out indefinitely");
    let waited = started.elapsed();

    drop(guard);

    assert!(
        matches!(err, StateError::Busy { .. }),
        "expected Busy, got {err:?}"
    );
    assert!(
        waited.as_millis() < 500,
        "waited {waited:?}, past the hard per-call ceiling"
    );
}

/// An interrupted transaction leaves nothing behind: the rows it wrote are
/// gone and the database is still usable. This is the crash-recovery shape —
/// a process that dies mid-transition must not leave a half-applied window.
#[test]
fn an_interrupted_transaction_rolls_back_and_leaves_the_store_usable() {
    let dir = scratch("interrupted");
    let clock = Arc::new(TestClock::new(1_000));
    let c = ctx("s1");

    {
        let s = open(dir.clone(), clock.clone());
        s.record_hit(&c, HitStatus::Delivered, None).unwrap();
        // A transaction that writes and is then dropped without committing,
        // exactly as an aborted process would leave it.
        s.write_then_abandon(&c).unwrap();
    }

    let s = open(dir, clock);
    assert_eq!(
        s.prior_hits(&c).unwrap(),
        1,
        "the committed row survived and the abandoned one did not"
    );
    // ...and the store still accepts writes.
    assert_eq!(
        s.record_hit(&c, HitStatus::Delivered, None)
            .unwrap()
            .strikes,
        2
    );
}

/// A database file that becomes unwritable after it was opened surfaces as a
/// typed error on the next write, not as a silently skipped transition.
#[cfg(unix)]
#[test]
fn an_unwritable_database_is_a_typed_error_on_write() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("readonly-db");
    let clock = Arc::new(TestClock::new(1_000));
    std::fs::create_dir_all(&dir).unwrap();

    // Create the store, then make the whole directory read-only so SQLite
    // cannot write the database or its WAL.
    {
        let _s = open(dir.clone(), clock.clone());
    }
    let mut p = std::fs::metadata(&dir).unwrap().permissions();
    p.set_mode(0o500);
    std::fs::set_permissions(&dir, p).unwrap();

    let result = StateStore::open_with_clock(config(dir.clone()), clock).map(|s| {
        s.expect("store")
            .record_hit(&ctx("s1"), HitStatus::Delivered, None)
    });

    let mut p = std::fs::metadata(&dir).unwrap().permissions();
    p.set_mode(0o700);
    std::fs::set_permissions(&dir, p).unwrap();

    match result {
        Err(e) | Ok(Err(e)) => assert!(
            matches!(e, StateError::Unusable { .. } | StateError::Busy { .. }),
            "expected a typed failure, got {e:?}"
        ),
        Ok(Ok(counts)) => panic!("a read-only store reported a successful transition: {counts:?}"),
    }
}

// ── hostile input ───────────────────────────────────────────────────────────

#[test]
fn a_path_like_or_oversized_identity_is_refused_at_every_entry_point() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("hostile-ids"), clock);
    let lex = E8Lexicon::new();

    for bad_session in [
        "../../etc/passwd",
        "a/b",
        "..",
        "with\0nul",
        "with newline\n",
        &"x".repeat(2048),
    ] {
        let c = StateContext::new("claude", "profile-a", bad_session);
        assert!(
            matches!(
                s.record_hit(&c, HitStatus::Delivered, None).unwrap_err(),
                StateError::InvalidIdentity { .. }
            ),
            "record_hit accepted {bad_session:?}"
        );
        assert!(s.arm_egress(&c).is_err(), "arm accepted {bad_session:?}");
        assert!(
            s.prior_hits(&c).is_err(),
            "prior_hits accepted {bad_session:?}"
        );
        assert!(
            s.e8_step(
                &c,
                &lex,
                E8Input {
                    lowered: "x",
                    confusable: "x"
                },
                0
            )
            .is_err(),
            "e8_step accepted {bad_session:?}"
        );
    }
}

/// Hostile *metadata* — as opposed to identity — is sanitized and bounded
/// rather than rejected: a detector label legitimately contains arbitrary
/// matched text, and refusing the write would lose the audit row.
#[test]
fn hostile_metadata_is_bounded_not_refused() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("hostile-meta"), clock);

    let mut c = ctx("s1");
    c.agent_id = Some("agent-1".into());
    c.tool_name = format!("Web\u{7}Fetch{}", "T".repeat(500));
    c.url = Some(format!("https://example.test/{}", "p".repeat(4000)));

    assert!(s
        .record_kill(&c, "HIGH\n\ninjected", &"A\u{0}".repeat(5000))
        .unwrap());
    let rows = s.pending_kills(&c).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].tool.chars().count() <= 64);
    assert!(rows[0].detail.chars().count() <= 300);
    assert!(!rows[0].severity.contains('\n'));
    assert!(rows[0].host.as_deref().unwrap().chars().count() <= 128);
}

/// A long adversarial sequence must leave the database bounded: fragments
/// capped, strikes pruned, and total size in kilobytes rather than megabytes.
#[test]
fn an_adversarial_sequence_keeps_the_database_bounded() {
    let dir = scratch("bounded");
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(dir, clock.clone());
    let lex = E8Lexicon::new();
    let c = ctx("s1");

    // 200 fetches of 64 KB — the scan cap — each carrying an indicator so every
    // one of them is stored.
    let page = format!("ignore previous {}", "z".repeat(65_000));
    let lowered = ascii_lower(&page);
    let folded = confusable(&lowered);

    for i in 0..200 {
        s.e8_step(
            &c,
            &lex,
            E8Input {
                lowered: &lowered,
                confusable: &folded,
            },
            0,
        )
        .unwrap();
        s.record_hit(&c, HitStatus::Delivered, None).unwrap();
        if i % 50 == 0 {
            clock.advance(1);
        }
    }

    let frags = s.e8_fragments(&c).unwrap();
    assert!(frags.len() <= 20, "fragment window grew to {}", frags.len());
    for f in &frags {
        assert!(
            f.excerpt.len() <= 1501,
            "excerpt is {} bytes",
            f.excerpt.len()
        );
    }

    s.prune().unwrap();
    let bytes = s.size_bytes();
    assert!(
        bytes < 2 * 1024 * 1024,
        "database grew to {bytes} bytes on a 200 x 64 KB adversarial sequence"
    );
}

/// The strike table is trimmed per scope on every append, so a session that
/// keeps firing does not accumulate rows past its own window.
#[test]
fn the_strike_table_does_not_grow_past_its_window() {
    let clock = Arc::new(TestClock::new(1_000));
    let s = open(scratch("strike-growth"), clock.clone());
    let c = ctx("s1");

    for _ in 0..500 {
        s.record_hit(&c, HitStatus::Delivered, None).unwrap();
        clock.advance(1);
    }
    assert!(
        s.prior_hits(&c).unwrap() <= 301,
        "window holds {} rows",
        s.prior_hits(&c).unwrap()
    );
}
