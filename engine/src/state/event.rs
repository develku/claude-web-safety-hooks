//! The transition orchestrator — one scan result in, one modelled outcome out.
//!
//! This is the only place that knows the *order* of the Bash emit stage, and
//! the order is load-bearing:
//!
//! 1. the pre-append strike read (which also gates E8 storage);
//! 2. a `C` row per Layer-5-cleared MEDIUM;
//! 3. the E8 step, which can promote a clean fetch to HIGH;
//! 4. the terminal branch — HIGH, then MEDIUM (with escalation *before*
//!    quarantine), then LOW/INFO, then clean.
//!
//! Two orderings inside that are easy to get subtly wrong and are pinned by
//! tests: the content-trust downgrade happens **before** the strike is
//! recorded, so a trusted source never feeds escalation; and the escalation
//! check happens **before** the search quarantine, so once the window holds a
//! genuine delivered hit the coordinated-attack signal outranks the
//! false-positive relief.
//!
//! [`StateLayer`] owns the failure semantics. It never returns `Err`: an
//! unusable store is a *reported* condition in `report` mode and *containment*
//! in `enforce` mode, and both are visible in the [`StateReport`] rather than
//! being papered over as a successful stateless scan.

use serde::{Deserialize, Serialize};

use super::arm::arm_decision;
use super::clock::{Clock, SystemClock};
use super::correlation::HitStatus;
use super::fragments::{E8Input, E8Lexicon};
use super::hash::{notify_hash, quarantine_hash};
use super::{
    Outcome, StateConfig, StateContext, StateError, StateMode, StateStore, STATE_CONTEXT_VERSION,
};
use crate::contract::{Decision, Disposition, ScanResponse, Severity};
use crate::normalize::{ascii_lower, confusable};
use std::sync::Arc;

/// Everything the transition needs beyond the context: the stateless verdict,
/// the bytes it was reached on, and the two operator switches that change which
/// branch the emit stage takes.
pub struct StateEvent<'a> {
    pub response: &'a ScanResponse,
    /// The scanned (post-cap) content — the same bytes Bash hashes and lowers.
    pub content: &'a str,
    /// The URL's host is on the operator's content-trust list.
    pub content_trusted: bool,
    /// `WEB_SAFETY_SEARCH_QUARANTINE_DISABLE=0` — the v8.12.0 default.
    pub quarantine_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateReport {
    pub version: u32,
    pub mode: StateMode,
    /// Whether the transition actually reached the store.
    pub applied: bool,
    /// Set whenever the store could not be used. Never `None` alongside
    /// `applied == false` in a non-`off` mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `enforce` could not use the store, so the call is contained.
    pub containment: bool,
    pub outcome: Outcome,
    pub strikes: u32,
    pub real_strikes: u32,
    pub escalated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flagged_tools: Vec<String>,
    /// Cross-fragment patterns firing for the first time this session.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reassembled: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub participating: Vec<String>,
    pub fragment_count: u32,
    /// This step armed the guard.
    pub armed: bool,
    /// The guard's window is still open AFTER this step — which is what an
    /// egress hook actually reads, and what the Bash flag file observes. A step
    /// that arms nothing can still leave `arm_active` true from an earlier one.
    pub arm_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arm_reason: Option<String>,
    pub ledgered: bool,
    /// The severity of the toast that survived dedup; `None` means no toast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<String>,
    /// Layer-5-cleared MEDIUMs recorded as `C` rows.
    pub cleared_rows: u32,
}

/// The `off`-mode, nothing-happened report. Exists so a caller that needs to
/// state one field (a test pinning an outcome, an adapter building a stub) does
/// not have to restate twenty defaults and silently drift from them later.
impl Default for StateReport {
    fn default() -> StateReport {
        StateReport::base(StateMode::Off, Outcome::Clean)
    }
}

impl StateReport {
    fn base(mode: StateMode, outcome: Outcome) -> StateReport {
        StateReport {
            version: STATE_CONTEXT_VERSION,
            mode,
            applied: false,
            error: None,
            containment: false,
            outcome,
            strikes: 0,
            real_strikes: 0,
            escalated: false,
            flagged_tools: Vec::new(),
            reassembled: Vec::new(),
            participating: Vec::new(),
            fragment_count: 0,
            armed: false,
            arm_active: false,
            arm_reason: None,
            ledgered: false,
            notify: None,
            cleared_rows: 0,
        }
    }
}

/// The store plus the derived lexicon, with the mode's failure policy applied.
pub struct StateLayer {
    mode: StateMode,
    store: Result<Option<StateStore>, StateError>,
    lex: E8Lexicon,
}

impl StateLayer {
    pub fn open(cfg: StateConfig) -> StateLayer {
        StateLayer::open_with_clock(cfg, Arc::new(SystemClock))
    }

    pub fn open_with_clock(cfg: StateConfig, clock: Arc<dyn Clock>) -> StateLayer {
        let mode = cfg.mode;
        StateLayer {
            mode,
            store: StateStore::open_with_clock(cfg, clock),
            // Built even in `off` mode: it is pure CPU, costs nothing on disk,
            // and building it lazily would put a first-call latency spike
            // exactly where the hard per-call ceiling is measured.
            lex: E8Lexicon::new(),
        }
    }

    pub fn mode(&self) -> StateMode {
        self.mode
    }

    pub fn store(&self) -> Option<&StateStore> {
        self.store.as_ref().ok().and_then(|s| s.as_ref())
    }

    /// The report a non-`off` mode owes its caller when the *context* is
    /// unusable — built without opening, creating or reading any store.
    ///
    /// This exists because "who is asking" has to be settled before "what does
    /// the database say". A call with no session identity cannot be given a
    /// bucket: any bucket it were given would be shared with every other call
    /// in the same position, which is precisely the cross-execution contamination
    /// the layer exists to prevent. So the refusal happens here, one step before
    /// [`StateStore::open`] would have created the file.
    pub fn rejected(mode: StateMode, event: &StateEvent<'_>, err: &StateError) -> StateReport {
        failure_report(mode, stateless_outcome(event), err.to_string())
    }

    /// Run the transition. Never fails: see the module docs.
    pub fn apply(&self, ctx: &StateContext, event: &StateEvent<'_>) -> StateReport {
        let stateless = stateless_outcome(event);
        if self.mode == StateMode::Off {
            return StateReport::base(StateMode::Off, stateless);
        }

        // Identity before storage, here too: `apply` is also reachable directly
        // by a library caller that never went through the CLI's pre-check.
        if let Err(e) = ctx.validate() {
            return self.failed(stateless, e.to_string());
        }

        let store = match &self.store {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Unreachable in practice — `open` only yields `None` for
                // `off`, which returned above. Treated as a failure rather than
                // as success, because "no store, mode says there should be one"
                // is exactly the silent-stateless case this layer forbids.
                return self.failed(stateless, "state store unavailable".to_string());
            }
            Err(e) => return self.failed(stateless, e.to_string()),
        };

        match self.run(store, ctx, event, stateless) {
            Ok(r) => r,
            Err(e) => self.failed(stateless, e.to_string()),
        }
    }

    /// The failure shape for whichever mode we are in.
    fn failed(&self, stateless: Outcome, why: String) -> StateReport {
        failure_report(self.mode, stateless, why)
    }

    fn run(
        &self,
        store: &StateStore,
        ctx: &StateContext,
        event: &StateEvent<'_>,
        stateless: Outcome,
    ) -> Result<StateReport, StateError> {
        let mut r = StateReport::base(self.mode, stateless);
        r.applied = true;

        let high: Vec<String> = kept_labels(event.response, Severity::High);
        let mut med: Vec<String> = kept_labels(event.response, Severity::Medium);
        let low_kept = event
            .response
            .findings
            .iter()
            .any(|f| f.severity == Severity::Low && f.counts_toward_verdict());

        // 1. the pre-append read — also the E8 store gate.
        let prior = store.prior_hits(ctx)?;
        r.flagged_tools = store.flagged_tools(ctx)?;

        // 2. one C row per Layer-5-cleared MEDIUM, exactly where Bash calls
        //    `record_session_hit cleared` inside the verifier loop.
        for f in &event.response.findings {
            if f.severity == Severity::Medium && f.disposition == Disposition::ClearedStructural {
                store.record_hit(ctx, HitStatus::Cleared, None)?;
                r.cleared_rows += 1;
            }
        }

        // 3. E8 — may promote an otherwise clean fetch to HIGH.
        let lowered = ascii_lower(event.content);
        let folded = confusable(&lowered);
        let reassembly = store.e8_step(
            ctx,
            &self.lex,
            E8Input {
                lowered: &lowered,
                confusable: &folded,
            },
            prior,
        )?;
        r.fragment_count = reassembly.fragment_count;
        r.reassembled = reassembly.new_matches.clone();
        r.participating = reassembly.participating.clone();

        let mut high = high;
        for m in &reassembly.new_matches {
            high.push(format!("[REASSEMBLED] {m}"));
        }
        // A reassembled pattern is promoted OUT of the MEDIUM set: Bash pushes
        // it into UNIQUE_HIGH and the HIGH branch owns the verdict from there.
        med.retain(|m| !reassembly.new_matches.contains(&ascii_lower(m)));

        // 4. the terminal branch.
        let outcome = if !high.is_empty() {
            if event.content_trusted {
                Outcome::TrustDowngrade
            } else {
                store.record_hit(ctx, HitStatus::Delivered, None)?;
                Outcome::High
            }
        } else if !med.is_empty() {
            if event.content_trusted {
                Outcome::TrustDowngrade
            } else {
                let quarantine =
                    event.quarantine_enabled && ctx.tool_name == "WebSearch" && ctx.is_subagent();
                let counts = if quarantine {
                    store.record_hit(
                        ctx,
                        HitStatus::Quarantined,
                        Some(&quarantine_hash(event.content)),
                    )?
                } else {
                    store.record_hit(ctx, HitStatus::Delivered, None)?
                };
                r.strikes = counts.strikes;
                r.real_strikes = counts.real_strikes;

                // Escalation outranks quarantine: once the window holds a
                // genuine delivered hit, the coordinated-attack signal wins.
                if counts.escalates() {
                    r.escalated = true;
                    Outcome::Escalated
                } else if quarantine {
                    Outcome::Quarantine
                } else {
                    Outcome::Medium
                }
            }
        } else {
            // LOW / INFO / clean: the state layer has no branch of its own here.
            // `low_kept` is read only to assert that fact holds — a LOW finding
            // must never reach a state transition.
            debug_assert!(
                !low_kept || matches!(stateless, Outcome::Low | Outcome::Note),
                "a LOW finding reached a non-LOW stateless outcome: {stateless:?}"
            );
            stateless
        };
        r.outcome = outcome;

        // The HIGH branch's strike is recorded above but its counters were not
        // read back; do it once here so every branch reports the same numbers.
        if matches!(outcome, Outcome::High) && !event.content_trusted {
            let seen = store.prior_hits(ctx)?;
            r.strikes = r.strikes.max(seen);
            r.real_strikes = r.real_strikes.max(1);
        }

        // 5. side effects, in the same order and under the same conditions.
        if let Some(reason) =
            arm_decision(outcome, ctx.is_subagent(), ctx.permission_mode.as_deref())
        {
            store.arm_egress(ctx)?;
            r.armed = true;
            r.arm_reason = Some(reason.as_str().to_string());
        }
        // Read the window back rather than inferring it from `armed`: an
        // earlier step in this session may have opened it, and that is exactly
        // what the egress guard will see.
        r.arm_active = store.armed(ctx)?.is_some();

        if let Some(severity) = kill_severity(outcome) {
            r.ledgered = store.record_kill(ctx, severity, &labels_for(&high, &med))?;
        }

        if let Some(severity) = notify_severity(outcome) {
            if store.notify_allowed(ctx, severity, &notify_hash(event.content))? {
                r.notify = Some(severity.to_string());
            }
        }

        Ok(r)
    }
}

/// One shape for every non-`off` failure, whether the store was unreadable or
/// the caller could not be identified at all.
///
/// `enforce` takes the HIGH branch because a call whose correlation state is
/// unavailable *cannot know it is not the third strike*; reporting the weaker
/// verdict would be a fail-open. `report` keeps the stateless verdict and says,
/// in `error`, that the transition did not happen — it never claims a failed
/// transition succeeded.
fn failure_report(mode: StateMode, stateless: Outcome, why: String) -> StateReport {
    let contained = mode == StateMode::Enforce;
    let mut r = StateReport::base(mode, if contained { Outcome::High } else { stateless });
    r.error = Some(why);
    r.containment = contained;
    r
}

/// The branch the stateless scan alone would reach — everything the state layer
/// can do is to promote it (E8, escalation) or reclassify it (trust downgrade,
/// quarantine).
fn stateless_outcome(event: &StateEvent<'_>) -> Outcome {
    let r = event.response;
    // Read the DECISION the policy layer already reached rather than
    // re-deriving one from the findings. Re-deriving is how the INFO note gets
    // lost: a truncation-coverage or topic-vocabulary finding is
    // `ReclassifiedInfo`, so it does not "count toward the verdict" — yet the
    // response is still a Note, and turning it into Allow would silently drop
    // the caveat that says part of the page was never scanned.
    match r.decision {
        Decision::Block => {
            if event.content_trusted {
                Outcome::TrustDowngrade
            } else {
                Outcome::High
            }
        }
        Decision::Ask => {
            if event.content_trusted {
                Outcome::TrustDowngrade
            } else {
                Outcome::Medium
            }
        }
        Decision::Note if r.severity >= Severity::Low => Outcome::Low,
        Decision::Note => Outcome::Note,
        Decision::Allow => Outcome::Clean,
    }
}

/// Which outcomes write a `[PENDING-KILLED]` row (subagent only — the ledger
/// call itself is a no-op in a main session).
fn kill_severity(outcome: Outcome) -> Option<&'static str> {
    match outcome {
        Outcome::High => Some("HIGH"),
        Outcome::Escalated => Some("ESCALATED"),
        Outcome::Medium => Some("MEDIUM"),
        // No agent died in a quarantine, and Layer 7 must not report a death
        // to the parent that never happened.
        Outcome::Quarantine
        | Outcome::TrustDowngrade
        | Outcome::Low
        | Outcome::Note
        | Outcome::Clean => None,
    }
}

fn notify_severity(outcome: Outcome) -> Option<&'static str> {
    match outcome {
        Outcome::High | Outcome::Escalated => Some("HIGH"),
        Outcome::Medium | Outcome::Quarantine => Some("MEDIUM"),
        Outcome::TrustDowngrade | Outcome::Low => Some("LOW"),
        // An INFO note is explicitly not a threat: audit line, no desktop toast.
        Outcome::Note | Outcome::Clean => None,
    }
}

fn kept_labels(r: &ScanResponse, severity: Severity) -> Vec<String> {
    r.findings
        .iter()
        .filter(|f| f.severity == severity && f.counts_toward_verdict())
        .map(|f| f.matched.clone())
        .collect()
}

/// Operator-facing detector labels for the ledger row. Bounded and stripped by
/// [`super::sanitize_detail`] on the way in.
fn labels_for(high: &[String], med: &[String]) -> String {
    let mut all: Vec<&str> = high.iter().map(String::as_str).collect();
    all.extend(med.iter().map(String::as_str));
    all.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_real_death_is_ledgered() {
        assert_eq!(kill_severity(Outcome::High), Some("HIGH"));
        assert_eq!(kill_severity(Outcome::Escalated), Some("ESCALATED"));
        assert_eq!(kill_severity(Outcome::Medium), Some("MEDIUM"));
        assert_eq!(kill_severity(Outcome::Quarantine), None);
        assert_eq!(kill_severity(Outcome::TrustDowngrade), None);
        assert_eq!(kill_severity(Outcome::Clean), None);
    }

    #[test]
    fn an_info_note_never_toasts() {
        assert_eq!(notify_severity(Outcome::Note), None);
        assert_eq!(notify_severity(Outcome::Clean), None);
        assert_eq!(notify_severity(Outcome::Low), Some("LOW"));
        assert_eq!(notify_severity(Outcome::TrustDowngrade), Some("LOW"));
        assert_eq!(notify_severity(Outcome::Quarantine), Some("MEDIUM"));
    }

    #[test]
    fn ledger_labels_join_both_tiers() {
        assert_eq!(
            labels_for(&["a".into()], &["b".into(), "c".into()]),
            "a, b, c"
        );
        assert_eq!(labels_for(&[], &[]), "");
    }
}
