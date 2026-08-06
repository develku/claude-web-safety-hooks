//! The Layer 6 armed window — `arm_egress_guard` and the flag file it writes.
//!
//! Bash writes `/tmp/web-safety-session-<id>-armed` and `web-safety-egress.sh`
//! escalates outbound network commands to a confirmation while that timestamp
//! is fresher than `SESSION_WINDOW`. Here it is one row keyed by the SESSION
//! scope — deliberately not the agent scope, because a subagent's HIGH has to
//! arm the window its parent's outbound calls are checked against.
//!
//! [`arm_decision`] is a pure function so the matrix can be read (and tested)
//! without a database. It is the whole of the Bash arming policy in one place:
//! the v8.6 rule that a single subagent MEDIUM arms only where the egress guard
//! enforces silently is the subtle member, and the one an accidental
//! simplification would erase.

use super::store::{map_sql, StateStore};
use super::{Outcome, StateContext, StateError};

/// Why the guard was armed. Carried into the report so an operator reading a
/// `state.armed` never has to re-derive which branch fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmReason {
    /// A surviving HIGH — definitive injection indicators.
    High,
    /// The 3-strike cross-tool escalation.
    Escalated,
    /// A content-trusted source: nothing was halted or redacted, so the
    /// outbound guard IS the backstop.
    TrustDowngrade,
    /// v8.6: a lone subagent MEDIUM, but only in a permission mode where the
    /// egress guard enforces as a silent hard block — the one place the
    /// backstop is load-bearing and the ask-flood cannot happen.
    SubagentMediumNonInteractive,
}

impl ArmReason {
    pub fn as_str(self) -> &'static str {
        match self {
            ArmReason::High => "high",
            ArmReason::Escalated => "escalated",
            ArmReason::TrustDowngrade => "trust_downgrade",
            ArmReason::SubagentMediumNonInteractive => "subagent_medium_non_interactive",
        }
    }
}

/// The permission modes where the egress guard hard-blocks instead of asking.
/// An unknown or absent mode is treated as interactive — the conservative
/// reading, and the one that matches a harness that omits the field.
pub const NON_INTERACTIVE_MODES: [&str; 3] = ["bypassPermissions", "auto", "dontAsk"];

pub fn is_non_interactive(mode: Option<&str>) -> bool {
    mode.is_some_and(|m| NON_INTERACTIVE_MODES.contains(&m))
}

/// `None` when this outcome does not arm.
pub fn arm_decision(
    outcome: Outcome,
    is_subagent: bool,
    permission_mode: Option<&str>,
) -> Option<ArmReason> {
    match outcome {
        Outcome::High => Some(ArmReason::High),
        Outcome::Escalated => Some(ArmReason::Escalated),
        Outcome::TrustDowngrade => Some(ArmReason::TrustDowngrade),
        Outcome::Medium if is_subagent && is_non_interactive(permission_mode) => {
            Some(ArmReason::SubagentMediumNonInteractive)
        }
        // A quarantined result was fully replaced: zero bytes reached the model,
        // so there is nothing for an outbound flow to carry back out.
        Outcome::Medium | Outcome::Quarantine | Outcome::Low | Outcome::Note | Outcome::Clean => {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmState {
    pub armed_at: i64,
    /// `armed_at + window`; the window is inclusive of this second, matching
    /// Bash's `[ $(( NOW - ARMED_AT )) -le "$WINDOW" ]`.
    pub expires_at: i64,
}

impl StateStore {
    /// Arm (or re-arm) the session's outbound guard. Idempotent: re-arming
    /// refreshes the timestamp rather than appending, exactly like the
    /// single-line flag file it replaces.
    pub fn arm_egress(&self, ctx: &StateContext) -> Result<ArmState, StateError> {
        ctx.validate()?;
        let now = self.now();
        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        tx.execute(
            "INSERT INTO armed (session_scope_id, armed_at) VALUES (?1, ?2)
             ON CONFLICT (session_scope_id) DO UPDATE SET armed_at = excluded.armed_at",
            (scope, now),
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(ArmState {
            armed_at: now,
            expires_at: now + self.config().window_secs,
        })
    }

    /// The armed window if it is still fresh. A stale row reads as `None` and
    /// is left for [`StateStore::prune`] — reading and expiring in one atomic
    /// step is what lets a future adapter consume it without a second race.
    pub fn armed(&self, ctx: &StateContext) -> Result<Option<ArmState>, StateError> {
        ctx.validate()?;
        let now = self.now();
        let cutoff = now - self.config().window_secs;
        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        let armed_at: Option<i64> = tx
            .query_row(
                "SELECT armed_at FROM armed WHERE session_scope_id = ?1 AND armed_at >= ?2",
                (scope, cutoff),
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(map_sql(other, 0)),
            })?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(armed_at.map(|armed_at| ArmState {
            armed_at,
            expires_at: armed_at + self.config().window_secs,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_permission_mode_is_treated_as_interactive() {
        assert!(!is_non_interactive(None));
        assert!(!is_non_interactive(Some("")));
        assert!(!is_non_interactive(Some("default")));
        assert!(is_non_interactive(Some("dontAsk")));
    }

    #[test]
    fn every_arm_reason_has_a_stable_label() {
        for r in [
            ArmReason::High,
            ArmReason::Escalated,
            ArmReason::TrustDowngrade,
            ArmReason::SubagentMediumNonInteractive,
        ] {
            assert!(!r.as_str().is_empty());
        }
    }
}
