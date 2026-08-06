//! Versioned, host-neutral scan contract.
//!
//! The engine never sees Claude / Codex / Hermes hook JSON. [`crate::hosts`]
//! maps a host envelope onto [`ScanRequest`] and encodes [`ScanResponse`] back
//! into that host's response schema; everything in between is host-agnostic.
//!
//! Every failure in this module is a *contract* error, and every contract error
//! is fail-closed at the CLI boundary — an envelope the engine cannot understand
//! must never degrade into "no findings, allow".

use serde::{Deserialize, Serialize};
use std::fmt;

/// Bump only for a breaking change to the request/response shape. Additive,
/// `Option`-typed fields do not need a bump (Hyrum's Law: consumers already
/// tolerate unknown fields, but not a changed meaning for a known one).
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// The label the Bash scanner prints in its `systemMessage`, which the
    /// differential runner parses on both sides.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Nothing to say — Bash exits 0 with no output.
    Allow,
    /// Informational systemMessage; no notification, not a threat count.
    Note,
    /// Operator confirmation required (Bash MEDIUM).
    Ask,
    /// Containment (Bash HIGH).
    Block,
}

/// What the engine was handed, stripped of every host-specific field name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub schema_version: u32,
    /// Originating runtime — recorded for later state scoping, never branched on
    /// by the matcher.
    pub runtime: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The host's task/execution dimension — Claude's `prompt_id`, and whatever
    /// the other runtimes come to expose. Additive and `Option`-typed, so it
    /// needs no [`SCHEMA_VERSION`] bump.
    ///
    /// Absent means the host did not report one, and absent is its **own**
    /// state scope. It is never synthesized from the session id: a fabricated
    /// task id would merge unrelated executions into one bucket, which is the
    /// exact failure the scope key exists to prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    /// The shell command a PRE-call envelope is about to run, when the tool is
    /// a terminal. Layer 6 reads it; a post-call envelope never carries one.
    ///
    /// Additive and `Option`-typed, so it needs no [`SCHEMA_VERSION`] bump —
    /// same reasoning as `task_id` and `state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub content: String,
}

impl ScanRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchemaVersion(self.schema_version));
        }
        Ok(())
    }
}

/// Why a finding fired and, when a suppression layer looked at it, what that
/// layer decided. Kept on the finding rather than in a side channel so the
/// differential runner can explain a divergence without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Survived every gate — counts toward the verdict.
    Kept,
    /// Cleared by Layer 5 structural verification.
    ClearedStructural,
    /// Cleared by the v8.4+ directive context gate.
    ClearedContextGate,
    /// Cleared by the v8.8 structural gate for HIGH control tokens.
    ClearedControlToken,
    /// Kept, but reclassified to INFO at emit time (truncation / topic vocab).
    ReclassifiedInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, e.g. `medium.jailbreak`, `low.unicode.bidi`.
    pub rule_id: String,
    pub severity: Severity,
    /// The matched literal, or the detector's human-readable label — the same
    /// string Bash puts in `FOUND_HIGH` / `FOUND_MEDIUM` / `FOUND_LOW`.
    pub matched: String,
    /// Normalized view the hit came from: one of [`crate::normalize::VIEW_NAMES`],
    /// or `raw` for the codepoint / base64 / leetspeak detectors.
    pub view: String,
    pub disposition: Disposition,
    /// Populated when a suppression layer acted, for the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Finding {
    pub fn counts_toward_verdict(&self) -> bool {
        matches!(self.disposition, Disposition::Kept)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub schema_version: u32,
    pub severity: Severity,
    pub decision: Decision,
    /// Every finding, including suppressed ones — a cleared finding is evidence,
    /// not noise, and dropping it would make a divergence unexplainable.
    pub findings: Vec<Finding>,
    pub truncated: bool,
    pub scanned_bytes: usize,
    pub elapsed_us: u128,
    /// Present only when a state mode other than `off` ran. Additive and
    /// `Option`-typed, so it needs no [`SCHEMA_VERSION`] bump: a consumer that
    /// does not know about state sees exactly the Stage-3 document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<crate::state::StateReport>,
    /// What must replace the tool result before a model reads it, when anything
    /// must. Present only for a containment tier — clean, INFO, LOW and the
    /// content-trust downgrade all deliver the original untouched and carry
    /// `None` here.
    ///
    /// Additive and `Option`-typed, so it needs no [`SCHEMA_VERSION`] bump for
    /// the same reason [`ScanResponse::state`] did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<crate::sanitize::Replacement>,
}

impl ScanResponse {
    pub fn kept(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.counts_toward_verdict())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    MalformedEnvelope(String),
    UnsupportedSchemaVersion(u32),
    UnknownHost(String),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::MalformedEnvelope(why) => write!(f, "malformed envelope: {why}"),
            ContractError::UnsupportedSchemaVersion(v) => write!(
                f,
                "unsupported schema_version {v}; this build speaks {SCHEMA_VERSION}"
            ),
            ContractError::UnknownHost(h) => write!(f, "unknown host: {h}"),
        }
    }
}

impl std::error::Error for ContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ScanRequest {
        ScanRequest {
            schema_version: SCHEMA_VERSION,
            runtime: "claude".into(),
            tool_name: "WebFetch".into(),
            url: Some("https://example.test/a".into()),
            session_id: None,
            task_id: None,
            agent_id: None,
            permission_mode: None,
            command: None,
            content: "hello".into(),
        }
    }

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_maps_to_the_bash_verdict_labels() {
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Info.as_str(), "INFO");
    }

    #[test]
    fn request_round_trips_through_json() {
        let back: ScanRequest =
            serde_json::from_str(&serde_json::to_string(&req()).unwrap()).unwrap();
        assert_eq!(back.content, "hello");
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn a_future_schema_version_is_a_contract_error_not_a_silent_allow() {
        let mut r = req();
        r.schema_version = SCHEMA_VERSION + 1;
        assert!(matches!(
            r.validate().unwrap_err(),
            ContractError::UnsupportedSchemaVersion(_)
        ));
    }

    #[test]
    fn a_current_schema_version_validates() {
        assert!(req().validate().is_ok());
    }

    #[test]
    fn contract_errors_carry_an_operator_readable_message() {
        let e = ContractError::MalformedEnvelope("expected a JSON object".into());
        assert!(e.to_string().contains("expected a JSON object"));
    }
}
