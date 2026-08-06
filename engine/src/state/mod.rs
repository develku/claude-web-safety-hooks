//! Runtime-neutral correlation / containment state.
//!
//! Stage 3 shipped a *stateless* scanner: one envelope in, one verdict out. Four
//! of the Bash scanner's protections are not expressible that way — they are
//! statements about a *sequence* of calls:
//!
//! | Bash | here |
//! |---|---|
//! | `record_session_hit` + the 3-strike escalation | [`correlation`] |
//! | the E8 fragment sidecar and its reassembly pass | [`fragments`] |
//! | `arm_egress_guard` / the Layer 6 armed window | [`arm`] |
//! | `record_agent_kill`'s `[PENDING-KILLED]` rows | [`ledger`] |
//! | the `{severity + content-hash}` toast dedup | [`notify`] |
//!
//! Everything here is **host-neutral**. [`StateContext`] carries the runtime,
//! the profile namespace, the session id, the optional task/execution id and
//! the optional agent id; `hosts.rs` may translate a host envelope into one,
//! but no host-specific security rule lives outside this crate.
//!
//! ## The scope key
//!
//! `runtime + namespace + session + task + agent`, in that order
//! ([`STATE_SCOPE_KEYS`]). Task and agent are the two dimensions a host may
//! legitimately leave absent, and an absent dimension is its **own** bucket —
//! never a wildcard that joins every other value. There is no cross-task state:
//! two tasks under one session share nothing, and any future exception has to
//! be written down in the table in `docs/state.md` before it is written in code.
//!
//! ## Three modes, and what a failure means in each
//!
//! | Mode | Database | A state failure |
//! |---|---|---|
//! | `off` (default) | never touched | impossible — nothing runs |
//! | `report` | used | scan still delivered, `state.error` set, `applied=false` |
//! | `enforce` | used | typed containment: [`StateError`] → HIGH/block |
//!
//! `off` is the default for this stage: Bash stays the production authority, the
//! existing stateless CLI path is byte-identical, and the differential fixtures
//! create no state at all.
//!
//! ## Untrusted identity
//!
//! Session ids, agent ids and namespaces arrive from the harness and are
//! attacker-influenceable. They are **never** interpolated into a path or into
//! SQL — the database path is fixed (`<state-dir>/state.db`) and every value is
//! a bound parameter. They are also *validated, not rewritten*: Bash strips a
//! session id to `[A-Za-z0-9_-]` and truncates at 64, which silently maps two
//! distinct sessions onto one bucket. Here an id that does not fit the contract
//! is [`StateError::InvalidIdentity`], because collapsing unrelated executions
//! into a shared bucket is precisely the failure this layer exists to prevent.

pub mod arm;
pub mod clock;
pub mod correlation;
pub mod event;
pub mod fragments;
pub mod hash;
pub mod ledger;
pub mod notify;
pub mod paths;
pub mod store;

pub use event::{StateEvent, StateLayer, StateReport};
pub use store::StateStore;

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Bump for a breaking change to the on-disk schema. A database written by a
/// NEWER build is rejected, never read on a best-effort basis; so is one whose
/// *key shape* this build cannot interpret — see [`StateError::IncompatibleSchema`].
///
/// **v2** added the task/execution dimension to both scope tables. v1 rows
/// carry no task column, so their keys cannot be mapped onto v2 keys without
/// asserting something about them that the writer never said. v1 never shipped
/// (Stage 4 is unreleased), so the strategy is refusal rather than migration:
/// see `docs/state.md` → "Migration contract".
pub const STATE_SCHEMA_VERSION: u32 = 2;

/// The oldest on-disk schema this build can still interpret. Equal to
/// [`STATE_SCHEMA_VERSION`] while no shipped schema predates the current key
/// shape; raise the two together whenever the key shape changes again.
pub const MIN_READABLE_SCHEMA_VERSION: u32 = 2;

/// Bump for a breaking change to [`StateContext`] / [`StateEvent`]. Independent
/// of the scan contract's `SCHEMA_VERSION`: a runtime may speak state v1 while
/// the scan envelope moves on, and vice versa.
///
/// **v2** added `task_id`.
pub const STATE_CONTEXT_VERSION: u32 = 2;

/// The scope key, in order, as `info` reports it to an adapter author.
pub const STATE_SCOPE_KEYS: [&str; 5] = ["runtime", "namespace", "session", "task", "agent"];

/// The 300-second sliding window every Bash correlation site uses
/// (`SESSION_WINDOW`), shared by strikes, fragments and the armed flag.
pub const DEFAULT_WINDOW_SECS: i64 = 300;

/// `WEB_SAFETY_NOTIFY_DEDUP_WINDOW` in `web-safety-scanner.sh`.
pub const DEFAULT_NOTIFY_WINDOW_SECS: i64 = 300;

/// The freshness window `web-safety-agent-result.sh` applies to a
/// `[PENDING-KILLED]` row before it stops being this call's context.
pub const DEFAULT_LEDGER_WINDOW_SECS: i64 = 900;

/// `E8_MAX_FRAGMENTS` / `E8_EXCERPT_SIZE` / `E8_INDICATOR_SCAN_BYTES`.
pub const DEFAULT_MAX_FRAGMENTS: usize = 20;
pub const DEFAULT_EXCERPT_BYTES: usize = 1500;
pub const DEFAULT_INDICATOR_SCAN_BYTES: usize = 4096;

/// Bash bounds `patterns=` to 300 characters after stripping control codes.
pub const MAX_DETAIL_CHARS: usize = 300;

/// A lock wait longer than this would eat the hard per-call ceiling, so it is a
/// configuration error rather than something to discover under contention.
pub const MAX_BUSY_TIMEOUT_MS: u64 = 2_000;

/// Identity fields are bounded well above any real runtime's ids and well below
/// anything that could be used to bloat the database through the key columns.
const MAX_RUNTIME_LEN: usize = 32;
const MAX_NAMESPACE_LEN: usize = 128;
const MAX_ID_LEN: usize = 128;

/// The terminal branch the emit stage took, in the vocabulary of the Bash
/// scanner's exit paths. Every state side effect is a function of this plus the
/// context, which is why it is one enum rather than a bag of booleans: adding a
/// branch forces every matrix in this module to be updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No output at all.
    Clean,
    /// `WEB CONTENT NOTE [INFO]` — truncation caveat / topic vocabulary only.
    Note,
    /// `WEB CONTENT NOTE [LOW SEVERITY]`.
    Low,
    /// `PROMPT INJECTION WARNING [MEDIUM SEVERITY]`.
    Medium,
    /// v8.12.0: a lone subagent `WebSearch` MEDIUM; the result is replaced and
    /// the agent survives.
    Quarantine,
    /// `ESCALATED TO HIGH SEVERITY` — the 3-strike cross-tool verdict.
    Escalated,
    /// `CRITICAL PROMPT INJECTION DETECTED [HIGH SEVERITY]`.
    High,
    /// A HIGH or MEDIUM on a content-trusted host: no halt, no redaction, but
    /// the audit row, the toast and the armed backstop all still happen.
    TrustDowngrade,
}

impl Outcome {
    /// The bucket the differential runner compares on, matching the label the
    /// Bash `systemMessage` carries.
    pub fn verdict_label(self) -> &'static str {
        match self {
            Outcome::Clean => "clean",
            Outcome::Note => "info",
            Outcome::Low => "low",
            Outcome::Medium | Outcome::Quarantine => "medium",
            Outcome::Escalated | Outcome::High => "high",
            // The downgrade emits a plain systemMessage with no severity label;
            // the differential treats it as its own bucket.
            Outcome::TrustDowngrade => "trust_downgrade",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StateMode {
    /// The database is never opened, created, or read.
    #[default]
    Off,
    /// Transitions run; an unusable store degrades to a reported failure.
    Report,
    /// Transitions run; an unusable store is containment.
    Enforce,
}

impl StateMode {
    pub fn parse(s: &str) -> Result<StateMode, StateError> {
        match s {
            "off" => Ok(StateMode::Off),
            "report" => Ok(StateMode::Report),
            "enforce" => Ok(StateMode::Enforce),
            other => Err(StateError::Config {
                why: format!("unknown state mode {other:?}; expected off|report|enforce"),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StateMode::Off => "off",
            StateMode::Report => "report",
            StateMode::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateConfig {
    pub mode: StateMode,
    /// The controlled state root. `<dir>/state.db` is the only file opened.
    pub dir: PathBuf,
    pub window_secs: i64,
    pub notify_window_secs: i64,
    pub ledger_window_secs: i64,
    pub max_fragments: usize,
    pub excerpt_bytes: usize,
    pub indicator_scan_bytes: usize,
    pub busy_timeout_ms: u64,
}

impl Default for StateConfig {
    fn default() -> StateConfig {
        StateConfig {
            mode: StateMode::Off,
            dir: PathBuf::new(),
            window_secs: DEFAULT_WINDOW_SECS,
            notify_window_secs: DEFAULT_NOTIFY_WINDOW_SECS,
            ledger_window_secs: DEFAULT_LEDGER_WINDOW_SECS,
            max_fragments: DEFAULT_MAX_FRAGMENTS,
            excerpt_bytes: DEFAULT_EXCERPT_BYTES,
            indicator_scan_bytes: DEFAULT_INDICATOR_SCAN_BYTES,
            // Short on purpose: 50 concurrent single-row transactions serialize
            // in well under this, and anything longer would put the hard
            // per-call ceiling at the mercy of a stuck writer.
            busy_timeout_ms: 250,
        }
    }
}

/// Everything the state layer needs to know about *who* is asking, with no
/// host-specific field name anywhere in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateContext {
    pub version: u32,
    /// `claude` / `codex` / `hermes` — the originating runtime.
    pub runtime: String,
    /// Profile or user namespace. Two profiles on one machine never share
    /// state. There is no default: an adapter that cannot name the profile it
    /// is running under cannot be given one, because the invented value would
    /// be shared by every other adapter in the same position.
    pub namespace: String,
    /// Session id, as the runtime reports it. Never synthesised.
    pub session_id: String,
    /// Task / execution id **where the host provides one**. `None` (or `""`)
    /// is the legitimate shape for a host that only exposes a session — it is
    /// its own bucket, not a wildcard, and it is never invented from the
    /// session id or from anything else.
    pub task_id: Option<String>,
    /// Subagent id when the call happens inside one; `None` in a main session.
    pub agent_id: Option<String>,
    pub tool_name: String,
    pub url: Option<String>,
    pub permission_mode: Option<String>,
}

impl StateContext {
    pub fn new(runtime: &str, namespace: &str, session_id: &str) -> StateContext {
        StateContext {
            version: STATE_CONTEXT_VERSION,
            runtime: runtime.to_string(),
            namespace: namespace.to_string(),
            session_id: session_id.to_string(),
            task_id: None,
            agent_id: None,
            tool_name: String::new(),
            url: None,
            permission_mode: None,
        }
    }

    /// `""` for the main session — the same "one bucket per agent, plus one for
    /// the main session" split Bash gets from its per-agent state filename.
    pub fn agent_key(&self) -> &str {
        self.agent_id.as_deref().unwrap_or("")
    }

    /// `""` when the host exposes no task. That empty key is a *bucket*, shared
    /// only by other calls the same host reported the same way — never a match
    /// for a named task.
    pub fn task_key(&self) -> &str {
        self.task_id.as_deref().unwrap_or("")
    }

    pub fn is_subagent(&self) -> bool {
        self.agent_id.as_deref().is_some_and(|a| !a.is_empty())
    }

    pub fn validate(&self) -> Result<(), StateError> {
        if self.version != STATE_CONTEXT_VERSION {
            return Err(StateError::UnsupportedContextVersion {
                found: self.version,
                supported: STATE_CONTEXT_VERSION,
            });
        }
        check_identity("runtime", &self.runtime, MAX_RUNTIME_LEN, false)?;
        check_identity("namespace", &self.namespace, MAX_NAMESPACE_LEN, false)?;
        check_identity("session_id", &self.session_id, MAX_ID_LEN, false)?;
        if let Some(t) = &self.task_id {
            check_identity("task_id", t, MAX_ID_LEN, true)?;
        }
        if let Some(a) = &self.agent_id {
            check_identity("agent_id", a, MAX_ID_LEN, true)?;
        }
        Ok(())
    }
}

/// Identity charset: alphanumerics plus the separators real runtimes actually
/// emit in ids (`-` in UUIDs, `_` and `.` in profile names, `:` and `@` in
/// namespaced tool/agent ids). Deliberately excludes `/`, `\`, whitespace and
/// every control code — not because those would reach a path (they cannot; the
/// path is fixed) but because an id that can express a path is an id whose
/// author expected path semantics somewhere.
fn identity_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@' | '+')
}

fn check_identity(
    field: &str,
    value: &str,
    max: usize,
    allow_empty: bool,
) -> Result<(), StateError> {
    let invalid = |why: &str| {
        Err(StateError::InvalidIdentity {
            field: field.to_string(),
            why: why.to_string(),
        })
    };
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            invalid(
                "is missing or empty — there is no default and no synthetic bucket, \
                 because one would collapse unrelated executions into shared state",
            )
        };
    }
    if value.len() > max {
        return invalid(&format!(
            "longer than {max} bytes (truncating would merge distinct scopes)"
        ));
    }
    if value == "." || value == ".." {
        return invalid("is a path traversal token");
    }
    if let Some(bad) = value.chars().find(|c| !identity_char_ok(*c)) {
        return invalid(&format!("contains the disallowed character {bad:?}"));
    }
    Ok(())
}

/// Every way the state layer can refuse to do its job. There is no variant that
/// means "carried on statelessly and it was fine".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// The configuration itself is wrong (bad mode, no dir, lock budget past
    /// the hook ceiling).
    Config {
        why: String,
    },
    /// The state root or database file is not somewhere we are willing to write:
    /// a symlink, a non-directory, or a path with a traversal component.
    UnsafePath {
        path: String,
        why: String,
    },
    /// Present but unusable: corrupt, read-only, or locked past the budget.
    Unusable {
        why: String,
    },
    /// Written by a build that speaks a schema this one does not.
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    /// Older than this build, and the older key shape cannot be interpreted
    /// under the current one. Refused rather than migrated: reading it would
    /// mean asserting a scope dimension its writer never recorded.
    IncompatibleSchema {
        found: u32,
        oldest_readable: u32,
        why: String,
    },
    UnsupportedContextVersion {
        found: u32,
        supported: u32,
    },
    /// An identity field that would have to be rewritten to be usable.
    InvalidIdentity {
        field: String,
        why: String,
    },
    /// A lock that could not be taken inside the configured budget.
    Busy {
        waited_ms: u64,
    },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Config { why } => write!(f, "state configuration: {why}"),
            StateError::UnsafePath { path, why } => {
                write!(f, "refusing to use state path {path}: {why}")
            }
            StateError::Unusable { why } => write!(f, "state store unusable: {why}"),
            StateError::UnsupportedSchema { found, supported } => write!(
                f,
                "state schema {found} was written by a newer build; this one speaks {supported}"
            ),
            StateError::IncompatibleSchema {
                found,
                oldest_readable,
                why,
            } => write!(
                f,
                "state schema {found} predates the oldest readable schema {oldest_readable} \
                 and its key shape cannot be interpreted ({why}); remove the state root to start clean"
            ),
            StateError::UnsupportedContextVersion { found, supported } => write!(
                f,
                "state context version {found} is not supported; this build speaks {supported}"
            ),
            StateError::InvalidIdentity { field, why } => {
                write!(f, "state identity {field} {why}")
            }
            StateError::Busy { waited_ms } => {
                write!(f, "state lock not acquired within {waited_ms}ms")
            }
        }
    }
}

impl std::error::Error for StateError {}

/// Strip control codes and bound to `MAX_DETAIL_CHARS`, mirroring
/// `record_agent_kill`'s `tr -d '\000-\037\177' | cut -c1-300`.
///
/// Applied to every attacker-influenced *metadata* string before it is
/// persisted. Unlike identity, metadata is sanitized rather than rejected:
/// a detector label legitimately contains arbitrary matched text, and refusing
/// to record the kill because the label was ugly would lose the audit row.
pub fn sanitize_detail(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_DETAIL_CHARS)
        .collect()
}

/// Bound a metadata string to `max` characters after control-stripping.
pub fn sanitize_meta(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_round_trip_through_their_cli_spelling() {
        for m in [StateMode::Off, StateMode::Report, StateMode::Enforce] {
            assert_eq!(StateMode::parse(m.as_str()).unwrap(), m);
        }
        assert!(matches!(
            StateMode::parse("on").unwrap_err(),
            StateError::Config { .. }
        ));
    }

    #[test]
    fn the_default_mode_is_off() {
        assert_eq!(StateConfig::default().mode, StateMode::Off);
        assert_eq!(StateMode::default(), StateMode::Off);
    }

    #[test]
    fn a_main_session_and_a_subagent_are_different_buckets() {
        let mut main = StateContext::new("claude", "p", "s");
        assert_eq!(main.agent_key(), "");
        assert!(!main.is_subagent());
        main.agent_id = Some("a1".into());
        assert_eq!(main.agent_key(), "a1");
        assert!(main.is_subagent());
    }

    #[test]
    fn an_empty_agent_id_is_the_main_session_not_an_invalid_one() {
        let mut c = StateContext::new("claude", "p", "s");
        c.agent_id = Some(String::new());
        c.validate().expect("an empty agent id is the main session");
        assert!(!c.is_subagent());
    }

    #[test]
    fn detail_sanitization_strips_control_codes_and_bounds_length() {
        let hostile = format!("a\nb\u{7f}c{}", "x".repeat(400));
        let s = sanitize_detail(&hostile);
        assert!(!s.contains('\n') && !s.contains('\u{7f}'));
        assert_eq!(s.chars().count(), MAX_DETAIL_CHARS);
        assert!(s.starts_with("abc"));
    }

    #[test]
    fn a_future_context_version_is_rejected() {
        let mut c = StateContext::new("claude", "p", "s");
        c.version = STATE_CONTEXT_VERSION + 1;
        assert!(matches!(
            c.validate().unwrap_err(),
            StateError::UnsupportedContextVersion { .. }
        ));
    }
}
