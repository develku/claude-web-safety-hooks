//! The subagent kill ledger — `record_agent_kill`'s `[PENDING-KILLED]` rows.
//!
//! A subagent killed by a `continue:false` verdict resolves in its parent as a
//! silent null: the `stopReason` dies with the agent, because nobody is
//! attached to a subagent to read it. Bash makes the death attributable by
//! writing a `k=v` row to the shared audit log *before* halting, which
//! `web-safety-agent-result.sh` then joins to the resolving Agent call.
//!
//! Three properties this port keeps and one it adds:
//!
//! * **subagent-only** — a main-session halt writes nothing, because the user
//!   reads that stopReason live;
//! * **scoped** by the full namespace plus the agent;
//! * **sanitized** — `detail` is control-stripped and bounded, and is never
//!   relayed to a model (see [`StateStore::summarize_kills`]);
//! * **one-shot** — [`StateStore::consume_kills`] marks rows consumed inside
//!   the same transaction that reads them, so two adapters racing on the same
//!   finding cannot both surface it. Bash's log-grep readers have no such
//!   guarantee; adding it here is what makes the neutral API safe for the
//!   Agent-result and Stop adapters a later stage will wire.

use super::store::{map_sql, StateStore};
use super::{sanitize_detail, sanitize_meta, StateContext, StateError};

const MAX_TOOL_CHARS: usize = 64;
const MAX_HOST_CHARS: usize = 128;
const MAX_SEVERITY_CHARS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub id: i64,
    pub ts: i64,
    pub severity: String,
    pub tool: String,
    /// Authority only. A full URL can carry instruction text in its query
    /// string, so the path and query never survive into the ledger.
    pub host: Option<String>,
    /// Operator-facing detector labels. May embed matched attacker substrings —
    /// never put this in front of a model.
    pub detail: String,
}

impl StateStore {
    /// Returns `false` (writing nothing) for a main-session halt.
    pub fn record_kill(
        &self,
        ctx: &StateContext,
        severity: &str,
        detail: &str,
    ) -> Result<bool, StateError> {
        ctx.validate()?;
        if !ctx.is_subagent() {
            return Ok(false);
        }
        let now = self.now();
        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        tx.execute(
            "INSERT INTO kill_ledger (scope_id, ts, severity, tool, host, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                scope,
                now,
                sanitize_meta(severity, MAX_SEVERITY_CHARS),
                sanitize_meta(&ctx.tool_name, MAX_TOOL_CHARS),
                ctx.url.as_deref().and_then(authority_of),
                sanitize_detail(detail),
            ),
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(true)
    }

    /// Fresh, unconsumed rows for this agent — a read, with no side effect.
    pub fn pending_kills(&self, ctx: &StateContext) -> Result<Vec<LedgerEntry>, StateError> {
        self.read_kills(ctx, false)
    }

    /// Fresh, unconsumed rows, marked consumed in the same transaction.
    pub fn consume_kills(&self, ctx: &StateContext) -> Result<Vec<LedgerEntry>, StateError> {
        self.read_kills(ctx, true)
    }

    fn read_kills(
        &self,
        ctx: &StateContext,
        consume: bool,
    ) -> Result<Vec<LedgerEntry>, StateError> {
        ctx.validate()?;
        if !ctx.is_subagent() {
            return Ok(Vec::new());
        }
        let now = self.now();
        let cutoff = now - self.config().ledger_window_secs;

        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        let mut stmt = tx
            .prepare(
                "SELECT id, ts, severity, tool, host, detail FROM kill_ledger
                 WHERE scope_id = ?1 AND ts >= ?2 AND consumed_at IS NULL
                 ORDER BY id",
            )
            .map_err(|e| map_sql(e, 0))?;
        let rows = stmt
            .query_map((scope, cutoff), |r| {
                Ok(LedgerEntry {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    severity: r.get(2)?,
                    tool: r.get(3)?,
                    host: r.get(4)?,
                    detail: r.get(5)?,
                })
            })
            .map_err(|e| map_sql(e, 0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_sql(e, 0))?;
        drop(stmt);

        if consume {
            // Same transaction as the read — this is the whole one-shot
            // guarantee. `BEGIN IMMEDIATE` already serialized us against the
            // other reader, so it sees an empty set rather than a duplicate.
            tx.execute(
                "UPDATE kill_ledger SET consumed_at = ?3
                 WHERE scope_id = ?1 AND ts >= ?2 AND consumed_at IS NULL",
                (scope, cutoff, now),
            )
            .map_err(|e| map_sql(e, 0))?;
        }
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(rows)
    }

    /// The model-facing sentence: severity via tool (host), and nothing else.
    ///
    /// `detail` is deliberately absent. A detector label is the *matched* text,
    /// which is the attacker's text — relaying it into the orchestrator's
    /// context would re-deliver the injection the kill just prevented.
    pub fn summarize_kills(entries: &[LedgerEntry]) -> String {
        entries
            .iter()
            .map(|e| match &e.host {
                Some(h) if !h.is_empty() => format!("{} via {} ({})", e.severity, e.tool, h),
                _ => format!("{} via {}", e.severity, e.tool),
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// The authority of a URL — everything after `://` and before the first `/`,
/// `?` or `#`, with any userinfo and port removed. Intentionally simple: this
/// is a log/display field, not an SSRF decision (that lives in the egress
/// guard's `normalize_host`, which is far stricter and belongs there).
fn authority_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    // Keep a bracketed IPv6 literal intact; strip a :port from everything else.
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{h}]"))?
    } else {
        host.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(sanitize_meta(&host.to_ascii_lowercase(), MAX_HOST_CHARS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authority_drops_path_query_userinfo_and_port() {
        assert_eq!(
            authority_of("https://user:pw@Example.test:8443/p?q=ignore+all"),
            Some("example.test".into())
        );
        assert_eq!(
            authority_of("http://[2001:db8::1]:80/x"),
            Some("[2001:db8::1]".into())
        );
        assert_eq!(authority_of("no-url"), Some("no-url".into()));
        assert_eq!(authority_of(""), None);
        assert_eq!(authority_of("https:///justpath"), None);
    }

    #[test]
    fn the_summary_is_empty_for_no_findings() {
        assert_eq!(StateStore::summarize_kills(&[]), "");
    }

    #[test]
    fn the_summary_omits_the_host_when_there_is_none() {
        let e = LedgerEntry {
            id: 1,
            ts: 0,
            severity: "HIGH".into(),
            tool: "WebSearch".into(),
            host: None,
            detail: "matched text".into(),
        };
        assert_eq!(StateStore::summarize_kills(&[e]), "HIGH via WebSearch");
    }
}
