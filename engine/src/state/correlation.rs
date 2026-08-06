//! Cross-call correlation — the port of `record_session_hit`.
//!
//! Bash appends one row per adjudicated finding to a per-scope state file and
//! then recounts the window *inside the same `mkdir` lock*. That lock is the
//! whole point: before v8 the count was taken once at script start, so N
//! parallel scanners all read the same pre-append total and none of them ever
//! reached the third strike. Here the append and the recount are one
//! `BEGIN IMMEDIATE` transaction, which gives the same guarantee without a
//! spin loop, a stale-lock heuristic, or an unlocked last-resort append.
//!
//! Two counters come back because a quarantined hit is weaker evidence than a
//! delivered one:
//!
//! * [`Counts::strikes`] — the total. `Q` rows collapse by content hash; `H`
//!   rows count one per row.
//! * [`Counts::real_strikes`] — `H` rows only. Escalation requires at least one,
//!   because the 3-strike rule measures *model exposure* and a fully-replaced
//!   result exposed the model to zero bytes.

use rusqlite::Transaction;

use super::store::{map_sql, StateStore};
use super::{sanitize_meta, StateContext, StateError};

/// Escalation needs this many fresh strikes …
pub const ESCALATION_STRIKES: u32 = 3;
/// … and at least this many of them genuinely delivered to the model.
pub const ESCALATION_REAL_STRIKES: u32 = 1;

const MAX_TOOL_CHARS: usize = 64;
/// `TOOL_URL=$(… | cut -c1-256)` in the Bash scanner.
const MAX_URL_CHARS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitStatus {
    /// `H` — a genuine finding that reached the model.
    Delivered,
    /// `C` — Layer 5's structural verifier cleared it. Never counts.
    Cleared,
    /// `Q` — quarantined; the result was replaced, so the model saw nothing.
    Quarantined,
}

impl HitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            HitStatus::Delivered => "H",
            HitStatus::Cleared => "C",
            HitStatus::Quarantined => "Q",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub strikes: u32,
    pub real_strikes: u32,
}

impl Counts {
    /// `[ "$SESSION_HITS_NOW" -ge 3 ] && [ "$SESSION_REAL_HITS_NOW" -ge 1 ]`.
    pub fn escalates(&self) -> bool {
        self.strikes >= ESCALATION_STRIKES && self.real_strikes >= ESCALATION_REAL_STRIKES
    }
}

impl StateStore {
    /// Append one row and recount the window, atomically.
    ///
    /// `content_hash` is meaningful only for [`HitStatus::Quarantined`]; an
    /// empty one is stored as NULL, which makes the row count *once* rather
    /// than collapsing with every other hashless quarantine — Bash's
    /// `key = ($5 == "" ? "nr:" NR : "q:" $5)` fail-toward-counting rule.
    pub fn record_hit(
        &self,
        ctx: &StateContext,
        status: HitStatus,
        content_hash: Option<&str>,
    ) -> Result<Counts, StateError> {
        ctx.validate()?;
        let now = self.now();
        let cutoff = now - self.config().window_secs;
        let hash = match status {
            HitStatus::Quarantined => content_hash.filter(|h| !h.is_empty()),
            // A hash on a non-Q row would be dead data that the collapse query
            // must then be careful to ignore. Drop it at the boundary instead.
            _ => None,
        };

        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        tx.execute(
            "INSERT INTO hits (scope_id, ts, tool, url, status, content_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                scope,
                now,
                sanitize_meta(&ctx.tool_name, MAX_TOOL_CHARS),
                sanitize_meta(ctx.url.as_deref().unwrap_or("no-url"), MAX_URL_CHARS),
                status.as_str(),
                hash.map(|h| sanitize_meta(h, 64)),
            ),
        )
        .map_err(|e| map_sql(e, 0))?;
        // Bounded growth: Bash rewrites the state file minus expired rows on
        // every run, so the equivalent trim belongs in the same critical
        // section. Scoped to this bucket, so it can never evict another
        // session's, agent's, profile's or runtime's evidence.
        tx.execute(
            "DELETE FROM hits WHERE scope_id = ?1 AND ts < ?2",
            (scope, cutoff),
        )
        .map_err(|e| map_sql(e, 0))?;
        let counts = count_window(&tx, scope, cutoff)?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(counts)
    }

    /// The pre-append read: `SESSION_HITS` in Bash, which gates the E8 store
    /// decision and builds the flagged-tools message. Same window and same
    /// "not cleared" filter as the recount, but no hash collapse — Bash counts
    /// *lines* here (`awk … | wc -l`).
    pub fn prior_hits(&self, ctx: &StateContext) -> Result<u32, StateError> {
        ctx.validate()?;
        let cutoff = self.now() - self.config().window_secs;
        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        let n: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM hits
                 WHERE scope_id = ?1 AND ts >= ?2 AND status <> 'C'",
                (scope, cutoff),
                |r| r.get(0),
            )
            .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(n.max(0) as u32)
    }

    /// `SESSION_FLAGGED_TOOLS` — the sorted, de-duplicated tools that carry a
    /// non-cleared row inside the window. Sorted with SQLite's BINARY
    /// collation, which is the same ordering `sort -u` gives in the C locale.
    pub fn flagged_tools(&self, ctx: &StateContext) -> Result<Vec<String>, StateError> {
        ctx.validate()?;
        let cutoff = self.now() - self.config().window_secs;
        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        let mut stmt = tx
            .prepare(
                "SELECT DISTINCT tool FROM hits
                 WHERE scope_id = ?1 AND ts >= ?2 AND status <> 'C'
                 ORDER BY tool",
            )
            .map_err(|e| map_sql(e, 0))?;
        let tools = stmt
            .query_map((scope, cutoff), |r| r.get::<_, String>(0))
            .map_err(|e| map_sql(e, 0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_sql(e, 0))?;
        drop(stmt);
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(tools)
    }
}

/// One pass, two counters — the SQL twin of Bash's single `awk` program.
fn count_window(tx: &Transaction<'_>, scope: i64, cutoff: i64) -> Result<Counts, StateError> {
    tx.query_row(
        "SELECT
           (SELECT COUNT(*) FROM hits
              WHERE scope_id = ?1 AND ts >= ?2 AND status = 'H')
         + (SELECT COUNT(DISTINCT content_hash) FROM hits
              WHERE scope_id = ?1 AND ts >= ?2 AND status = 'Q' AND content_hash IS NOT NULL)
         + (SELECT COUNT(*) FROM hits
              WHERE scope_id = ?1 AND ts >= ?2 AND status = 'Q' AND content_hash IS NULL),
           (SELECT COUNT(*) FROM hits
              WHERE scope_id = ?1 AND ts >= ?2 AND status = 'H')",
        (scope, cutoff),
        |r| {
            Ok(Counts {
                strikes: r.get::<_, i64>(0)?.max(0) as u32,
                real_strikes: r.get::<_, i64>(1)?.max(0) as u32,
            })
        },
    )
    .map_err(|e| map_sql(e, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_needs_three_strikes_and_one_real_exposure() {
        assert!(!Counts {
            strikes: 2,
            real_strikes: 2
        }
        .escalates());
        assert!(!Counts {
            strikes: 9,
            real_strikes: 0
        }
        .escalates());
        assert!(Counts {
            strikes: 3,
            real_strikes: 1
        }
        .escalates());
    }

    #[test]
    fn statuses_use_the_single_letter_bash_writes() {
        assert_eq!(HitStatus::Delivered.as_str(), "H");
        assert_eq!(HitStatus::Cleared.as_str(), "C");
        assert_eq!(HitStatus::Quarantined.as_str(), "Q");
    }
}
