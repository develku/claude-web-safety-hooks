//! Notification dedup and the generic one-shot claim.
//!
//! ## Dedup
//!
//! v8.5.0 replaced a blunt 5-second global timer with a `{severity +
//! content-hash}` key over a 300-second window. The old timer failed in both
//! directions at once: it let a fan-out burst through when the same injected
//! content was re-detected more than 5s apart across N subagents, and it muted
//! genuinely DIFFERENT threats that happened within 5s of each other.
//!
//! **This gate is toast-only.** The audit row, the sanitization, the subagent
//! kill, the egress arm and the scan verdict are per-event and never consult
//! it. [`StateStore::notify_allowed`] returning `false` means "do not toast",
//! never "do not act".
//!
//! One deliberate scoping difference from Bash, called out because it is a
//! divergence rather than a port: Bash's key is the FILE
//! `/tmp/web-safety-scanner-notify-<severity>-<hash>`, which is global across
//! sessions. The architecture invariant for this stage requires every state key
//! to carry runtime + namespace + session, so the key here is session-scoped.
//! Agent is deliberately NOT part of it — collapsing a fan-out across sibling
//! subagents is the entire reason the dedup exists. The observable difference
//! is confined to two CONCURRENT distinct sessions scanning byte-identical
//! content: Bash toasts once, this toasts once per session.
//!
//! ## One-shot claims
//!
//! [`StateStore::claim_once`] is the primitive a future explicit-approval flow
//! needs — "this exact thing may happen once, and exactly one caller may be
//! told it owns it". No host approval is wired in this stage; the primitive is
//! here so the adapter that does can be built on something already proven
//! atomic under contention.

use super::store::{map_sql, StateStore};
use super::{sanitize_meta, StateContext, StateError};

const MAX_SEVERITY_CHARS: usize = 16;
const MAX_HASH_CHARS: usize = 64;
const MAX_KIND_CHARS: usize = 64;
const MAX_KEY_CHARS: usize = 128;

impl StateStore {
    /// `true` when the toast should be dispatched. Records the key on `true`.
    pub fn notify_allowed(
        &self,
        ctx: &StateContext,
        severity: &str,
        content_hash: &str,
    ) -> Result<bool, StateError> {
        ctx.validate()?;
        let now = self.now();
        let cutoff = now - self.config().notify_window_secs;
        let severity = sanitize_meta(severity, MAX_SEVERITY_CHARS);
        let hash = sanitize_meta(content_hash, MAX_HASH_CHARS);

        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        let last: Option<i64> = tx
            .query_row(
                "SELECT last_ts FROM notify_dedup
                 WHERE session_scope_id = ?1 AND severity = ?2 AND content_hash = ?3",
                (scope, &severity, &hash),
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(map_sql(other, 0)),
            })?;

        // `now - last < window`, i.e. the boundary second still suppresses —
        // Bash's `[ $(( now - last )) -lt "$NOTIFY_DEDUP_WINDOW" ]`.
        let suppressed = last.is_some_and(|l| l > cutoff);
        if !suppressed {
            tx.execute(
                "INSERT INTO notify_dedup (session_scope_id, severity, content_hash, last_ts)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (session_scope_id, severity, content_hash)
                 DO UPDATE SET last_ts = excluded.last_ts",
                (scope, &severity, &hash, now),
            )
            .map_err(|e| map_sql(e, 0))?;
        }
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(!suppressed)
    }

    /// `true` for the single caller that wins the claim; `false` for everyone
    /// after. The insert and the consume are one statement, so there is no
    /// window in which two callers can both see "unclaimed".
    pub fn claim_once(
        &self,
        ctx: &StateContext,
        kind: &str,
        key: &str,
    ) -> Result<bool, StateError> {
        ctx.validate()?;
        let now = self.now();
        let kind = sanitize_meta(kind, MAX_KIND_CHARS);
        let key = sanitize_meta(key, MAX_KEY_CHARS);

        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO one_time (session_scope_id, kind, key, created_at, consumed_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                (scope, &kind, &key, now),
            )
            .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(inserted == 1)
    }

    /// Whether a claim exists at all, without taking it.
    pub fn claim_taken(
        &self,
        ctx: &StateContext,
        kind: &str,
        key: &str,
    ) -> Result<bool, StateError> {
        ctx.validate()?;
        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        let n: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM one_time
                 WHERE session_scope_id = ?1 AND kind = ?2 AND key = ?3",
                (
                    scope,
                    sanitize_meta(kind, MAX_KIND_CHARS),
                    sanitize_meta(key, MAX_KEY_CHARS),
                ),
                |r| r.get(0),
            )
            .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(n > 0)
    }
}
