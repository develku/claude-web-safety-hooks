//! The SQLite state store: path safety, schema/version contract, transactions.
//!
//! One file, at a fixed name under an operator-chosen root: `<dir>/state.db`.
//! Nothing about a session, an agent, a namespace or a tool ever reaches the
//! path — those are columns, bound as parameters. That is what makes a hostile
//! `session_id` a data problem instead of a filesystem problem.
//!
//! WAL plus short `BEGIN IMMEDIATE` transactions is the whole concurrency
//! design: readers never block, writers serialize, and a writer that cannot get
//! the lock inside `busy_timeout_ms` fails *typed* rather than waiting out the
//! hook budget.

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use super::clock::{Clock, SystemClock};
use super::paths;
use super::{
    StateConfig, StateContext, StateError, StateMode, MAX_BUSY_TIMEOUT_MS,
    MIN_READABLE_SCHEMA_VERSION, STATE_SCHEMA_VERSION,
};

pub use super::paths::DB_FILENAME;

const SCHEMA_V2: &str = r#"
-- One row per (runtime, namespace, session, task, agent) correlation bucket.
-- The task column is '' when the host exposes no execution id, and the agent
-- column is '' for the main session: an absent dimension is its own bucket,
-- which is how Bash's per-agent state FILE split maps onto a relational key
-- without a nullable UNIQUE.
CREATE TABLE scopes (
  id         INTEGER PRIMARY KEY,
  runtime    TEXT NOT NULL,
  namespace  TEXT NOT NULL,
  session_id TEXT NOT NULL,
  task_id    TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  UNIQUE (runtime, namespace, session_id, task_id, agent_id)
);

-- One row per (runtime, namespace, session, task). Cross-AGENT by design — E8
-- reassembly and the Layer 6 armed window are session facts, not agent facts —
-- and deliberately NOT cross-task: two executions under one long-lived session
-- are two unrelated pieces of work.
CREATE TABLE session_scopes (
  id         INTEGER PRIMARY KEY,
  runtime    TEXT NOT NULL,
  namespace  TEXT NOT NULL,
  session_id TEXT NOT NULL,
  task_id    TEXT NOT NULL,
  UNIQUE (runtime, namespace, session_id, task_id)
);

-- record_session_hit's append-only row. status is 'H' (delivered hit),
-- 'C' (cleared false positive) or 'Q' (quarantined). content_hash is set only
-- for Q rows, and may still be NULL there — see correlation::counts.
CREATE TABLE hits (
  id           INTEGER PRIMARY KEY,
  scope_id     INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  ts           INTEGER NOT NULL,
  tool         TEXT NOT NULL,
  url          TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('H','C','Q')),
  content_hash TEXT
);
CREATE INDEX hits_by_scope_ts ON hits (scope_id, ts);

-- The E8 fragment sidecar. excerpt is the bounded, confusable-folded,
-- already-lowercased slice — never a raw response body.
CREATE TABLE fragments (
  id               INTEGER PRIMARY KEY,
  session_scope_id INTEGER NOT NULL REFERENCES session_scopes(id) ON DELETE CASCADE,
  ts               INTEGER NOT NULL,
  seq              INTEGER NOT NULL,
  tool             TEXT NOT NULL,
  url_hash         TEXT NOT NULL,
  excerpt          TEXT NOT NULL
);
CREATE INDEX fragments_by_scope_ts ON fragments (session_scope_id, ts, id);

-- ${SESSION_FRAGMENTS}.fired — patterns already reported for this session, so a
-- still-open window cannot re-fire the same reassembly on every later fetch.
CREATE TABLE fired_patterns (
  session_scope_id INTEGER NOT NULL REFERENCES session_scopes(id) ON DELETE CASCADE,
  pattern          TEXT NOT NULL,
  ts               INTEGER NOT NULL,
  PRIMARY KEY (session_scope_id, pattern)
);

-- /tmp/web-safety-session-<id>-armed.
CREATE TABLE armed (
  session_scope_id INTEGER PRIMARY KEY REFERENCES session_scopes(id) ON DELETE CASCADE,
  armed_at         INTEGER NOT NULL
);

-- record_agent_kill's [PENDING-KILLED] rows. detail is operator-facing only.
CREATE TABLE kill_ledger (
  id          INTEGER PRIMARY KEY,
  scope_id    INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  ts          INTEGER NOT NULL,
  severity    TEXT NOT NULL,
  tool        TEXT NOT NULL,
  host        TEXT,
  detail      TEXT NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX ledger_by_scope_ts ON kill_ledger (scope_id, ts);

-- The {severity + content-hash} toast dedup key.
CREATE TABLE notify_dedup (
  session_scope_id INTEGER NOT NULL REFERENCES session_scopes(id) ON DELETE CASCADE,
  severity         TEXT NOT NULL,
  content_hash     TEXT NOT NULL,
  last_ts          INTEGER NOT NULL,
  PRIMARY KEY (session_scope_id, severity, content_hash)
);

-- Generic atomic one-shot state, for the approvals/consumption an adapter will
-- need without this stage wiring any host approval.
CREATE TABLE one_time (
  session_scope_id INTEGER NOT NULL REFERENCES session_scopes(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL,
  key              TEXT NOT NULL,
  created_at       INTEGER NOT NULL,
  consumed_at      INTEGER,
  PRIMARY KEY (session_scope_id, kind, key)
);
"#;

pub struct StateStore {
    conn: Connection,
    cfg: StateConfig,
    clock: Arc<dyn Clock>,
}

/// Deliberately opaque: the point of `{:?}` on a store is to say which database
/// and mode a test is looking at, never to dump session keys or excerpts.
impl std::fmt::Debug for StateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateStore")
            .field("dir", &self.cfg.dir)
            .field("mode", &self.cfg.mode.as_str())
            .finish_non_exhaustive()
    }
}

impl StateStore {
    /// `Ok(None)` when the mode is `off`: nothing is created, opened or read.
    pub fn open(cfg: StateConfig) -> Result<Option<StateStore>, StateError> {
        StateStore::open_with_clock(cfg, Arc::new(SystemClock))
    }

    pub fn open_with_clock(
        cfg: StateConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Option<StateStore>, StateError> {
        if cfg.mode == StateMode::Off {
            return Ok(None);
        }
        if cfg.busy_timeout_ms == 0 || cfg.busy_timeout_ms > MAX_BUSY_TIMEOUT_MS {
            return Err(StateError::Config {
                why: format!(
                    "busy timeout {}ms is outside 1..={MAX_BUSY_TIMEOUT_MS} — a longer wait would spend the hard per-call ceiling",
                    cfg.busy_timeout_ms
                ),
            });
        }
        if cfg.dir.as_os_str().is_empty() {
            return Err(StateError::Config {
                why: format!(
                    "mode {} requires an explicit state directory",
                    cfg.mode.as_str()
                ),
            });
        }

        // Path safety first, and in one place: everything about symlinks,
        // ownership, modes, link counts and the check-to-use window lives in
        // `paths`, so this function reads as "validate, open, verify, migrate".
        let prepared = paths::prepare(&cfg.dir)?;
        testing::fire_preopen_hook(&prepared.db);
        let conn = open_db(&prepared.db, &cfg)?;
        paths::verify_after_open(&prepared.db, &prepared.identity)?;
        migrate(&conn, &cfg)?;

        Ok(Some(StateStore { conn, cfg, clock }))
    }

    pub fn config(&self) -> &StateConfig {
        &self.cfg
    }

    pub fn mode(&self) -> StateMode {
        self.cfg.mode
    }

    pub fn now(&self) -> i64 {
        self.clock.now_secs()
    }

    pub fn schema_version(&self) -> u32 {
        read_user_version(&self.conn).unwrap_or(0)
    }

    pub fn validate(&self, ctx: &StateContext) -> Result<(), StateError> {
        ctx.validate()
    }

    /// Size of the database file plus its WAL, for the growth budget.
    pub fn size_bytes(&self) -> u64 {
        let base = self.cfg.dir.join(DB_FILENAME);
        std::iter::once(base.clone())
            .chain(
                paths::SIDECAR_SUFFIXES
                    .iter()
                    .map(|s| paths::sidecar(&base, s)),
            )
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// `BEGIN IMMEDIATE`, so two writers contend at BEGIN rather than at the
    /// first write — which is what makes "append and recount" one critical
    /// section instead of a read-modify-write race.
    pub(crate) fn tx(&self) -> Result<Transaction<'_>, StateError> {
        let started = Instant::now();
        Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .map_err(|e| map_sql(e, started.elapsed().as_millis() as u64))
    }

    /// Resolve (and create) the per-agent correlation bucket.
    pub(crate) fn scope_id(tx: &Transaction<'_>, ctx: &StateContext) -> Result<i64, StateError> {
        let key = (
            &ctx.runtime,
            &ctx.namespace,
            &ctx.session_id,
            ctx.task_key(),
            ctx.agent_key(),
        );
        tx.execute(
            "INSERT OR IGNORE INTO scopes (runtime, namespace, session_id, task_id, agent_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            key,
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.query_row(
            "SELECT id FROM scopes
             WHERE runtime = ?1 AND namespace = ?2 AND session_id = ?3
               AND task_id = ?4 AND agent_id = ?5",
            key,
            |r| r.get(0),
        )
        .map_err(|e| map_sql(e, 0))
    }

    /// Resolve (and create) the session-wide bucket — cross-agent by design,
    /// and per-task, because two tasks under one session are two executions.
    pub(crate) fn session_scope_id(
        tx: &Transaction<'_>,
        ctx: &StateContext,
    ) -> Result<i64, StateError> {
        let key = (
            &ctx.runtime,
            &ctx.namespace,
            &ctx.session_id,
            ctx.task_key(),
        );
        tx.execute(
            "INSERT OR IGNORE INTO session_scopes (runtime, namespace, session_id, task_id)
             VALUES (?1, ?2, ?3, ?4)",
            key,
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.query_row(
            "SELECT id FROM session_scopes
             WHERE runtime = ?1 AND namespace = ?2 AND session_id = ?3 AND task_id = ?4",
            key,
            |r| r.get(0),
        )
        .map_err(|e| map_sql(e, 0))
    }

    /// Take and hold the write lock, for fault injection only.
    ///
    /// Contention and crash recovery are the two failure modes that cannot be
    /// simulated from outside the store, so the two hooks that simulate them
    /// are here rather than mocked. Both are `#[doc(hidden)]`: they are part of
    /// the test surface, not of the API an adapter should reach for.
    #[doc(hidden)]
    pub fn begin_write_lock(&self) -> Result<Transaction<'_>, StateError> {
        self.tx()
    }

    /// Write a row and abandon the transaction without committing — the shape a
    /// process killed mid-transition leaves behind.
    #[doc(hidden)]
    pub fn write_then_abandon(&self, ctx: &StateContext) -> Result<(), StateError> {
        ctx.validate()?;
        let tx = self.tx()?;
        let scope = StateStore::scope_id(&tx, ctx)?;
        tx.execute(
            "INSERT INTO hits (scope_id, ts, tool, url, status) VALUES (?1, ?2, 'X', 'X', 'H')",
            (scope, self.now()),
        )
        .map_err(|e| map_sql(e, 0))?;
        // No commit. `Transaction`'s drop rolls back.
        Ok(())
    }

    /// Drop every row whose TTL has passed, in one transaction.
    ///
    /// Scoped by nothing on purpose: expiry is a property of the row's own
    /// timestamp, so pruning can never move a row between scopes and therefore
    /// can never contaminate one session, task, profile or runtime with another.
    pub fn prune(&self) -> Result<u64, StateError> {
        let now = self.now();
        let hit_cut = now - self.cfg.window_secs;
        let frag_cut = now - self.cfg.window_secs;
        let arm_cut = now - self.cfg.window_secs;
        let notify_cut = now - self.cfg.notify_window_secs;
        let ledger_cut = now - self.cfg.ledger_window_secs;

        let tx = self.tx()?;
        let mut removed = 0u64;
        for (sql, cut) in [
            ("DELETE FROM hits WHERE ts < ?1", hit_cut),
            ("DELETE FROM fragments WHERE ts < ?1", frag_cut),
            ("DELETE FROM fired_patterns WHERE ts < ?1", frag_cut),
            ("DELETE FROM armed WHERE armed_at < ?1", arm_cut),
            ("DELETE FROM notify_dedup WHERE last_ts < ?1", notify_cut),
            ("DELETE FROM kill_ledger WHERE ts < ?1", ledger_cut),
            ("DELETE FROM one_time WHERE created_at < ?1", ledger_cut),
        ] {
            removed += tx.execute(sql, [cut]).map_err(|e| map_sql(e, 0))? as u64;
        }
        // A scope with nothing left in it is dead weight in the key columns.
        tx.execute(
            "DELETE FROM scopes WHERE id NOT IN (SELECT scope_id FROM hits)
                                  AND id NOT IN (SELECT scope_id FROM kill_ledger)",
            [],
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.execute(
            "DELETE FROM session_scopes
             WHERE id NOT IN (SELECT session_scope_id FROM fragments)
               AND id NOT IN (SELECT session_scope_id FROM fired_patterns)
               AND id NOT IN (SELECT session_scope_id FROM armed)
               AND id NOT IN (SELECT session_scope_id FROM notify_dedup)
               AND id NOT IN (SELECT session_scope_id FROM one_time)",
            [],
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;

        // Deleting rows frees pages inside the database but leaves the WAL at
        // its high-water mark; checkpointing here is what turns "pruned" into
        // "smaller on disk". Best-effort: a checkpoint blocked by a concurrent
        // reader is a deferred truncation, not a failed prune.
        let _ = self
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum;");
        Ok(removed)
    }
}

/// A `#[doc(hidden)]` seam for the one failure mode that cannot be observed
/// from outside the store: an object replaced *between* path validation and
/// SQLite's open.
///
/// It is an ordinary (non-`cfg(test)`) module because the race it drives is a
/// property of the shipped code path, and a hook that only exists under
/// `cfg(test)` would prove something about a different binary. Nothing in the
/// crate ever arms it; a caller has to reach past `#[doc(hidden)]` and register
/// a function pointer, which no adapter has any reason to do.
#[doc(hidden)]
pub mod testing {
    use std::path::Path;
    use std::sync::Mutex;

    pub type PreOpenHook = fn(&Path);

    static HOOK: Mutex<Option<PreOpenHook>> = Mutex::new(None);

    /// Disarms on drop, so a panicking test cannot leave the hook armed for
    /// every other test sharing the process.
    pub struct ArmedHook(());

    impl Drop for ArmedHook {
        fn drop(&mut self) {
            *lock() = None;
        }
    }

    fn lock() -> std::sync::MutexGuard<'static, Option<PreOpenHook>> {
        HOOK.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn arm_preopen_hook(f: PreOpenHook) -> ArmedHook {
        *lock() = Some(f);
        ArmedHook(())
    }

    pub(crate) fn fire_preopen_hook(db: &Path) {
        let hook = *lock();
        if let Some(f) = hook {
            f(db);
        }
    }
}

fn open_db(db: &Path, cfg: &StateConfig) -> Result<Connection, StateError> {
    // `SQLITE_OPEN_NOFOLLOW` is the one redirection defence SQLite itself can
    // apply to the name we hand it: a symlinked database is `SQLITE_CANTOPEN`
    // inside the VFS rather than a silent write to wherever the link points.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(db, flags).map_err(|e| StateError::Unusable {
        why: format!("cannot open {}: {e}", db.display()),
    })?;
    conn.busy_timeout(std::time::Duration::from_millis(cfg.busy_timeout_ms))
        .map_err(|e| map_sql(e, cfg.busy_timeout_ms))?;
    // WAL is the reason a reader never blocks a writer here. It is also the
    // first statement that actually touches the file, so a corrupt or read-only
    // database surfaces as a typed error at open rather than mid-transition.
    let mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(|e| map_sql(e, cfg.busy_timeout_ms))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StateError::Unusable {
            why: format!("journal_mode is {mode:?}, not WAL"),
        });
    }
    // `journal_size_limit` is the reason the WAL does not become the growth
    // story: without it SQLite lets the WAL keep whatever size it reached and
    // a long adversarial sequence leaves megabytes behind for rows that were
    // pruned seconds later. With it, every checkpoint truncates back.
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA synchronous=NORMAL;
         PRAGMA journal_size_limit=1048576;",
    )
    .map_err(|e| map_sql(e, cfg.busy_timeout_ms))?;
    Ok(conn)
}

fn read_user_version(conn: &Connection) -> Result<u32, StateError> {
    conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
        .map(|v| v.max(0) as u32)
        .map_err(|e| map_sql(e, 0))
}

/// The version contract, in one place.
///
/// * `0` — an empty file: this build owns it, create the current schema.
/// * `1..MIN_READABLE` — a *known older key shape*. Refused, never migrated:
///   v1 has no `task_id` column, so mapping its rows onto v2 keys would mean
///   asserting that every one of them belongs to the task-absent bucket —
///   a claim its writer never made. v1 never shipped (Stage 4 is unreleased),
///   so refusing costs an operator one `rm -rf` of a dev directory and buys a
///   guarantee that no database is ever read under keys that do not mean what
///   they meant when it was written.
/// * `MIN_READABLE..=STATE_SCHEMA_VERSION` — readable; migrate forward.
/// * `> STATE_SCHEMA_VERSION` — written by a newer build. Refused.
fn check_version(found: u32) -> Result<(), StateError> {
    if found > STATE_SCHEMA_VERSION {
        return Err(StateError::UnsupportedSchema {
            found,
            supported: STATE_SCHEMA_VERSION,
        });
    }
    if found > 0 && found < MIN_READABLE_SCHEMA_VERSION {
        return Err(StateError::IncompatibleSchema {
            found,
            oldest_readable: MIN_READABLE_SCHEMA_VERSION,
            why: "the scope tables gained the task/execution dimension in schema 2, so \
                  pre-2 rows carry no task key this build could honour"
                .to_string(),
        });
    }
    Ok(())
}

/// Transactional and downgrade-safe: an unreadable schema is refused outright,
/// and a migration that fails rolls back rather than leaving a half-applied
/// database that the next run would read as complete.
fn migrate(conn: &Connection, cfg: &StateConfig) -> Result<(), StateError> {
    let found = read_user_version(conn)?;
    check_version(found)?;
    if found == STATE_SCHEMA_VERSION {
        return Ok(());
    }
    let started = Instant::now();
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|e| map_sql(e, started.elapsed().as_millis() as u64))?;
    // Re-read inside the lock: another process may have migrated while we waited.
    let found = tx
        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
        .map(|v| v.max(0) as u32)
        .map_err(|e| map_sql(e, 0))?;
    check_version(found)?;
    if found == 0 {
        tx.execute_batch(SCHEMA_V2).map_err(|e| map_sql(e, 0))?;
    }
    tx.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)
        .map_err(|e| map_sql(e, 0))?;
    tx.commit().map_err(|e| map_sql(e, 0))?;
    let _ = cfg;
    Ok(())
}

/// Map a SQLite failure onto the typed vocabulary. There is deliberately no
/// "probably fine" branch: an unclassified failure is [`StateError::Unusable`],
/// which `enforce` turns into containment.
pub(crate) fn map_sql(e: rusqlite::Error, waited_ms: u64) -> StateError {
    use rusqlite::ffi::ErrorCode;
    if let rusqlite::Error::SqliteFailure(inner, _) = &e {
        match inner.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                return StateError::Busy { waited_ms }
            }
            ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt => {
                return StateError::Unusable {
                    why: format!("database is corrupt or not a database: {e}"),
                }
            }
            ErrorCode::ReadOnly | ErrorCode::CannotOpen | ErrorCode::PermissionDenied => {
                return StateError::Unusable {
                    why: format!("database is not writable: {e}"),
                }
            }
            _ => {}
        }
    }
    StateError::Unusable { why: e.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// `std::env::temp_dir()` is `/var/folders/...` on macOS, and `/var` is a
    /// symlink. The store requires a symlink-free absolute root, so the base is
    /// resolved once here rather than tripping every test on a system link.
    fn tmp(tag: &str) -> PathBuf {
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("the temp dir resolves");
        let p = base.join(format!("ws-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn store(dir: PathBuf) -> StateStore {
        StateStore::open(StateConfig {
            mode: StateMode::Report,
            dir,
            ..StateConfig::default()
        })
        .expect("open")
        .expect("store")
    }

    #[test]
    fn a_fresh_store_is_at_the_current_schema_version() {
        let s = store(tmp("fresh"));
        assert_eq!(s.schema_version(), STATE_SCHEMA_VERSION);
        assert!(s.size_bytes() > 0);
    }

    #[test]
    fn scopes_are_created_once_and_reused() {
        let s = store(tmp("scopes"));
        let ctx = StateContext::new("claude", "p", "s1");
        let tx = s.tx().unwrap();
        let a = StateStore::scope_id(&tx, &ctx).unwrap();
        let b = StateStore::scope_id(&tx, &ctx).unwrap();
        tx.commit().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn an_agent_scope_is_distinct_from_its_main_session_scope() {
        let s = store(tmp("agent-scope"));
        let main = StateContext::new("claude", "p", "s1");
        let mut sub = main.clone();
        sub.agent_id = Some("a1".into());

        let tx = s.tx().unwrap();
        let m = StateStore::scope_id(&tx, &main).unwrap();
        let a = StateStore::scope_id(&tx, &sub).unwrap();
        // ...but they share ONE session scope, which is what lets E8 correlate
        // across agents while strikes stay per-agent.
        let sm = StateStore::session_scope_id(&tx, &main).unwrap();
        let sa = StateStore::session_scope_id(&tx, &sub).unwrap();
        tx.commit().unwrap();

        assert_ne!(m, a);
        assert_eq!(sm, sa);
    }

    #[test]
    fn every_key_dimension_partitions_the_scope() {
        let s = store(tmp("partition"));
        let base = StateContext::new("claude", "p", "s1");
        let mut other_runtime = base.clone();
        other_runtime.runtime = "codex".into();
        let mut other_ns = base.clone();
        other_ns.namespace = "q".into();
        let mut other_session = base.clone();
        other_session.session_id = "s2".into();
        let mut other_task = base.clone();
        other_task.task_id = Some("t1".into());
        let mut other_agent = base.clone();
        other_agent.agent_id = Some("a1".into());

        let tx = s.tx().unwrap();
        let ids: Vec<i64> = [
            &base,
            &other_runtime,
            &other_ns,
            &other_session,
            &other_task,
            &other_agent,
        ]
        .iter()
        .map(|c| StateStore::scope_id(&tx, c).unwrap())
        .collect();
        tx.commit().unwrap();

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 6, "every field must partition: {ids:?}");
    }

    /// The session-wide table is cross-agent — that is the E8 invariant — but
    /// it must still split on the task.
    #[test]
    fn the_session_scope_is_cross_agent_but_never_cross_task() {
        let s = store(tmp("session-partition"));
        let main = StateContext::new("claude", "p", "s1");
        let mut sub = main.clone();
        sub.agent_id = Some("a1".into());
        let mut other_task = main.clone();
        other_task.task_id = Some("t1".into());

        let tx = s.tx().unwrap();
        let m = StateStore::session_scope_id(&tx, &main).unwrap();
        let a = StateStore::session_scope_id(&tx, &sub).unwrap();
        let t = StateStore::session_scope_id(&tx, &other_task).unwrap();
        tx.commit().unwrap();

        assert_eq!(m, a, "E8 reassembly must stay cross-agent inside a session");
        assert_ne!(m, t, "two tasks under one session share nothing");
    }

    #[test]
    fn a_pre_task_schema_is_refused_rather_than_reinterpreted() {
        assert!(matches!(
            check_version(1).unwrap_err(),
            StateError::IncompatibleSchema { found: 1, .. }
        ));
        assert!(matches!(
            check_version(STATE_SCHEMA_VERSION + 1).unwrap_err(),
            StateError::UnsupportedSchema { .. }
        ));
        check_version(0).expect("an empty file is ours to create");
        check_version(STATE_SCHEMA_VERSION).expect("the current schema is readable");
    }

    #[test]
    fn pruning_an_empty_store_is_a_no_op() {
        let s = store(tmp("prune-empty"));
        assert_eq!(s.prune().unwrap(), 0);
    }
}
