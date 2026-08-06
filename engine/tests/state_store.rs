//! Storage security, schema/version contract, modes, and failure behaviour.
//!
//! The state store is the first part of the engine that writes to disk. Every
//! test here is about the thing that makes that safe: a controlled path, a
//! versioned schema, least-privilege permissions, bounded lock waits, and a
//! typed failure that never degrades into "behaved statelessly, reported fine".

use std::path::{Path, PathBuf};
use std::sync::Arc;
use web_safety_engine::state::clock::TestClock;
use web_safety_engine::state::{
    StateConfig, StateContext, StateError, StateMode, StateStore, STATE_CONTEXT_VERSION,
    STATE_SCHEMA_VERSION,
};

/// A fresh directory under the OS temp dir, unique per test.
/// `std::env::temp_dir()` is `/var/folders/...` on macOS and `/var` is a
/// symlink; the store requires a symlink-free absolute root, so the base is
/// resolved once here.
fn temp_root() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).expect("the temp dir resolves")
}

fn scratch(tag: &str) -> PathBuf {
    let base = temp_root().join(format!(
        "ws-state-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("scratch dir");
    base
}

fn cfg(dir: &Path, mode: StateMode) -> StateConfig {
    StateConfig {
        mode,
        dir: dir.join("state"),
        ..StateConfig::default()
    }
}

fn ctx() -> StateContext {
    StateContext::new("claude", "profile-a", "sess-1")
}

#[test]
fn off_mode_never_touches_the_database() {
    let root = scratch("off");
    let c = cfg(&root, StateMode::Off);
    let dir = c.dir.clone();
    let handle = StateStore::open(c).expect("off mode opens");
    assert!(handle.is_none(), "off mode must not produce a store");
    assert!(
        !dir.exists(),
        "off mode created {dir:?} — it must not touch the filesystem at all"
    );
}

#[test]
fn report_and_enforce_create_the_store_and_a_readable_schema_version() {
    let root = scratch("create");
    let store = StateStore::open(cfg(&root, StateMode::Report))
        .expect("open")
        .expect("report mode yields a store");
    assert_eq!(store.schema_version(), STATE_SCHEMA_VERSION);
    assert!(root.join("state/state.db").exists());
}

#[cfg(unix)]
#[test]
fn the_state_directory_is_0700_and_the_database_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("perms");
    let c = cfg(&root, StateMode::Report);
    let dir = c.dir.clone();
    let _store = StateStore::open(c).expect("open").expect("store");

    let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    let fmode = std::fs::metadata(dir.join("state.db"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dmode, 0o700, "state dir mode");
    assert_eq!(fmode, 0o600, "database mode");
}

#[cfg(unix)]
#[test]
fn a_symlinked_state_root_is_rejected() {
    let root = scratch("symlink-root");
    let real = root.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = root.join("state");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = StateStore::open(cfg(&root, StateMode::Enforce)).unwrap_err();
    assert!(
        matches!(err, StateError::UnsafePath { .. }),
        "expected UnsafePath, got {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_database_file_is_rejected() {
    let root = scratch("symlink-db");
    let dir = root.join("state");
    std::fs::create_dir_all(&dir).unwrap();
    let elsewhere = root.join("elsewhere.db");
    std::fs::write(&elsewhere, b"").unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.join("state.db")).unwrap();

    let err = StateStore::open(cfg(&root, StateMode::Enforce)).unwrap_err();
    assert!(
        matches!(err, StateError::UnsafePath { .. }),
        "expected UnsafePath, got {err:?}"
    );
}

#[test]
fn a_non_directory_state_root_is_rejected() {
    let root = scratch("not-a-dir");
    std::fs::write(root.join("state"), b"i am a file").unwrap();
    let err = StateStore::open(cfg(&root, StateMode::Enforce)).unwrap_err();
    assert!(
        matches!(err, StateError::UnsafePath { .. }),
        "expected UnsafePath, got {err:?}"
    );
}

#[test]
fn a_traversal_component_in_the_state_root_is_rejected() {
    let root = scratch("traversal");
    let mut c = cfg(&root, StateMode::Enforce);
    c.dir = root.join("a/../../escape");
    let err = StateStore::open(c).unwrap_err();
    assert!(
        matches!(err, StateError::UnsafePath { .. }),
        "expected UnsafePath, got {err:?}"
    );
}

#[test]
fn a_newer_schema_version_fails_closed_rather_than_reading_it_anyway() {
    let root = scratch("newer-schema");
    {
        let _store = StateStore::open(cfg(&root, StateMode::Report))
            .expect("open")
            .expect("store");
    }
    // Simulate a future build having written this database.
    let conn = rusqlite::Connection::open(root.join("state/state.db")).unwrap();
    conn.pragma_update(None, "user_version", STATE_SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);

    let err = StateStore::open(cfg(&root, StateMode::Report)).unwrap_err();
    match err {
        StateError::UnsupportedSchema { found, supported } => {
            assert_eq!(found, STATE_SCHEMA_VERSION + 1);
            assert_eq!(supported, STATE_SCHEMA_VERSION);
        }
        other => panic!("expected UnsupportedSchema, got {other:?}"),
    }
}

#[test]
fn reopening_an_existing_store_is_a_no_op_migration() {
    let root = scratch("reopen");
    for _ in 0..3 {
        let store = StateStore::open(cfg(&root, StateMode::Report))
            .expect("open")
            .expect("store");
        assert_eq!(store.schema_version(), STATE_SCHEMA_VERSION);
    }
}

#[test]
fn a_corrupt_database_is_a_typed_error_not_a_silent_stateless_run() {
    let root = scratch("corrupt");
    let dir = root.join("state");
    std::fs::create_dir_all(&dir).unwrap();
    // A file that is emphatically not a SQLite database.
    std::fs::write(dir.join("state.db"), vec![0x41u8; 8192]).unwrap();

    let err = StateStore::open(cfg(&root, StateMode::Enforce)).unwrap_err();
    assert!(
        matches!(
            err,
            StateError::Unusable { .. } | StateError::UnsafePath { .. }
        ),
        "expected a typed unusable/unsafe error, got {err:?}"
    );
    assert!(
        !err.to_string().is_empty(),
        "errors carry an operator message"
    );
}

#[cfg(unix)]
#[test]
fn a_read_only_state_root_is_a_typed_error() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("readonly");
    let dir = root.join("state");
    std::fs::create_dir_all(&dir).unwrap();
    let mut p = std::fs::metadata(&dir).unwrap().permissions();
    p.set_mode(0o500);
    std::fs::set_permissions(&dir, p).unwrap();

    let got = StateStore::open(cfg(&root, StateMode::Enforce));

    // Restore before asserting so the scratch dir can be cleaned up.
    let mut p = std::fs::metadata(&dir).unwrap().permissions();
    p.set_mode(0o700);
    std::fs::set_permissions(&dir, p).unwrap();

    let err = got.expect_err("a read-only state root cannot be written");
    assert!(
        matches!(err, StateError::Unusable { .. }),
        "expected Unusable, got {err:?}"
    );
}

#[test]
fn the_busy_timeout_is_bounded_and_configurable_within_the_hook_budget() {
    let root = scratch("busy");
    let mut c = cfg(&root, StateMode::Report);
    c.busy_timeout_ms = 10_000;
    let err = StateStore::open(c).unwrap_err();
    assert!(
        matches!(err, StateError::Config { .. }),
        "a busy timeout past the hook budget is a config error, got {err:?}"
    );
}

#[test]
fn an_empty_or_path_like_namespace_is_rejected_rather_than_collapsed() {
    let root = scratch("ns");
    let store = StateStore::open(cfg(&root, StateMode::Report))
        .expect("open")
        .expect("store");

    for bad in ["", "..", "a/b", "a\\b", "with\0nul", "with\nnewline"] {
        let c = StateContext::new("claude", bad, "sess-1");
        let err = store.validate(&c).unwrap_err();
        assert!(
            matches!(err, StateError::InvalidIdentity { .. }),
            "namespace {bad:?} should be rejected, got {err:?}"
        );
    }
}

#[test]
fn an_oversized_identity_is_rejected_rather_than_truncated_into_a_shared_bucket() {
    let root = scratch("oversize");
    let store = StateStore::open(cfg(&root, StateMode::Report))
        .expect("open")
        .expect("store");

    let long = "s".repeat(4096);
    let c = StateContext::new("claude", "profile-a", &long);
    let err = store.validate(&c).unwrap_err();
    assert!(
        matches!(err, StateError::InvalidIdentity { .. }),
        "an oversized session id must not be truncated, got {err:?}"
    );
}

#[test]
fn a_well_formed_context_validates() {
    let root = scratch("ok-ctx");
    let store = StateStore::open(cfg(&root, StateMode::Report))
        .expect("open")
        .expect("store");
    let mut c = ctx();
    c.agent_id = Some("agent-01".into());
    assert_eq!(c.version, STATE_CONTEXT_VERSION);
    store.validate(&c).expect("a well-formed context validates");
}

#[test]
fn the_clock_is_injected_through_the_library_not_the_envelope() {
    let root = scratch("clock");
    let clock = Arc::new(TestClock::new(1_000));
    let store = StateStore::open_with_clock(cfg(&root, StateMode::Report), clock.clone())
        .expect("open")
        .expect("store");
    assert_eq!(store.now(), 1_000);
    clock.advance(42);
    assert_eq!(store.now(), 1_042);
}
