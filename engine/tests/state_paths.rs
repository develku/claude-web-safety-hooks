//! Filesystem redirection and TOCTOU hardening for the state root.
//!
//! MAC-21's third finding: the store checked paths with `symlink_metadata` and
//! then re-resolved the *name* for the SQLite open and the chmod, accepted a
//! final-file hardlink, and never validated the parent components. A same-UID
//! attacker could redirect the database between the check and the use.
//!
//! What is defended here, and what is honestly not:
//!
//! * every **static** redirection — a symlinked root, a symlinked parent
//!   component, a symlinked database, a symlinked WAL/SHM sidecar, a hardlinked
//!   database, a group/world-writable controlled root, a foreign-owned
//!   component — is rejected before SQLite is given the path;
//! * a redirection that lands **between** validation and SQLite's open is
//!   *detected* after the fact by re-checking the object's identity, and turns
//!   into a typed error rather than a silent write to the attacker's file. The
//!   `replacement` test drives exactly that window through a controlled hook;
//! * a same-UID process that can rename parent directories *continuously* is
//!   **not** defeated by a pathname-based SQLite VFS. See `docs/state.md`.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use web_safety_engine::state::{StateConfig, StateError, StateMode, StateStore};

fn temp_root() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).expect("the temp dir resolves")
}

/// A fresh, symlink-free, 0700 sandbox. Returns the sandbox, not the state root:
/// each test decides what to put at the state root's name.
fn sandbox(tag: &str) -> PathBuf {
    let base = temp_root().join(format!(
        "ws-paths-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("sandbox");
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    base
}

fn config(dir: PathBuf) -> StateConfig {
    StateConfig {
        mode: StateMode::Report,
        dir,
        ..StateConfig::default()
    }
}

fn open(dir: PathBuf) -> Result<Option<StateStore>, StateError> {
    StateStore::open(config(dir))
}

fn unsafe_path_err(dir: PathBuf) -> StateError {
    match open(dir) {
        Err(e) => e,
        Ok(_) => panic!("the path must be refused"),
    }
}

fn assert_unsafe(dir: PathBuf, needle: &str) {
    let e = unsafe_path_err(dir);
    match &e {
        StateError::UnsafePath { why, .. } => assert!(
            why.contains(needle),
            "expected {needle:?} in the reason, got {why:?}"
        ),
        other => panic!("expected UnsafePath, got {other:?}"),
    }
}

// ── static redirection ──────────────────────────────────────────────────────

#[test]
fn a_symlinked_state_root_is_refused() {
    let s = sandbox("root-symlink");
    let real = s.join("real");
    std::fs::create_dir(&real).expect("mkdir");
    let link = s.join("state");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert_unsafe(link, "symbolic link");
}

/// The gap the old code left open: only the final two components were checked,
/// so a symlinked *parent* redirected the whole state root.
#[test]
fn a_symlinked_parent_component_is_refused() {
    let s = sandbox("parent-symlink");
    let real = s.join("real");
    std::fs::create_dir(&real).expect("mkdir");
    let link = s.join("via");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert_unsafe(link.join("state"), "symbolic link");
}

#[test]
fn a_symlinked_database_is_refused() {
    let s = sandbox("db-symlink");
    let dir = s.join("state");
    std::fs::create_dir(&dir).expect("mkdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let target = s.join("elsewhere.db");
    std::fs::write(&target, b"").expect("target");
    std::os::unix::fs::symlink(&target, dir.join("state.db")).expect("symlink");

    assert_unsafe(dir, "symbolic link");
}

/// A hardlink has no symlink to see: the second name is the same inode, so the
/// only signal is the link count.
#[test]
fn a_hardlinked_database_is_refused() {
    let s = sandbox("db-hardlink");
    let dir = s.join("state");
    std::fs::create_dir(&dir).expect("mkdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let db = dir.join("state.db");
    std::fs::write(&db, b"").expect("db");
    std::fs::hard_link(&db, s.join("attacker-copy.db")).expect("hardlink");

    assert_unsafe(dir, "link count");
}

#[test]
fn a_database_that_is_not_a_regular_file_is_refused() {
    let s = sandbox("db-dir");
    let dir = s.join("state");
    std::fs::create_dir_all(dir.join("state.db")).expect("mkdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");

    assert_unsafe(dir, "regular file");
}

#[test]
fn a_state_root_that_is_not_a_directory_is_refused() {
    let s = sandbox("root-file");
    let dir = s.join("state");
    std::fs::write(&dir, b"not a directory").expect("write");

    assert_unsafe(dir, "not a directory");
}

// ── permissions and ownership ───────────────────────────────────────────────

#[test]
fn a_group_or_world_writable_state_root_is_refused() {
    for mode in [0o770u32, 0o707, 0o777] {
        let s = sandbox(&format!("root-mode-{mode:o}"));
        let dir = s.join("state");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).expect("chmod");

        assert_unsafe(dir, "writable");
    }
}

/// A world-writable *ancestor* without the sticky bit lets anyone rename the
/// component out from under us. With the sticky bit (the `/tmp` shape) only the
/// owner can, which is the guarantee the walk relies on.
#[test]
fn a_world_writable_non_sticky_ancestor_is_refused_but_a_sticky_one_is_not() {
    let s = sandbox("ancestor-mode");
    let loose = s.join("loose");
    std::fs::create_dir(&loose).expect("mkdir");
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).expect("chmod");
    assert_unsafe(loose.join("state"), "writable");

    let sticky = s.join("sticky");
    std::fs::create_dir(&sticky).expect("mkdir");
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).expect("chmod");
    open(sticky.join("state")).expect("a sticky world-writable ancestor is the /tmp shape");
}

#[test]
fn a_relative_state_root_is_refused_because_its_components_cannot_be_pinned() {
    let e = unsafe_path_err(PathBuf::from("relative/state"));
    match &e {
        StateError::UnsafePath { why, .. } => {
            assert!(why.contains("absolute"), "got {why:?}")
        }
        other => panic!("expected UnsafePath, got {other:?}"),
    }
}

#[test]
fn a_dot_or_dotdot_component_is_still_refused() {
    let s = sandbox("traversal");
    assert_unsafe(s.join("..").join("state"), "`.` or `..`");
}

// ── what a successful open guarantees ───────────────────────────────────────

#[test]
fn a_created_root_is_0700_and_the_database_is_0600_at_creation() {
    let s = sandbox("modes");
    let dir = s.join("deep").join("state");
    let store = open(dir.clone()).expect("open").expect("store");
    drop(store);

    let mode = |p: &Path| {
        std::fs::symlink_metadata(p)
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode(&dir), 0o700, "the state root");
    assert_eq!(mode(&s.join("deep")), 0o700, "every component we created");
    assert_eq!(mode(&dir.join("state.db")), 0o600, "the database");
    for sidecar in ["state.db-wal", "state.db-shm"] {
        let p = dir.join(sidecar);
        if p.exists() {
            assert_eq!(
                mode(&p) & 0o077,
                0,
                "{sidecar} must not be group/world accessible"
            );
        }
    }
}

#[test]
fn reopening_a_store_this_build_created_is_accepted() {
    let s = sandbox("reopen");
    let dir = s.join("state");
    drop(open(dir.clone()).expect("first open").expect("store"));
    drop(open(dir).expect("second open").expect("store"));
}

/// A symlinked sidecar is a redirection of the *write path*, even though the
/// database file itself is clean.
#[test]
fn a_symlinked_wal_sidecar_is_refused() {
    let s = sandbox("wal-symlink");
    let dir = s.join("state");
    drop(open(dir.clone()).expect("seed the store").expect("store"));
    for sidecar in ["state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(dir.join(sidecar));
    }
    std::os::unix::fs::symlink(s.join("stolen-wal"), dir.join("state.db-wal")).expect("symlink");

    assert_unsafe(dir, "symbolic link");
}

// ── the check-to-use window ─────────────────────────────────────────────────

/// The race the pathname API cannot close, driven deterministically.
///
/// The hook fires *after* the path has been validated and the database file has
/// been opened and identified, and *before* SQLite is handed the name. It swaps
/// a different inode into place — exactly what a same-UID attacker would do.
/// The post-open identity re-check must catch it and fail typed.
#[test]
fn an_object_replaced_between_validation_and_open_is_detected() {
    let s = sandbox("replacement");
    let dir = s.join("state");
    let decoy = s.join("decoy.db");
    std::fs::write(&decoy, b"").expect("decoy");

    let armed = web_safety_engine::state::store::testing::arm_preopen_hook(|db| {
        // Only act on this test's root; the hook is a process-wide static and
        // other tests open stores concurrently.
        if !db.to_string_lossy().contains("ws-paths-replacement-") {
            return;
        }
        let decoy = db
            .parent()
            .expect("parent")
            .parent()
            .expect("sandbox")
            .join("decoy.db");
        let _ = std::fs::remove_file(db);
        let _ = std::fs::rename(&decoy, db);
    });

    let err = open(dir).expect_err("a replaced object must not be written to");
    drop(armed);

    match &err {
        StateError::UnsafePath { why, .. } => assert!(
            why.contains("changed"),
            "expected a replacement report, got {why:?}"
        ),
        other => panic!("expected UnsafePath, got {other:?}"),
    }
}

// ── mode mapping ────────────────────────────────────────────────────────────

/// A path failure is not special: `report` reports it and `enforce` contains.
#[test]
fn a_path_failure_maps_onto_report_and_enforce_exactly_like_any_state_failure() {
    use web_safety_engine::contract::{Decision, ScanResponse, Severity, SCHEMA_VERSION};
    use web_safety_engine::state::{StateContext, StateEvent, StateLayer};

    let s = sandbox("mapping");
    let link = s.join("state");
    std::os::unix::fs::symlink(s.join("nowhere"), &link).expect("symlink");

    let response = ScanResponse {
        schema_version: SCHEMA_VERSION,
        severity: Severity::Medium,
        decision: Decision::Ask,
        findings: vec![],
        truncated: false,
        scanned_bytes: 0,
        elapsed_us: 0,
        state: None,
        replacement: None,
    };
    let ctx = StateContext::new("claude", "profile-a", "s1");
    let event = StateEvent {
        response: &response,
        content: "x",
        content_trusted: false,
        quarantine_enabled: true,
    };

    for (mode, contained) in [(StateMode::Report, false), (StateMode::Enforce, true)] {
        let layer = StateLayer::open(StateConfig {
            mode,
            dir: link.clone(),
            ..StateConfig::default()
        });
        let r = layer.apply(&ctx, &event);
        assert!(!r.applied, "{mode:?}");
        assert_eq!(r.containment, contained, "{mode:?}");
        assert!(r.error.is_some(), "{mode:?}");
    }
}

/// The hardening is a handful of `lstat` calls, not a new latency class.
#[test]
fn validation_stays_far_inside_the_per_call_budget() {
    let s = sandbox("latency");
    let dir = s.join("state");
    drop(open(dir.clone()).expect("seed").expect("store"));

    let started = std::time::Instant::now();
    for _ in 0..20 {
        drop(open(dir.clone()).expect("open").expect("store"));
    }
    let per_open = started.elapsed() / 20;
    assert!(
        per_open < std::time::Duration::from_millis(50),
        "path validation + open took {per_open:?} per call"
    );
}
