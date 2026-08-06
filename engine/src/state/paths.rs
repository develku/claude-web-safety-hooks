//! Path safety for the state root: what is checked, in what order, and what is
//! honestly still out of reach.
//!
//! SQLite's public API takes a **pathname**, not a descriptor. Every guarantee
//! below is therefore built out of two things: refusing every redirection that
//! is already in place before the name is handed over, and *detecting* one that
//! lands in the window between the check and the open.
//!
//! ## The order
//!
//! 1. the root must be absolute and free of `.` / `..` — a relative root is
//!    resolved against a working directory this process does not own;
//! 2. every **existing** component from `/` down to the root's parent is
//!    `lstat`ed: not a symlink, a directory, owned by this uid or by root, and
//!    not group/world-writable unless it carries the sticky bit (the `/tmp`
//!    shape, where only the owner can rename an entry);
//! 3. every **missing** component is created one at a time with mode `0700` at
//!    creation — never `0777`-then-chmod, which leaves a window a concurrent
//!    process can walk through;
//! 4. the controlled root itself is held to the stricter rule: owned by this
//!    uid and not group/world-writable, sticky bit or not;
//! 5. the database is `lstat`ed (regular file, link count 1, our uid, not
//!    group/world-writable), then opened by *us* with `O_NOFOLLOW | O_CLOEXEC`
//!    and mode `0600`, and `fstat`ed through that descriptor so the identity we
//!    record is the object we actually opened rather than the name we asked for;
//! 6. any existing WAL/SHM sidecar is held to the same rule *before* SQLite is
//!    allowed to create or reuse one;
//! 7. SQLite opens with `SQLITE_OPEN_NOFOLLOW`;
//! 8. afterwards the database name is `lstat`ed again and compared field for
//!    field against the recorded identity, and the sidecars are re-validated and
//!    tightened to `0600`.
//!
//! ## What this does not do
//!
//! A same-UID process that can rename the state root's parent directories
//! *continuously* is not defeated by any of this. Step 8 detects the swap after
//! the fact — which is enough to refuse the transition, and is why every
//! detection is a typed error rather than a warning — but a sufficiently
//! persistent attacker can keep losing that race and trying again. Closing it
//! needs a descriptor-based VFS or a privileged broker, neither of which is in
//! this stage. `docs/state.md` states the residual limitation and the
//! containment gate production cutover stays blocked on.

use std::path::{Component, Path, PathBuf};

use super::StateError;

/// The only filename this crate ever opens under the state root.
pub const DB_FILENAME: &str = "state.db";

/// SQLite derives these from the database name. We never open them, but we do
/// refuse to run when one of them is a redirection.
pub const SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

pub fn unsafe_path(p: &Path, why: impl Into<String>) -> StateError {
    StateError::UnsafePath {
        path: p.display().to_string(),
        why: why.into(),
    }
}

fn unusable(p: &Path, what: &str, e: std::io::Error) -> StateError {
    StateError::Unusable {
        why: format!("cannot {what} {}: {e}", p.display()),
    }
}

/// A validated state root plus the identity of the database object inside it.
pub struct PreparedRoot {
    pub db: PathBuf,
    pub identity: FileIdentity,
}

/// Shape-independent identity of an opened object. Compared field for field
/// after SQLite's open; any difference means the name now refers to something
/// else than the thing that was validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub nlink: u64,
    pub is_regular_file: bool,
}

/// Structural checks that hold on every platform: absolute, no `.` / `..`.
fn check_shape(dir: &Path) -> Result<(), StateError> {
    if dir.as_os_str().is_empty() {
        return Err(unsafe_path(dir, "is empty"));
    }
    if dir
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(unsafe_path(
            dir,
            "contains a `.` or `..` component; the state root must be a direct path",
        ));
    }
    if !dir.is_absolute() {
        return Err(unsafe_path(
            dir,
            "is not absolute; a relative state root is resolved against a working \
             directory this process does not control — pass a fully resolved path",
        ));
    }
    Ok(())
}

/// The prefixes of `dir`, shallowest first, including `dir` itself.
fn prefixes(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut acc = PathBuf::new();
    for c in dir.components() {
        acc.push(c.as_os_str());
        out.push(acc.clone());
    }
    out
}

// ── Unix ────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;
    use std::fs::{DirBuilder, File, Metadata, OpenOptions, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    fn euid() -> u32 {
        // SAFETY: `geteuid` is always successful and touches no memory.
        unsafe { libc::geteuid() }
    }

    fn identity(md: &Metadata) -> FileIdentity {
        FileIdentity {
            dev: md.dev(),
            ino: md.ino(),
            uid: md.uid(),
            nlink: md.nlink(),
            is_regular_file: md.file_type().is_file(),
        }
    }

    /// Owned by us, or by root. Anything else means a component of the path we
    /// are about to write through belongs to somebody who can replace it.
    fn check_owner(p: &Path, md: &Metadata) -> Result<(), StateError> {
        let uid = md.uid();
        if uid != euid() && uid != 0 {
            return Err(unsafe_path(
                p,
                format!("is owned by uid {uid}, which is neither this process's uid nor root"),
            ));
        }
        Ok(())
    }

    /// A component someone else can rename is a component that can redirect the
    /// path. The sticky bit is the documented exception: on a sticky directory
    /// only the entry's owner may rename or remove it, which is exactly the
    /// property `/tmp` relies on.
    fn check_ancestor_mode(p: &Path, md: &Metadata) -> Result<(), StateError> {
        let mode = md.mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(unsafe_path(
                p,
                format!(
                    "is group/world-writable ({:o}) without the sticky bit, so any local user \
                     can rename it and redirect the state root",
                    mode & 0o7777
                ),
            ));
        }
        Ok(())
    }

    fn check_existing_ancestor(p: &Path, md: &Metadata) -> Result<(), StateError> {
        if md.file_type().is_symlink() {
            return Err(unsafe_path(
                p,
                "is a symbolic link; a redirectable component is not a controlled path",
            ));
        }
        if !md.is_dir() {
            return Err(unsafe_path(p, "exists and is not a directory"));
        }
        check_owner(p, md)?;
        check_ancestor_mode(p, md)
    }

    /// The controlled root is held to the stricter rule: the sticky bit does
    /// not rescue it, because write access to the state root itself is write
    /// access to the database's directory entry.
    fn check_controlled_root(p: &Path, md: &Metadata) -> Result<(), StateError> {
        if md.file_type().is_symlink() {
            return Err(unsafe_path(
                p,
                "is a symbolic link; a redirectable state root is not a controlled path",
            ));
        }
        if !md.is_dir() {
            return Err(unsafe_path(p, "exists and is not a directory"));
        }
        check_owner(p, md)?;
        let mode = md.mode();
        if mode & 0o022 != 0 {
            return Err(unsafe_path(
                p,
                format!(
                    "is group/world-writable ({:o}); the state root must be reachable only by \
                     its owner",
                    mode & 0o7777
                ),
            ));
        }
        Ok(())
    }

    /// Walk the chain, validating what exists and creating what does not with a
    /// restrictive mode **at creation**.
    pub fn ensure_root(dir: &Path) -> Result<(), StateError> {
        let chain = prefixes(dir);
        let (root, ancestors) = chain.split_last().expect("an absolute path has components");

        for p in ancestors {
            match std::fs::symlink_metadata(p) {
                Ok(md) => check_existing_ancestor(p, &md)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    create_private_dir(p)?;
                }
                Err(e) => return Err(unusable(p, "stat", e)),
            }
        }

        match std::fs::symlink_metadata(root) {
            Ok(md) => check_controlled_root(root, &md),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_private_dir(root),
            Err(e) => Err(unusable(root, "stat", e)),
        }
    }

    /// `mkdir(0700)`, then validate what we got. `mode()` on `DirBuilder` sets
    /// the mode in the `mkdir` call itself, so there is no window in which the
    /// directory exists at a looser mode — but `mkdir`'s mode is still masked by
    /// the process umask, so the result is verified rather than assumed.
    fn create_private_dir(p: &Path) -> Result<(), StateError> {
        match DirBuilder::new().mode(0o700).create(p) {
            Ok(()) => {}
            // Somebody created it while we were walking. That is legal (two
            // scanners starting at once) but it is now an object we did not
            // make, so it goes through the same validation as any other.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(unusable(p, "create", e)),
        }
        let md = std::fs::symlink_metadata(p).map_err(|e| unusable(p, "stat", e))?;
        if md.file_type().is_symlink() {
            return Err(unsafe_path(
                p,
                "became a symbolic link while the state root was being created",
            ));
        }
        if !md.is_dir() {
            return Err(unsafe_path(p, "exists and is not a directory"));
        }
        check_owner(p, &md)?;
        if md.mode() & 0o077 != 0 {
            std::fs::set_permissions(p, Permissions::from_mode(0o700))
                .map_err(|e| unusable(p, "tighten", e))?;
        }
        Ok(())
    }

    /// Validate, then open the database **ourselves** with `O_NOFOLLOW`, and
    /// take the identity from the descriptor rather than from the name.
    pub fn open_and_identify(db: &Path) -> Result<FileIdentity, StateError> {
        if let Some(md) = lstat_opt(db)? {
            check_data_file(db, &md, "database")?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(db)
            .map_err(|e| match e.raw_os_error() {
                // ELOOP is what `O_NOFOLLOW` reports for a symlinked final
                // component; it is a redirection, not an I/O problem.
                Some(code) if code == libc::ELOOP => unsafe_path(
                    db,
                    "is a symbolic link; the database must be a real file inside the state root",
                ),
                _ => unusable(db, "open", e),
            })?;

        let md = file.metadata().map_err(|e| unusable(db, "stat", e))?;
        check_data_file(db, &md, "database")?;
        // Through the descriptor: no name is resolved a second time.
        if md.mode() & 0o077 != 0 {
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|e| unusable(db, "tighten", e))?;
        }
        Ok(identity(&md))
    }

    /// Common rule for the database and for its sidecars: a regular file, with
    /// exactly one name, owned by us, unreachable by anybody else's writes.
    fn check_data_file(p: &Path, md: &Metadata, what: &str) -> Result<(), StateError> {
        if md.file_type().is_symlink() {
            return Err(unsafe_path(
                p,
                format!("is a symbolic link; the {what} must be a real file inside the state root"),
            ));
        }
        if !md.file_type().is_file() {
            return Err(unsafe_path(p, "exists and is not a regular file"));
        }
        if md.nlink() != 1 {
            return Err(unsafe_path(
                p,
                format!(
                    "has a link count of {}, not 1 — a second name for the {what} is a second \
                     writer we cannot see",
                    md.nlink()
                ),
            ));
        }
        check_owner(p, md)?;
        if md.mode() & 0o022 != 0 {
            return Err(unsafe_path(
                p,
                format!(
                    "is group/world-writable ({:o}); the {what} must be writable only by its owner",
                    md.mode() & 0o7777
                ),
            ));
        }
        Ok(())
    }

    /// The sidecars, before SQLite may create them and again after it has.
    /// `tighten` is off on the first pass (nothing of ours exists yet) and on
    /// for the second.
    pub fn check_sidecars(db: &Path, tighten: bool) -> Result<(), StateError> {
        for suffix in SIDECAR_SUFFIXES {
            let p = sidecar(db, suffix);
            let Some(md) = lstat_opt(&p)? else { continue };
            check_data_file(&p, &md, "WAL/SHM sidecar")?;
            if tighten && md.mode() & 0o077 != 0 {
                std::fs::set_permissions(&p, Permissions::from_mode(0o600))
                    .map_err(|e| unusable(&p, "tighten", e))?;
            }
        }
        Ok(())
    }

    /// The post-open comparison. Anything that moved between the validation and
    /// SQLite's open shows up here as a difference in the recorded identity.
    pub fn recheck(db: &Path, expected: &FileIdentity) -> Result<(), StateError> {
        let md = lstat_opt(db)?.ok_or_else(|| {
            unsafe_path(
                db,
                "changed between validation and open: the database disappeared",
            )
        })?;
        let found = identity(&md);
        if found != *expected {
            return Err(unsafe_path(
                db,
                format!(
                    "changed between validation and open (was dev/ino {}/{} uid {} links {}, \
                     now {}/{} uid {} links {}) — refusing to write through a redirected name",
                    expected.dev,
                    expected.ino,
                    expected.uid,
                    expected.nlink,
                    found.dev,
                    found.ino,
                    found.uid,
                    found.nlink
                ),
            ));
        }
        check_sidecars(db, true)
    }

    fn lstat_opt(p: &Path) -> Result<Option<Metadata>, StateError> {
        match std::fs::symlink_metadata(p) {
            Ok(md) => Ok(Some(md)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(unusable(p, "stat", e)),
        }
    }

    /// Unused on this platform but part of the shared surface.
    #[allow(dead_code)]
    fn _assert_file_type(_: &File) {}
}

// ── everything else ─────────────────────────────────────────────────────────
//
// No mode bits and no uid to check. The structural checks (absolute, no `..`,
// not a symlink, not a directory-where-a-file-belongs) still apply; ownership
// and permission validation do not, and `docs/state.md` records that as a
// platform limitation rather than pretending it away.

#[cfg(not(unix))]
mod imp {
    use super::*;
    use std::fs::Metadata;

    pub fn ensure_root(dir: &Path) -> Result<(), StateError> {
        for p in prefixes(dir) {
            match std::fs::symlink_metadata(&p) {
                Ok(md) => {
                    if md.file_type().is_symlink() {
                        return Err(unsafe_path(&p, "is a symbolic link"));
                    }
                    if !md.is_dir() {
                        return Err(unsafe_path(&p, "exists and is not a directory"));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&p).map_err(|e| unusable(&p, "create", e))?;
                }
                Err(e) => return Err(unusable(&p, "stat", e)),
            }
        }
        Ok(())
    }

    fn identity(md: &Metadata) -> FileIdentity {
        FileIdentity {
            dev: 0,
            ino: 0,
            uid: 0,
            nlink: 1,
            is_regular_file: md.file_type().is_file(),
        }
    }

    pub fn open_and_identify(db: &Path) -> Result<FileIdentity, StateError> {
        match std::fs::symlink_metadata(db) {
            Ok(md) => {
                if md.file_type().is_symlink() {
                    return Err(unsafe_path(db, "is a symbolic link"));
                }
                if !md.file_type().is_file() {
                    return Err(unsafe_path(db, "exists and is not a regular file"));
                }
                Ok(identity(&md))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileIdentity {
                dev: 0,
                ino: 0,
                uid: 0,
                nlink: 1,
                is_regular_file: true,
            }),
            Err(e) => Err(unusable(db, "stat", e)),
        }
    }

    pub fn check_sidecars(db: &Path, _tighten: bool) -> Result<(), StateError> {
        for suffix in SIDECAR_SUFFIXES {
            let p = sidecar(db, suffix);
            if let Ok(md) = std::fs::symlink_metadata(&p) {
                if md.file_type().is_symlink() {
                    return Err(unsafe_path(&p, "is a symbolic link"));
                }
            }
        }
        Ok(())
    }

    pub fn recheck(db: &Path, _expected: &FileIdentity) -> Result<(), StateError> {
        check_sidecars(db, true)
    }
}

/// `<db>-wal` / `<db>-shm`, the names SQLite derives from the database name.
pub fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Steps 1–6: everything that must hold before SQLite is handed the name.
pub fn prepare(dir: &Path) -> Result<PreparedRoot, StateError> {
    check_shape(dir)?;
    imp::ensure_root(dir)?;
    let db = dir.join(DB_FILENAME);
    imp::check_sidecars(&db, false)?;
    let identity = imp::open_and_identify(&db)?;
    Ok(PreparedRoot { db, identity })
}

/// Step 8: the object SQLite opened is still the object that was validated.
pub fn verify_after_open(db: &Path, expected: &FileIdentity) -> Result<(), StateError> {
    imp::recheck(db, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_root_is_refused_before_anything_touches_the_disk() {
        let e = check_shape(Path::new("relative/state")).unwrap_err();
        assert!(e.to_string().contains("absolute"), "{e}");
    }

    #[test]
    fn a_traversal_component_is_refused() {
        let e = check_shape(Path::new("/tmp/../etc/state")).unwrap_err();
        assert!(e.to_string().contains("`.` or `..`"), "{e}");
    }

    #[test]
    fn prefixes_walk_root_to_leaf() {
        let p = prefixes(Path::new("/a/b/c"));
        assert_eq!(
            p,
            vec![
                PathBuf::from("/"),
                PathBuf::from("/a"),
                PathBuf::from("/a/b"),
                PathBuf::from("/a/b/c"),
            ]
        );
    }

    #[test]
    fn sidecar_names_match_sqlites_derivation() {
        let db = Path::new("/s/state.db");
        assert_eq!(sidecar(db, "-wal"), PathBuf::from("/s/state.db-wal"));
        assert_eq!(sidecar(db, "-shm"), PathBuf::from("/s/state.db-shm"));
    }
}
