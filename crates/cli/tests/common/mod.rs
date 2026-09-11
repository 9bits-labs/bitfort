//! Shared helpers for the CLI e2e tests. Every test drives `bitfort` with the identity
//! supplied via `BITFORT_IDENTITY`/`BITFORT_SIGN_IDENTITY`, so the OS keyring is never
//! touched (the headless/CI path, docs/SPEC.md §3.1) and the suite stays hermetic.
//!
//! Each test binary includes this module but uses only a subset of it, so helpers that
//! one file doesn't touch would read as dead code in that binary.
#![allow(dead_code)]

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use bitfort_core::{Identity, Roster, Vault};
use tempfile::TempDir;

/// An initialized project plus the identity it was initialized with.
pub struct Fixture {
    pub dir: TempDir,
    pub id: Identity,
}

/// A `bitfort` command rooted at `dir` with `id` supplied out-of-band as the identity.
pub fn bf(dir: &Path, id: &Identity) -> Command {
    let mut cmd = Command::cargo_bin("bitfort").unwrap();
    cmd.current_dir(dir);
    cmd.env("BITFORT_IDENTITY", id.enc_secret().as_str());
    cmd.env("BITFORT_SIGN_IDENTITY", id.sign_secret().as_str());
    // Make sure a stray file-based source in the environment can't shadow the pair above.
    cmd.env_remove("BITFORT_IDENTITY_FILE");
    cmd
}

/// The same command as [`bf`], as a plain [`std::process::Command`].
///
/// [`bf`] returns an `assert_cmd::Command`, which runs the child to completion, so a test
/// that has to signal `bitfort` while it waits, or hand it a pty, needs the raw type.
pub fn raw_bf(dir: &Path, id: &Identity) -> std::process::Command {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("bitfort"));
    cmd.current_dir(dir);
    cmd.env("BITFORT_IDENTITY", id.enc_secret().as_str());
    cmd.env("BITFORT_SIGN_IDENTITY", id.sign_secret().as_str());
    cmd.env_remove("BITFORT_IDENTITY_FILE");
    cmd
}

/// Generate a fresh identity and run `bitfort init` in a new temp dir with it.
pub fn init_project() -> Fixture {
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    bf(dir.path(), &id).arg("init").assert().success();
    Fixture { dir, id }
}

/// Like [`init_project`], but also makes the dir a git repo and commits the v1 roster, so
/// anti-rollback is enforced.
pub fn init_git_project() -> Fixture {
    let f = init_project();
    git(f.dir.path(), &["init", "-q"]);
    git_commit_all(f.dir.path(), "init");
    f
}

/// Run a git command in `dir`, asserting success. Identity is supplied via env so no
/// global git config is required on the runner.
pub fn git(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@e.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@e.com")
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?} failed");
}

/// Stage everything and commit with `msg`.
pub fn git_commit_all(dir: &Path, msg: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", msg]);
}

/// Run a git command that is allowed to fail (e.g. a `merge` that conflicts), returning
/// whether it succeeded.
pub fn git_try(dir: &Path, args: &[&str]) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@e.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@e.com")
        .status()
        .unwrap()
        .success()
}

/// The environment's `vault.enc` path, through the same API the tool uses, so the on-disk
/// layout is not spelled out again in each test file.
pub fn vault_path(dir: &Path, env: &str) -> PathBuf {
    bitfort_core::Project::discover(dir)
        .unwrap()
        .vault_path(env)
}

/// Overwrite the environment's `vault.enc` with one `signer` signed, encrypted to `roster`.
/// The only way a test can produce a payload the CLI refuses to write - a hostile member's
/// vault, or one holding a name `set` rejects - since it goes through the core API rather
/// than a command.
pub fn write_vault(
    dir: &Path,
    env: &str,
    roster: &Roster,
    signer: &Identity,
    vars: &[(&str, &str)],
) {
    let mut vault = Vault::new(env);
    for (key, value) in vars {
        vault.set(key, *value).unwrap();
    }
    std::fs::write(vault_path(dir, env), vault.encrypt(roster, signer).unwrap()).unwrap();
}

/// Put the vault into a git merge conflict: edit it on `main`, edit it again on a `feature`
/// branch, then merge. `feature_edit` makes the second edit, so a caller can use a command or
/// write the payload directly. Returns with the working tree holding conflict markers.
///
/// The recipe is brittle - default branch naming, and the expectation that the merge conflicts
/// at all - so it lives here rather than once per test binary.
pub fn make_vault_conflict(f: &Fixture, main_key: &str, feature_edit: impl FnOnce(&Fixture)) {
    // Normalize the default branch name (git may init `master` or `main`).
    git(f.dir.path(), &["branch", "-M", "main"]);
    bf(f.dir.path(), &f.id)
        .args(["set", "BASE=b"])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "base secret");

    git(f.dir.path(), &["branch", "feature"]);
    bf(f.dir.path(), &f.id)
        .args(["set", main_key])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "main edit");

    git(f.dir.path(), &["checkout", "-q", "feature"]);
    feature_edit(f);
    git_commit_all(f.dir.path(), "feature edit");

    git(f.dir.path(), &["checkout", "-q", "main"]);
    assert!(
        !git_try(f.dir.path(), &["merge", "--no-edit", "feature"]),
        "the vault edits should have conflicted"
    );
}

/// The invite blob a developer with `id` would hand to a maintainer.
pub fn invite_for(id: &Identity, name: &str) -> String {
    bitfort_core::Invite::from_identity(id, name)
        .encode()
        .unwrap()
}

/// A pty pair, with the master set non-blocking so a test can read with a deadline instead
/// of hanging the suite.
pub fn open_pty() -> (OwnedFd, OwnedFd) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");

        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname failed");
        let name = std::ffi::CStr::from_ptr(name).to_owned();

        let slave = libc::open(name.as_ptr(), libc::O_RDWR);
        assert!(slave >= 0, "opening the pty slave failed");

        let flags = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, flags | libc::O_NONBLOCK);

        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    }
}
