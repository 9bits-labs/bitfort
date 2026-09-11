//! Regression tests: environment variables that redirect git's discovery or configuration
//! must not reach the anti-rollback lookup.
//!
//! Two failure shapes are covered. `GIT_DIR` pointed the lookup at a decoy repository.
//! `GIT_COMMON_DIR` made every git call fail, which the old code read as "not a repository"
//! and turned into a ceiling of zero - anti-rollback silently off. Both are now stripped in
//! [`bitfort_core::git`], and a git failure inside a repository is an error rather than a
//! degraded answer.
//!
//! Kept in its own integration-test binary so the process-global env mutation runs
//! single-threaded and cannot race the crate's unit tests.

use std::fs;
use std::path::Path;
use std::process::Command;

use bitfort_core::git::{committed_blobs, repo_state, stage_and_commit, RepoState};

fn run_git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn commit_version(dir: &Path, version: u64) {
    fs::write(
        dir.join("keys.json"),
        format!("{{\"roster_version\": {version}}}"),
    )
    .unwrap();
    run_git(dir, &["add", "keys.json"]);
    run_git(
        dir,
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            "c",
        ],
    );
}

/// The highest `roster_version` visible in `dir`'s history for `keys.json`.
fn highest(dir: &Path) -> u64 {
    committed_blobs(dir, "keys.json")
        .unwrap()
        .iter()
        .filter_map(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .filter_map(|v| v["roster_version"].as_u64())
        .max()
        .unwrap_or(0)
}

/// All three cases live in one test on purpose: `cargo test` runs the functions in an
/// integration binary in parallel, and the process environment is shared, so separate
/// `#[test]`s would poison each other's `git` invocations.
#[test]
fn redirecting_env_vars_cannot_disable_the_witness() {
    gitdir_cannot_redirect_the_lookup();
    git_common_dir_cannot_disable_the_witness();
    git_config_cannot_inject_configuration();
}

fn gitdir_cannot_redirect_the_lookup() {
    let real = tempfile::tempdir().unwrap();
    run_git(real.path(), &["init", "-q"]);
    commit_version(real.path(), 99);

    let decoy = tempfile::tempdir().unwrap();
    run_git(decoy.path(), &["init", "-q"]);
    commit_version(decoy.path(), 1);

    // Point GIT_DIR at the low-version decoy; the sanitized lookup must ignore it and
    // still read the real repo's history. (Edition 2021: env mutation is safe; this test
    // has its own single-threaded process so there is no getenv/setenv race.)
    std::env::set_var("GIT_DIR", decoy.path().join(".git"));
    let got = highest(real.path());
    std::env::remove_var("GIT_DIR");

    assert_eq!(got, 99, "GIT_DIR redirected the anti-rollback lookup");
}

fn git_common_dir_cannot_disable_the_witness() {
    // Regression: GIT_COMMON_DIR was missing from the strip list, so setting it to a
    // nonexistent path made `rev-parse` exit 128. That read as "not a repository", the
    // ceiling became 0, and `bitfort set` re-encrypted to a rolled-back roster while
    // `verify` printed OK.
    let repo = tempfile::tempdir().unwrap();
    run_git(repo.path(), &["init", "-q"]);
    commit_version(repo.path(), 42);

    std::env::set_var("GIT_COMMON_DIR", "/nonexistent");
    let state = repo_state(repo.path()).unwrap();
    let got = highest(repo.path());
    std::env::remove_var("GIT_COMMON_DIR");

    assert_eq!(
        state,
        RepoState::Full,
        "GIT_COMMON_DIR made the repository look absent"
    );
    assert_eq!(got, 42, "GIT_COMMON_DIR disabled the anti-rollback witness");
}

fn git_config_cannot_inject_configuration() {
    // Two channels inject arbitrary git settings into every git invocation, `core.hooksPath`
    // among them - which turns the commit-for-me path into "run my script". `GIT_CONFIG_COUNT`
    // carries numbered key/value pairs; `GIT_CONFIG_PARAMETERS` carries a whole `-c` list and
    // needs no count, which is why stripping the count alone was not enough.
    hooks_path_injection_is_ignored("counted", |hooks| {
        vec![
            ("GIT_CONFIG_COUNT", "1".to_string()),
            ("GIT_CONFIG_KEY_0", "core.hooksPath".to_string()),
            ("GIT_CONFIG_VALUE_0", hooks.to_string()),
        ]
    });
    hooks_path_injection_is_ignored("parameters", |hooks| {
        vec![("GIT_CONFIG_PARAMETERS", format!("'core.hooksPath={hooks}'"))]
    });
}

/// Plant a `pre-commit` hook, set the environment `vars` build from its directory, and commit
/// through [`stage_and_commit`]. The hook is the observable: a setting that only changes what
/// git *reports* proves nothing about what a commit would run.
fn hooks_path_injection_is_ignored(
    label: &str,
    vars: impl Fn(&str) -> Vec<(&'static str, String)>,
) {
    let repo = tempfile::tempdir().unwrap();
    run_git(repo.path(), &["init", "-q"]);
    run_git(repo.path(), &["config", "user.email", "t@example.com"]);
    run_git(repo.path(), &["config", "user.name", "test"]);
    commit_version(repo.path(), 7);

    let hooks = repo.path().join("hooks");
    let marker = repo.path().join("PWNED");
    fs::create_dir(&hooks).unwrap();
    let script = hooks.join("pre-commit");
    fs::write(&script, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let planted = vars(&hooks.display().to_string());
    for (var, value) in &planted {
        std::env::set_var(var, value);
    }
    fs::write(repo.path().join("keys.json"), "{\"roster_version\": 8}").unwrap();
    let committed = stage_and_commit(repo.path(), &["keys.json"], "roster: bump");
    let state = repo_state(repo.path()).unwrap();
    let got = highest(repo.path());
    for (var, _) in &planted {
        std::env::remove_var(var);
    }

    committed.unwrap();
    assert!(
        !marker.exists(),
        "{label}: an injected core.hooksPath ran a planted hook"
    );
    assert_eq!(state, RepoState::Full);
    assert_eq!(got, 8, "{label}: injected git config reached the lookup");
}
