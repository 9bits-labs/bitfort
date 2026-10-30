//! End-to-end coverage for `bitfort status`, including the MCP/pipe-safety
//! guarantee that human-facing chrome never leaks escape codes into piped
//! output (an MCP host or script consuming `bitfort` must get clean bytes).

mod common;

use common::*;
use predicates::prelude::*;

#[test]
fn status_reports_posture_on_a_fresh_project() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("BitFort"))
        .stdout(predicate::str::contains("anchor"))
        .stdout(predicate::str::contains("roster"))
        .stdout(predicate::str::contains("vault"))
        // The open CLI has no paid tier, so there is no license line to report.
        .stdout(predicate::str::contains("license").not());
}

#[test]
fn status_flags_a_non_git_project() {
    // A bare `init` is not a git repo, so status must surface the best-effort warning
    // and steer the user toward `git init`.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not a git repo"))
        .stdout(predicate::str::contains("git init"));
}

#[test]
fn an_uncommitted_roster_does_not_count_as_rollback_protection() {
    // The ceiling used to come back as `Enforced { highest: 0 }` whenever the repository had
    // any commit at all, even one that never touched `.bitfort`. Zero is not a ceiling: every
    // roster starts at v1, so `>= 0` accepts anything. Invariant 3 wants a witness that cannot
    // run reported, never folded into a zero.
    let f = init_project();
    git(f.dir.path(), &["init", "-q"]);
    std::fs::write(f.dir.path().join("README.md"), "unrelated\n").unwrap();
    git(f.dir.path(), &["add", "README.md"]);
    git(f.dir.path(), &["commit", "-q", "-m", "unrelated"]);

    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("never been committed"))
        .stdout(predicate::str::contains("all set").not());

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure();

    // Committing `.bitfort` is what turns it on.
    git_commit_all(f.dir.path(), "commit bitfort");
    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .success();
}

#[test]
fn every_write_path_reports_an_absent_rollback_witness() {
    // Read paths warned; write paths did not, so `set`, `import`, `rotate` and the membership
    // commands changed the roster and the vault in a shallow clone or outside a repository
    // with no word that a downgrade would not be caught. The warning now sits at the one
    // verification call all of them share.
    let f = init_project();
    let bob = bitfort_core::Identity::generate().unwrap();
    let invite = invite_for(&bob, "bob");
    std::fs::write(f.dir.path().join("seed.env"), "SEEDED=1\n").unwrap();

    for args in [
        vec!["set", "API_KEY=x"],
        vec!["import", "seed.env"],
        vec!["rotate"],
        vec!["unset", "API_KEY", "--yes"],
        vec!["member", "add", &invite],
        vec!["member", "rm", "bob", "--yes"],
    ] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .success()
            .stderr(predicate::str::contains(
                "rollback protection is not enforced here",
            ));
    }
}

#[test]
fn status_names_a_missing_vault_as_the_next_step() {
    // The `next_step` chain skipped `Unreadable`, so a deleted vault printed the failure line
    // and then "all set", while `verify` exited 1 on the same state.
    let f = init_git_project();
    let vault = bitfort_core::Project::discover(f.dir.path())
        .unwrap()
        .vault_path("development");
    std::fs::remove_file(vault).unwrap();

    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("missing or damaged"))
        .stdout(predicate::str::contains("all set").not());
}

#[test]
fn status_reports_a_healthy_committed_project() {
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("rollback"))
        .stdout(predicate::str::contains(
            "enforced against committed history",
        ))
        .stdout(predicate::str::contains("all set"));
}

#[test]
fn status_names_the_real_cause_when_identity_cannot_decrypt() {
    // Regression: a valid identity that is not a recipient of this vault must not be
    // told to run `keygen` (they already have an identity). Status must name the real
    // cause - the local identity can't decrypt - not "no local identity".
    let f = init_project();
    let stranger = bitfort_core::Identity::generate().unwrap();
    bf(f.dir.path(), &stranger)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("holds no seat here"))
        .stdout(predicate::str::contains("no local identity").not());
}

#[test]
fn status_names_a_failing_identity_source() {
    // Regression: a configured identity source that fails is not "no local identity", and
    // `keygen` does not fix it. `verify` still exits 0 and reports the vault as not checked,
    // the same as with no identity, but `verify --strict` fails: in CI this is a broken
    // secret, and the gate would pass a vault it never authenticated (docs/SPEC.md §5.5). A git
    // project, so that the identity is the only thing `--strict` can fail on.
    let f = init_git_project();
    let sign = f.id.sign_secret();
    let bad = format!("{}!{}", &sign[..10], &sign[11..]);
    let why = "BITFORT_SIGN_IDENTITY is not valid base64: character 11 is wrong";
    let run = |args: &[&str]| {
        bf(f.dir.path(), &f.id)
            .env("BITFORT_SIGN_IDENTITY", &bad)
            .args(args)
            .assert()
    };
    run(&["status"])
        .success()
        .stdout(predicate::str::contains(why))
        .stdout(predicate::str::contains(
            "the local identity does not load - fix",
        ))
        .stdout(predicate::str::contains("keygen").not());
    run(&["--json", "status"])
        .success()
        .stdout(predicate::str::contains("\"identity-unusable\""))
        .stdout(predicate::str::contains(why));
    run(&["verify"])
        .success()
        .stdout(predicate::str::contains(why));
    run(&["verify", "--strict"])
        .code(1)
        .stdout(predicate::str::contains(why))
        .stderr(predicate::str::contains(
            "FAILED: --strict requires a local identity that loads",
        ));
    run(&["--json", "verify", "--strict"])
        .code(1)
        .stdout(predicate::str::contains("\"identity-unusable\""));
}

/// Regression: with no env identity and an OS keyring that cannot be reached, `status` told the
/// user to run `bitfort keygen`, and `keygen` failed on the same keyring. The vault line now
/// names the keyring error and the variables to set. The variables are set but empty, as a
/// GitHub Actions job from a fork gets them, so the test also checks that an empty pair counts
/// as no identity: the vault is not checked, and `verify --strict` passes. The advice says the
/// variables are empty; without that it told the user to set variables that were already set.
///
/// macOS only: `sandbox-exec` denies the keychain to the child, so each command reaches the
/// keyring and fails there, and the owner's keychain item is never read or written.
#[cfg(target_os = "macos")]
#[test]
fn an_unreachable_keyring_is_not_reported_as_no_identity() {
    let f = init_git_project();
    let home = std::env::var("HOME").unwrap();
    let profile = format!(
        r#"(version 1)(allow default)
(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd")
  (global-name "com.apple.securityd.xpc") (global-name "com.apple.secd"))
(deny file-read* file-write* (subpath "{home}/Library/Keychains"))"#
    );
    let run = |args: &[&str]| {
        assert_cmd::Command::new("sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .arg(assert_cmd::cargo::cargo_bin("bitfort"))
            .args(args)
            .current_dir(f.dir.path())
            .env("BITFORT_IDENTITY", "")
            .env("BITFORT_SIGN_IDENTITY", "")
            .env_remove("BITFORT_IDENTITY_FILE")
            .assert()
    };
    let empty = "these are empty: BITFORT_IDENTITY, BITFORT_SIGN_IDENTITY)";
    run(&["status"])
        .success()
        .stdout(predicate::str::contains("no local identity: keyring error"))
        .stdout(predicate::str::contains(empty))
        .stdout(predicate::str::contains("keygen").not());
    run(&["--json", "status"])
        .success()
        .stdout(predicate::str::contains("\"no-keyring\""));
    run(&["verify", "--strict"])
        .success()
        .stdout(predicate::str::contains("no local identity: keyring error"));
    run(&["get", "API_KEY"])
        .failure()
        .stderr(predicate::str::contains("No usable identity source"))
        .stderr(predicate::str::contains(empty))
        .stderr(predicate::str::contains("no identity available").not())
        .stderr(predicate::str::contains("keygen").not());
}

#[test]
fn status_names_who_last_wrote_the_vault() {
    // The vault's signature lives inside the ciphertext, where no diff shows it. `status`
    // is where a reviewer sees who signed the payload they are about to trust.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "K=v"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("signed by"));
}

#[test]
fn status_reports_no_vault_read_when_the_roster_does_not_verify() {
    // Without a verified roster there is nothing to authenticate the vault against, so the
    // readout must say that rather than claim the local identity cannot decrypt.
    let f = init_project();
    let path = f
        .dir
        .path()
        .join(".bitfort/environments/development/keys.json");
    let tampered = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"role\": \"maintainer\"", "\"role\": \"member\"");
    std::fs::write(&path, tampered).unwrap();

    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("the roster does not verify"));
}

#[test]
fn status_emits_color_under_clicolor_force() {
    // CLICOLOR_FORCE forces color even when piped, so `bitfort status | less -R` stays
    // colored. (This is the color-force side of the decoupling; layout is unaffected.)
    let f = init_project();
    let assert = bf(f.dir.path(), &f.id)
        .env("CLICOLOR_FORCE", "1")
        .arg("status")
        .assert()
        .success();
    assert!(
        assert.get_output().stdout.contains(&0x1b),
        "expected ANSI color under CLICOLOR_FORCE"
    );
}

#[test]
fn status_output_is_free_of_ansi_when_piped() {
    // assert_cmd captures stdout through a pipe (not a TTY), so color must
    // auto-strip: no ESC byte may reach a machine consumer or a wrapped stdio
    // protocol like MCP.
    let f = init_project();
    let assert = bf(f.dir.path(), &f.id).arg("status").assert().success();
    let stdout = &assert.get_output().stdout;
    assert!(
        !stdout.contains(&0x1b),
        "piped status stdout contained ANSI escapes"
    );
}
