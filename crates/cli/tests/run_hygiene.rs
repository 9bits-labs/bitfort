//! End-to-end coverage for what `bitfort run` hands a child process (docs/SPEC.md §7,
//! invariant 6). Two separate rules: the child never receives the identity that opened the
//! vault, and the vault never supplies a variable that decides how the child runs.
//!
//! Driven through the real binary, because both failures end at a child's environment and a
//! unit test cannot see one.

mod common;

use std::fs;
use std::path::Path;

use common::*;
use predicates::prelude::*;

const ENV: &str = "development";

/// Write a vault holding `vars`, signed by the fixture's own identity - a legitimate member,
/// so nothing in the read path objects to its origin. Every command refuses to *write* these
/// names, which is why the fixture goes through the core API.
fn write_vault_as_member(f: &Fixture, vars: &[(&str, &str)]) {
    let roster = bitfort_core::Project::discover(f.dir.path())
        .unwrap()
        .load_roster(ENV)
        .unwrap();
    write_vault(f.dir.path(), ENV, &roster, &f.id, vars);
}

/// The child prints the variable, or `ABSENT` when it is unset, so a passing assertion means
/// the variable really was missing rather than the command having failed.
fn report_var(dir: &Path, id: &bitfort_core::Identity, var: &str) -> assert_cmd::Command {
    let mut cmd = bf(dir, id);
    cmd.args([
        "run",
        "--",
        "sh",
        "-c",
        &format!("printenv {var} || echo ABSENT"),
    ]);
    cmd
}

#[test]
fn run_does_not_hand_the_child_the_identity_that_opened_the_vault() {
    // Finding 1.5. The CI recipe in docs/SPEC.md §7.1 puts the keys in bitfort's own
    // environment, and without --clean the child inherits everything: any build step could
    // read a key that decrypts every vault revision in git history, for every environment
    // that member belongs to.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    for var in ["BITFORT_IDENTITY", "BITFORT_SIGN_IDENTITY"] {
        report_var(f.dir.path(), &f.id, var)
            .assert()
            .success()
            .stdout(predicate::str::contains("ABSENT"))
            .stdout(predicate::str::contains("AGE-SECRET-KEY").not());
    }

    // The secrets still arrive: stripping the identity is not stripping the environment.
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("real"));
}

#[test]
fn run_refuses_to_inject_a_process_control_variable() {
    // Finding 1.2's second half: a signature proves a member wrote the vault, not that a
    // member may run code on every teammate's machine. `LD_PRELOAD` loads a library into
    // every child, so it is refused rather than injected.
    let f = init_project();
    write_vault_as_member(&f, &[("API_KEY", "real"), ("LD_PRELOAD", "/tmp/evil.so")]);

    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "LD_PRELOAD"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"))
        .stderr(predicate::str::contains("controls how a process runs"));
}

#[test]
fn a_vault_path_cannot_win_over_the_clean_environment() {
    // Reported under finding 1.2: the vault overlay ran after the --clean PATH copy, so a
    // vault `PATH` chose which program the child ran - and under --clean it was the only
    // PATH. Refusing the name closes both the clean and the inherited path.
    let f = init_project();
    write_vault_as_member(&f, &[("PATH", "/tmp/evilbin")]);

    for args in [
        vec!["run", "--", "sh", "-c", "echo ran"],
        vec!["run", "--clean", "--", "sh", "-c", "echo ran"],
    ] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("`PATH`"));
    }
}

#[test]
fn export_refuses_to_emit_a_process_control_variable() {
    // `export`'s output is `eval`ed or fed to a dotenv loader, so emitting one of these names
    // is the same injection `run` refuses, one step later. Every format, because the JSON one
    // reaches a runner just as directly.
    let f = init_project();
    write_vault_as_member(&f, &[("API_KEY", "real"), ("NODE_OPTIONS", "--require /x")]);

    for format in ["shell", "dotenv", "json"] {
        bf(f.dir.path(), &f.id)
            .args(["export", "--force", "--format", format])
            .assert()
            .failure()
            .stderr(predicate::str::contains("NODE_OPTIONS"))
            .stdout(predicate::str::contains("--require /x").not());
    }
}

#[test]
fn the_ci_gate_fails_on_a_vault_run_would_refuse() {
    // SPEC §5.5: `verify` is what a pull request runs, so it has to see what the read paths
    // would refuse, on the diff that introduces it. It classified this vault as `Unlocked` and
    // exited 0 while `run` refused it, so a teammate could land the payload past a green gate.
    let f = init_git_project();
    write_vault_as_member(&f, &[("API_KEY", "real"), ("LD_PRELOAD", "/tmp/evil.so")]);

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"));

    // `status` reads the same classification, so the two cannot disagree about the file.
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("LD_PRELOAD"))
        .stdout(predicate::str::contains("all set").not());
}

#[test]
fn resolve_refuses_to_re_sign_a_process_control_variable() {
    // `resolve` re-signs its output under the local identity, so a name taken out of a hostile
    // conflict side would look authentic from then on. Refuse before signing.
    let f = init_git_project();
    make_vault_conflict(&f, "MAIN_K=m", |f| {
        write_vault_as_member(f, &[("BASE", "b"), ("LD_PRELOAD", "/tmp/evil.so")]);
    });

    bf(f.dir.path(), &f.id)
        .args(["resolve", "--theirs"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"));
}

#[test]
fn a_process_control_variable_cannot_be_stored() {
    // The earlier half of the same rule: `set` and `import` refuse the name, so the refusal
    // lands where the user can act on it rather than at the next `run`.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "NODE_OPTIONS=--require /tmp/evil.js"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("controls how a process runs"));

    let dotenv = f.dir.path().join(".env");
    fs::write(&dotenv, "API_KEY=fine\nLD_PRELOAD=/tmp/evil.so\n").unwrap();
    bf(f.dir.path(), &f.id)
        .args(["import", ".env"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"));

    // The refusal is not partial: nothing from that file was stored.
    bf(f.dir.path(), &f.id)
        .args(["get", "API_KEY"])
        .assert()
        .failure();
}

#[test]
fn import_does_not_echo_the_line_it_could_not_parse() {
    // Finding 1.13: a PEM body wraps onto lines with no `=`, so the parse error was printing
    // key material into the terminal, CI logs, and the --json payload.
    let f = init_project();
    let dotenv = f.dir.path().join(".env");
    fs::write(
        &dotenv,
        "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n",
    )
    .unwrap();

    for args in [vec!["import", ".env"], vec!["--json", "import", ".env"]] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("MIIEow").not())
            .stdout(predicate::str::contains("MIIEow").not())
            // The way out stays: `import` adds it, since the shared parser cannot.
            .stderr(predicate::str::contains("add them with `bitfort set`"));
    }
}

/// The multi-line advice fits only a line with no `=`. A line with a bad name is a typo in
/// the name, and `bitfort set` refuses that name too.
#[test]
fn import_gives_the_multi_line_advice_only_for_a_line_with_no_assignment() {
    let f = init_project();
    let dotenv = f.dir.path().join(".env");
    fs::write(&dotenv, "my-key=abc\n").unwrap();

    bf(f.dir.path(), &f.id)
        .args(["import", ".env"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "not a valid environment variable name",
        ))
        .stderr(predicate::str::contains("bitfort set").not());
}

/// A vault holding two process-control names must still be repairable.
///
/// `decrypt` admits such a name on purpose so `list` and `status` can show what to remove
/// (invariant 6), but the write guard refused any vault containing one - and it reported the
/// first offender anywhere, so removing `NODE_OPTIONS` failed because of `PATH` and removing
/// `PATH` failed because of `NODE_OPTIONS`. Neither could ever be removed. The guard now
/// refuses only a name the write would introduce.
#[test]
fn unset_can_clear_process_control_vars_even_when_several_are_present() {
    let f = init_project();
    write_vault_as_member(
        &f,
        &[
            ("API_KEY", "real"),
            ("NODE_OPTIONS", "--require /evil.js"),
            ("PATH", "/evil/bin"),
        ],
    );

    for key in ["NODE_OPTIONS", "PATH"] {
        bf(f.dir.path(), &f.id)
            .args(["unset", key, "-y"])
            .assert()
            .success();
    }

    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("NODE_OPTIONS").not())
        .stdout(predicate::str::contains("PATH").not());
}

/// The other half of the same rule: repairing a vault must not become a way to add one.
#[test]
fn a_new_process_control_var_is_still_refused_in_a_vault_that_already_held_one() {
    let f = init_project();
    write_vault_as_member(&f, &[("API_KEY", "real"), ("PATH", "/evil/bin")]);

    bf(f.dir.path(), &f.id)
        .args(["set", "LD_PRELOAD=/evil.so"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"));
}
