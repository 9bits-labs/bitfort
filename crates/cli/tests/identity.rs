//! `bitfort identity new`: provisioning a member for a machine with no keyring.
//!
//! This is the only command that prints private key material, so the tests cover the guard as
//! closely as the happy path. The end-to-end test is the one that matters: before this command
//! existed there was no way at all to obtain the `BITFORT_IDENTITY` / `BITFORT_SIGN_IDENTITY`
//! pair a CI runner needs, because `keygen` is idempotent and never reveals a secret.

mod common;

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::Stdio;
use std::time::Duration;

use common::{bf, init_project, open_pty, raw_bf, Fixture};
use predicates::prelude::*;

/// Run `identity new` with stdout on a real terminal, so the scrollback guard is exercised.
/// Returns (exit code, everything the terminal saw).
fn on_a_terminal(
    dir: &std::path::Path,
    id: &bitfort_core::Identity,
    args: &[&str],
) -> (i32, String) {
    let (master, slave) = open_pty();
    let mut cmd = raw_bf(dir, id);
    cmd.arg("identity").arg("new").args(args);
    cmd.stdout(Stdio::from(slave.try_clone().unwrap()));
    cmd.stderr(Stdio::from(slave.try_clone().unwrap()));
    cmd.stdin(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let code = child.wait().unwrap().code().unwrap_or(-1);
    drop(slave);

    // The master is non-blocking; drain what is there now that the child has exited.
    let mut file = unsafe { std::fs::File::from_raw_fd(libc::dup(master.as_raw_fd())) };
    let mut seen = String::new();
    let mut buf = [0u8; 1024];
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    (code, seen)
}

/// Let a maintainer add the minted member with `invite`, then read `API_KEY` on a second
/// machine that holds only the printed pair. The caller stores `API_KEY=s3cret` first.
fn assert_pair_reads_the_vault(f: &Fixture, enc: &str, sign: &str, invite: &str) {
    // The minted key cannot decrypt the vault until `member add` runs.
    bf(f.dir.path(), &f.id)
        .args(["member", "add", invite])
        .assert()
        .success();

    let read = assert_cmd::Command::cargo_bin("bitfort")
        .unwrap()
        .current_dir(f.dir.path())
        .env("BITFORT_IDENTITY", enc)
        .env("BITFORT_SIGN_IDENTITY", sign)
        .env_remove("BITFORT_IDENTITY_FILE")
        .args(["get", "API_KEY"])
        .output()
        .unwrap();
    assert!(
        read.status.success(),
        "the minted identity could not read the vault: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&read.stdout).trim(), "s3cret");
}

/// The whole point of the command: a second machine, holding only the printed pair, can read
/// the vault after a maintainer adds it. This is the CI recipe, end to end.
#[test]
fn a_minted_identity_can_read_the_vault_once_a_maintainer_adds_it() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();

    let minted = bf(f.dir.path(), &f.id)
        .args(["identity", "new", "--name", "ci"])
        .output()
        .unwrap();
    assert!(minted.status.success());
    let printed = String::from_utf8(minted.stdout).unwrap();

    let mut enc = None;
    let mut sign = None;
    let mut invite = None;
    for line in printed.lines() {
        if let Some(v) = line.strip_prefix("BITFORT_IDENTITY=") {
            enc = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("BITFORT_SIGN_IDENTITY=") {
            sign = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("# bfinvite1:") {
            invite = Some(format!("bfinvite1:{v}"));
        }
    }
    assert_pair_reads_the_vault(&f, &enc.unwrap(), &sign.unwrap(), &invite.unwrap());
}

/// The printed block is also a valid `BITFORT_IDENTITY_FILE`, because the parser skips `#`
/// comment lines - so `bitfort identity new > ci.key` needs no editing.
#[test]
fn the_printed_block_is_a_valid_identity_file() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();

    let minted = bf(f.dir.path(), &f.id)
        .args(["identity", "new", "--name", "ci"])
        .output()
        .unwrap();
    let printed = String::from_utf8(minted.stdout).unwrap();
    let invite = printed
        .lines()
        .find_map(|l| l.strip_prefix("# bfinvite1:"))
        .map(|v| format!("bfinvite1:{v}"))
        .unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite])
        .assert()
        .success();

    let key_file = f.dir.path().join("ci.key");
    std::fs::write(&key_file, &printed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let read = assert_cmd::Command::cargo_bin("bitfort")
        .unwrap()
        .current_dir(f.dir.path())
        .env("BITFORT_IDENTITY_FILE", &key_file)
        .env_remove("BITFORT_IDENTITY")
        .env_remove("BITFORT_SIGN_IDENTITY")
        .args(["get", "API_KEY"])
        .output()
        .unwrap();
    assert!(
        read.status.success(),
        "the printed block did not parse as an identity file: {}",
        String::from_utf8_lossy(&read.stderr)
    );
}

/// Unlike `keygen`, this mints a fresh identity every time. A CI key must not be the
/// operator's own key, and rotating one must not hand back the key being replaced.
#[test]
fn each_run_mints_a_different_identity() {
    let f = init_project();
    let first = bf(f.dir.path(), &f.id)
        .args(["identity", "new"])
        .output()
        .unwrap();
    let second = bf(f.dir.path(), &f.id)
        .args(["identity", "new"])
        .output()
        .unwrap();
    assert_ne!(first.stdout, second.stdout);

    // And neither is the operator's own identity, which stays where it was.
    let mine = format!("BITFORT_IDENTITY={}", f.id.enc_secret().as_str());
    let printed = String::from_utf8(first.stdout).unwrap();
    assert!(!printed.contains(&mine), "minted the caller's own identity");
}

/// An automated caller provisions a CI or agent member with this command, so `--json` gives it
/// one object instead of the text block, and the pair in it reads the vault.
#[test]
fn json_carries_a_working_pair_and_the_invite() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();

    let minted = bf(f.dir.path(), &f.id)
        .args(["identity", "new", "--name", "ci", "--json"])
        .output()
        .unwrap();
    assert!(minted.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&minted.stdout).expect("stdout is not valid JSON");
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["BITFORT_IDENTITY", "BITFORT_SIGN_IDENTITY", "invite"]
    );
    let field = |k: &str| v[k].as_str().unwrap();

    assert_pair_reads_the_vault(
        &f,
        field("BITFORT_IDENTITY"),
        field("BITFORT_SIGN_IDENTITY"),
        field("invite"),
    );
}

/// A derived default is not text the user typed. A `$USER` the name rule refuses falls
/// through to the next source, so a container with a strange `$USER` still mints; an
/// explicit `--name` is refused, because there the user can correct it.
#[test]
fn an_unusable_user_variable_falls_back_but_an_explicit_name_does_not() {
    let f = init_project();
    let minted = bf(f.dir.path(), &f.id)
        .env("USER", "ci\nops")
        .env_remove("USERNAME")
        .args(["identity", "new"])
        .output()
        .unwrap();
    assert!(
        minted.status.success(),
        "a bad $USER failed the command: {}",
        String::from_utf8_lossy(&minted.stderr)
    );

    bf(f.dir.path(), &f.id)
        .args(["identity", "new", "--name", "ci\nops"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid member name"));
}

/// The scrollback guard, driven through a real terminal.
#[test]
fn it_refuses_a_terminal_without_force() {
    let f = init_project();
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &[]);

    assert_ne!(code, 0, "expected a refusal, got success:\n{seen}");
    assert!(
        seen.contains("refusing to print a private identity to a terminal"),
        "missing the refusal:\n{seen}"
    );
    // The age prefix finds the encryption secret in any output format; the variable name
    // finds the line or the JSON key that would carry the signing secret.
    assert!(
        !seen.contains("AGE-SECRET-KEY") && !seen.contains("BITFORT_SIGN_IDENTITY"),
        "a secret reached the terminal despite the guard:\n{seen}"
    );
    // The suggested command must be the one the operator can run: a file outside the work
    // tree, and no `--json` when the caller did not ask for it.
    assert!(seen.contains("~/ci.key"), "wrong try command:\n{seen}");
    assert!(!seen.contains("--json"), "wrong try command:\n{seen}");
}

/// With `--json` the guard still refuses a terminal, and the refusal is the JSON error object.
#[test]
fn json_refuses_a_terminal_with_a_json_error() {
    let f = init_project();
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["--json"]);

    assert_ne!(code, 0, "expected a refusal, got success:\n{seen}");
    assert!(
        !seen.contains("AGE-SECRET-KEY") && !seen.contains("BITFORT_SIGN_IDENTITY"),
        "a secret reached the terminal despite the guard:\n{seen}"
    );
    // One line of the capture is the error object; the pty carries stdout and stderr alike.
    let line = seen
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("no JSON error printed");
    let error: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("the refusal is not JSON");
    assert!(error["error"]
        .as_str()
        .unwrap()
        .starts_with("refusing to print a private identity to a terminal"));
    // The suggested command keeps `--json`, so its output is the form the caller asked for.
    let try_cmd = error["try"].as_str().unwrap();
    assert!(try_cmd.contains("--json"), "wrong try command: {try_cmd}");
    assert!(
        try_cmd.contains("~/ci.json"),
        "wrong try command: {try_cmd}"
    );
    assert!(try_cmd.contains("--force"), "wrong try command: {try_cmd}");
}

/// `--force` is the deliberate override, matching `export`.
#[test]
fn force_prints_on_a_terminal() {
    let f = init_project();
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["--force"]);

    assert_eq!(code, 0, "expected success with --force:\n{seen}");
    assert!(
        seen.contains("BITFORT_IDENTITY="),
        "no identity printed:\n{seen}"
    );
    assert!(
        seen.contains("BITFORT_SIGN_IDENTITY="),
        "the signing half is missing, so the pair is unusable:\n{seen}"
    );
}

/// `--json --force` prints the same object on a terminal that a pipe gets.
#[test]
fn json_force_prints_the_object_on_a_terminal() {
    let f = init_project();
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["--force", "--json"]);

    assert_eq!(code, 0, "expected success with --force:\n{seen}");
    let line = seen
        .lines()
        .find(|l| l.starts_with('{'))
        .expect("no JSON object printed");
    let v: serde_json::Value = serde_json::from_str(line.trim_end()).expect("the line is not JSON");
    assert!(v["BITFORT_IDENTITY"]
        .as_str()
        .unwrap()
        .starts_with("AGE-SECRET-KEY-"));
    assert!(!v["BITFORT_SIGN_IDENTITY"].as_str().unwrap().is_empty());
    assert!(v["invite"].as_str().unwrap().starts_with("bfinvite1:"));
}

/// The printed pair is the only copy of the minted key, so a write that fails must fail the
/// command, and the warning that a key was printed must not follow it. A file size limit of
/// zero, with `SIGXFSZ` ignored, makes each write to the stdout file return `EFBIG`, which
/// stands in for a full disk. `member list` covers the human emitters the same way, and the
/// commands after it the plain output written past them, which used to panic with exit 101.
#[test]
fn a_failed_write_to_stdout_exits_nonzero() {
    use std::os::unix::process::CommandExt;

    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();
    for args in [
        &["identity", "new", "--json"][..],
        &["identity", "new"],
        &["member", "list"],
        &["get", "API_KEY"],
        &["list"],
        &["export"],
        &["verify"],
        &["anchor", "--share"],
        &["completions", "bash"],
        &["man"],
    ] {
        let mut cmd = raw_bf(f.dir.path(), &f.id);
        cmd.args(args)
            .stdout(std::fs::File::create(f.dir.path().join("out")).unwrap());
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                let none = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &none) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "{args:?} exited 0 after a failed write:\n{stderr}"
        );
        assert!(
            stderr.contains("could not write to standard output"),
            "{args:?} did not name the failed write:\n{stderr}"
        );
        assert!(
            !stderr.contains("this printed a private identity"),
            "{args:?} claimed to print a key it did not write:\n{stderr}"
        );
    }
}

/// `BITFORT_SIGN_IDENTITY` without `BITFORT_IDENTITY` is half an env source. It used to count
/// as no env source at all, so the command took the keyring identity instead: on a developer
/// machine it ran as the developer, on a runner it failed with a keyring error. An identity
/// file does not complete the pair either, because the stray half would be ignored.
///
/// Only `get` runs here. If the check regressed, `keygen` would go on to the keyring and store
/// a new key in the developer's own; `get` would only read it. `find_identity`, which `keygen`
/// uses, shares this check, and the keystore unit tests cover it without the keyring.
#[test]
fn a_lone_signing_identity_is_refused_before_the_keyring() {
    let f = init_project();
    let key_file = f.dir.path().join("ci.key");
    std::fs::write(
        &key_file,
        format!(
            "BITFORT_IDENTITY={}\nBITFORT_SIGN_IDENTITY={}\n",
            f.id.enc_secret().as_str(),
            f.id.sign_secret().as_str()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    for file in [None, Some(&key_file)] {
        let mut cmd = bf(f.dir.path(), &f.id);
        cmd.env_remove("BITFORT_IDENTITY");
        if let Some(file) = file {
            cmd.env("BITFORT_IDENTITY_FILE", file);
        }
        cmd.args(["get", "API_KEY"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "BITFORT_IDENTITY must be set when BITFORT_SIGN_IDENTITY is set",
            ));
    }
}

/// A configured identity source that fails reports its own error once, and the error names the
/// variable or the file to fix. "no identity available" and `try bitfort keygen` fit only a
/// machine where no source is configured: here `keygen` fails on the same source. Every failing
/// source takes the same path, and the keystore tests check each message. The missing file is
/// the case whose error printed its cause twice.
///
/// Both cases fail before the keyring, so the test never reaches it.
#[test]
fn a_failing_identity_source_is_not_reported_as_no_identity() {
    let f = init_project();
    let sign = f.id.sign_secret();
    let missing = f.dir.path().join("missing.key");
    let mut bad_key = bf(f.dir.path(), &f.id);
    bad_key.env(
        "BITFORT_SIGN_IDENTITY",
        format!("{}!{}", &sign[..10], &sign[11..]),
    );
    let mut bad_file = bf(f.dir.path(), &f.id);
    bad_file
        .env_remove("BITFORT_IDENTITY")
        .env_remove("BITFORT_SIGN_IDENTITY")
        .env("BITFORT_IDENTITY_FILE", &missing);

    for (mut cmd, expected) in [
        (
            bad_key,
            "BITFORT_SIGN_IDENTITY is not valid base64: character 11 is wrong".to_string(),
        ),
        (
            bad_file,
            format!("cannot read identity file \"{}\": ", missing.display()),
        ),
    ] {
        cmd.args(["get", "API_KEY"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected).count(1))
            .stderr(predicate::str::contains("no identity available").not())
            .stderr(predicate::str::contains("keygen").not());
    }
}

/// Regression: an identity file path that is not UTF-8 was shown with U+FFFD in place of the
/// byte, so the error named a file that does not exist. The byte is now written as `\xNN`.
/// The read fails before the keyring.
#[cfg(unix)]
#[test]
fn an_identity_file_path_that_is_not_utf8_is_shown_byte_for_byte() {
    use std::os::unix::ffi::OsStrExt;
    let f = init_project();
    let mut path = f.dir.path().as_os_str().to_owned();
    path.push(std::ffi::OsStr::from_bytes(b"/\xff.key"));
    bf(f.dir.path(), &f.id)
        .env_remove("BITFORT_IDENTITY")
        .env_remove("BITFORT_SIGN_IDENTITY")
        .env("BITFORT_IDENTITY_FILE", &path)
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(r#"/\xff.key": "#))
        .stderr(predicate::str::contains('\u{fffd}').not());
}
