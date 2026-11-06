//! `bitfort identity new` and `bitfort member add --agent`: provisioning a member for a machine
//! or an AI agent with no keyring.
//!
//! These are the only two commands that print private key material, so the tests cover the
//! guard as closely as the happy path. The end-to-end tests are the ones that matter: before
//! `identity new` existed there was no way at all to obtain the `BITFORT_IDENTITY` /
//! `BITFORT_SIGN_IDENTITY` pair a CI runner needs, because `keygen` is idempotent and never
//! reveals a secret.

mod common;

use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::Stdio;
use std::time::Duration;

use common::{bf, init_project, open_pty, raw_bf, Fixture};
use predicates::prelude::*;

/// Run `bitfort <args>` with stdout on a real terminal, so the scrollback guard is exercised.
/// Returns (exit code, everything the terminal saw).
fn on_a_terminal(
    dir: &std::path::Path,
    id: &bitfort_core::Identity,
    args: &[&str],
) -> (i32, String) {
    let (master, slave) = open_pty();
    let mut cmd = raw_bf(dir, id);
    cmd.args(args);
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

    assert_reads_api_key(f, enc, sign);
}

/// Run `bitfort <args>` on a second machine that holds only the pair `enc` and `sign`.
fn with_pair(f: &Fixture, enc: &str, sign: &str, args: &[&str]) -> std::process::Output {
    assert_cmd::Command::cargo_bin("bitfort")
        .unwrap()
        .current_dir(f.dir.path())
        .env("BITFORT_IDENTITY", enc)
        .env("BITFORT_SIGN_IDENTITY", sign)
        .env_remove("BITFORT_IDENTITY_FILE")
        .args(args)
        .output()
        .unwrap()
}

/// The pair `enc` and `sign` reads `API_KEY=s3cret`, which the caller stored.
fn assert_reads_api_key(f: &Fixture, enc: &str, sign: &str) {
    let read = with_pair(f, enc, sign, &["get", "API_KEY"]);
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
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["identity", "new"]);

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
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["identity", "new", "--json"]);

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
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["identity", "new", "--force"]);

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
    let (code, seen) = on_a_terminal(
        f.dir.path(),
        &f.id,
        &["identity", "new", "--force", "--json"],
    );

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

// --- `member add --agent` ---

/// Run `member add --agent <args>` as the project's maintainer, off a terminal.
fn add_agent(f: &Fixture, args: &[&str]) -> std::process::Output {
    bf(f.dir.path(), &f.id)
        .args(["member", "add", "--agent"])
        .args(args)
        .output()
        .unwrap()
}

/// The value of the `<key>=` line in a printed identity block.
fn printed_value<'a>(printed: &'a str, key: &str) -> &'a str {
    printed
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {key} line in:\n{printed}"))
}

fn roster_version(f: &Fixture, env: &str) -> u64 {
    bitfort_core::Project::discover(f.dir.path())
        .unwrap()
        .load_roster(env)
        .unwrap()
        .roster_version
}

/// The whole flow: one command adds the agent, and the pair it prints reads the
/// vault on a machine that holds nothing else. Stdout is the key file, so the status lines and
/// the warning go to stderr.
#[test]
fn an_agent_reads_its_environment_with_the_printed_pair() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();

    let out = add_agent(&f, &["bot"]);
    let (printed, stderr) = (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    );
    assert!(out.status.success(), "member add --agent failed:\n{stderr}");
    assert!(
        stderr.contains("Added agent bot as member to 'development' (roster v2)."),
        "{stderr}"
    );
    assert!(
        stderr.contains("this printed a private identity"),
        "{stderr}"
    );
    assert!(
        !printed.contains("Added"),
        "a status line reached the key file:\n{printed}"
    );
    assert!(
        printed.contains("# Revoke it with: bitfort --env development member rm 'bot'"),
        "{printed}"
    );

    assert_reads_api_key(
        &f,
        printed_value(&printed, "BITFORT_IDENTITY"),
        printed_value(&printed, "BITFORT_SIGN_IDENTITY"),
    );
}

/// The printed block is a `BITFORT_IDENTITY_FILE` as it stands, comments and all.
#[test]
fn the_agent_block_is_a_valid_identity_file() {
    use std::os::unix::fs::PermissionsExt;

    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();
    let out = add_agent(&f, &["bot"]);
    assert!(out.status.success());

    let key_file = f.dir.path().join("agent.key");
    std::fs::write(&key_file, &out.stdout).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_cmd::Command::cargo_bin("bitfort")
        .unwrap()
        .current_dir(f.dir.path())
        .env("BITFORT_IDENTITY_FILE", &key_file)
        .env_remove("BITFORT_IDENTITY")
        .env_remove("BITFORT_SIGN_IDENTITY")
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout("s3cret\n");
}

/// The capability boundary: the agent opens the environment it was added to and no
/// other, and the other environment's roster does not change.
#[test]
fn the_agent_is_a_recipient_of_its_environment_only() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "set", "PROD_SECRET=p"])
        .assert()
        .success();

    let out = add_agent(&f, &["bot"]);
    assert!(out.status.success());
    let printed = String::from_utf8(out.stdout).unwrap();
    let (enc, sign) = (
        printed_value(&printed, "BITFORT_IDENTITY"),
        printed_value(&printed, "BITFORT_SIGN_IDENTITY"),
    );

    assert!(with_pair(&f, enc, sign, &["list"]).status.success());
    let prod = with_pair(
        &f,
        enc,
        sign,
        &["--env", "production", "get", "PROD_SECRET"],
    );
    assert!(!prod.status.success(), "the agent read production");
    assert!(!String::from_utf8_lossy(&prod.stdout).contains('p'));
    assert_eq!(roster_version(&f, "production"), 1);
    assert_eq!(roster_version(&f, "development"), 2);
}

/// Revocation is the ordinary `member rm`, under the name the agent was added with.
#[test]
fn member_rm_revokes_the_agent() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();
    let out = add_agent(&f, &["bot"]);
    assert!(out.status.success());
    let printed = String::from_utf8(out.stdout).unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "--yes", "bot"])
        .assert()
        .success();
    let read = with_pair(
        &f,
        printed_value(&printed, "BITFORT_IDENTITY"),
        printed_value(&printed, "BITFORT_SIGN_IDENTITY"),
        &["get", "API_KEY"],
    );
    assert!(
        !read.status.success(),
        "a revoked agent still reads the vault"
    );
    assert!(!String::from_utf8_lossy(&read.stdout).contains("s3cret"));
}

/// `--json` gives an automated launcher one object: the two variables, and where the agent
/// was added.
#[test]
fn agent_json_carries_the_pair_and_its_environment() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=s3cret"])
        .assert()
        .success();
    let out = add_agent(&f, &["bot", "--json"]);
    assert!(out.status.success());

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is not JSON");
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "BITFORT_IDENTITY",
            "BITFORT_SIGN_IDENTITY",
            "env",
            "name",
            "roster_version"
        ]
    );
    assert_eq!(v["name"], "bot");
    assert_eq!(v["env"], "development");
    assert_eq!(v["roster_version"], 2);
    assert_reads_api_key(
        &f,
        v["BITFORT_IDENTITY"].as_str().unwrap(),
        v["BITFORT_SIGN_IDENTITY"].as_str().unwrap(),
    );
}

/// The scrollback guard runs before the key exists and before the roster changes, so a
/// refused run adds no member that nobody holds a key for.
#[test]
fn agent_refuses_a_terminal_and_changes_nothing() {
    let f = init_project();
    let (code, seen) = on_a_terminal(f.dir.path(), &f.id, &["member", "add", "--agent", "bot"]);

    assert_ne!(code, 0, "expected a refusal, got success:\n{seen}");
    assert!(
        seen.contains("refusing to print a private identity to a terminal"),
        "missing the refusal:\n{seen}"
    );
    assert!(
        !seen.contains("AGE-SECRET-KEY") && !seen.contains("BITFORT_SIGN_IDENTITY"),
        "a secret reached the terminal despite the guard:\n{seen}"
    );
    assert!(
        seen.contains("bitfort --env development member add --agent 'bot' > ~/agent.key"),
        "wrong try command:\n{seen}"
    );
    assert_eq!(roster_version(&f, "development"), 1);
}

#[test]
fn agent_force_prints_on_a_terminal() {
    let f = init_project();
    let (code, seen) = on_a_terminal(
        f.dir.path(),
        &f.id,
        &["member", "add", "--agent", "bot", "--force"],
    );
    assert_eq!(code, 0, "expected success with --force:\n{seen}");
    assert!(seen.contains("BITFORT_IDENTITY="), "{seen}");
    assert!(seen.contains("BITFORT_SIGN_IDENTITY="), "{seen}");
    assert_eq!(roster_version(&f, "development"), 2);
}

/// Adding an agent changes membership, so a plain member cannot do it, and no key is printed.
#[test]
fn only_a_maintainer_can_add_an_agent() {
    let f = init_project();
    let bob = bitfort_core::Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &common::invite_for(&bob, "bob")])
        .assert()
        .success();

    bf(f.dir.path(), &bob)
        .args(["member", "add", "--agent", "bot"])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("only a maintainer"));
}

/// `member rm` addresses a member by name, so a second agent under a taken name is refused,
/// before any key is printed and before the roster changes.
#[test]
fn a_taken_agent_name_is_refused_before_a_key_is_printed() {
    let f = init_project();
    assert!(add_agent(&f, &["bot"]).status.success());

    let again = add_agent(&f, &["BOT"]);
    assert!(!again.status.success());
    assert!(
        again.stdout.is_empty(),
        "a key was printed for a refused add"
    );
    assert!(String::from_utf8_lossy(&again.stderr).contains("already exists"));
    assert_eq!(roster_version(&f, "development"), 2);
}

/// `--agent` takes no invite and makes a plain member, so the invite and the flags that shape
/// an invited member conflict with it, and `--force` means nothing without it.
#[test]
fn agent_conflicts_with_an_invite_and_its_flags() {
    let f = init_project();
    let bob = bitfort_core::Identity::generate().unwrap();
    let invite = common::invite_for(&bob, "bob");
    for args in [
        &["member", "add", "--agent", "bot", invite.as_str()][..],
        &["member", "add", "--agent", "bot", "--maintainer"],
        &["member", "add", "--agent", "bot", "--name", "other"],
        &["member", "add", "--force", invite.as_str()],
        &["member", "add"],
    ] {
        bf(f.dir.path(), &f.id).args(args).assert().code(2);
    }
    assert_eq!(roster_version(&f, "development"), 1);
}

/// When the key cannot be written after the roster changed, the error says that the agent is a
/// member whose key nobody holds, and how to remove it. Linux only: `/dev/full` fails every
/// write and nothing else, and macOS has no such device (its file size limit holds only at zero,
/// which also stops the roster write).
#[cfg(target_os = "linux")]
#[test]
fn a_failed_agent_write_names_the_member_to_remove() {
    let f = init_project();
    let out = raw_bf(f.dir.path(), &f.id)
        .args(["member", "add", "--agent", "bot"])
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr
            .contains("agent 'bot' is now a member of 'development', but its key was not printed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("bitfort --env development member rm 'bot'"),
        "{stderr}"
    );
    assert!(
        stderr.contains("could not write to standard output"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("this printed a private identity"),
        "{stderr}"
    );
}
