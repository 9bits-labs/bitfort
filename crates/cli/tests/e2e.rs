//! End-to-end tests for the single-user command surface (init / keygen / import / set /
//! get / unset / list / verify / run), driven through the real binary with `assert_cmd`.

mod common;

use std::fs;

use bitfort_core::Identity;
use common::{bf, init_project};
use predicates::prelude::*;

#[test]
fn init_creates_layout_and_gitignores_dotenv() {
    let f = init_project();
    let bitfort = f.dir.path().join(".bitfort");
    assert!(bitfort.join("config.toml").exists());
    assert!(bitfort.join("environments/development/keys.json").exists());
    assert!(bitfort.join("environments/development/vault.enc").exists());

    let gitignore = fs::read_to_string(f.dir.path().join(".gitignore")).unwrap();
    assert!(gitignore.contains(".env*"));

    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets"));
}

/// `set KEY` with no inline value: stdin is not a terminal here, so the value comes from
/// the pipe. Without this there is no headless way to set a secret except putting it in
/// argv, where every process on the machine can read it.
#[test]
fn set_without_an_inline_value_reads_the_value_from_stdin() {
    let f = init_project();

    bf(f.dir.path(), &f.id)
        .args(["set", "PIPED"])
        .write_stdin("s3cr3t\n")
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .args(["get", "PIPED"])
        .assert()
        .success()
        .stdout("s3cr3t\n");
}

/// One trailing newline is the shell's, not the secret's. Everything else survives, so a
/// multi-line value can be piped in.
#[test]
fn a_piped_value_keeps_everything_but_one_trailing_newline() {
    let f = init_project();

    bf(f.dir.path(), &f.id)
        .args(["set", "PEM"])
        .write_stdin("line1\nline2\n")
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .args(["get", "PEM"])
        .assert()
        .success()
        .stdout("line1\nline2\n");
}

/// Empty stdin is a mistake, not an empty secret: refuse with the pipe recipe rather than
/// storing nothing under the key. A bare newline counts as empty - `echo | bitfort set K`
/// and `echo "$UNSET_VAR" | bitfort set K` are the exact shell slips this guards, and both
/// send `"\n"` rather than nothing at all.
#[test]
fn set_with_no_inline_value_and_empty_stdin_is_refused() {
    let f = init_project();

    for (case, stdin) in [("NOTHING", ""), ("JUST_A_NEWLINE", "\n")] {
        bf(f.dir.path(), &f.id)
            .args(["set", case])
            .write_stdin(stdin)
            .assert()
            .failure()
            .stderr(predicate::str::contains(format!(
                "no value for `{case}` on stdin"
            )));

        bf(f.dir.path(), &f.id)
            .args(["get", case])
            .assert()
            .failure();
    }

    // The deliberate empty value still has a way in, and the refusal names it.
    bf(f.dir.path(), &f.id)
        .args(["set", "EMPTY="])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["get", "EMPTY"])
        .assert()
        .success()
        .stdout("\n");
}

/// A trailing `\r` is part of the value unless a `\n` followed it. Only the line ending
/// comes off, so a CRLF pipe stores the same value a LF pipe does, and a value that really
/// ends in `\r` survives.
#[test]
fn only_the_line_ending_is_stripped_from_a_piped_value() {
    let f = init_project();

    for (key, stdin, want) in [
        ("CRLF", "abc\r\n", "abc\n"),
        ("BARE_CR", "abc\r", "abc\r\n"),
        ("NO_ENDING", "abc", "abc\n"),
    ] {
        bf(f.dir.path(), &f.id)
            .args(["set", key])
            .write_stdin(stdin)
            .assert()
            .success();
        bf(f.dir.path(), &f.id)
            .args(["get", key])
            .assert()
            .success()
            .stdout(want);
    }
}

/// A NUL cannot go into a process environment, so `set` refuses it instead of storing a
/// value that makes every later `run` for this environment fail to spawn at all.
#[test]
fn a_piped_value_holding_a_nul_is_refused() {
    let f = init_project();

    bf(f.dir.path(), &f.id)
        .args(["set", "NULV"])
        .write_stdin("a\0b\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("NUL"));

    bf(f.dir.path(), &f.id)
        .args(["get", "NULV"])
        .assert()
        .failure();
    // The environment is still runnable.
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "true"])
        .assert()
        .success();
}

#[test]
fn a_failed_init_leaves_nothing_behind_to_retry_against() {
    // `init` refuses a `.gitignore` it cannot read as UTF-8 rather than replacing the user's
    // ignore list. That check used to run last, after `.bitfort/` and `config.toml` existed,
    // so the retry hit "already exists; refusing to re-initialize" with nothing saying to
    // delete the directory. A Latin-1 comment is enough to trigger it.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".gitignore"), b"# caf\xe9\ntarget/\n").unwrap();

    bf(dir.path(), &id).arg("init").assert().failure();
    assert!(
        !dir.path().join(".bitfort").exists(),
        "a failed init must not leave a project behind"
    );

    // With the file readable, the retry works - no manual cleanup needed.
    fs::write(dir.path().join(".gitignore"), "target/\n").unwrap();
    bf(dir.path(), &id).arg("init").assert().success();
    let gitignore = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(gitignore.contains("target/"), "the ignore list survived");
    assert!(gitignore.contains(".env*"));
}

#[test]
fn discover_error_hints_init_only_when_the_dir_exists() {
    // In a real directory with no project, the error carries the actionable `bitfort init`
    // try-line. Against an unresolvable `--dir`, `init` is the wrong fix, so it is withheld.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();

    bf(dir.path(), &id)
        .args(["set", "FOO=bar"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("no .bitfort/ found")
                .and(predicate::str::contains("try  bitfort init")),
        );

    bf(dir.path(), &id)
        .args(["--dir", "/no/such/path/here", "set", "FOO=bar"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("cannot resolve")
                .and(predicate::str::contains("bitfort init").not()),
        );
}

#[test]
fn init_refuses_to_reinitialize() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to re-initialize"));
}

#[test]
fn set_list_run_roundtrip_keeps_values_out_of_list() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=sk-live-42"])
        .assert()
        .success();

    // `list` shows the key but never the value.
    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("API_KEY").and(predicate::str::contains("sk-live-42").not()),
        );

    // `run` injects the value into the child's environment.
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk-live-42"));
}

#[test]
fn set_updates_an_existing_key() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "K=one"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "K=two", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated K"));
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "K"])
        .assert()
        .success()
        .stdout(predicate::str::contains("two"));
}

#[test]
fn set_rejects_invalid_key_names() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "1BAD=x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "not a valid environment variable name",
        ));
}

#[test]
fn import_migrates_a_dotenv_file() {
    let f = init_project();
    let src = f.dir.path().join("legacy.env");
    fs::write(&src, "# old config\nexport FOO=1\nBAR=\"two words\"\n").unwrap();

    bf(f.dir.path(), &f.id)
        .args(["import", src.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secret(s)"));

    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("BAR").and(predicate::str::contains("FOO")));

    // Value with a space survives the round trip into the child env.
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "BAR"])
        .assert()
        .success()
        .stdout(predicate::str::contains("two words"));

    // Without --delete-source the file is left in place (but warned about).
    assert!(src.exists());
}

#[test]
fn import_delete_source_removes_the_file() {
    let f = init_project();
    let src = f.dir.path().join("legacy.env");
    fs::write(&src, "TOKEN=abc\n").unwrap();

    bf(f.dir.path(), &f.id)
        .args(["import", src.to_str().unwrap(), "--delete-source"])
        .assert()
        .success();
    assert!(!src.exists());
}

#[test]
fn keygen_is_idempotent_via_env_identity() {
    // With the identity supplied out-of-band, keygen must adopt it (not mint a new one)
    // and print an invite carrying that identity's public keys.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    bf(dir.path(), &id).arg("keygen").assert().success().stdout(
        predicate::str::contains("using your existing local identity")
            .and(predicate::str::contains(id.enc_pubkey()))
            .and(predicate::str::contains("bfinvite1:")),
    );
}

#[test]
fn init_honors_name_flag_and_stays_noninteractive() {
    // Off a terminal the wizard takes its defaults with no prompts: --name sets the
    // maintainer, the first environment defaults to `development`.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    bf(dir.path(), &id)
        .args(["init", "--name", "Alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Alice").and(predicate::str::contains("development")));
    assert!(dir
        .path()
        .join(".bitfort/environments/development/keys.json")
        .exists());
}

#[test]
fn init_off_tty_makes_no_git_commit() {
    // The git step is interactive-only. Off a terminal, even inside a repo, init must not
    // commit on the user's behalf.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["init", "-q"])
        .status()
        .unwrap();
    bf(dir.path(), &id).arg("init").assert().success();
    let log = std::process::Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["log", "--oneline"])
        .output()
        .unwrap();
    assert!(
        log.stdout.is_empty(),
        "init must not auto-commit off a terminal; git log: {}",
        String::from_utf8_lossy(&log.stdout)
    );
}

#[test]
fn banner_is_terminal_only_never_piped() {
    // The wordmark shows only on a terminal. Piped --version/--help/help must stay clean so
    // version parsers and scripts never see the art (the pipe/MCP guarantee). `/_____/` is
    // the banner's distinctive bottom-left run, absent from any real command output.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate().unwrap();
    bf(dir.path(), &id)
        .arg("--version")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bitfort 0.1.0")
                .and(predicate::str::contains("/_____/").not()),
        );
    bf(dir.path(), &id)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("/_____/").not());
    bf(dir.path(), &id)
        .arg("help")
        .assert()
        .success()
        .stdout(predicate::str::contains("/_____/").not());
    // Bare `bitfort` shows help (non-zero by clap convention) but still no banner when piped.
    bf(dir.path(), &id)
        .assert()
        .failure()
        .stdout(predicate::str::contains("/_____/").not());
}

#[test]
fn help_opens_with_the_package_description() {
    // clap takes `about` from `description` in Cargo.toml, which the Homebrew formula shows
    // too. Without that field, `--help` loses its one-line summary.
    assert_cmd::Command::cargo_bin("bitfort")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "Encrypted project secrets, injected at run time\n",
        ));
}

#[test]
fn anchor_shows_hex_and_six_word_phrase() {
    let f = init_project();
    let anchor = f.id.anchor();
    let words = bitfort_core::wordlist::anchor_words(&anchor).unwrap();
    assert_eq!(words.split(' ').count(), 6);
    // Default: styled readout carries both the hex source-of-truth and the word phrase.
    bf(f.dir.path(), &f.id)
        .arg("anchor")
        .assert()
        .success()
        .stdout(predicate::str::contains(&anchor).and(predicate::str::contains(&words)));
    // --share: a plain paste block for a README/Slack, carrying both.
    bf(f.dir.path(), &f.id)
        .args(["anchor", "--share"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("verify this matches")
                .and(predicate::str::contains(&anchor))
                .and(predicate::str::contains(&words)),
        );
}

#[test]
fn anchor_json_carries_words() {
    let f = init_project();
    let words = bitfort_core::wordlist::anchor_words(&f.id.anchor()).unwrap();
    bf(f.dir.path(), &f.id)
        .args(["--json", "anchor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"anchor_words\"").and(predicate::str::contains(&words)));
}

#[test]
fn export_emits_every_secret_in_each_format() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "DB=postgres://x"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "NOTE=hello world"]) // needs quoting in dotenv
        .assert()
        .success();

    // dotenv (default): bare where safe, quoted where needed; warns on stderr.
    bf(f.dir.path(), &f.id)
        .arg("export")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("DB=postgres://x")
                .and(predicate::str::contains("NOTE=\"hello world\"")),
        )
        .stderr(predicate::str::contains("exposing 2 plaintext secret"));

    // shell: eval-able assignments.
    bf(f.dir.path(), &f.id)
        .args(["export", "--format", "shell"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("export DB='postgres://x'")
                .and(predicate::str::contains("export NOTE='hello world'")),
        );

    // json: a single object.
    bf(f.dir.path(), &f.id)
        .args(["export", "--format", "json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"DB\": \"postgres://x\"")
                .and(predicate::str::contains("\"NOTE\": \"hello world\"")),
        );
}

#[test]
fn export_dotenv_round_trips_through_import() {
    // export -> file -> import into a fresh project recovers the same values, byte for byte.
    //
    // Finding 1.14: `export` escaped `\` and `"` and `import` never read them back, so a
    // password holding a quote and a Windows path came back corrupted - with exit 0 and no
    // warning. The only round-trip test used `postgres://x`, which never reaches the
    // escaping branch, so every value that does is here.
    let f = init_project();
    for pair in [
        "DB=postgres://x",
        "PW=p@ss\"w0rd",
        "WINPATH=C:\\Users\\app",
        "PEM=-----BEGIN-----\nbody\n-----END-----",
        "TABBED=a\tb",
    ] {
        bf(f.dir.path(), &f.id)
            .args(["set", pair])
            .assert()
            .success();
    }
    let dump = f.dir.path().join("dumped.env");
    let text = bf(f.dir.path(), &f.id)
        .arg("export")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    fs::write(&dump, text).unwrap();

    let g = init_project();
    bf(g.dir.path(), &g.id)
        .args(["import", dump.to_str().unwrap()])
        .assert()
        .success();

    // Compare through the JSON exporter, which quotes nothing of its own: equal payloads
    // mean equal values.
    let json_of = |f: &common::Fixture| {
        bf(f.dir.path(), &f.id)
            .args(["export", "--format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    assert_eq!(
        String::from_utf8(json_of(&g)).unwrap(),
        String::from_utf8(json_of(&f)).unwrap(),
        "the round trip changed a value"
    );
}

#[test]
fn quiet_drops_headers_and_hints_but_keeps_facts() {
    let f = init_project();
    // Normal status prints a header and a next-step hint (init_project has no git repo).
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("BitFort ·").and(predicate::str::contains("git init")));
    // --quiet drops the header and hint but keeps the fact lines.
    bf(f.dir.path(), &f.id)
        .args(["--quiet", "status"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("anchor")
                .and(predicate::str::contains("BitFort ·").not())
                .and(predicate::str::contains("git init").not()),
        );
}

#[test]
fn completions_and_man_generate() {
    // Structural commands - no project needed; they render from the clap definition.
    let dir = tempfile::tempdir().unwrap();
    let id = Identity::generate().unwrap();
    bf(dir.path(), &id)
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef bitfort"));
    bf(dir.path(), &id)
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bitfort"));
    bf(dir.path(), &id)
        .arg("man")
        .assert()
        .success()
        .stdout(predicate::str::contains(".TH bitfort"));
}

#[test]
fn verify_prints_the_anchor_words() {
    // verify is the primary "compare the anchor" command, so the word phrase must appear.
    let f = init_project();
    let words = bitfort_core::wordlist::anchor_words(&f.id.anchor()).unwrap();
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains(&words));
}

#[test]
fn run_propagates_child_exit_code() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "exit 42"])
        .assert()
        .code(42);
}

#[test]
fn run_clean_drops_non_secret_parent_env_but_keeps_secrets() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "SECRET=xyz"])
        .assert()
        .success();

    // MARKER is a normal parent env var; under --clean it must not reach the child,
    // while the secret still does.
    bf(f.dir.path(), &f.id)
        .env("MARKER", "present")
        .args([
            "run",
            "--clean",
            "--",
            "sh",
            "-c",
            "printenv SECRET; printenv MARKER || echo NOMARKER",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("xyz").and(predicate::str::contains("NOMARKER")));
}

#[test]
fn headless_run_from_subdir_uses_env_identity() {
    // The whole suite is keyring-free; this test additionally proves discovery works
    // from a nested working directory using only the env-supplied identity.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "DB=postgres://x"])
        .assert()
        .success();

    let nested = f.dir.path().join("services/api");
    fs::create_dir_all(&nested).unwrap();
    bf(&nested, &f.id)
        .args(["run", "--", "printenv", "DB"])
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://x"));
}

#[test]
fn verify_reports_ok_and_prints_anchor() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("trust anchor:")
                .and(predicate::str::contains("roster v1 verified")),
        );
}

#[test]
fn verify_fails_hard_on_tampered_roster_regardless_of_strict() {
    // A hard verification failure (here a version bump with no predecessor to chain from)
    // exits non-zero whether or not --strict is passed.
    let f = init_project();
    let roster_path = f
        .dir
        .path()
        .join(".bitfort/environments/development/keys.json");
    let tampered = fs::read_to_string(&roster_path)
        .unwrap()
        .replace("\"roster_version\": 1", "\"roster_version\": 2");
    fs::write(&roster_path, tampered).unwrap();

    for args in [vec!["verify"], vec!["verify", "--strict"]] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("FAILED"));
    }
}

#[test]
fn verify_strict_fails_outside_git_but_bare_passes() {
    // The roster verifies from `chain.json` with no git at all. Anti-rollback is the one
    // check that still needs history, so outside a repo a bare verify passes with a warning
    // and --strict treats the missing protection as a failure.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: roster v1 verified"))
        .stderr(predicate::str::contains("no committed history"));

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--strict requires git-backed"));
}

#[test]
fn get_prints_value_on_stdout_and_warns_on_stderr() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "TOKEN=sk-99"])
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .args(["get", "TOKEN"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk-99"))
        .stderr(predicate::str::contains("exposing the plaintext value"));
}

#[test]
fn get_unknown_key_errors() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["get", "NOPE"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secret named `NOPE`"));
}

#[test]
fn unset_removes_a_secret() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "GONE=1"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["unset", "GONE", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed GONE"));

    // The child no longer sees it.
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "printenv GONE || echo ABSENT"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ABSENT"));
}

#[test]
fn unset_unknown_key_errors() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["unset", "NOPE"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secret named `NOPE`"));
}

#[test]
fn unset_without_yes_off_tty_refuses() {
    // A destructive op has no one to answer its prompt off a terminal, so it refuses and
    // points at --yes rather than proceeding silently. The secret survives.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "KEEP=1"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["unset", "KEEP"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("bitfort unset KEEP --yes")
                .and(predicate::str::contains("non-interactive")),
        );
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "KEEP"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1"));
}

#[test]
fn set_overwrite_without_yes_off_tty_refuses() {
    // Overwriting an existing key is destructive; off a terminal it refuses and keeps the
    // old value. The --yes hint hides the value so no secret leaks into the error.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "TOK=old"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "TOK=new"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("bitfort set TOK=... --yes")
                .and(predicate::str::contains("new").not()),
        );
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "TOK"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old"));
}

#[test]
fn set_a_new_key_needs_no_confirmation() {
    // Only an overwrite is gated; adding a fresh key proceeds off a terminal without --yes.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "FRESH=v"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Set FRESH"));
}

#[test]
fn set_refuses_when_roster_fails_verification() {
    // Write paths must verify the roster before re-encrypting (docs/SPEC.md §5.5).
    // Bumping the on-disk version to 2 leaves it with no predecessor to chain from,
    // so verification must fail and the write must be refused.
    let f = init_project();
    let roster_path = f
        .dir
        .path()
        .join(".bitfort/environments/development/keys.json");
    let tampered = fs::read_to_string(&roster_path)
        .unwrap()
        .replace("\"roster_version\": 1", "\"roster_version\": 2");
    fs::write(&roster_path, tampered).unwrap();

    bf(f.dir.path(), &f.id)
        .args(["set", "X=1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to set"));
}
