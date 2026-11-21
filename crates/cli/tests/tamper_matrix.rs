//! Every command that reads the signed files, run against every way of tampering with them.
//!
//! A tamper here is a change that write access to the repository allows without a member's
//! key: an edited `keys.json` or `chain.json`, a file restored from an older commit, a vault
//! forged or copied from elsewhere. A command that reads the changed file must refuse it,
//! print no secret, and write nothing; the two readouts, `status` and `env list`, must stop
//! calling the environment healthy (invariants 2, 3 and 7).
//!
//! The command list comes from `--help`, so a new command fails `every_command_is_classified`
//! until it has a row here. Each command also runs once on the untampered project and must
//! succeed there, so a refusal in the matrix is the tamper's doing.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use bitfort_core::{Identity, Role, Vault};
use common::*;
use serde_json::json;
use tempfile::TempDir;

const ENV: &str = "development";
/// `API_KEY` in the base project. No refused command may print it.
const SECRET: &str = "real-value";
/// The value the forged files carry.
const FORGED: &str = "attacker-value";

/// Commands that open no environment's signed files, so no tamper reaches them.
const OPENS_NO_ENVIRONMENT: &[&str] = &[
    // Refuses an existing project before it reads one.
    "init",
    // Mint or print a local identity.
    "keygen",
    "identity new",
    // Prints the anchor pinned in `config.toml`, which a reviewer compares with the published
    // one; reading the roster would not make that comparison stronger.
    "anchor",
    "completions",
    "man",
];

/// Cells where the command accepts the tamper on purpose.
const BY_DESIGN: &[(&str, &str)] = &[
    // `rotate` re-signs a vault older than the roster: it is the repair for an interrupted
    // membership change, and it warns first. vault_auth.rs covers the warning.
    ("rotate", "vault.enc from an older commit"),
];

/// Which signed files a command reads. Each level includes the one before it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reads {
    /// `keys.json` and `chain.json`.
    Roster,
    /// The roster and `vault.enc`.
    RosterAndVault,
}

/// What a command must do with a tampered file.
#[derive(Clone, Copy)]
enum Answer {
    /// Exit non-zero, print no secret, and leave `.bitfort` as it was.
    Refuse,
    /// Exit zero, and leave out `healthy`, which the command prints for the base project.
    Report { healthy: &'static str },
}

struct Case {
    path: &'static str,
    args: Vec<String>,
    reads: Reads,
    answer: Answer,
    /// Run in the project with a vault merge in progress, where `resolve` has work to do.
    conflicted: bool,
}

fn case(path: &'static str, reads: Reads, answer: Answer, args: &[&str]) -> Case {
    Case {
        path,
        args: args.iter().map(|a| a.to_string()).collect(),
        reads,
        answer,
        conflicted: false,
    }
}

/// One row per command that opens an environment. `invite` is a non-member's invite blob.
fn cases(invite: &str) -> Vec<Case> {
    use Answer::*;
    use Reads::*;
    vec![
        case(
            "status",
            RosterAndVault,
            Report { healthy: "all set" },
            &["status"],
        ),
        case("verify", RosterAndVault, Refuse, &["verify"]),
        case(
            "run",
            RosterAndVault,
            Refuse,
            &["run", "--", "printenv", "API_KEY"],
        ),
        case("get", RosterAndVault, Refuse, &["get", "API_KEY"]),
        case("list", RosterAndVault, Refuse, &["list"]),
        case("export", RosterAndVault, Refuse, &["export"]),
        case("set", RosterAndVault, Refuse, &["set", "NEW_KEY=new-value"]),
        case(
            "unset",
            RosterAndVault,
            Refuse,
            &["unset", "API_KEY", "--yes"],
        ),
        case("import", RosterAndVault, Refuse, &["import", ".env.import"]),
        case("rotate", RosterAndVault, Refuse, &["rotate"]),
        case(
            "member add",
            RosterAndVault,
            Refuse,
            &["member", "add", invite],
        ),
        case(
            "member rm",
            RosterAndVault,
            Refuse,
            &["member", "rm", "bob", "--yes"],
        ),
        case("member list", Roster, Refuse, &["member", "list"]),
        // Reads the existing rosters for the name the anchor holder already uses.
        case("env add", Roster, Refuse, &["env", "add", "production"]),
        case(
            "env list",
            Roster,
            Report {
                healthy: "development (default)  verified",
            },
            &["env", "list"],
        ),
        // `resolve` takes both sides from the git index, not from `vault.enc`, so only the
        // roster tampers reach it.
        Case {
            conflicted: true,
            ..case("resolve", Roster, Refuse, &["resolve"])
        },
    ]
}

struct Tamper {
    name: &'static str,
    /// The least a command must read to see this tamper.
    hits: Reads,
    /// Change the project copy at the path; the identity is the project's maintainer.
    apply: fn(&Path, &Identity),
}

fn tampers() -> Vec<Tamper> {
    use Reads::*;
    vec![
        Tamper {
            name: "keys.json signature altered",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).roster_path(ENV), |r| {
                    let sig = r["signatures"][0]["signature"].as_str().unwrap();
                    let first = if sig.starts_with('A') { 'B' } else { 'A' };
                    r["signatures"][0]["signature"] = json!(format!("{first}{}", &sig[1..]));
                })
            },
        },
        Tamper {
            name: "keys.json member promoted without a signature",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).roster_path(ENV), |r| {
                    assert_eq!(r["members"][1]["name"], "bob");
                    r["members"][1]["role"] = json!("maintainer");
                })
            },
        },
        Tamper {
            name: "keys.json signatures removed",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).roster_path(ENV), |r| {
                    r["signatures"] = json!([])
                })
            },
        },
        Tamper {
            name: "keys.json field removed",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).roster_path(ENV), |r| {
                    r.as_object_mut().unwrap().remove("prev_digest");
                })
            },
        },
        Tamper {
            name: "keys.json roster_version lowered",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).roster_path(ENV), |r| {
                    r["roster_version"] = json!(1)
                })
            },
        },
        Tamper {
            name: "keys.json from an older commit",
            hits: Roster,
            apply: |dir, _| restore_v1(dir, &project(dir).roster_path(ENV)),
        },
        Tamper {
            // Every signed file is authentic for v1, so only the git history shows the
            // downgrade.
            name: "the environment from an older commit",
            hits: Roster,
            apply: |dir, _| {
                let env_dir = project(dir).env_dir(ENV);
                fs::remove_dir_all(&env_dir).unwrap();
                restore_v1(dir, &env_dir);
            },
        },
        Tamper {
            name: "keys.json amended and signed by a non-member",
            hits: Roster,
            apply: |dir, _| {
                let project = project(dir);
                let current = project.load_roster(ENV).unwrap();
                let mallory = Identity::generate().unwrap();
                let mut next = current.amend().unwrap();
                next.members
                    .push(member(&mallory, "mallory", Role::Maintainer));
                next.sign(&mallory, "mallory").unwrap();
                let mut vault = Vault::new(ENV);
                vault.set("API_KEY", FORGED).unwrap();
                project
                    .commit_amendment(ENV, &current, &next, &vault, &mallory)
                    .unwrap();
            },
        },
        Tamper {
            name: "chain.json removed",
            hits: Roster,
            apply: |dir, _| fs::remove_file(project(dir).chain_path(ENV)).unwrap(),
        },
        Tamper {
            name: "chain.json predecessor edited",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).chain_path(ENV), |c| {
                    c["rosters"][0]["members"][0]["name"] = json!("mallory")
                })
            },
        },
        Tamper {
            // As many links as the roster's version, and the last one is not `keys.json`. Only
            // a crash inside an amendment leaves an extra link, and that link is `keys.json`.
            name: "chain.json given an extra link",
            hits: Roster,
            apply: |dir, _| {
                edit_json(&project(dir).chain_path(ENV), |c| {
                    let first = c["rosters"][0].clone();
                    c["rosters"].as_array_mut().unwrap().push(first);
                })
            },
        },
        Tamper {
            name: "config.toml anchor replaced",
            hits: Roster,
            apply: |dir, _| {
                let project = project(dir);
                let mut config = project.load_config().unwrap();
                config.trust_anchor_fingerprint = Identity::generate().unwrap().anchor();
                project.save_config(&config).unwrap();
            },
        },
        Tamper {
            name: "config.toml names another project",
            hits: Roster,
            apply: |dir, _| {
                let project = project(dir);
                let mut config = project.load_config().unwrap();
                config.project_id = "0".repeat(32);
                project.save_config(&config).unwrap();
            },
        },
        Tamper {
            name: "vault.enc signed by a non-member",
            hits: RosterAndVault,
            apply: |dir, _| {
                let mallory = Identity::generate().unwrap();
                forge_vault(dir, ENV, &mallory, &[("API_KEY", FORGED)]);
            },
        },
        Tamper {
            name: "vault.enc encrypted to a key outside the roster",
            hits: RosterAndVault,
            apply: |dir, maintainer| {
                let outsider = Identity::generate().unwrap();
                let roster = roster_plus(dir, ENV, &outsider, "outsider", Role::Member);
                write_vault(dir, ENV, &roster, maintainer, &[("API_KEY", FORGED)]);
            },
        },
        Tamper {
            name: "vault.enc from another project",
            hits: RosterAndVault,
            apply: |dir, maintainer| {
                let mut roster = project(dir).load_roster(ENV).unwrap();
                roster.project_id = "0".repeat(32);
                write_vault(dir, ENV, &roster, maintainer, &[("API_KEY", FORGED)]);
            },
        },
        Tamper {
            name: "vault.enc from another environment",
            hits: RosterAndVault,
            apply: |dir, _| {
                let project = project(dir);
                fs::copy(project.vault_path("staging"), project.vault_path(ENV)).unwrap();
            },
        },
        Tamper {
            name: "vault.enc from an older commit",
            hits: RosterAndVault,
            apply: |dir, _| restore_v1(dir, &vault_path(dir, ENV)),
        },
        Tamper {
            name: "vault.enc byte altered",
            hits: RosterAndVault,
            apply: |dir, _| {
                // The first character of the last armor line, inside the ciphertext body.
                let path = vault_path(dir, ENV);
                let mut lines: Vec<String> = fs::read_to_string(&path)
                    .unwrap()
                    .lines()
                    .map(String::from)
                    .collect();
                let body = lines.len() - 2;
                let first = if lines[body].starts_with('A') {
                    "B"
                } else {
                    "A"
                };
                lines[body].replace_range(..1, first);
                fs::write(&path, lines.join("\n") + "\n").unwrap();
            },
        },
        Tamper {
            name: "vault.enc removed",
            hits: RosterAndVault,
            apply: |dir, _| fs::remove_file(vault_path(dir, ENV)).unwrap(),
        },
    ]
}

/// The projects every cell copies.
struct Base {
    /// A committed project: the initializer as maintainer, bob a member at roster v2,
    /// `API_KEY` set, a `staging` environment, and the v1 state tagged `v1`.
    clean: Fixture,
    /// The same project with a vault merge in progress.
    conflicted: TempDir,
}

fn base() -> Base {
    let f = init_git_project();
    git(f.dir.path(), &["tag", "v1"]);
    let bob = Identity::generate().unwrap();
    for args in [
        vec!["member", "add", &invite_for(&bob, "bob")],
        vec!["set", &format!("API_KEY={SECRET}")],
        vec!["env", "add", "staging"],
        vec!["--env", "staging", "set", "STAGING_KEY=staging-value"],
    ] {
        bf(f.dir.path(), &f.id).args(&args).assert().success();
    }
    git_commit_all(f.dir.path(), "v2");
    // Gitignored by `init`, like the file a real migration starts from.
    fs::write(
        f.dir.path().join(".env.import"),
        "IMPORTED=imported-value\n",
    )
    .unwrap();

    let conflicted = Fixture {
        dir: copy_project(f.dir.path()),
        id: Identity::from_secret_strings(&f.id.enc_secret(), &f.id.sign_secret()).unwrap(),
    };
    make_vault_conflict(&conflicted, "MAIN_KEY=m", |f| {
        bf(f.dir.path(), &f.id)
            .args(["set", "FEATURE_KEY=f"])
            .assert()
            .success();
    });
    Base {
        clean: f,
        conflicted: conflicted.dir,
    }
}

#[test]
fn every_command_is_classified() {
    let classified: BTreeSet<String> = OPENS_NO_ENVIRONMENT
        .iter()
        .map(|p| p.to_string())
        .chain(cases("").iter().map(|c| c.path.to_string()))
        .collect();
    assert_eq!(
        command_paths(),
        classified,
        "add the command to `cases` with what it reads, or to OPENS_NO_ENVIRONMENT"
    );
}

#[test]
fn every_command_refuses_every_tamper_it_reads() {
    let base = base();
    let carol = invite_for(&Identity::generate().unwrap(), "carol");
    let cases = cases(&carol);
    let tampers = tampers();

    let mut failures: Vec<String> = Vec::new();
    std::thread::scope(|s| {
        let (base, cases) = (&base, &cases);
        let clean = s.spawn(move || {
            cases
                .iter()
                .filter_map(|c| run_clean(base, c))
                .collect::<Vec<_>>()
        });
        let tampered: Vec<_> = tampers
            .iter()
            .map(|tamper| {
                s.spawn(move || {
                    cases
                        .iter()
                        .filter(|c| c.reads >= tamper.hits)
                        .filter(|c| !BY_DESIGN.contains(&(c.path, tamper.name)))
                        .filter_map(|c| run_tampered(base, c, tamper))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in std::iter::once(clean).chain(tampered) {
            failures.extend(handle.join().unwrap());
        }
    });
    assert!(
        failures.is_empty(),
        "{} cell(s) failed:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Run `case` on an untampered copy, which must succeed. Returns the failure, if any.
fn run_clean(base: &Base, case: &Case) -> Option<String> {
    let copy = copy_project(start(base, case));
    let out = bf(copy.path(), &base.clean.id)
        .args(&case.args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let problem = match case.answer {
        _ if !out.status.success() => "failed on the untampered project",
        Answer::Report { healthy } if !stdout.contains(healthy) => {
            "did not print its healthy line on the untampered project"
        }
        _ => return None,
    };
    Some(describe(case.path, "none", problem, &out))
}

/// Run `case` on a copy changed by `tamper`. Returns the failure, if any.
fn run_tampered(base: &Base, case: &Case, tamper: &Tamper) -> Option<String> {
    let copy = copy_project(start(base, case));
    (tamper.apply)(copy.path(), &base.clean.id);
    let before = snapshot(copy.path());
    let out = bf(copy.path(), &base.clean.id)
        .args(&case.args)
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let leaked = [SECRET, FORGED]
        .iter()
        .any(|v| stdout.contains(v) || stderr.contains(v));
    let problem = match case.answer {
        _ if stderr.contains("panicked") => "panicked",
        Answer::Refuse if out.status.success() => "accepted it",
        Answer::Refuse if leaked => "printed a secret value",
        Answer::Refuse if snapshot(copy.path()) != before => "refused, but wrote to .bitfort",
        Answer::Report { .. } if !out.status.success() => "failed instead of reporting",
        Answer::Report { healthy } if stdout.contains(healthy) => "reported it as healthy",
        _ => return None,
    };
    Some(describe(case.path, tamper.name, problem, &out))
}

fn start<'a>(base: &'a Base, case: &Case) -> &'a Path {
    if case.conflicted {
        base.conflicted.path()
    } else {
        base.clean.dir.path()
    }
}

fn describe(command: &str, tamper: &str, problem: &str, out: &std::process::Output) -> String {
    format!(
        "`{command}` x {tamper}: {problem}\n  stdout: {}\n  stderr: {}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

fn edit_json(path: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    edit(&mut doc);
    fs::write(path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}

/// Check out `path`, a file or directory in the project, as it was at tag `v1`.
fn restore_v1(dir: &Path, path: &Path) {
    let project = project(dir);
    let relative = path.strip_prefix(project.root()).unwrap().to_str().unwrap();
    git(project.root(), &["checkout", "-q", "v1", "--", relative]);
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files
}

/// `copy_project` lists the files of a repository and then copies each one, so no process
/// may still change the repository after the git command that made it returns.
#[test]
fn a_test_git_commit_starts_no_background_process() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    let out = git_command(dir.path())
        .args(["commit", "-q", "--allow-empty", "-m", "c"])
        .env("GIT_TRACE", "1")
        .output()
        .unwrap();
    let trace = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{trace}");
    assert!(!trace.contains("maintenance"), "{trace}");
}

/// A copy of the project at `from`, its git repository included.
fn copy_project(from: &Path) -> TempDir {
    let to = tempfile::tempdir().unwrap();
    for file in files_under(from) {
        let target = to.path().join(file.strip_prefix(from).unwrap());
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(&file, target).unwrap();
    }
    to
}

/// The bytes of every file under `.bitfort`, to show that a refused command wrote nothing.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    files_under(&dir.join(".bitfort"))
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}
