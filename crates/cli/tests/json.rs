//! End-to-end coverage for the `--json` machine contract on the read/report commands.
//! Each case drives the real binary and parses stdout (or, for failures, stderr) as JSON,
//! so the shape scripts and MCP hosts depend on is pinned. Human chrome (color, glyphs,
//! tables) is off under `--json`, so payloads never carry escape codes.

mod common;

use std::fs;

use assert_cmd::assert::Assert;
use bitfort_core::Identity;
use common::*;
use serde_json::{json, Value};

/// Parse a successful command's stdout as JSON.
fn json_ok(assert: Assert) -> Value {
    let out = assert.success().get_output().stdout.clone();
    assert!(
        !out.contains(&0x1b),
        "json stdout carried an escape byte: {out:?}"
    );
    serde_json::from_slice(&out).expect("stdout is valid JSON")
}

#[test]
fn status_json_reports_every_posture_fact() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=x"])
        .assert()
        .success();

    let v = json_ok(bf(f.dir.path(), &f.id).args(["status", "--json"]).assert());

    assert_eq!(v["environment"], "development");
    assert!(v["anchor"].as_str().unwrap().starts_with("bf1"));
    assert_eq!(v["roster"]["verified"], true);
    assert_eq!(v["roster"]["roster_version"], 1);
    assert_eq!(v["vault"]["unlocked"], true);
    assert_eq!(v["vault"]["secrets"], 1);
    // Vault provenance, read off the payload signature the roster authenticates.
    assert_eq!(v["vault"]["roster_version"], 1);
    assert!(v["vault"]["written_by"].as_str().is_some());
    assert!(v["vault"]["written_at"].as_str().unwrap().ends_with('Z'));
    assert!(
        v.get("license").is_none(),
        "status must not report a license tier"
    );
    // init_project is not a git repo, so anti-rollback cannot be enforced and the next step
    // says so. The roster itself still verifies, from `chain.json`.
    assert_eq!(v["rollback"]["enforced"], false);
    assert!(v["rollback"]["warning"]
        .as_str()
        .unwrap()
        .contains("no committed history"));
    assert!(v["next_step"].as_str().unwrap().contains("git init"));
}

#[test]
fn list_json_is_a_keys_array() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=x"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "DB_URL=y"])
        .assert()
        .success();

    let v = json_ok(bf(f.dir.path(), &f.id).args(["list", "--json"]).assert());
    assert_eq!(v["environment"], "development");
    assert_eq!(v["keys"], serde_json::json!(["API_KEY", "DB_URL"]));
}

#[test]
fn verify_json_carries_the_verified_roster() {
    let f = init_project();
    let v = json_ok(bf(f.dir.path(), &f.id).args(["verify", "--json"]).assert());
    assert_eq!(v["verified"], true);
    assert_eq!(v["roster_version"], 1);
    // `member_count` is the count everywhere; `members` is the array `member list` emits.
    assert_eq!(v["member_count"], 1);
    assert_eq!(v["rollback_enforced"], false);
    assert_eq!(v["strict"], false);
    assert_eq!(v["exit_code"], 0);
    assert!(v["anchor"].as_str().unwrap().starts_with("bf1"));
}

#[test]
fn verify_json_strict_outside_git_emits_payload_but_exits_nonzero() {
    // `--strict` requires git-backed rollback protection; outside a repo it exits 1, but the
    // JSON payload is still emitted. `verified` stays true - the roster itself is fine - so
    // the payload must also carry why the exit code disagrees with it.
    let f = init_project();
    let out = bf(f.dir.path(), &f.id)
        .args(["verify", "--strict", "--json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["rollback_enforced"], false);
    assert_eq!(v["strict"], true);
    assert_eq!(v["exit_code"], 1);
    assert!(v["rollback_warning"].as_str().unwrap().contains("git"));
}

#[test]
fn verify_json_reports_an_unverified_roster() {
    // Tamper a signed field so the signature no longer matches: `verify --json` must carry
    // the failure in the payload (`verified:false` + `error`) and still exit nonzero.
    let f = init_project();
    let roster_path = f
        .dir
        .path()
        .join(".bitfort/environments/development/keys.json");
    let mut roster: Value =
        serde_json::from_str(&fs::read_to_string(&roster_path).unwrap()).unwrap();
    roster["members"][0]["added_at"] = json!("1999-01-01T00:00:00Z");
    fs::write(&roster_path, serde_json::to_string_pretty(&roster).unwrap()).unwrap();

    let out = bf(f.dir.path(), &f.id)
        .args(["verify", "--json"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["verified"], false);
    assert!(!v["error"].as_str().unwrap().is_empty());
}

#[test]
fn env_list_json_marks_the_default() {
    let f = init_project();
    let v = json_ok(
        bf(f.dir.path(), &f.id)
            .args(["env", "list", "--json"])
            .assert(),
    );
    let envs = v["environments"].as_array().unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0]["name"], "development");
    assert_eq!(envs[0]["default"], true);
    assert_eq!(envs[0]["verified"], true);
    assert_eq!(envs[0]["roster_version"], 1);
    assert_eq!(envs[0]["rollback_enforced"], false);
}

#[test]
fn member_list_json_marks_the_local_identity() {
    let f = init_project();
    let v = json_ok(
        bf(f.dir.path(), &f.id)
            .args(["member", "list", "--json"])
            .assert(),
    );
    assert_eq!(v["environment"], "development");
    assert_eq!(v["verified"], true);
    let members = v["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(v["member_count"], 1, "the count travels under its own key");
    assert_eq!(members[0]["role"], "maintainer");
    assert_eq!(members[0]["you"], true);
    assert!(members[0]["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("bf1"));
}

#[test]
fn errors_are_json_objects_under_json() {
    // `--json` turns errors into `{"error": .., "try": ..}` on stderr, even for a write
    // command that ignores `--json` for its own success output.
    let id = Identity::generate().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = bf(dir.path(), &id)
        .args(["--json", "set", "FOO=bar"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let v: Value = serde_json::from_slice(&out).expect("stderr is valid JSON");
    assert!(v["error"].as_str().unwrap().contains("no .bitfort/ found"));
    assert_eq!(v["try"], "bitfort init");
}
