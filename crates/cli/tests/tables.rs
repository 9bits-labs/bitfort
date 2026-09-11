//! Coverage for the read commands' machine contract: piped/CI output stays the
//! stable plain format, and `CLICOLOR_FORCE` forces color without changing that
//! layout. The rich terminal tables render only on a real TTY (verified
//! behaviorally); here we lock the parseable side that scripts depend on.

mod common;

use common::*;
use predicates::prelude::*;

#[test]
fn list_is_one_key_per_line_when_piped() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=x"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "DB_URL=y"])
        .assert()
        .success();
    // Machine payload: sorted keys, one per line, no header or chrome.
    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout("API_KEY\nDB_URL\n");
}

#[test]
fn clicolor_force_does_not_change_list_layout() {
    // CLICOLOR_FORCE forces color, not layout: a piped `list` stays one key per line, so
    // a script that happens to set CLICOLOR_FORCE never breaks on `bitfort list | grep`.
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=x"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "DB_URL=y"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .env("CLICOLOR_FORCE", "1")
        .arg("list")
        .assert()
        .success()
        .stdout("API_KEY\nDB_URL\n");
}

#[test]
fn member_list_is_stable_and_headerless_when_piped() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["member", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("maintainer"))
        .stdout(predicate::str::contains("bf1:"))
        .stdout(predicate::str::contains("ROSTER").not())
        .stdout(predicate::str::contains("(you)").not());
}

#[test]
fn env_list_is_stable_format_when_piped() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["env", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("development (default)"))
        .stdout(predicate::str::contains("ENVIRONMENTS").not());
}
