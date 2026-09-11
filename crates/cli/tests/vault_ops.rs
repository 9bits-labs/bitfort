//! End-to-end tests for `rotate` and `resolve`, including a real git merge conflict in
//! the armored vault. Driven through the real binary with `assert_cmd`.

mod common;

use std::fs;

use common::{bf, init_git_project, make_vault_conflict};
use predicates::prelude::*;

#[test]
fn rotate_reencrypts_and_stamps_config() {
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "K=v"])
        .assert()
        .success();

    let before = fs::read_to_string(
        f.dir
            .path()
            .join(".bitfort/environments/development/vault.enc"),
    )
    .unwrap();

    bf(f.dir.path(), &f.id)
        .arg("rotate")
        .assert()
        .success()
        .stdout(predicate::str::contains("Re-encrypted"));

    // rotate stamps config and produces fresh ciphertext, but keeps the value readable.
    let config = fs::read_to_string(f.dir.path().join(".bitfort/config.toml")).unwrap();
    assert!(config.contains("rotated_at"));
    let after = fs::read_to_string(
        f.dir
            .path()
            .join(".bitfort/environments/development/vault.enc"),
    )
    .unwrap();
    assert_ne!(before, after, "ciphertext should be freshly re-encrypted");

    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "K"])
        .assert()
        .success()
        .stdout(predicate::str::contains("v"));
}

#[test]
fn resolve_is_a_noop_without_a_conflict() {
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to resolve"));
}

#[test]
fn resolve_merges_disjoint_branch_edits() {
    let f = init_git_project();
    make_vault_conflict(&f, "MAIN_K=m", |f| {
        bf(f.dir.path(), &f.id)
            .args(["set", "FEAT_K=f"])
            .assert()
            .success();
    });

    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .success()
        .stdout(predicate::str::contains("Resolved"));

    // All three keys survive the merge, cleanly re-encrypted.
    bf(f.dir.path(), &f.id)
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "printenv BASE; printenv MAIN_K; printenv FEAT_K",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("b")
                .and(predicate::str::contains("m"))
                .and(predicate::str::contains("f")),
        );
}

#[test]
fn resolve_keeps_a_secret_unset_on_one_branch_deleted() {
    // Finding 1.7: the merge was a two-way union of both sides, which cannot tell "deleted
    // here" from "added there", so `bitfort unset` was undone by the next merge and a
    // revoked secret came back with no warning. The common ancestor is what separates them,
    // and it is read from the git index - never from the conflicted file, whose `|||||||`
    // section anyone who can write that file chooses.
    let f = init_git_project();
    make_vault_conflict(&f, "MAIN_K=m", |f| {
        bf(f.dir.path(), &f.id)
            .args(["unset", "BASE", "-y"])
            .assert()
            .success();
    });

    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .success()
        .stdout(predicate::str::contains("Resolved"));

    bf(f.dir.path(), &f.id)
        .args(["get", "BASE"])
        .assert()
        .failure();
    // The other branch's addition still survives: only the deletion was applied.
    bf(f.dir.path(), &f.id)
        .args(["get", "MAIN_K"])
        .assert()
        .success()
        .stdout(predicate::str::contains("m"));
}

#[test]
fn resolve_refuses_once_the_merge_state_is_gone() {
    // `git add` on the conflicted path drops every index stage, and the index is the only
    // source a merge input may come from - so there is nothing left to merge. Resolving from
    // the markers instead is what would let whoever wrote the file pick the answer, so this
    // refuses and names the command that brings the merge back.
    let f = init_git_project();
    make_vault_conflict(&f, "MAIN_K=m", |f| {
        bf(f.dir.path(), &f.id)
            .args(["unset", "BASE", "-y"])
            .assert()
            .success();
    });
    let vault = ".bitfort/environments/development/vault.enc";
    common::git(f.dir.path(), &["add", vault]);

    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("git has no conflict for it")
                .and(predicate::str::contains("git checkout --merge")),
        );

    // And the named command is the way out: it restores the stages, and the merge then runs
    // with its ancestor, so the deletion still wins.
    common::git(f.dir.path(), &["checkout", "--merge", "--", vault]);
    bf(f.dir.path(), &f.id).arg("resolve").assert().success();
    bf(f.dir.path(), &f.id)
        .args(["get", "BASE"])
        .assert()
        .failure();
}

#[test]
fn a_second_resolve_keeps_what_was_written_after_the_first() {
    // Git holds the unmerged entry until the path is staged, so a second `resolve` reads the
    // same stages - and rebuilding the vault from them would discard every `set` made since,
    // silently. The merged file has no conflict markers, which is what says the conflict was
    // already settled.
    let f = init_git_project();
    make_vault_conflict(&f, "MAIN_K=m", |f| {
        bf(f.dir.path(), &f.id)
            .args(["set", "FEAT_K=f"])
            .assert()
            .success();
    });

    bf(f.dir.path(), &f.id).arg("resolve").assert().success();
    bf(f.dir.path(), &f.id)
        .args(["set", "POST_RESOLVE=x"])
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .success()
        .stdout(predicate::str::contains("already been resolved"));
    bf(f.dir.path(), &f.id)
        .args(["get", "POST_RESOLVE"])
        .assert()
        .success()
        .stdout(predicate::str::contains("x"));
}

#[test]
fn resolve_names_a_secret_the_merge_brings_back() {
    // A three-way merge is only as good as its ancestor, and whoever pushes chooses the branch
    // point and so the ancestor. Branching before a secret was first set makes the other side
    // read as *adding* it: an ordinary merge, no conflict, no warning, and nothing the tool can
    // tell apart from a teammate adding that name. Naming what changed hands is the guard, so
    // the person who ran `unset` sees the secret come back.
    let f = init_git_project();
    common::git(f.dir.path(), &["branch", "-M", "main"]);
    let before_secret = String::from_utf8(
        std::process::Command::new("git")
            .arg("-C")
            .arg(f.dir.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    bf(f.dir.path(), &f.id)
        .args(["set", "SECRET=leaked"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "add the secret");
    bf(f.dir.path(), &f.id)
        .args(["unset", "SECRET", "-y"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "MAIN=m"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "withdraw the secret");

    // A branch from before the secret existed, carrying the vault that still holds it.
    common::git(
        f.dir.path(),
        &["checkout", "-q", "-b", "old", before_secret.trim()],
    );
    common::git(
        f.dir.path(),
        &["checkout", "-q", "main~1", "--", ".bitfort"],
    );
    common::git_commit_all(f.dir.path(), "restore the old vault");

    common::git(f.dir.path(), &["checkout", "-q", "main"]);
    assert!(
        !common::git_try(f.dir.path(), &["merge", "--no-edit", "old"]),
        "the vault edits should have conflicted"
    );

    // The merge is conflict-free and correct for its ancestor, so the summary is the only
    // thing that shows the withdrawn secret coming back.
    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "added by the other branch: SECRET",
        ));
    bf(f.dir.path(), &f.id)
        .args(["get", "SECRET"])
        .assert()
        .success();
}

#[test]
fn resolve_reports_a_vault_deleted_on_one_branch() {
    // Git records an ancestor and one side. There is no second version to merge, and whether
    // the environment still exists is not a question the tool can answer - so it names which
    // branch dropped the vault, and the hint points at the side that still has it.
    let f = init_git_project();
    let vault = ".bitfort/environments/development/vault.enc";
    common::git(f.dir.path(), &["branch", "-M", "main"]);
    bf(f.dir.path(), &f.id)
        .args(["set", "BASE=b"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "base secret");

    common::git(f.dir.path(), &["branch", "feature"]);
    bf(f.dir.path(), &f.id)
        .args(["set", "MAIN_K=m"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "main edit");

    common::git(f.dir.path(), &["checkout", "-q", "feature"]);
    common::git(f.dir.path(), &["rm", "-q", vault]);
    common::git_commit_all(f.dir.path(), "drop the vault");

    common::git(f.dir.path(), &["checkout", "-q", "main"]);
    assert!(
        !common::git_try(f.dir.path(), &["merge", "--no-edit", "feature"]),
        "a delete against an edit should have conflicted"
    );

    // The hint has to be `git add`: in a modify/delete conflict the surviving side is already
    // in the working tree, so `git checkout --ours` is a no-op that leaves the path unmerged
    // and the next `git commit` refusing.
    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("deleted on their branch and changed on ours")
                .and(predicate::str::contains("git add")),
        );

    // Drive the named recovery, and prove it is the one that clears the merge.
    common::git(f.dir.path(), &["add", vault]);
    common::git_commit_all(f.dir.path(), "keep the vault");
    bf(f.dir.path(), &f.id)
        .args(["get", "BASE"])
        .assert()
        .success();
}

#[test]
fn resolve_warns_when_the_branches_share_no_version_of_the_vault() {
    // Git reports no stage 1 when the merge base commit does not hold the path. That is not
    // "the vault is new and nothing could have been deleted" - any branch taken before the
    // vault existed produces it, and its side can carry a vault restored from history. So the
    // merge is two-way and it warns.
    let f = init_git_project();
    common::git(f.dir.path(), &["branch", "-M", "main"]);

    common::git(f.dir.path(), &["checkout", "-q", "-b", "feature"]);
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "staging"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["--env", "staging", "set", "FEAT=f"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "staging on the branch");

    common::git(f.dir.path(), &["checkout", "-q", "main"]);
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "staging"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["--env", "staging", "set", "MAIN=m"])
        .assert()
        .success();
    common::git_commit_all(f.dir.path(), "staging on main");
    assert!(
        !common::git_try(f.dir.path(), &["merge", "--no-edit", "feature"]),
        "both branches created the staging vault, so it should conflict"
    );

    // Only the vault is resolvable here; the roster conflicts too, so take main's. A v1
    // roster has no predecessors, so there is no `chain.json` to settle.
    common::git(
        f.dir.path(),
        &[
            "checkout",
            "--ours",
            "--",
            ".bitfort/environments/staging/keys.json",
        ],
    );

    bf(f.dir.path(), &f.id)
        .args(["--env", "staging", "resolve"])
        .assert()
        .success()
        .stderr(predicate::str::contains("no common version"))
        // And the summary names what came across, which is what a resurrection looks like.
        .stdout(predicate::str::contains("added by the other branch: FEAT"));
}

#[test]
fn resolve_needs_a_side_for_a_doubly_edited_key() {
    let f = init_git_project();
    // Both branches set K to different values.
    make_vault_conflict(&f, "K=main", |f| {
        bf(f.dir.path(), &f.id)
            .args(["set", "K=feat"])
            .assert()
            .success();
    });

    // Without a side, resolve reports the conflict and refuses.
    bf(f.dir.path(), &f.id)
        .arg("resolve")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("re-run with --ours or --theirs")
                .and(predicate::str::contains("K")),
        );

    // --ours keeps main's value (we are on main).
    bf(f.dir.path(), &f.id)
        .args(["resolve", "--ours"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "K"])
        .assert()
        .success()
        .stdout(predicate::str::contains("main"));
}
