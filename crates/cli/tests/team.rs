//! End-to-end tests for the M3 team surface: environments (`env add/list`) and members
//! (`member add/rm/list`), including the rogue-roster, downgrade, and cross-environment
//! isolation cases. Driven through the real binary with `assert_cmd`.

mod common;

use bitfort_core::{clock, Identity, Invite, Member, Project, Role};
use common::{bf, git, git_commit_all, init_git_project, init_project, invite_for};
use predicates::prelude::*;

#[test]
fn env_add_creates_a_verified_isolated_environment() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created environment 'production'"));

    // Both environments show up, both verify.
    bf(f.dir.path(), &f.id)
        .args(["env", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("development (default)")
                .and(predicate::str::contains("production"))
                .and(predicate::str::contains("verified")),
        );

    // Secrets are per-environment: a value set in production is invisible to development.
    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "set", "PROD_ONLY=p"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "DEV_ONLY=d"])
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("PROD_ONLY").and(predicate::str::contains("DEV_ONLY").not()),
        );
    bf(f.dir.path(), &f.id)
        .arg("list")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("DEV_ONLY").and(predicate::str::contains("PROD_ONLY").not()),
        );
}

#[test]
fn env_add_rejects_duplicate_and_bad_names() {
    let f = init_project();
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "development"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    bf(f.dir.path(), &f.id)
        .args(["env", "add", "../evil"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a valid environment name"));
}

#[test]
fn env_add_requires_the_anchor_holder() {
    // A developer who is not the trust-anchor holder cannot mint a new environment,
    // because its v1 roster would not self-verify against the pinned anchor (§5.1).
    let f = init_project();
    let outsider = Identity::generate().unwrap();
    bf(f.dir.path(), &outsider)
        .args(["env", "add", "staging"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only the trust-anchor holder"));
}

#[test]
fn member_add_grants_the_new_member_vault_access() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    let invite = invite_for(&bob, "bob");

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added bob as member"));

    bf(f.dir.path(), &f.id)
        .args(["member", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob"));

    // A secret set after the add is encrypted to the new roster, so bob can read it.
    bf(f.dir.path(), &f.id)
        .args(["set", "SHARED=top"])
        .assert()
        .success();
    bf(f.dir.path(), &bob)
        .args(["get", "SHARED"])
        .assert()
        .success()
        .stdout(predicate::str::contains("top"));
}

#[test]
fn member_add_with_a_malformed_key_leaves_the_roster_unchanged() {
    // A bad enc_pubkey must be rejected while re-encrypting the vault (which happens before
    // the roster is written), so the on-disk roster never gets ahead of the vault.
    let f = init_git_project();
    let mallory = Identity::generate().unwrap();
    let bad = Invite {
        name: "bad".into(),
        enc_pubkey: "age1this-is-not-a-valid-key".into(),
        sign_pubkey: mallory.sign_pubkey(),
    };
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &bad.encode().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key material"));

    // Still v1: the failed add did not write a partial roster.
    let project = Project::discover(f.dir.path()).unwrap();
    assert_eq!(
        project.load_roster("development").unwrap().roster_version,
        1
    );
}

#[test]
fn member_add_needs_no_git_at_all() {
    // The predecessor is recorded in `chain.json`, not reconstructed from git history, so a
    // membership change works with no repository - and the result still verifies. This used
    // to refuse with "commit the current roster first".
    let f = init_project();
    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();

    let project = Project::discover(f.dir.path()).unwrap();
    assert_eq!(
        project.load_roster("development").unwrap().roster_version,
        2
    );
    let chain = project.load_chain("development").unwrap();
    assert_eq!(chain.rosters.len(), 1, "v1 must be recorded as predecessor");
    assert_eq!(chain.rosters[0].roster_version, 1);

    let verified = project.verify_roster("development").unwrap();
    assert_eq!(verified.roster.roster_version, 2);
    // bob can decrypt, so the vault really was re-encrypted to the new roster.
    bf(f.dir.path(), &bob).arg("list").assert().success();
}

#[test]
fn member_add_is_maintainer_only() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    let carol = Identity::generate().unwrap();

    // alice adds bob as a plain member.
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();

    // bob (not a maintainer) cannot add carol.
    bf(f.dir.path(), &bob)
        .args(["member", "add", &invite_for(&carol, "carol")])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only a maintainer"));
}

#[test]
fn member_add_as_maintainer_can_then_manage() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    let carol = Identity::generate().unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", "--maintainer", &invite_for(&bob, "bob")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added bob as maintainer"));
    git_commit_all(f.dir.path(), "add bob as maintainer");

    // bob is now a maintainer, so he can add carol.
    bf(f.dir.path(), &bob)
        .args(["member", "add", &invite_for(&carol, "carol")])
        .assert()
        .success();
}

#[test]
fn member_rm_revokes_vault_access() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "add bob");
    bf(f.dir.path(), &f.id)
        .args(["set", "S1=a"])
        .assert()
        .success();
    // Sanity: bob can read while a member.
    bf(f.dir.path(), &bob)
        .args(["get", "S1"])
        .assert()
        .success();

    // Removing a member is destructive; off a terminal it refuses without --yes, leaving
    // bob's access intact.
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("bitfort member rm bob --yes"));
    bf(f.dir.path(), &bob)
        .args(["get", "S1"])
        .assert()
        .success();

    // Remove bob and re-encrypt without his key.
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "-y"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed bob"));

    bf(f.dir.path(), &f.id)
        .args(["member", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob").not());

    // bob can no longer decrypt the re-encrypted vault.
    bf(f.dir.path(), &bob)
        .args(["get", "S1"])
        .assert()
        .failure();
}

#[test]
fn consecutive_member_changes_need_no_commit_between_them() {
    // Each amendment records its predecessor in `chain.json` as it goes, so a second change
    // does not have to wait for the first to be committed. The old design reconstructed the
    // chain from git history and refused here with "commit the current roster first".
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    let carol = Identity::generate().unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();
    // v2 is still uncommitted, and adding carol on top of it must work anyway.
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&carol, "carol")])
        .assert()
        .success();

    let project = Project::discover(f.dir.path()).unwrap();
    let verified = project.verify_roster("development").unwrap();
    assert_eq!(verified.roster.roster_version, 3);
    assert_eq!(verified.roster.members.len(), 3);
    let chain = project.load_chain("development").unwrap();
    assert_eq!(
        chain
            .rosters
            .iter()
            .map(|r| r.roster_version)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );

    // Nothing was committed on the user's behalf along the way.
    let log = std::process::Command::new("git")
        .arg("-C")
        .arg(f.dir.path())
        .args(["log", "--format=%s"])
        .output()
        .unwrap();
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(
        !subjects.contains("roster: commit"),
        "no commit should be made for us; git log was:\n{subjects}"
    );
}

#[test]
fn member_rm_refuses_the_last_maintainer() {
    let f = init_git_project();
    // The initializer's display name comes from $USER; look it up from the roster.
    let project = Project::discover(f.dir.path()).unwrap();
    let roster = project.load_roster("development").unwrap();
    let alice = &roster.members[0].name;
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", alice])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only maintainer"));
}

#[test]
fn rogue_self_added_maintainer_is_rejected() {
    // A repo-write attacker commits a v2 that self-adds mallory as maintainer, signed only
    // by mallory. The chain walk verifies v2 against v1's maintainers, so every path that
    // verifies must reject it.
    let f = init_git_project();
    let mallory = Identity::generate().unwrap();
    let project = Project::discover(f.dir.path()).unwrap();

    let current = project.load_roster("development").unwrap();
    let mut rogue = current.amend().unwrap();
    rogue.members.push(Member {
        name: "mallory".into(),
        enc_pubkey: mallory.enc_pubkey(),
        sign_pubkey: mallory.sign_pubkey(),
        role: Role::Maintainer,
        added_by: "mallory".into(),
        added_at: clock::now_rfc3339(),
    });
    rogue.sign(&mallory, "mallory").unwrap();
    // Write the chain entry too, so the attacker's v2 is as well-formed as it can be: only
    // the missing maintainer signature should reject it.
    let mut chain = project.load_chain("development").unwrap();
    chain.append(current).unwrap();
    project.save_chain("development", &chain).unwrap();
    project.save_roster("development", &rogue).unwrap();
    git_commit_all(f.dir.path(), "rogue v2");

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("FAILED"));
    // And a write path refuses to act on it.
    bf(f.dir.path(), &f.id)
        .args(["set", "X=1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to set"));
}

#[test]
fn committed_downgrade_is_rejected_under_strict() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "v2 add bob");

    // Roll the working-tree roster back to the committed v1; history still holds v2.
    git(
        f.dir.path(),
        &[
            "checkout",
            "HEAD~1",
            "--",
            ".bitfort/environments/development/keys.json",
        ],
    );

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("downgrade"));
}

#[test]
fn secrets_do_not_cross_environments_for_a_non_member() {
    // bob is a member of development only. He must not be able to decrypt production's
    // vault, whose recipient set is a different roster (least privilege, §4.1).
    let f = init_git_project();
    let bob = Identity::generate().unwrap();

    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();

    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "set", "PROD_SECRET=p"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "DEV_SECRET=d"])
        .assert()
        .success();

    // bob reads development fine but is locked out of production.
    bf(f.dir.path(), &bob)
        .args(["get", "DEV_SECRET"])
        .assert()
        .success()
        .stdout(predicate::str::contains("d"));
    bf(f.dir.path(), &bob)
        .args(["--env", "production", "get", "PROD_SECRET"])
        .assert()
        .failure();
}

#[test]
fn member_add_rejects_a_duplicate_encryption_key() {
    // Regression: only the *signing* key was checked for collisions, so one decryption key
    // could hold two seats under different names. `member rm` of one seat then re-encrypted
    // to the other, leaving the removed key still able to decrypt - a silent revocation
    // failure that `verify` and `status` both reported as healthy.
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    let second_key = Identity::generate().unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();

    // Same encryption key, a different signing key, a different name: previously accepted.
    let cloned_seat = bitfort_core::Invite {
        name: "bob-ci".into(),
        enc_pubkey: bob.enc_pubkey(),
        sign_pubkey: second_key.sign_pubkey(),
    }
    .encode()
    .unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &cloned_seat])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("encryption key is already in")
                .and(predicate::str::contains("bob")),
        );

    // The roster did not advance, so removing bob really does revoke him.
    let project = Project::discover(f.dir.path()).unwrap();
    assert_eq!(
        project.load_roster("development").unwrap().roster_version,
        2
    );
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "-y"])
        .assert()
        .success();
    bf(f.dir.path(), &bob).arg("list").assert().failure();
}

#[test]
fn member_add_rejects_a_malformed_invite_before_writing_anything() {
    // An invite is untrusted text pasted from a chat message. A bad key must be caught
    // before the roster or the chain is touched, whichever order the write would use.
    let f = init_git_project();
    let mallory = Identity::generate().unwrap();
    let bad = bitfort_core::Invite {
        name: "bad".into(),
        enc_pubkey: "age1this-is-not-a-valid-key".into(),
        sign_pubkey: mallory.sign_pubkey(),
    }
    .encode()
    .unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &bad])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invite enc_pubkey"));

    let project = Project::discover(f.dir.path()).unwrap();
    assert_eq!(
        project.load_roster("development").unwrap().roster_version,
        1
    );
    assert!(project
        .load_chain("development")
        .unwrap()
        .rosters
        .is_empty());
}

#[test]
fn env_add_refuses_to_clobber_an_existing_environment() {
    // Regression: `env add` trusted the `config.toml` list alone. A merge that dropped an
    // `environments` entry left the roster, chain, and vault on disk, and re-adding the name
    // wrote a fresh v1 over them: members lost access and every later command refused the
    // downgrade. Nothing warned, and there was no --force or `env rm`.
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "set", "PROD_DB=secret"])
        .assert()
        .success();

    // Drop only the config entry, exactly as a bad merge resolution would.
    let config_path = f.dir.path().join(".bitfort/config.toml");
    let config = std::fs::read_to_string(&config_path).unwrap();
    let stripped = config.replace("\"production\",\n", "").replace(
        "environments = [\"development\", \"production\"]",
        "environments = [\"development\"]",
    );
    std::fs::write(&config_path, stripped).unwrap();

    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("already has files")
                .and(predicate::str::contains("restore the entry")),
        );

    // The vault is untouched: restoring the config entry recovers the secret.
    std::fs::write(&config_path, &config).unwrap();
    bf(f.dir.path(), &f.id)
        .args(["--env", "production", "get", "PROD_DB"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret"));
}

#[test]
fn a_roster_grows_past_one_recipient_with_no_license() {
    // The open CLI has no seat gate: a maintainer adds as many members as the team has, and
    // nothing asks for a license token.
    let f = init_git_project();
    for name in ["bob", "carol", "dave"] {
        let id = Identity::generate().unwrap();
        bf(f.dir.path(), &f.id)
            .args(["member", "add", &invite_for(&id, name)])
            .assert()
            .success();
        git_commit_all(f.dir.path(), name);
    }
    bf(f.dir.path(), &f.id)
        .args(["member", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dave"));
}

/// Re-sign `development`'s roster with the initializer's name replaced by `forged`, so the
/// project looks like one written before the name rule existed.
fn rename_initializer(f: &common::Fixture, forged: &str) {
    let project = Project::discover(f.dir.path()).unwrap();
    let current = project.load_roster("development").unwrap();
    let mut next = current.amend().unwrap();
    next.members[0].name = forged.to_string();
    next.sign(&f.id, "maintainer").unwrap();
    let mut chain = project.load_chain("development").unwrap();
    chain.append(current).unwrap();
    project.save_chain("development", &chain).unwrap();
    project.save_roster("development", &next).unwrap();
}

/// A roster written before this rule can still hold a forged name, and a read path prints
/// what it finds. The display sanitizer keeps those bytes off the screen, and `env add`
/// refuses to copy such a name into a new signed roster.
#[test]
fn a_forged_name_in_an_older_roster_is_sanitized_and_stops_spreading() {
    let f = init_project();
    rename_initializer(&f, "ops\u{1b}[31m\nbf1:0000000000000000  maintainer  admin");

    // Piped, and with color forced, which restores anstream's pass-through.
    for force in ["0", "1"] {
        let out = bf(f.dir.path(), &f.id)
            .env("CLICOLOR_FORCE", force)
            .args(["member", "list"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        // The forged text still reads, but on the one row its member owns: the newline and
        // the escape are replacement markers, so no second row and no repainted terminal.
        assert_eq!(
            text.lines().count(),
            1,
            "the name printed as more than one row: {text:?}"
        );
        assert!(
            !text.lines().any(|l| l.starts_with("bf1:0000000000000000")),
            "forged row reached the consumer: {text:?}"
        );
        assert!(!text.contains('\u{1b}'), "escape byte printed: {text:?}");
        assert!(text.contains('\u{FFFD}'), "no replacement marker: {text:?}");
    }

    // `env add` reuses the holder's name for the new environment's roster.
    bf(f.dir.path(), &f.id)
        .args(["env", "add", "production"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid member name"));
}

/// `member rm` takes a name, so two members whose names differ only in case read as one row
/// to the maintainer who revokes one of them.
#[test]
fn a_name_that_differs_only_in_case_is_refused() {
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "ci")])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "add ci");

    let mallory = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&mallory, "CI")])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

/// The display name comes from whoever mints the invite, travels inside the signed roster,
/// and is printed back by `member list`. A newline in it adds a row that reads as a member
/// nobody approved, and the roster signature then covers that forged text.
#[test]
fn a_name_that_would_forge_a_member_list_row_is_refused() {
    let f = init_project();
    let rogue = Identity::generate().unwrap();
    let forged_name = "ci\nbf1:0000000000000000  maintainer  ops";

    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&rogue, forged_name)])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid member name"));

    // The `--name` override reaches the roster by the same path, so it faces the same rule.
    bf(f.dir.path(), &f.id)
        .args([
            "member",
            "add",
            &invite_for(&rogue, "ci"),
            "--name",
            forged_name,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid member name"));

    // Minting refuses it too, so a rejected name costs no identity.
    bf(f.dir.path(), &f.id)
        .args(["identity", "new", "--name", forged_name])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid member name"));

    // Nothing reached the roster: the initializer is still the only member.
    bf(f.dir.path(), &f.id)
        .args(["member", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("maintainer").count(1));
}

/// Editing `keys.json` needs no key, so a `member list` that prints an unverified roster shows
/// whatever the editor wrote, as a row nobody signed. It refuses instead, like every other
/// read path, and prints no member under either output format.
#[test]
fn member_list_refuses_a_roster_edited_without_a_signature() {
    let f = init_project();
    let project = Project::discover(f.dir.path()).unwrap();
    let mut roster = project.load_roster("development").unwrap();
    // No `sign`: the signature still covers the old name.
    roster.members[0].name = "forged".to_string();
    project.save_roster("development", &roster).unwrap();

    for args in [&["member", "list"][..], &["--json", "member", "list"]] {
        bf(f.dir.path(), &f.id)
            .args(args)
            .assert()
            .failure()
            .stdout("")
            .stderr(predicate::str::contains("refusing to list members"));
    }
}
