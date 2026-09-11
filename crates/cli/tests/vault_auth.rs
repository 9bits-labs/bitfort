//! End-to-end coverage for vault origin authentication: a `vault.enc` is trusted only if a
//! member of the verified roster signed its payload. Driven through the real binary, because
//! the failure this guards against ends at `run` handing a forged value to a child process.

mod common;

use std::fs;
use std::path::Path;

use bitfort_core::{clock, Identity, Member, Role, Roster, Vault};
use common::*;
use predicates::prelude::*;

const ENV: &str = "development";

/// The project, through the same API the tool uses, so the on-disk layout is not spelled out
/// again here.
fn project(dir: &Path) -> bitfort_core::Project {
    bitfort_core::Project::discover(dir).unwrap()
}

/// The project's roster plus one member built from `identity`, for the attacks that need a key
/// the real `keys.json` does not list.
fn roster_plus(dir: &Path, identity: &Identity, name: &str, role: Role) -> Roster {
    let mut roster = project(dir).load_roster(ENV).unwrap();
    roster.members.push(Member {
        name: name.into(),
        enc_pubkey: identity.enc_pubkey(),
        sign_pubkey: identity.sign_pubkey(),
        role,
        added_by: name.into(),
        added_at: clock::now_rfc3339(),
    });
    roster
}

/// Overwrite the project's `vault.enc` with one `mallory` signed, encrypted to the real
/// roster's recipients. This is what repo write access alone buys an attacker: every
/// `enc_pubkey` in `keys.json` is public, so the file decrypts for the real members.
fn forge_vault(dir: &Path, mallory: &Identity, vars: &[(&str, &str)]) {
    let forged = roster_plus(dir, mallory, "mallory", Role::Maintainer);
    write_vault(dir, ENV, &forged, mallory, vars);
}

/// A committed project holding `API_KEY=bob-knows-this`, with bob a member. Returns bob's
/// identity and the vault as it stands while he can still read it.
fn project_with_bob(f: &Fixture) -> (Identity, String) {
    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=bob-knows-this"])
        .assert()
        .success();
    let vault = fs::read_to_string(vault_path(f.dir.path(), ENV)).unwrap();
    (bob, vault)
}

#[test]
fn run_refuses_a_vault_no_member_signed() {
    // The reported attack: overwrite `vault.enc` with a payload that sets `LD_PRELOAD`, and
    // `bitfort run` injects it into every child. The roster verifies and the file decrypts;
    // only the payload signature separates it from a real vault.
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    let mallory = Identity::generate().unwrap();
    forge_vault(f.dir.path(), &mallory, &[("LD_PRELOAD", "/tmp/evil.so")]);

    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "LD_PRELOAD"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in roster v"));
}

#[test]
fn run_refuses_a_vault_encrypted_to_a_key_outside_the_roster() {
    // A member may write the vault; that does not license them to choose who else can read
    // it. Here the payload is signed by the real maintainer and holds the real values - only
    // the ciphertext is addressed to one more key than the roster has members.
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    let outsider = Identity::generate().unwrap();
    let widened = roster_plus(f.dir.path(), &outsider, "outsider", Role::Member);
    write_vault(f.dir.path(), ENV, &widened, &f.id, &[("API_KEY", "real")]);

    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not list"));
}

#[test]
fn every_read_path_refuses_a_forged_vault() {
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    let mallory = Identity::generate().unwrap();
    forge_vault(f.dir.path(), &mallory, &[("API_KEY", "attacker")]);

    for args in [
        vec!["get", "API_KEY"],
        vec!["list"],
        vec!["export", "--force"],
    ] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("not in roster v"));
    }
}

#[test]
fn a_write_path_refuses_a_forged_vault() {
    // `set` decrypts before it re-encrypts, so the forged payload must be refused there too
    // - otherwise the next write launders the attacker's values into a signed vault.
    let f = init_git_project();
    let mallory = Identity::generate().unwrap();
    forge_vault(f.dir.path(), &mallory, &[("LD_PRELOAD", "/tmp/evil.so")]);

    bf(f.dir.path(), &f.id)
        .args(["set", "K=v"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in roster v"));
}

#[test]
fn status_separates_a_forged_vault_from_one_it_cannot_decrypt() {
    // A forged vault opens fine for a member, so reporting "the local identity can't decrypt
    // this vault" would name the wrong cause and hide tampering.
    let f = init_git_project();
    let mallory = Identity::generate().unwrap();
    forge_vault(f.dir.path(), &mallory, &[("LD_PRELOAD", "/tmp/evil.so")]);

    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("not in roster v"))
        .stdout(predicate::str::contains("can't decrypt this vault").not())
        .stdout(predicate::str::contains(
            "treat every value in it as compromised",
        ));
}

#[test]
fn a_vault_from_another_project_is_refused() {
    // A developer on two projects is a recipient of both, so a vault moved between them
    // decrypts cleanly and the signer is a key this roster knows. Only the payload's
    // `project_id` stops the replay.
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    let mut other_project = project(f.dir.path()).load_roster(ENV).unwrap();
    other_project.project_id = "some-other-project".into();

    let mut vault = Vault::new(ENV);
    vault.set("API_KEY", "from-the-other-project").unwrap();
    fs::write(
        vault_path(f.dir.path(), ENV),
        vault.encrypt(&other_project, &f.id).unwrap(),
    )
    .unwrap();

    bf(f.dir.path(), &f.id)
        .args(["list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("project mismatch"));
}

#[test]
fn a_vault_that_predates_a_revocation_is_refused() {
    // Restoring an older `vault.enc` is the cheapest attack left once forgery is closed: an
    // old payload stays validly signed for ever. Here it is the pre-removal vault, so reading
    // it would hand back the value the removed member knows and undo `member rm` + `rotate`.
    let f = init_git_project();
    let (_bob, pre_removal) = project_with_bob(&f);

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=rotated-after-bob-left", "--yes"])
        .assert()
        .success();

    fs::write(vault_path(f.dir.path(), ENV), &pre_removal).unwrap();

    for args in [vec!["run", "--", "printenv", "API_KEY"], vec!["list"]] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("predates a membership change"));
    }

    // The gate CI runs must see it too, not only the command that would inject it.
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("refused by every read path"));

    // And the posture readout must not call it healthy.
    bf(f.dir.path(), &f.id)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("refused by every read path"));

    // `rotate` is the one deliberate way back: it re-signs against the current roster.
    bf(f.dir.path(), &f.id)
        .arg("rotate")
        .assert()
        .success()
        .stderr(predicate::str::contains("check that it does not hold"));
    bf(f.dir.path(), &f.id)
        .args(["run", "--", "printenv", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob-knows-this"));
}

#[test]
fn verify_passes_on_a_healthy_vault_and_fails_on_a_forged_one() {
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("signed by"));

    let mallory = Identity::generate().unwrap();
    forge_vault(f.dir.path(), &mallory, &[("API_KEY", "attacker")]);
    bf(f.dir.path(), &f.id)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in roster v"));
}

#[test]
fn a_member_cannot_remove_themselves() {
    // The re-encrypted vault must be signed by a member of the roster it is written for, and
    // a departing maintainer is not one. Refuse with the fix rather than failing at the write.
    let f = init_git_project();
    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", "--maintainer", &invite_for(&bob, "bob")])
        .assert()
        .success();

    bf(f.dir.path(), &bob)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot remove themselves"));

    // Another maintainer can, and the vault stays readable afterwards.
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id).arg("list").assert().success();
}

/// Build the state a crash inside a `member rm` leaves behind: `keys.json` at v3 without bob,
/// while `vault.enc` is still the v2 file he can read. An amendment publishes the roster
/// before the vault, so this is the only split a crash can produce. Returns bob's identity.
fn interrupted_removal(f: &Fixture) -> Identity {
    let (bob, vault_v2) = project_with_bob(f);

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    // Roll only the vault back, the way a crash between the two renames would.
    fs::write(vault_path(f.dir.path(), ENV), vault_v2).unwrap();
    bob
}

/// The same crash, with the departing member as the last writer of the vault: bob runs `set`,
/// so the stale `vault.enc` carries *his* signature, and the new `keys.json` no longer lists
/// him. Returns bob's identity.
fn interrupted_removal_of_the_last_writer(f: &Fixture) -> Identity {
    let (bob, _) = project_with_bob(f);
    bf(f.dir.path(), &bob)
        .args(["set", "API_KEY=bob-wrote-this", "--yes"])
        .assert()
        .success();
    let bob_vault = fs::read_to_string(vault_path(f.dir.path(), ENV)).unwrap();

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    fs::write(vault_path(f.dir.path(), ENV), bob_vault).unwrap();
    bob
}

/// Build the opposite split, which no write path produces: `keys.json` rolled back to the v2
/// that still lists bob, while the vault is the v3 written without him. Returns bob's
/// identity.
fn rolled_back_roster(f: &Fixture) -> Identity {
    let (bob, _) = project_with_bob(f);

    let project = project(f.dir.path());
    let roster_v2 = fs::read_to_string(project.roster_path(ENV)).unwrap();
    let chain_v2 = fs::read_to_string(project.chain_path(ENV)).unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    fs::write(project.roster_path(ENV), roster_v2).unwrap();
    fs::write(project.chain_path(ENV), chain_v2).unwrap();
    bob
}

#[test]
fn resolve_refuses_a_hand_written_conflict() {
    // `resolve` re-signs its output at the current version, so it is the laundering path
    // around every other refusal: an attacker who cannot overwrite `vault.enc` outright
    // writes it as a synthetic conflict whose other side is the pre-revocation file.
    //
    // The markers are no longer an input. A merge is resolved from what git recorded for the
    // path, so a file git has no unmerged entry for is refused before anything is decrypted,
    // and the attacker cannot choose either side or the ancestor.
    let f = init_git_project();
    let (_bob, pre_removal) = project_with_bob(&f);
    let path = vault_path(f.dir.path(), ENV);

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=rotated-after-bob-left", "--yes"])
        .assert()
        .success();
    let current = fs::read_to_string(&path).unwrap();

    fs::write(
        &path,
        format!("<<<<<<< HEAD\n{current}=======\n{pre_removal}>>>>>>> attacker\n"),
    )
    .unwrap();

    bf(f.dir.path(), &f.id)
        .args(["resolve", "--theirs"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("git has no conflict for it")
                .and(predicate::str::contains("git checkout --merge")),
        );
}

#[test]
fn resolve_refuses_a_merged_side_from_another_roster_version() {
    // The same laundering attempt through a real merge, which is the one shape `resolve` will
    // still act on: a branch restores the pre-revocation vault and merges it back. Git records
    // both sides, so the sides are genuine - and the drift check is what refuses this one,
    // because that side was written for the roster that still listed bob.
    let f = init_git_project();
    let (_bob, pre_removal) = project_with_bob(&f);
    let path = vault_path(f.dir.path(), ENV);

    bf(f.dir.path(), &f.id)
        .args(["member", "rm", "bob", "--yes"])
        .assert()
        .success();
    git(f.dir.path(), &["branch", "-M", "main"]);
    git_commit_all(f.dir.path(), "remove bob");

    // The branch puts the old vault back, touching nothing else - so only `vault.enc`
    // conflicts and the roster still verifies.
    git(f.dir.path(), &["checkout", "-q", "-b", "attacker"]);
    fs::write(&path, &pre_removal).unwrap();
    git_commit_all(f.dir.path(), "restore the old vault");

    git(f.dir.path(), &["checkout", "-q", "main"]);
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=rotated-after-bob-left", "--yes"])
        .assert()
        .success();
    git_commit_all(f.dir.path(), "rotate the value");
    assert!(
        !git_try(f.dir.path(), &["merge", "--no-edit", "attacker"]),
        "the vault edits should have conflicted"
    );

    bf(f.dir.path(), &f.id)
        .args(["resolve", "--theirs"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("written for roster v"));
}

#[test]
fn an_interrupted_removal_is_repaired_by_rotate_and_keeps_the_member_out() {
    // The crash window the write order chooses: `keys.json` is already v3 without bob, and
    // `vault.enc` is still the v2 he can decrypt. Every read refuses it rather than serving a
    // vault written for a roster that is not the current one, and `rotate` - which the refusal
    // names - re-encrypts to the roster on disk, completing the removal.
    let f = init_git_project();
    let bob = interrupted_removal(&f);

    for args in [
        vec!["run", "--", "printenv", "API_KEY"],
        vec!["get", "API_KEY"],
        vec!["list"],
        vec!["set", "NEW=1"],
    ] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("bitfort rotate"));
    }

    bf(f.dir.path(), &f.id).arg("rotate").assert().success();
    bf(f.dir.path(), &f.id).arg("list").assert().success();
    bf(f.dir.path(), &bob).arg("list").assert().failure();
}

#[test]
fn an_interrupted_removal_is_repaired_even_when_the_departing_member_wrote_the_vault() {
    // The sharp edge of publishing the roster before the vault: the stale file can be signed by
    // the very member the change removed. Authenticating it against the current roster would
    // call bob's authentic vault a forgery, and `rotate` - which has to read it to re-sign it -
    // would fail with the rest, leaving no repair at all. It is checked against the roster it
    // names instead, so the repair still runs and bob still loses access.
    let f = init_git_project();
    let bob = interrupted_removal_of_the_last_writer(&f);

    bf(f.dir.path(), &f.id)
        .args(["get", "API_KEY"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("bitfort rotate"))
        .stderr(predicate::str::contains("not in roster v").not());

    bf(f.dir.path(), &f.id)
        .arg("rotate")
        .assert()
        .success()
        .stderr(predicate::str::contains("written by 'bob'"));

    bf(f.dir.path(), &f.id)
        .args(["get", "API_KEY"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bob-wrote-this"));
    bf(f.dir.path(), &bob).arg("list").assert().failure();
}

#[test]
fn a_roster_older_than_the_vault_is_refused_by_every_command() {
    // `keys.json` rolled back to a version the vault has already moved past. No write path
    // produces this, so it is a rollback or a partial checkout, and the vault stamped for the
    // newer roster is the only local evidence of it - the git ceiling cannot see a downgrade
    // outside a repository or in a shallow clone. Reads refuse rather than serve values against
    // a roster that still lists a member the newer one removed, and every re-encryption refuses
    // too. `rotate` is no escape: it re-encrypts to the roster on disk.
    let f = init_git_project();
    let bob = rolled_back_roster(&f);

    let carol = Identity::generate().unwrap();
    for args in [
        vec!["run", "--", "printenv", "API_KEY"],
        vec!["get", "API_KEY"],
        vec!["list"],
        vec!["set", "NEW=1"],
        vec!["unset", "API_KEY", "--yes"],
        vec!["rotate"],
        vec!["member", "rm", "bob", "--yes"],
        vec!["member", "add", &invite_for(&carol, "carol")],
    ] {
        bf(f.dir.path(), &f.id)
            .args(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "keys.json is older than the vault",
            ));
    }

    // The gate CI runs must see it too, not only the commands.
    bf(f.dir.path(), &f.id).arg("verify").assert().failure();

    // Bob stays out throughout: nothing re-encrypted to the roster that still lists him.
    bf(f.dir.path(), &bob).arg("list").assert().failure();
}

#[test]
fn verify_fails_on_a_missing_vault_instead_of_blaming_the_identity() {
    let f = init_git_project();
    fs::remove_file(vault_path(f.dir.path(), ENV)).unwrap();

    bf(f.dir.path(), &f.id)
        .args(["verify", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("vault.enc"))
        .stdout(predicate::str::contains("not checked").not());
}

#[test]
fn a_normal_vault_still_reads_after_a_membership_change() {
    // The other half of the guarantee: adding a member re-signs the vault for the new
    // roster, so both the old and the new member read it with no warning.
    let f = init_git_project();
    bf(f.dir.path(), &f.id)
        .args(["set", "API_KEY=real"])
        .assert()
        .success();

    let bob = Identity::generate().unwrap();
    bf(f.dir.path(), &f.id)
        .args(["member", "add", &invite_for(&bob, "bob")])
        .assert()
        .success();

    for id in [&f.id, &bob] {
        bf(f.dir.path(), id)
            .args(["run", "--", "printenv", "API_KEY"])
            .assert()
            .success()
            .stdout(predicate::str::contains("real"))
            .stderr(predicate::str::contains("did not finish").not());
    }
}
