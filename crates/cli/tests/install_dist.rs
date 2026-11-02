//! Checks `scripts/install-dist.sh`, which installs dist for `.github/workflows/release.yml`.
//!
//! The release workflow runs the script on every pull request, but only with the
//! `dist-workspace.toml` of the repository, so the failure paths below run nowhere else.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn install_dist_stops_when_the_version_line_does_not_parse() {
    // The script reads `cargo-dist-version = "<version>"` from the dist-workspace.toml above its
    // scripts/ folder. Another spelling of that line leaves the version empty; the script must
    // name the line and stop before it downloads anything.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("scripts/install-dist.sh");
    fs::create_dir(dir.path().join("scripts")).unwrap();
    fs::copy(repo.join("scripts/install-dist.sh"), &script).unwrap();
    fs::write(
        dir.path().join("dist-workspace.toml"),
        "[dist]\ncargo-dist-version  = \"0.33.1\"\n",
    )
    .unwrap();

    Command::new("bash")
        .arg(&script)
        .arg(dir.path().join("bin"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "install-dist: found no cargo-dist-version line",
        ));
    assert!(!dir.path().join("bin").exists());
}
