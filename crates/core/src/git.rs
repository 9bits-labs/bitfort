//! Git is BitFort's anti-rollback witness, and nothing else.
//!
//! The roster *chain* lives in `chain.json` (see [`crate::chain`]), so verification never
//! reads Git history. What Git still provides, and no file in the working tree can, is an
//! append-only record an attacker cannot rewrite quietly: the highest `roster_version` ever
//! committed for a roster file. A reverted `keys.json` is rejected against that ceiling
//! (docs/SPEC.md §4.3).
//!
//! Fail model, and the reason it is spelled out: a ceiling that silently reads low is not a
//! weaker check, it is no check. So the three states are distinguished by
//! [`repo_state`] and never collapsed:
//!
//! - [`RepoState::Outside`]: not a work tree, or no commits yet. The ceiling is unavailable
//!   and the caller reports that (`--strict` refuses).
//! - [`RepoState::Shallow`]: a work tree whose history is truncated, the `actions/checkout`
//!   default. `git log` sees only the tip, so the ceiling would equal whatever version the
//!   tip happens to carry - including a version an attacker just committed. Treated as
//!   unavailable, not as zero.
//! - [`RepoState::Full`]: the ceiling is enforced. From here every git or parse failure is
//!   an error, never a degraded value.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::error::{Error, Result};

/// Environment variables that redirect git's repository discovery or configuration. They are
/// cleared on every invocation so `-C <repo_dir>` is authoritative; otherwise an attacker who
/// can set one of them (a shell profile, an earlier CI step, a hostile `.envrc`) could point
/// the anti-rollback lookup at a decoy repo and hide a downgrade, or inject `core.hooksPath`
/// to run code from the commit-for-me path.
const REDIRECT_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    // Where git finds the helper programs it runs, and the hooks a fresh `git init` copies
    // into `.git/hooks`. Both end in code this process would execute.
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    // Stripping the count is what disables the whole numbered mechanism: git ignores
    // `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` without it. The two unnumbered names below
    // are belt and braces, in case that ever stops being true.
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY",
    "GIT_CONFIG_VALUE",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    // The one git reads as a whole `-c` list rather than as a single setting, so it reaches
    // `core.hooksPath` the same way the numbered `GIT_CONFIG_*` trio does.
    "GIT_CONFIG_PARAMETERS",
];

/// Whether Git can serve as the anti-rollback witness here. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoState {
    /// Not inside a git work tree, or the repository has no commits yet.
    Outside,
    /// A work tree with truncated history (`git clone --depth`). The ceiling is not
    /// trustworthy: `git log` sees only what the shallow boundary kept.
    Shallow,
    /// Full history. The ceiling is enforceable.
    Full,
}

/// Start a `git -C <repo_dir>` command with discovery-redirecting env vars stripped.
fn git_command(repo_dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo_dir);
    for var in REDIRECT_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// Run `git -C <repo_dir> <args>`. `None` only if the `git` binary could not be executed.
fn git(repo_dir: &Path, args: &[&str]) -> Option<Output> {
    git_command(repo_dir).args(args).output().ok()
}

/// Run a git query that must succeed, mapping both "git did not run" and "git failed" to an
/// error. Used everywhere the alternative would be to silently under-report.
fn git_checked(repo_dir: &Path, args: &[&str], what: &str) -> Result<Vec<u8>> {
    let out = git(repo_dir, args).ok_or_else(|| Error::Git(format!("{what}: git did not run")))?;
    if !out.status.success() {
        return Err(Error::Git(format!(
            "{what}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Classify `dir` for anti-rollback purposes. Never returns an error for "no repository":
/// that is a legitimate state the caller reports. It does error when git is present but
/// answering anomalously, because that must not read as "no history".
pub fn repo_state(dir: &Path) -> Result<RepoState> {
    // git missing, or not a work tree -> outside. This is the one place a non-zero exit is
    // an expected answer rather than a failure.
    let Some(inside) = git(dir, &["rev-parse", "--is-inside-work-tree"]) else {
        return Ok(RepoState::Outside);
    };
    if !inside.status.success() {
        return Ok(RepoState::Outside);
    }
    // A repo with no commits yet has no history to witness anything.
    let Some(head) = git(dir, &["rev-parse", "--verify", "--quiet", "HEAD"]) else {
        return Ok(RepoState::Outside);
    };
    if !head.status.success() {
        return Ok(RepoState::Outside);
    }
    // From here we are in a readable repo, so a failure is anomalous and is surfaced.
    let shallow = git_checked(
        dir,
        &["rev-parse", "--is-shallow-repository"],
        "shallow check",
    )?;
    if String::from_utf8_lossy(&shallow).trim() == "true" {
        return Ok(RepoState::Shallow);
    }
    Ok(RepoState::Full)
}

/// Feed `specs` to one `git cat-file --batch` and return each object's contents, with
/// `None` for a spec git reports as missing.
///
/// One process for the whole history, rather than a `cat-file -e` plus a `show` per
/// revision. At 31 roster revisions that was 62 process spawns on every `bitfort run`.
fn cat_file_batch(repo_dir: &Path, specs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    // The protocol is one spec per line, so a spec carrying a newline would be read as two -
    // and every answer after it would line up against the wrong request. That misreads a
    // present object as another one's content, or as absent, which is a silent wrong answer on
    // the anti-rollback ceiling and on the merge inputs alike. It needs a path component with a
    // newline in it, which is legal on unix.
    if let Some(bad) = specs.iter().find(|s| s.contains('\n')) {
        return Err(Error::Git(format!(
            "refusing to query git for a path containing a newline ({} bytes)",
            bad.len()
        )));
    }
    let mut child = git_command(repo_dir)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Git(format!("git cat-file failed to run: {e}")))?;

    // Write the specs from a thread: with a large history the child's stdout can fill its
    // pipe buffer before we finish writing, and a single-threaded write-then-read deadlocks.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Git("git cat-file gave no stdin".into()))?;
    let input = specs.join("\n") + "\n";
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));

    let out = child
        .wait_with_output()
        .map_err(|e| Error::Git(format!("git cat-file failed: {e}")))?;
    writer
        .join()
        .map_err(|_| Error::Git("git cat-file writer panicked".into()))?
        .map_err(|e| Error::Git(format!("git cat-file input failed: {e}")))?;
    if !out.status.success() {
        return Err(Error::Git(format!(
            "git cat-file failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_batch(&out.stdout, specs.len())
}

/// Parse `git cat-file --batch` output: per object either `<oid> <type> <size>\n<bytes>\n`
/// or `<spec> missing\n`.
fn parse_batch(stdout: &[u8], expected: usize) -> Result<Vec<Option<Vec<u8>>>> {
    let mut objects = Vec::with_capacity(expected);
    let mut pos = 0usize;
    while pos < stdout.len() && objects.len() < expected {
        let end = stdout[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| Error::Git("git cat-file output ended mid-header".into()))?
            + pos;
        let header = String::from_utf8_lossy(&stdout[pos..end]).into_owned();
        pos = end + 1;

        // `<spec> missing`, and also the ambiguous/dangling forms, all end in a word that
        // is not a size. Treat every non-object answer as absent.
        let Some(size) = header
            .rsplit(' ')
            .next()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            objects.push(None);
            continue;
        };
        let body_end = pos
            .checked_add(size)
            .filter(|e| *e <= stdout.len())
            .ok_or_else(|| Error::Git("git cat-file reported a size past its output".into()))?;
        objects.push(Some(stdout[pos..body_end].to_vec()));
        pos = body_end + 1; // skip the trailing newline git appends
    }
    Ok(objects)
}

/// The absolute path of the work-tree root containing `dir`, or `None` if `dir` is not
/// inside a Git work tree (or `git` is unavailable). Anti-rollback pathspecs are computed
/// relative to this root so `git log`/`git show` agree on the roster file (both must be
/// repo-root-relative), regardless of where `.bitfort/` sits under the repo.
pub fn repo_root(dir: &Path) -> Option<PathBuf> {
    let out = git(dir, &["rev-parse", "--show-toplevel"])?;
    if !out.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// The content of every committed revision of `rel_path` (relative to `repo_dir`), newest
/// first. The caller has already established [`RepoState::Full`], so every failure here is
/// anomalous and is surfaced rather than degraded to an empty history.
///
/// Two details are load-bearing:
///
/// - `--full-history`. Default history simplification drops the side of a merge whose copy of
///   the file was not kept, so an ordinary `git merge -s ours` could hide a committed roster
///   version entirely and let a downgrade pass.
/// - `./<rel_path>`. Git reads a leading `:` in a pathspec as magic. A repository whose path
///   starts with `:` would otherwise match nothing, exit 0, and report an empty history.
pub fn committed_blobs(repo_dir: &Path, rel_path: &str) -> Result<Vec<Vec<u8>>> {
    let pathspec = format!("./{rel_path}");
    let stdout = git_checked(
        repo_dir,
        &["log", "--full-history", "--format=%H", "--", &pathspec],
        "git log",
    )?;

    let specs: Vec<String> = String::from_utf8_lossy(&stdout)
        .lines()
        .map(|hash| format!("{hash}:{rel_path}"))
        .collect();

    // A revision where the path has no blob is normal history: `git log -- <path>` also lists
    // the commit that *deleted* the roster (a `git rm`, rename, or directory restructure).
    // Skip those rather than failing, or one historical deletion would wedge every write path.
    Ok(cat_file_batch(repo_dir, &specs)?
        .into_iter()
        .flatten()
        .collect())
}

/// The three unmerged index entries for `rel_path` - stage 1 the common ancestor, stage 2
/// ours, stage 3 theirs - each `None` when the index holds no such stage.
///
/// **This is the only place a merge's inputs may be read from.** The alternative is to parse
/// the conflict markers in the working-tree file, and those are ordinary file content:
/// whoever can write the file chooses what the merge sees, including the ancestor, which
/// decides per key which side wins (see [`crate::resolve::merge_vars`]). What the index
/// holds, git computed from the two commits, and a pushed branch cannot write it.
///
/// The four shapes an answer can take, and what each one means:
///
/// - **1, 2, 3** - an ordinary content conflict.
/// - **2 and 3 only** - an add/add conflict: the merge base commit does not hold this path,
///   so git has no ancestor version to offer. Note what this does *not* mean. It is not
///   "the file is new"; any branch taken before the file existed produces it, and that
///   branch's side can still carry content restored from history. The caller merges two-way
///   and must say so.
/// - **1 with one side** - one branch deleted the file outright.
/// - **nothing** - git has no conflict here. The path was `git add`ed, the merge was
///   committed, or the markers in the file came from somewhere other than a merge.
pub fn unmerged_stages(repo_dir: &Path, rel_path: &str) -> Result<[Option<Vec<u8>>; 3]> {
    // `<stage>:<path>` is index syntax, not a pathspec, so the `./` guard `committed_blobs`
    // needs does not apply - and would be read as part of the path here.
    let specs: Vec<String> = (1..=3).map(|s| format!(":{s}:{rel_path}")).collect();
    let mut stages = cat_file_batch(repo_dir, &specs)?.into_iter();
    let mut next = || stages.next().flatten();
    Ok([next(), next(), next()])
}

/// Initialize a git repository at `dir` (`git init`). Used by the `init` wizard when the
/// user opts to start version control so the roster chain has a history to live in. Reuses
/// the hardened [`git`] runner, so a stray `GIT_DIR` can't redirect the new repo elsewhere.
pub fn init_repo(dir: &Path) -> Result<()> {
    let out = git(dir, &["init"]).ok_or_else(|| Error::Git("git init failed to run".into()))?;
    if !out.status.success() {
        return Err(Error::Git(format!(
            "git init failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// A staging file left by a hard crash between a write and its rename. Excluded from every
/// commit this module makes: `.bitfort` is staged whole, so a leftover would otherwise be
/// committed as though it were part of the project (see `Project::commit_amendment`).
const EXCLUDE_STAGING: &str = ":(exclude)*.tmp*";

/// Stage `pathspecs` (repo-root-relative) and commit just those paths with `message`.
/// Any changes staged elsewhere in the index are left uncommitted, so committing on the
/// user's behalf (the "commit-for-me" wall, docs/SPEC.md §4.3, and the `init` wizard) never
/// sweeps in their unrelated staged work. Reuses the hardened [`git`] runner so
/// discovery-redirecting env vars can't retarget the commit at a decoy repo.
pub fn stage_and_commit(repo_dir: &Path, pathspecs: &[&str], message: &str) -> Result<()> {
    let mut add_args = vec!["add", "--"];
    add_args.extend_from_slice(pathspecs);
    add_args.push(EXCLUDE_STAGING);
    let add = git(repo_dir, &add_args).ok_or_else(|| Error::Git("git add failed to run".into()))?;
    if !add.status.success() {
        return Err(Error::Git(format!(
            "git add failed: {}",
            String::from_utf8_lossy(&add.stderr).trim()
        )));
    }
    // Pass the pathspecs so only these paths are committed, ignoring anything else staged.
    let mut commit_args = vec!["commit", "-m", message, "--"];
    commit_args.extend_from_slice(pathspecs);
    commit_args.push(EXCLUDE_STAGING);
    let commit =
        git(repo_dir, &commit_args).ok_or_else(|| Error::Git("git commit failed to run".into()))?;
    if !commit.status.success() {
        return Err(Error::Git(format!(
            "git commit failed: {}",
            String::from_utf8_lossy(&commit.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const ROSTER: &str = "keys.json";

    fn run_git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_at(dir: &Path) {
        run_git(dir, &["init", "-q", "-b", "main"]);
        run_git(dir, &["config", "user.email", "t@example.com"]);
        run_git(dir, &["config", "user.name", "test"]);
    }

    fn commit_version(dir: &Path, version: u64) {
        fs::write(
            dir.join(ROSTER),
            format!("{{\"roster_version\": {version}}}"),
        )
        .unwrap();
        run_git(dir, &["add", ROSTER]);
        run_git(dir, &["commit", "-q", "-m", &format!("v{version}")]);
    }

    /// The `roster_version` of each returned blob, in the order git reported them.
    fn versions(dir: &Path) -> Vec<u64> {
        committed_blobs(dir, ROSTER)
            .unwrap()
            .iter()
            .map(|b| {
                let v: serde_json::Value = serde_json::from_slice(b).unwrap();
                v["roster_version"].as_u64().unwrap()
            })
            .collect()
    }

    #[test]
    fn committed_blobs_returns_every_revision_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        init_at(dir.path());
        commit_version(dir.path(), 1);
        commit_version(dir.path(), 3);
        commit_version(dir.path(), 2);
        // Roll the working tree back to 1; history still holds all three.
        fs::write(dir.path().join(ROSTER), "{\"roster_version\": 1}").unwrap();

        assert_eq!(versions(dir.path()), vec![2, 3, 1]);
    }

    #[test]
    fn full_history_sees_a_version_hidden_by_a_merge() {
        // Regression: default history simplification drops the merge side whose copy of the
        // file was not kept. `git merge -s ours` therefore hid a committed roster version
        // from `git log -- <path>` entirely, so a downgrade to the lower version passed.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        commit_version(root, 1);
        run_git(root, &["checkout", "-q", "-b", "revoke"]);
        commit_version(root, 3);
        run_git(root, &["checkout", "-q", "main"]);
        commit_version(root, 2);
        run_git(
            root,
            &["merge", "-q", "-s", "ours", "revoke", "-m", "merge"],
        );

        let seen = versions(root);
        assert!(
            seen.contains(&3),
            "v3 was hidden by the merge; anti-rollback would accept a downgrade. saw {seen:?}"
        );
    }

    #[test]
    fn deletion_revision_is_skipped() {
        // A `git rm` (or rename) leaves a commit in `git log -- <path>` where the path has no
        // blob. That revision must be skipped, not treated as a hard error, or one historical
        // deletion would wedge every write path permanently.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        commit_version(root, 1);
        commit_version(root, 5);
        run_git(root, &["rm", "-q", ROSTER]);
        run_git(root, &["commit", "-q", "-m", "remove roster"]);
        commit_version(root, 2);

        let seen = versions(root);
        assert!(seen.contains(&5), "pre-deletion revision lost: {seen:?}");
        assert!(seen.contains(&2), "post-deletion revision lost: {seen:?}");
    }

    #[test]
    fn a_colon_prefixed_repo_path_still_reads_history() {
        // Regression: git reads a leading `:` in a pathspec as magic. Passing the roster path
        // bare made `git log` match nothing and exit 0, which read as "no history" and
        // silently disabled anti-rollback. The `./` prefix forces a literal path.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(":weird");
        fs::create_dir(&root).unwrap();
        init_at(&root);
        commit_version(&root, 7);

        assert_eq!(versions(&root), vec![7]);
    }

    #[test]
    fn repo_state_distinguishes_outside_full_and_shallow() {
        // Shallow is the `actions/checkout` default. `git log` there sees only the tip, so a
        // ceiling read from it equals whatever version the tip carries - including one an
        // attacker just committed. It must never be reported as enforceable.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(repo_state(dir.path()).unwrap(), RepoState::Outside);

        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        init_at(&src);
        assert_eq!(
            repo_state(&src).unwrap(),
            RepoState::Outside,
            "a repo with no commits witnesses nothing"
        );

        commit_version(&src, 1);
        commit_version(&src, 2);
        assert_eq!(repo_state(&src).unwrap(), RepoState::Full);

        let shallow = dir.path().join("shallow");
        run_git(
            dir.path(),
            &[
                "clone",
                "-q",
                "--depth",
                "1",
                &format!("file://{}", src.display()),
                shallow.to_str().unwrap(),
            ],
        );
        assert_eq!(repo_state(&shallow).unwrap(), RepoState::Shallow);
        // And the reason it must not be trusted: the predecessor is simply gone.
        assert_eq!(versions(&shallow), vec![2]);
    }

    #[test]
    fn stage_and_commit_commits_only_the_pathspec() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        fs::create_dir_all(root.join(".bitfort")).unwrap();
        fs::write(root.join(".bitfort/keys.json"), "v1").unwrap();
        fs::write(root.join("other.txt"), "a").unwrap();
        run_git(root, &["add", "-A"]);
        run_git(root, &["commit", "-q", "-m", "init"]);

        // A new untracked roster change plus an unrelated staged file, and the staging file a
        // hard crash between a write and its rename would leave behind.
        fs::write(root.join(".bitfort/keys.json"), "v2").unwrap();
        fs::write(root.join(".bitfort/vault.enc"), "ct").unwrap();
        fs::write(root.join(".bitfort/vault.enc.tmp999.0"), "half").unwrap();
        fs::write(root.join("other.txt"), "b").unwrap();
        run_git(root, &["add", "other.txt"]);

        stage_and_commit(root, &[".bitfort"], "roster: commit").unwrap();

        let show = git(
            root,
            &["show", "--stat", "--name-only", "--format=", "HEAD"],
        )
        .unwrap();
        let files = String::from_utf8_lossy(&show.stdout);
        assert!(
            files.contains(".bitfort/keys.json"),
            "roster missing: {files}"
        );
        assert!(
            files.contains(".bitfort/vault.enc"),
            "vault missing: {files}"
        );
        assert!(
            !files.contains("other.txt"),
            "unrelated file swept in: {files}"
        );
        assert!(
            !files.contains(".tmp999"),
            "a leftover staging file was committed: {files}"
        );

        // other.txt's staged change survives, still uncommitted.
        let status = git(root, &["status", "--short"]).unwrap();
        assert!(
            String::from_utf8_lossy(&status.stdout).contains("M  other.txt"),
            "expected other.txt to remain staged"
        );
    }

    #[test]
    fn init_repo_creates_a_work_tree() {
        let dir = tempfile::tempdir().unwrap();
        assert!(repo_root(dir.path()).is_none(), "not a repo before init");
        init_repo(dir.path()).unwrap();
        assert!(repo_root(dir.path()).is_some(), "a work tree after init");
    }

    #[test]
    fn stage_and_commit_takes_multiple_pathspecs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        fs::create_dir_all(root.join(".bitfort")).unwrap();
        fs::write(root.join(".bitfort/keys.json"), "v1").unwrap();
        fs::write(root.join(".gitignore"), ".env*\n").unwrap();
        fs::write(root.join("scratch.txt"), "x").unwrap(); // untracked, must stay out

        stage_and_commit(root, &[".bitfort", ".gitignore"], "init").unwrap();

        let show = git(root, &["show", "--name-only", "--format=", "HEAD"]).unwrap();
        let files = String::from_utf8_lossy(&show.stdout);
        assert!(
            files.contains(".bitfort/keys.json"),
            "roster missing: {files}"
        );
        assert!(files.contains(".gitignore"), "gitignore missing: {files}");
        assert!(
            !files.contains("scratch.txt"),
            "unrelated file swept in: {files}"
        );
    }

    #[test]
    fn untracked_file_in_a_populated_repo_has_no_history() {
        let dir = tempfile::tempdir().unwrap();
        init_at(dir.path());
        commit_version(dir.path(), 7); // commits keys.json...
        fs::write(dir.path().join("other.json"), "{\"roster_version\": 9}").unwrap();
        // ...but other.json is never committed, so its history is empty.
        assert!(committed_blobs(dir.path(), "other.json")
            .unwrap()
            .is_empty());
    }

    /// The three stages as text, for the assertions below.
    fn stages_at(root: &Path, rel: &str) -> Vec<Option<String>> {
        unmerged_stages(root, rel)
            .unwrap()
            .into_iter()
            .map(|s| s.map(|b| String::from_utf8(b).unwrap()))
            .collect()
    }

    /// Merge `branch`, asserting that it conflicts. `run_git` cannot serve: it asserts
    /// success, and a conflicting merge exits non-zero.
    fn merge_expecting_conflict(root: &Path, branch: &str) {
        let out = git(root, &["merge", "--no-edit", branch]).unwrap();
        assert!(!out.status.success(), "the merge should have conflicted");
    }

    #[test]
    fn unmerged_stages_reads_a_content_conflict() {
        // The ancestor git's default conflict style leaves out of the file. Without it a merge
        // cannot tell a deletion from an addition (finding 1.7), and the copy the file does
        // carry under `diff3` is attacker-chosen.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        commit_version(root, 1);
        assert_eq!(
            stages_at(root, ROSTER),
            vec![None, None, None],
            "no merge in progress, so no unmerged entry at all"
        );

        run_git(root, &["branch", "feature"]);
        commit_version(root, 2);
        run_git(root, &["checkout", "-q", "feature"]);
        commit_version(root, 3);
        run_git(root, &["checkout", "-q", "main"]);
        merge_expecting_conflict(root, "feature");

        assert_eq!(
            stages_at(root, ROSTER),
            vec![
                Some("{\"roster_version\": 1}".to_string()),
                Some("{\"roster_version\": 2}".to_string()),
                Some("{\"roster_version\": 3}".to_string()),
            ]
        );

        // `git add` on the conflicted path drops every stage, which is how a merge loses the
        // one source its inputs may come from.
        run_git(root, &["add", ROSTER]);
        assert_eq!(stages_at(root, ROSTER), vec![None, None, None]);
    }

    #[test]
    fn an_add_add_conflict_has_two_stages_and_no_ancestor() {
        // Both branches created the file, so no ancestor ever existed. That is a real state
        // and not a lost one: a two-way merge is the correct merge there.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        fs::write(root.join("seed"), "x").unwrap();
        run_git(root, &["add", "seed"]);
        run_git(root, &["commit", "-q", "-m", "seed"]);
        run_git(root, &["branch", "feature"]);
        commit_version(root, 2);
        run_git(root, &["checkout", "-q", "feature"]);
        commit_version(root, 3);
        run_git(root, &["checkout", "-q", "main"]);
        merge_expecting_conflict(root, "feature");

        assert_eq!(
            stages_at(root, ROSTER),
            vec![
                None,
                Some("{\"roster_version\": 2}".to_string()),
                Some("{\"roster_version\": 3}".to_string()),
            ]
        );
    }

    #[test]
    fn a_delete_conflict_is_missing_the_side_that_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_at(root);
        commit_version(root, 1);
        run_git(root, &["branch", "feature"]);
        commit_version(root, 2);
        run_git(root, &["checkout", "-q", "feature"]);
        run_git(root, &["rm", "-q", ROSTER]);
        run_git(root, &["commit", "-q", "-m", "remove roster"]);
        run_git(root, &["checkout", "-q", "main"]);
        merge_expecting_conflict(root, "feature");

        let stages = stages_at(root, ROSTER);
        assert!(stages[0].is_some(), "the ancestor is still there");
        assert!(stages[1].is_some(), "our side kept the file");
        assert_eq!(stages[2], None, "their side deleted it");
    }

    #[test]
    fn parse_batch_reads_contents_and_marks_missing_objects() {
        // The wire format `git cat-file --batch` speaks: a header line, then exactly `size`
        // bytes, then a newline; or `<spec> missing` with no body.
        let stdout = b"abc123 blob 5\nhello\ndeadbeef:x missing\ndef456 blob 2\nhi\n";
        let got = parse_batch(stdout, 3).unwrap();
        assert_eq!(
            got,
            vec![Some(b"hello".to_vec()), None, Some(b"hi".to_vec())]
        );
    }

    #[test]
    fn parse_batch_rejects_a_size_past_the_output() {
        let stdout = b"abc123 blob 999\nshort\n";
        assert!(parse_batch(stdout, 1).is_err());
    }
}
