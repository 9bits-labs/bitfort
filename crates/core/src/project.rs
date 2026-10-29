//! The on-disk `.bitfort/` project: discovery, layout, and the load/save/verify
//! orchestration shared by every front end (docs/SPEC.md §4). This is where the
//! "verify the signed roster before re-encrypting" invariant lives, so no front end
//! can re-derive it differently.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::chain::Chain;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::git;
use crate::identity::Identity;
use crate::roster::Roster;
use crate::vault::Vault;

/// Whether Git could serve as the anti-rollback witness for a verification, and with what
/// ceiling. Verification itself never degrades - the chain is read from the working tree -
/// but this one check needs an append-only record, so its availability is reported rather
/// than silently folded into a zero (docs/SPEC.md §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackGuard {
    /// Enforced against `highest`, the greatest `roster_version` ever committed here.
    Enforced { highest: u64 },
    /// Not inside a git work tree, or the repository has no commits yet.
    NoRepository,
    /// Inside a full repository, but no committed revision of this `keys.json` counts toward
    /// a ceiling - it has never been committed, or every revision of it in history failed the
    /// parse, project/env, or maintainer-signature filters.
    ///
    /// Distinct from `Enforced { highest: 0 }`, which this used to report. Zero is not a
    /// ceiling: every roster starts at v1, so `>= 0` accepts anything and the check is off.
    /// Invariant 3 requires a witness that cannot run to be reported, never folded into a zero.
    Uncommitted,
    /// A shallow clone (`actions/checkout` defaults to `fetch-depth: 1`). History is
    /// truncated, so a ceiling read from it would equal whatever the tip carries.
    ShallowRepository,
}

impl RollbackGuard {
    /// Whether a downgrade would actually be caught here.
    pub fn is_enforced(&self) -> bool {
        matches!(self, Self::Enforced { .. })
    }

    /// The version to reject below. Zero when no witness is available, which disables the
    /// comparison rather than pretending nothing was ever committed.
    fn ceiling(&self) -> u64 {
        match self {
            Self::Enforced { highest } => *highest,
            Self::NoRepository | Self::ShallowRepository | Self::Uncommitted => 0,
        }
    }

    /// Why rollback protection is unavailable and what fixes it, for the caller to surface.
    /// `None` when it is enforced.
    ///
    /// One method for both strings, because `status` prints them together - the first as the
    /// `rollback` line, the second as the next step - and two methods meant every new variant
    /// had to be answered twice, in two crates.
    pub fn unavailable(&self) -> Option<Unavailable> {
        let (why, fix) = match self {
            Self::Enforced { .. } => return None,
            Self::NoRepository => (
                "no committed history - rollback protection is not enforced here; \
                 commit .bitfort into a git repository",
                "not a git repository - `git init` and commit .bitfort so rollback protection \
                 is enforced",
            ),
            Self::ShallowRepository => (
                "shallow clone - rollback protection is not enforced here; \
                 fetch full history (actions/checkout: fetch-depth: 0)",
                "shallow clone - fetch full history (actions/checkout: fetch-depth: 0) so \
                 rollback protection is enforced",
            ),
            Self::Uncommitted => (
                "this roster has never been committed - rollback protection is not enforced \
                 here; commit .bitfort so history can witness its version",
                "this roster has never been committed - commit .bitfort so history can witness \
                 its version and rollback protection is enforced",
            ),
        };
        Some(Unavailable { why, fix })
    }

    /// Why rollback protection is unavailable, for a caller that only warns.
    pub fn warning(&self) -> Option<&'static str> {
        self.unavailable().map(|u| u.why)
    }
}

/// Why the anti-rollback witness could not run here, and the step that would fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable {
    /// One line of posture, for a status readout or a warning.
    pub why: &'static str,
    /// The action that turns the witness back on.
    pub fix: &'static str,
}

/// A verified roster, the verified chain behind it, and the state of the anti-rollback
/// witness that checked them.
///
/// The chain travels with the roster because a vault read needs both: the payload is
/// authenticated against the roster it names, which is a chain link whenever the vault
/// predates the current `keys.json` (see [`Vault::decrypt`]). Carrying it here rather than
/// re-reading `chain.json` at the point of use is what keeps the file from being read a
/// second, unverified time.
#[derive(Debug, Clone)]
pub struct Verified {
    pub roster: Roster,
    pub chain: Chain,
    pub guard: RollbackGuard,
}

/// The `.bitfort` directory name, found by walking up from the working directory.
pub const DIR_NAME: &str = ".bitfort";
const ENVIRONMENTS: &str = "environments";
const CONFIG_FILE: &str = "config.toml";
const ROSTER_FILE: &str = "keys.json";
const CHAIN_FILE: &str = "chain.json";
const VAULT_FILE: &str = "vault.enc";

/// A file written to a staging path and fsynced, waiting for the `rename` that publishes it.
///
/// Splitting the write from the rename is what lets several files land together. Everything
/// slow and fallible - encryption, serialization, the write, the fsync - happens while every
/// target still holds its old bytes, so the window a crash can land in shrinks to consecutive
/// `rename` calls (see [`Project::commit_amendment`]). Dropped without [`Staged::publish`],
/// it removes its staging file, so a failure part-way through leaves no debris and no target
/// half-updated.
struct Staged {
    tmp: PathBuf,
    target: PathBuf,
}

impl Staged {
    /// Write `contents` to `target`'s staging path and fsync them, at the process umask's
    /// permissions.
    fn write(target: &Path, contents: &[u8], seq: u64) -> Result<Self> {
        let tmp = staging_path(target, seq);
        // `create_new`, not `create`: the staging name is predictable, and `create` follows a
        // symlink, so anyone able to write into `.bitfort/` could pre-plant a link and have a
        // vault or roster write land outside the project.
        let mut options = std::fs::File::options();
        options.write(true).create_new(true);
        let mut f = options.open(&tmp)?;
        // Constructed only once the file exists, so a `Staged` never owns - and never deletes -
        // a path this process did not create.
        let staged = Self {
            tmp,
            target: target.to_path_buf(),
        };
        f.write_all(contents)?;
        f.sync_all()?;
        Ok(staged)
    }

    /// Rename the staged file over its target. A reader sees either the old bytes or the
    /// complete new ones, never a truncated file.
    fn publish(self) -> Result<()> {
        std::fs::rename(&self.tmp, &self.target)?;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // A no-op after `publish` moved the file away; the point is the error paths.
        let _ = std::fs::remove_file(&self.tmp);
    }
}

/// The next staging sequence number. The temp name carries the pid plus this process-wide
/// counter, so two concurrent writers - across processes (distinct pids) or within one
/// (distinct counter values) - never clobber each other's staging file.
fn next_seq() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Persist a rename: fsync `dir` so the new link survives power loss, not just a process
/// crash. Best-effort - a platform that can't open a directory as a file (Windows) skips it.
fn sync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
}

/// Write `contents` to `path` atomically: stage them, then `rename` over the target.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    write_atomic_seq(path, contents, next_seq())
}

/// The staging file [`write_atomic`] writes through for `path` at `seq`.
fn staging_path(path: &Path, seq: u64) -> PathBuf {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}.{seq}", std::process::id()));
    PathBuf::from(tmp)
}

/// [`write_atomic`] with the sequence number supplied, so a test can pin the staging name.
fn write_atomic_seq(path: &Path, contents: &[u8], seq: u64) -> Result<()> {
    Staged::write(path, contents, seq)?.publish()?;
    if let Some(dir) = path.parent() {
        sync_dir(dir);
    }
    Ok(())
}

/// Serialize as pretty JSON with a trailing newline - the on-disk form of every JSON file
/// this crate writes, so `keys.json` and `chain.json` cannot drift apart in layout.
fn pretty_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let mut json = serde_json::to_string_pretty(value).map_err(Error::serde)?;
    json.push('\n');
    Ok(json)
}

/// Sign `vault` as `identity`, encrypt it to every recipient in `roster`, and return the
/// armored document - refusing first a variable that decides how a process runs
/// ([`vault::is_process_control_key`]).
///
/// Every command that writes a vault comes through here - `set`, `unset`, `import`,
/// `resolve`, `rotate` and the membership commands - so the rule holds once instead of at
/// each of them, and none can be forgotten. It sits on the write side rather than in
/// [`Vault::decrypt`] on purpose: a vault that already holds such a name must stay readable,
/// or `list` and `status` cannot show the user what to remove. `run` and `export` apply the
/// same rule at the other boundary, where vault contents become a process environment
/// (docs/SPEC.md §7).
///
/// [`vault::is_process_control_key`]: crate::vault::is_process_control_key
fn vault_bytes(vault: &Vault, roster: &Roster, identity: &Identity) -> Result<String> {
    // Only a name this write would *introduce*. A vault that already held one has to be
    // writable, or `unset` cannot remove it - and with two present, each removal was refused
    // because of the other, wedging the vault for good.
    if let Some(key) = vault.introduced_process_control_key() {
        return Err(Error::VaultContent(format!(
            "`{key}` controls how a process runs, not what it reads, so it cannot be \
             written to a vault. Set it in the environment you launch bitfort from."
        )));
    }
    vault.encrypt(roster, identity)
}

/// Decrypt and authenticate one index stage. `what` names it in an error ("our side of").
fn decrypt_stage(
    blob: Vec<u8>,
    what: &str,
    identity: &Identity,
    verified: &Verified,
    env: &str,
    rel: &str,
) -> Result<Box<Vault>> {
    let armored = String::from_utf8(blob)
        .map_err(|_| Error::Project(format!("the {what} {rel} is not text")))?;
    Vault::decrypt(&armored, identity, &verified.roster, &verified.chain, env)
        .map(Box::new)
        .map_err(|e| Error::Project(format!("the {what} {rel}: {e}")))
}

/// Authenticate index stage 1 for [`Project::load_vault_conflict`].
fn merge_base(
    blob: Option<Vec<u8>>,
    identity: &Identity,
    verified: &Verified,
    env: &str,
    rel: &str,
) -> Result<MergeBase> {
    let Some(blob) = blob else {
        return Ok(MergeBase::Absent);
    };
    let armored = String::from_utf8(blob)
        .map_err(|_| Error::Project(format!("the common ancestor of {rel} is not text")))?;

    match Vault::decrypt(&armored, identity, &verified.roster, &verified.chain, env) {
        Ok(vault) => Ok(MergeBase::Found(Box::new(vault))),
        // Two readable-but-unusable ancestors, and both say something about the past rather
        // than about this merge. `NotARecipient`: written before this identity had a seat
        // here. `VaultContent`: an authentic writer put a name in it that today's rules
        // reject, which an old enough vault can carry. Neither is evidence of tampering, so
        // neither may stop the merge - the caller degrades instead.
        Err(e @ (Error::NotARecipient | Error::VaultContent(_))) => {
            Ok(MergeBase::Unusable(e.to_string()))
        }
        // Everything else - a bad signature, a signer outside the roster, another project or
        // environment - is tampering with the file the merge is arbitrated against, and is
        // refused exactly as it is on any other read path.
        Err(e) => Err(e),
    }
}

/// Relativize `target` against the git work-tree `root` (already canonicalized by the
/// caller), returning the `/`-joined repo-root-relative pathspec that `git log`/`show`/
/// `commit` all expect. `target` is canonicalized here so a symlinked path or, on Windows,
/// the `\\?\` verbatim prefix `canonicalize` adds can't defeat `strip_prefix`. Callers are
/// confirmed inside a repo, so a `target` outside `root` is anomalous and fails closed with
/// an error rather than silently disabling the git-backed check.
///
/// A component that is not UTF-8 fails the same way. Dropping it would build a pathspec for a
/// different file, and `git log` over a path nothing was ever committed at returns no
/// revisions: for the anti-rollback ceiling that reads as version zero, which is the silent
/// zero invariant 3 forbids.
fn relativize_under_root(root: &Path, target: &Path) -> Result<String> {
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    let rel = target.strip_prefix(root).map_err(|_| {
        Error::Git(format!(
            "{} is not under the git root {}",
            target.display(),
            root.display()
        ))
    })?;
    let parts = rel
        .components()
        .map(|c| {
            c.as_os_str().to_str().map(str::to_owned).ok_or_else(|| {
                Error::Git(format!(
                    "{} has a path component that is not UTF-8, so it cannot be used as a git \
                     pathspec",
                    target.display()
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}

/// What [`Project::load_vault_conflict`] found in git's index for a conflicted vault.
///
/// Every variant is a state git itself reports, so the front end never has to guess one from
/// the contents of the working-tree file (docs/SPEC.md §4.5).
#[derive(Debug)]
pub enum VaultConflict {
    /// The project is not inside a git work tree, so there is no index to read a merge from.
    NoRepository,
    /// Git holds no unmerged entry for the vault, so there is no merge to resolve. The path
    /// was `git add`ed, the merge was committed, or the markers in the file never came from a
    /// merge at all.
    None,
    /// Two versions to merge, each authenticated. Boxed because a `Vault` dwarfs the rest.
    Sides {
        /// Stage 1, or [`MergeBase::Absent`] for an add/add conflict.
        base: MergeBase,
        ours: Box<Vault>,
        theirs: Box<Vault>,
    },
    /// Git has an unmerged entry, but not two versions to merge - one or both branches
    /// deleted `vault.enc`, or only one branch ever had it. The three flags say exactly what
    /// the index holds, because the resolution differs per shape and only the user can pick
    /// it: whether the environment still exists is not a question the merge can answer.
    ///
    /// The five reachable shapes, as `(ancestor, ours, theirs)`:
    /// `(true, true, false)` and `(true, false, true)` - one branch deleted it;
    /// `(true, false, false)` - both did, which a rename on both branches also produces;
    /// `(false, true, false)` and `(false, false, true)` - one branch added it and the other
    /// never had it.
    Incomplete {
        ancestor: bool,
        ours: bool,
        theirs: bool,
    },
}

/// The common ancestor of a conflicted vault, or why there is none to merge against.
///
/// Three states rather than an `Option`, because "no ancestor exists" and "an ancestor exists
/// that this identity cannot use" call for different words from the front end, and because a
/// merge without one is a two-way merge (see [`crate::resolve::merge_vars`]).
#[derive(Debug)]
pub enum MergeBase {
    /// An add/add conflict: the merge base commit does not hold the vault, so git has no
    /// ancestor version. A degraded merge, not a safe one - see [`VaultConflict`] and
    /// [`git::unmerged_stages`] for why that shape does not mean the file is new.
    Absent,
    /// Read, but not usable by this identity, carrying the reason for the caller's message.
    Unusable(String),
    Found(Box<Vault>),
}

/// A located BitFort project. `root` is the directory that *contains* `.bitfort/`
/// (typically the repo root), so `run` finds the vault from any subdirectory.
#[derive(Debug, Clone)]
pub struct Project {
    root: PathBuf,
}

impl Project {
    /// Walk up from `start` until a directory containing `.bitfort/` is found.
    pub fn discover(start: &Path) -> Result<Self> {
        let start = start
            .canonicalize()
            .map_err(|e| Error::Project(format!("cannot resolve {}: {e}", start.display())))?;
        for dir in start.ancestors() {
            if dir.join(DIR_NAME).is_dir() {
                return Ok(Self {
                    root: dir.to_path_buf(),
                });
            }
        }
        Err(Error::Project(format!(
            "no {DIR_NAME}/ found in {} or any parent directory",
            start.display()
        )))
    }

    /// Create the `.bitfort/` skeleton for a brand-new project and return the handle.
    /// Refuses to clobber an existing project.
    pub fn init(root: impl Into<PathBuf>, config: &Config) -> Result<Self> {
        let root = root.into();
        let bitfort = root.join(DIR_NAME);
        if bitfort.exists() {
            return Err(Error::Project(format!(
                "{} already exists; refusing to re-initialize",
                bitfort.display()
            )));
        }
        // Canonicalize like `discover` does, so a handle from `init()` relativizes paths
        // against git's canonical toplevel identically (keeps anti-rollback consistent if
        // a caller reuses the init-time handle instead of re-discovering).
        let root = root.canonicalize().unwrap_or(root);
        let project = Self { root };
        // First, because it is the step that can fail on a file the user already had: it
        // refuses a `.gitignore` it cannot read as UTF-8, which one Latin-1 comment is enough
        // to cause. It is also idempotent, so a later failure leaves nothing to undo.
        project.ensure_dotenv_gitignored()?;

        // Everything after this creates `.bitfort/`, and a half-made one is worse than none:
        // the guard above then refuses every retry with "already exists", and nothing tells
        // the user to delete it. So it is removed on any failure here.
        let build = || -> Result<()> {
            std::fs::create_dir_all(project.root.join(DIR_NAME).join(ENVIRONMENTS))?;
            project.save_config(config)
        };
        if let Err(e) = build() {
            let _ = std::fs::remove_dir_all(project.root.join(DIR_NAME));
            return Err(e);
        }
        Ok(project)
    }

    /// Ensure the repo-root `.gitignore` ignores `.env*`, so a plaintext dotenv file cannot
    /// be committed (docs/SPEC.md §6). A protective invariant of project creation, so it
    /// travels with `init` for every front end rather than living in one binary. Idempotent.
    fn ensure_dotenv_gitignored(&self) -> Result<()> {
        let path = self.root.join(".gitignore");
        // Only a genuinely absent file may start from empty. Any other read failure - a
        // `.gitignore` that is not valid UTF-8, or one this process cannot read - used to
        // become "" through `unwrap_or_default`, and the rewrite below then replaced the
        // user's whole ignore list with a single `.env*` line.
        let existing = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(Error::Project(format!(
                    "cannot read {}: {e}. Refusing to rewrite it; add `.env*` by hand.",
                    path.display()
                )))
            }
        };
        if Self::ignores_dotenv(&existing) {
            return Ok(());
        }
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(".env*\n");
        // Atomic write: a crash mid-write must not truncate `.gitignore` and drop the
        // `.env*` rule, which would silently let a plaintext dotenv become committable
        // (invariant 1 / docs/SPEC.md §6).
        write_atomic(&path, content.as_bytes())
    }

    /// Whether the repo-root `.gitignore` already ignores `.env*` - the read-only
    /// counterpart to [`Self::ensure_dotenv_gitignored`], used by `status` reporting
    /// (invariant 1: a plaintext dotenv must stay uncommittable).
    pub fn is_dotenv_gitignored(&self) -> bool {
        std::fs::read_to_string(self.root.join(".gitignore"))
            .map(|c| Self::ignores_dotenv(&c))
            .unwrap_or(false)
    }

    fn ignores_dotenv(gitignore: &str) -> bool {
        gitignore.lines().any(|l| l.trim() == ".env*")
    }

    /// The directory containing `.bitfort/`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn bitfort_dir(&self) -> PathBuf {
        self.root.join(DIR_NAME)
    }

    fn config_path(&self) -> PathBuf {
        self.bitfort_dir().join(CONFIG_FILE)
    }

    /// The directory holding one environment's roster and vault.
    pub fn env_dir(&self, env: &str) -> PathBuf {
        self.bitfort_dir().join(ENVIRONMENTS).join(env)
    }

    /// Path to an environment's signed roster (`keys.json`).
    pub fn roster_path(&self, env: &str) -> PathBuf {
        self.env_dir(env).join(ROSTER_FILE)
    }

    /// Path to an environment's roster chain (`chain.json`) - every predecessor of the
    /// current `keys.json` (docs/SPEC.md §4.3).
    pub fn chain_path(&self, env: &str) -> PathBuf {
        self.env_dir(env).join(CHAIN_FILE)
    }

    /// Path to an environment's encrypted vault (`vault.enc`).
    pub fn vault_path(&self, env: &str) -> PathBuf {
        self.env_dir(env).join(VAULT_FILE)
    }

    /// Load an environment's roster chain. An absent file is an empty chain, which is the
    /// correct state for an environment still at roster v1; [`Chain::verify`] rejects an
    /// empty chain for any higher version, so this cannot be used to skip the walk.
    pub fn load_chain(&self, env: &str) -> Result<Chain> {
        match std::fs::read(self.chain_path(env)) {
            Ok(bytes) => Chain::from_json(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Chain::new()),
            Err(e) => Err(Error::Project(format!(
                "cannot read {}: {e}",
                self.chain_path(env).display()
            ))),
        }
    }

    /// Write an environment's roster chain as pretty JSON (stable, diff-friendly).
    pub fn save_chain(&self, env: &str, chain: &Chain) -> Result<()> {
        std::fs::create_dir_all(self.env_dir(env))?;
        write_atomic(&self.chain_path(env), pretty_json(chain)?.as_bytes())
    }

    /// The chain with `superseded` recorded as a predecessor, or `None` when it is already
    /// the tail - which is what re-running an interrupted amendment finds.
    fn amended_chain(&self, env: &str, superseded: &Roster) -> Result<Option<Chain>> {
        let mut chain = self.load_chain(env)?;
        let tail = chain.rosters.last().map(|r| r.digest()).transpose()?;
        if tail == Some(superseded.digest()?) {
            return Ok(None);
        }
        chain.append(superseded.clone())?;
        Ok(Some(chain))
    }

    /// Persist a roster amendment together with the vault re-encrypted to it: `chain.json`,
    /// `keys.json` and `vault.enc` in one staged write. `vault` must have been decrypted
    /// against `superseded` and `identity` must be a member of `next`, which signs it.
    ///
    /// All three files are written to staging paths and fsynced before any of them is
    /// published, so everything that can fail - the encryption, the serialization, a full
    /// disk, a pre-planted staging symlink - fails with every target still untouched. What is
    /// left between them is three `rename` calls.
    ///
    /// They are published chain, roster, vault, and that order decides what a crash inside
    /// that window leaves behind. It is the same answer for an addition and for a removal:
    ///
    /// - After the chain: a redundant tail holding the roster still in `keys.json`, which
    ///   [`Chain::verify`] ignores.
    /// - After the roster: `keys.json` at the new version with a vault still written for the
    ///   old one - [`Drift::Behind`](crate::vault::Drift::Behind). Every read refuses it and
    ///   names `bitfort rotate`, which re-encrypts and re-signs the vault against the roster
    ///   on disk and so completes the change, in either direction.
    ///
    /// Vault-first would leave the opposite state, which is worse both ways: on an addition
    /// the vault is readable by a key no signed roster lists, a silent grant; on a removal
    /// reads continue against a `keys.json` that still lists the member being removed, and the
    /// repair - re-running the membership change - cannot be checked to be the *same* one, so
    /// removing anybody else silently undoes it.
    pub fn commit_amendment(
        &self,
        env: &str,
        superseded: &Roster,
        next: &Roster,
        vault: &Vault,
        identity: &Identity,
    ) -> Result<()> {
        std::fs::create_dir_all(self.env_dir(env))?;
        let armored = vault_bytes(vault, next, identity)?;

        let mut staged = Vec::with_capacity(3);
        if let Some(chain) = self.amended_chain(env, superseded)? {
            staged.push(Staged::write(
                &self.chain_path(env),
                pretty_json(&chain)?.as_bytes(),
                next_seq(),
            )?);
        }
        staged.push(Staged::write(
            &self.roster_path(env),
            pretty_json(next)?.as_bytes(),
            next_seq(),
        )?);
        staged.push(Staged::write(
            &self.vault_path(env),
            armored.as_bytes(),
            next_seq(),
        )?);

        // The directory is fsynced whatever the loop does: a rename that already landed has to
        // be durable even if a later one fails, or a partial publish could move back toward the
        // old files on power loss.
        let published = staged.into_iter().try_for_each(Staged::publish);
        sync_dir(&self.env_dir(env));
        published
    }

    /// Whether this environment already has files on disk, whatever `config.toml` says.
    /// `env add` and `init` consult this: the config list alone is not the truth, and a
    /// merge that drops an entry would otherwise let a fresh v1 roster overwrite a live
    /// environment and wedge it against its own committed history.
    pub fn environment_exists(&self, env: &str) -> bool {
        self.roster_path(env).exists()
            || self.vault_path(env).exists()
            || self.chain_path(env).exists()
    }

    /// Load and parse `config.toml`.
    pub fn load_config(&self) -> Result<Config> {
        let text = std::fs::read_to_string(self.config_path())?;
        Config::from_toml(&text)
    }

    /// Write `config.toml` atomically, so a crash mid-write can't leave a truncated config
    /// that would make the project unopenable.
    pub fn save_config(&self, config: &Config) -> Result<()> {
        write_atomic(&self.config_path(), config.to_toml()?.as_bytes())
    }

    /// Resolve the target environment: an explicit `--env`, else the config default.
    /// Rejects an environment not declared in `config.toml`.
    pub fn resolve_env(&self, requested: Option<&str>, config: &Config) -> Result<String> {
        let env = requested.unwrap_or(&config.default_env);
        if !config.has_env(env) {
            return Err(Error::Project(format!(
                "unknown environment '{env}'; known: {}",
                config.environments.join(", ")
            )));
        }
        Ok(env.to_string())
    }

    /// Load and parse an environment's roster.
    pub fn load_roster(&self, env: &str) -> Result<Roster> {
        let bytes = std::fs::read(self.roster_path(env))?;
        Roster::from_json(&bytes)
    }

    /// Write an environment's roster as pretty JSON (stable, diff-friendly).
    pub fn save_roster(&self, env: &str, roster: &Roster) -> Result<()> {
        std::fs::create_dir_all(self.env_dir(env))?;
        write_atomic(&self.roster_path(env), pretty_json(roster)?.as_bytes())
    }

    /// Decrypt an environment's vault with `identity` and authenticate it against
    /// `verified`, the result of [`Self::verify_roster`].
    ///
    /// The verification result is not optional on any path, reads included: the vault carries
    /// a signature over its own payload, and checking it needs the set of keys allowed to have
    /// written one - the current roster, or the chain link the payload names. See
    /// [`Vault::decrypt`] for what that check refuses.
    pub fn load_vault(&self, env: &str, identity: &Identity, verified: &Verified) -> Result<Vault> {
        let path = self.vault_path(env);
        // Name the file: a bare `No such file or directory` from `set`/`rotate`/`import`
        // gives the user nothing to act on.
        let armored = std::fs::read_to_string(&path)
            .map_err(|e| Error::Project(format!("cannot read {}: {e}", path.display())))?;
        Vault::decrypt(&armored, identity, &verified.roster, &verified.chain, env)
    }

    /// The three inputs of an in-progress merge of this environment's vault, read from git's
    /// index and authenticated, for the three-way merge `resolve` performs (docs/SPEC.md
    /// §4.5).
    ///
    /// **The index is the only source, for all three.** The alternative is to parse the
    /// conflict markers in `vault.enc`, and those are ordinary file content: whoever can write
    /// that file would choose what the merge sees. That matters most for the ancestor, which
    /// decides per key which side wins, but it is the same objection for the two sides. What
    /// the index holds, git computed from the two commits. See [`git::unmerged_stages`] for
    /// the shapes it can report.
    ///
    /// It decrypts and authenticates here rather than handing the caller ciphertext, for the
    /// reason [`Self::load_vault`] does: invariant 7 is that every vault read verifies its
    /// payload signature against the verified roster, and an API that returns armored text
    /// makes an unverified vault representable for the next front end that calls it.
    ///
    /// The drift policy stays with the caller, because it differs per input: a side is about
    /// to be re-encrypted, while an ancestor is *expected* to predate a membership change and
    /// contributes no value to the merged result.
    pub fn load_vault_conflict(
        &self,
        env: &str,
        identity: &Identity,
        verified: &Verified,
    ) -> Result<VaultConflict> {
        let Some(root) = self.git_root() else {
            return Ok(VaultConflict::NoRepository);
        };
        let rel = relativize_under_root(&root, &self.vault_path(env))?;
        let [base, ours, theirs] = git::unmerged_stages(&root, &rel)?;

        // Two versions is the only shape that can be merged. Everything else is reported as
        // what git holds and left to the user: an unmerged entry with one side or none means a
        // branch deleted the vault or only one branch ever had it, and whether the environment
        // still exists is not a question a merge can answer. `(false, false, false)` is not an
        // unmerged entry at all.
        let held = (base.is_some(), ours.is_some(), theirs.is_some());
        let (Some(ours), Some(theirs)) = (ours, theirs) else {
            let (ancestor, ours, theirs) = held;
            return Ok(if ancestor || ours || theirs {
                VaultConflict::Incomplete {
                    ancestor,
                    ours,
                    theirs,
                }
            } else {
                VaultConflict::None
            });
        };

        Ok(VaultConflict::Sides {
            base: merge_base(base, identity, verified, env, &rel)?,
            ours: decrypt_stage(ours, "our side of", identity, verified, env, &rel)?,
            theirs: decrypt_stage(theirs, "their side of", identity, verified, env, &rel)?,
        })
    }

    /// Whether the environment's `vault.enc` carries git conflict markers.
    ///
    /// Read together with [`Self::load_vault_conflict`], this separates "nothing to do" from
    /// "the merge this file came from is gone". It answers `false` for a missing file, since
    /// a vault that is not there carries nothing.
    pub fn vault_has_conflict_markers(&self, env: &str) -> Result<bool> {
        match std::fs::read_to_string(self.vault_path(env)) {
            Ok(text) => Ok(crate::resolve::has_conflict_markers(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Project(format!(
                "cannot read {}: {e}",
                self.vault_path(env).display()
            ))),
        }
    }

    /// Sign `vault` as `identity`, encrypt it to every recipient in `roster`, and write
    /// `vault.enc`. The caller must have verified the roster first (see
    /// [`Self::verify_roster`]), and `identity` must be one of its members. See
    /// [`vault_bytes`] for the rule this refuses on the way out.
    ///
    /// This writes the vault alone. A membership change writes it with the roster it was
    /// encrypted to, through [`Self::commit_amendment`].
    pub fn save_vault(
        &self,
        env: &str,
        vault: &Vault,
        roster: &Roster,
        identity: &Identity,
    ) -> Result<()> {
        std::fs::create_dir_all(self.env_dir(env))?;
        let armored = vault_bytes(vault, roster, identity)?;
        write_atomic(&self.vault_path(env), armored.as_bytes())
    }

    /// The canonicalized git work-tree root containing this project, or `None` when it is not
    /// inside one. Canonicalized here because [`relativize_under_root`] requires it and each
    /// caller would otherwise have to remember: three do, and each keeps its own policy for
    /// `None` - two report an error, and [`Self::load_vault_conflict`] reports
    /// [`VaultConflict::NoRepository`].
    fn git_root(&self) -> Option<PathBuf> {
        let root = git::repo_root(&self.root)?;
        Some(root.canonicalize().unwrap_or(root))
    }

    /// Whether the project sits inside a git work tree. Used by the `init` wizard to decide
    /// whether to offer `git init`. Verification does not consult this: the roster chain is
    /// read from `chain.json`, and the anti-rollback witness reports its own state through
    /// [`RollbackGuard`].
    pub fn in_git_work_tree(&self) -> bool {
        git::repo_root(&self.root).is_some()
    }

    /// Commit the `.bitfort` directory (roster, vault, config) with `message`, on the
    /// user's behalf, so a write path can clear the "commit the roster first" wall without
    /// making them drop to a shell (docs/SPEC.md §4.3). Commits only `.bitfort` paths, so
    /// unrelated staged work is left alone. Returns `Err` if not inside a git work tree -
    /// there is nothing to commit into, and the caller keeps its refusal.
    pub fn commit_bitfort_dir(&self, message: &str) -> Result<()> {
        self.commit_targets(message, &[self.bitfort_dir()])
    }

    /// Initialize a git repository at the project root (`git init`), for the `init` wizard
    /// when the user opts into version control. A no-op on an already-initialized repo.
    pub fn init_git(&self) -> Result<()> {
        git::init_repo(&self.root)
    }

    /// Commit the initial project - `.bitfort` plus the `.gitignore` that keeps `.env*`
    /// uncommittable (invariant 1) - for the `init` wizard, so a teammate cloning the repo
    /// gets both the trust anchor and the dotenv guard. Like [`Self::commit_bitfort_dir`]
    /// it commits only those paths and errs outside a git work tree.
    pub fn commit_init(&self, message: &str) -> Result<()> {
        self.commit_targets(message, &[self.bitfort_dir(), self.root.join(".gitignore")])
    }

    /// Stage and commit exactly `targets` (each canonicalized and relativized to the repo
    /// root) with `message`, leaving any other staged work untouched. Shared by the
    /// commit-for-me wall and the `init` wizard.
    fn commit_targets(&self, message: &str, targets: &[PathBuf]) -> Result<()> {
        let Some(root) = self.git_root() else {
            return Err(Error::Git("not inside a git repository".into()));
        };
        let rels = targets
            .iter()
            .map(|t| relativize_under_root(&root, t))
            .collect::<Result<Vec<_>>>()?;
        let specs = rels.iter().map(String::as_str).collect::<Vec<_>>();
        git::stage_and_commit(&root, &specs, message)
    }

    /// The anti-rollback ceiling for this environment, and whether Git could supply one.
    ///
    /// A committed revision counts toward the ceiling only if it parses as a roster for this
    /// project and environment *and* carries a signature from a key that holds, or has held,
    /// maintainer authority here. Both filters are load-bearing:
    ///
    /// - Parsing leniently (skip, don't fail) means one committed `{}` cannot wedge every
    ///   write path forever. History is append-only, so a garbage revision never hides a real
    ///   one - it only adds noise.
    /// - The signature filter is what stops a denial of service. The ceiling is consulted
    ///   before any signature check, so without it anyone able to commit could push
    ///   `{"roster_version": 18446744073709551615}` and permanently refuse every write.
    fn rollback_guard(&self, env: &str, chain: &Chain, current: &Roster) -> Result<RollbackGuard> {
        match git::repo_state(&self.root)? {
            git::RepoState::Outside => return Ok(RollbackGuard::NoRepository),
            git::RepoState::Shallow => return Ok(RollbackGuard::ShallowRepository),
            git::RepoState::Full => {}
        }
        // Confirmed inside a repo, so failing to relativize is anomalous: error rather than
        // return None, which would silently open a rollback hole.
        let root = self
            .git_root()
            .ok_or_else(|| Error::Git("git reported a work tree but no root".into()))?;
        let rel = relativize_under_root(&root, &self.roster_path(env))?;

        let authorized = chain.known_maintainer_keys(current);
        let mut highest = 0u64;
        for blob in git::committed_blobs(&root, &rel)? {
            let Ok(roster) = Roster::from_json(&blob) else {
                continue;
            };
            if roster.project_id != current.project_id || roster.env != current.env {
                continue;
            }
            if !roster.is_signed_by_any(&authorized)? {
                continue;
            }
            highest = highest.max(roster.roster_version);
        }
        // Every roster starts at v1, so nothing counted iff `highest` is still 0 - and a
        // ceiling of 0 accepts every version, which is the check being off rather than the
        // check passing. Report that instead of claiming enforcement (invariant 3).
        if highest == 0 {
            return Ok(RollbackGuard::Uncommitted);
        }
        Ok(RollbackGuard::Enforced { highest })
    }

    /// Verify an environment's roster: the signature chain from the pinned anchor, every
    /// `prev_digest` link, the project and environment binding, and anti-rollback.
    ///
    /// The chain comes from `chain.json` in the working tree, not from Git history, so this
    /// is total: it works in a shallow clone, in an exported tarball, and with no `git` on
    /// PATH (see [`crate::chain`] for why that changed). Git is consulted for one thing only,
    /// the anti-rollback ceiling, and the [`RollbackGuard`] in the result says whether it
    /// could supply one. Callers refuse on `Err`; `--strict` additionally refuses a guard
    /// that is not enforced (docs/SPEC.md §4.3, §5.5).
    pub fn verify_roster(&self, env: &str) -> Result<Verified> {
        let config = self.load_config()?;
        let roster = self.load_roster(env)?;
        let chain = self.load_chain(env)?;

        let guard = self.rollback_guard(env, &chain, &roster)?;
        chain.verify(
            &roster,
            &config.trust_anchor_fingerprint,
            guard.ceiling(),
            &config.project_id,
            env,
        )?;
        Ok(Verified {
            roster,
            chain,
            guard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::generate_project_id;
    use crate::roster::{Member, Role};

    /// A silently dropped component would send `git log` at a different path, and a path with
    /// no commits returns no revisions. The anti-rollback ceiling would then read zero, and a
    /// rolled-back roster would pass. So the relativization fails closed instead.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_component_fails_rather_than_vanishing() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // A real directory, canonicalized as `discover` leaves it, so `strip_prefix` sees the
        // same prefix the callers pass.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join(OsStr::from_bytes(b"\xff\xfe")).join("vault.enc");
        let err = relativize_under_root(&root, &target).unwrap_err();
        assert!(matches!(err, Error::Git(_)), "unexpected error: {err}");

        // A UTF-8 path still relativizes to the `/`-joined pathspec git expects.
        let ok = relativize_under_root(&root, &root.join(".bitfort/environments/dev/vault.enc"))
            .unwrap();
        assert_eq!(ok, ".bitfort/environments/dev/vault.enc");
    }

    fn dev_config(anchor: &str) -> Config {
        Config::new(generate_project_id().unwrap(), "development", anchor)
    }

    fn member(id: &Identity, name: &str, role: Role) -> Member {
        Member {
            name: name.into(),
            enc_pubkey: id.enc_pubkey(),
            sign_pubkey: id.sign_pubkey(),
            role,
            added_by: name.into(),
            added_at: "2026-07-03T00:00:00Z".into(),
        }
    }

    /// A fully initialized project on disk with a signed v1 dev roster + empty vault.
    fn init_project() -> (tempfile::TempDir, Project, Identity) {
        let id = Identity::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dev_config(&id.anchor());
        let project = Project::init(dir.path(), &config).unwrap();

        let mut roster = Roster::new_v1(
            config.project_id.clone(),
            "development",
            vec![member(&id, "alice", Role::Maintainer)],
        );
        roster.sign(&id, "alice").unwrap();
        project.save_roster("development", &roster).unwrap();
        project
            .save_vault("development", &Vault::new("development"), &roster, &id)
            .unwrap();
        (dir, project, id)
    }

    fn run_git(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?} failed");
    }

    fn git_init(root: &Path) {
        run_git(root, &["init", "-q", "-b", "main"]);
        run_git(root, &["config", "user.email", "t@e.com"]);
        run_git(root, &["config", "user.name", "t"]);
    }

    fn git_commit_all(root: &Path, msg: &str) {
        run_git(root, &["add", "-A"]);
        run_git(root, &["commit", "-q", "-m", msg]);
    }

    /// The roster on disk plus `edit`, signed as `signer`. Persists nothing.
    fn amended(
        project: &Project,
        signer: &Identity,
        signer_name: &str,
        edit: impl FnOnce(&mut Vec<Member>),
    ) -> (Roster, Roster) {
        let current = project.load_roster("development").unwrap();
        let mut next = current.amend().unwrap();
        edit(&mut next.members);
        next.sign(signer, signer_name).unwrap();
        (current, next)
    }

    /// Supersede the on-disk roster without touching the vault, which is what leaves the two
    /// one version apart. No command does this; the states it builds are the ones a crash or
    /// an attacker produces.
    fn supersede_only(
        project: &Project,
        signer: &Identity,
        signer_name: &str,
        edit: impl FnOnce(&mut Vec<Member>),
    ) -> Roster {
        let (current, next) = amended(project, signer, signer_name, edit);
        let mut chain = project.load_chain("development").unwrap();
        chain.append(current).unwrap();
        project.save_chain("development", &chain).unwrap();
        project.save_roster("development", &next).unwrap();
        next
    }

    /// Supersede the on-disk roster and re-encrypt the vault to it, the way a membership
    /// command does. `signer` must be a member of the amended roster, since it writes the
    /// vault too.
    fn amend_roster(
        project: &Project,
        signer: &Identity,
        signer_name: &str,
        edit: impl FnOnce(&mut Vec<Member>),
    ) -> Roster {
        let (current, next) = amended(project, signer, signer_name, edit);
        let verified = project.verify_roster("development").unwrap();
        let vault = project
            .load_vault("development", signer, &verified)
            .unwrap();
        project
            .commit_amendment("development", &current, &next, &vault, signer)
            .unwrap();
        next
    }

    #[test]
    fn init_then_discover_from_subdir() {
        let (dir, _project, _id) = init_project();
        let sub = dir.path().join("a/b/c");
        std::fs::create_dir_all(&sub).unwrap();
        let found = Project::discover(&sub).unwrap();
        assert_eq!(
            found.root().canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn init_refuses_to_clobber() {
        let (dir, _project, id) = init_project();
        assert!(Project::init(dir.path(), &dev_config(&id.anchor())).is_err());
    }

    #[test]
    fn discover_without_project_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Project::discover(dir.path()).is_err());
    }

    #[test]
    fn vault_roundtrips_through_disk() {
        let (_dir, project, id) = init_project();
        let verified = project.verify_roster("development").unwrap();
        let mut vault = project.load_vault("development", &id, &verified).unwrap();
        vault.set("API_KEY", "sk-123").unwrap();
        project
            .save_vault("development", &vault, &verified.roster, &id)
            .unwrap();

        let reloaded = project.load_vault("development", &id, &verified).unwrap();
        assert_eq!(reloaded.vars().get("API_KEY").unwrap(), "sk-123");
        assert_eq!(reloaded.provenance().unwrap().signer, "alice");
    }

    #[test]
    fn a_vault_forged_by_a_non_member_is_refused_on_load() {
        // Finding 1.2 end to end: the roster's `enc_pubkey` values are public, so anyone
        // able to write the repo can encrypt a vault alice can decrypt. Only the payload
        // signature separates that file from one alice's own team wrote.
        let (_dir, project, alice) = init_project();
        let verified = project.verify_roster("development").unwrap();
        let mallory = Identity::generate().unwrap();

        let mut forged_roster = verified.roster.clone();
        forged_roster
            .members
            .push(member(&mallory, "mallory", Role::Maintainer));
        let mut forged = Vault::new("development");
        forged.set("LD_PRELOAD", "/tmp/evil.so").unwrap();
        std::fs::write(
            project.vault_path("development"),
            forged.encrypt(&forged_roster, &mallory).unwrap(),
        )
        .unwrap();

        let err = project
            .load_vault("development", &alice, &verified)
            .unwrap_err();
        assert!(
            matches!(&err, Error::VaultOrigin(m) if m.contains("not in roster v1")),
            "expected a forged-vault rejection, got {err:?}"
        );
    }

    #[test]
    fn the_vault_records_the_roster_it_was_written_for() {
        // A crash inside a membership change leaves the vault and `keys.json` one version
        // apart. The payload names its roster so a reader can see that split.
        let (_dir, project, alice) = init_project();
        let verified = project.verify_roster("development").unwrap();
        let vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        assert_eq!(vault.provenance().unwrap().roster_version, 1);

        let v2 = supersede_only(&project, &alice, "alice", |_| {});
        // The vault still carries v1; it is readable, and the drift is visible.
        let verified = project.verify_roster("development").unwrap();
        let stale = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        assert_eq!(stale.provenance().unwrap().roster_version, 1);
        assert_eq!(
            stale.drift(&verified.roster),
            crate::vault::Drift::Behind {
                vault: 1,
                roster: 2
            }
        );
        assert_eq!(v2.roster_version, 2);
    }

    #[test]
    fn a_vault_signed_by_a_since_removed_member_stays_readable() {
        // The crash window of a removal, and the reason a payload is authenticated against the
        // roster it names. Bob writes the vault at v1; alice removes him, and the process stops
        // after `keys.json` is published and before `vault.enc` is. Looking bob up in v2 would
        // call his authentic file a forgery and leave the environment with no repair - `rotate`
        // included, since it has to read the vault to re-sign it.
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        let v2 = amend_roster(&project, &alice, "alice", |m| {
            m.push(member(&bob, "bob", Role::Member))
        });
        let verified = project.verify_roster("development").unwrap();
        let mut vault = project.load_vault("development", &bob, &verified).unwrap();
        vault.set("API_KEY", "bob-wrote-this").unwrap();
        project
            .save_vault("development", &vault, &v2, &bob)
            .unwrap();

        // The roster advances without the vault, which is exactly the crash state.
        supersede_only(&project, &alice, "alice", |m| m.retain(|x| x.name != "bob"));

        let verified = project.verify_roster("development").unwrap();
        let stale = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        assert_eq!(stale.provenance().unwrap().signer, "bob");
        assert_eq!(stale.vars().get("API_KEY").unwrap(), "bob-wrote-this");
        // Re-signing it against the current roster is the repair, and bob is not a recipient
        // of the result.
        project
            .save_vault("development", &stale, &verified.roster, &alice)
            .unwrap();
        assert!(project.load_vault("development", &bob, &verified).is_err());
    }

    #[test]
    fn v1_verifies_outside_git_and_reports_no_witness() {
        let (_dir, project, _id) = init_project();
        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 1);
        assert_eq!(verified.guard, RollbackGuard::NoRepository);
        assert!(!verified.guard.is_enforced());
    }

    #[test]
    fn the_chain_verifies_without_git_at_all() {
        // The point of moving the chain into the tree: a v3 roster verifies with no
        // repository, which is also what makes a shallow clone work. Under the old
        // git-history chain this failed with "predecessor v1 is not in git history".
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        amend_roster(&project, &alice, "alice", |m| {
            m.push(member(&bob, "bob", Role::Member))
        });
        amend_roster(&project, &alice, "alice", |m| m[1].role = Role::Maintainer);

        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 3);
        assert_eq!(project.load_chain("development").unwrap().rosters.len(), 2);
    }

    #[test]
    fn tampered_roster_fails_verification() {
        let (_dir, project, _id) = init_project();
        let outsider = Identity::generate().unwrap();
        let mut roster = project.load_roster("development").unwrap();
        roster
            .members
            .push(member(&outsider, "mallory", Role::Member));
        project.save_roster("development", &roster).unwrap();
        assert!(project.verify_roster("development").is_err());
    }

    #[test]
    fn a_truncated_chain_file_fails_closed() {
        let (_dir, project, alice) = init_project();
        amend_roster(&project, &alice, "alice", |_| {});
        project.save_chain("development", &Chain::new()).unwrap();

        let err = project.verify_roster("development").unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("predecessor")),
            "expected a truncation rejection, got {err:?}"
        );
    }

    #[test]
    fn committed_downgrade_is_rejected() {
        // Anti-rollback end to end: commit v1 and v2, then roll `keys.json` back to the
        // validly-signed v1. The chain still verifies, but the git ceiling must refuse it.
        let (dir, project, alice) = init_project();
        let root = dir.path();
        git_init(root);
        let v1 = project.load_roster("development").unwrap();
        let v1_chain = project.load_chain("development").unwrap();
        git_commit_all(root, "v1");

        amend_roster(&project, &alice, "alice", |_| {});
        git_commit_all(root, "v2");

        project.save_roster("development", &v1).unwrap();
        project.save_chain("development", &v1_chain).unwrap();
        let err = project.verify_roster("development").unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("downgrade")),
            "expected a downgrade rejection, got {err:?}"
        );
    }

    #[test]
    fn a_merge_cannot_hide_a_committed_version() {
        // Regression: `git merge -s ours` dropped the merge side from `git log -- <path>`
        // under default history simplification, so the higher committed version became
        // invisible and a downgrade passed. `--full-history` is what closes it.
        let (dir, project, alice) = init_project();
        let root = dir.path();
        git_init(root);
        let v1 = project.load_roster("development").unwrap();
        let v1_chain = project.load_chain("development").unwrap();
        git_commit_all(root, "v1");

        run_git(root, &["checkout", "-q", "-b", "bump"]);
        amend_roster(&project, &alice, "alice", |_| {});
        git_commit_all(root, "v2 on a branch");
        run_git(root, &["checkout", "-q", "main"]);
        run_git(root, &["merge", "-q", "-s", "ours", "bump", "-m", "merge"]);

        // main's tree is back at v1, and history holds v2 only on the merged-away side.
        project.save_roster("development", &v1).unwrap();
        project.save_chain("development", &v1_chain).unwrap();
        let err = project.verify_roster("development").unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("downgrade")),
            "the merge hid v2 from the ceiling, got {err:?}"
        );
    }

    #[test]
    fn unparseable_history_does_not_wedge_the_ceiling() {
        // Regression: a single committed `{}` over keys.json used to make every write path
        // fail forever with "unparseable roster in history". History is append-only, so a
        // garbage revision can only add noise - skip it.
        let (dir, project, _alice) = init_project();
        let root = dir.path();
        git_init(root);
        git_commit_all(root, "v1");

        let real = std::fs::read_to_string(project.roster_path("development")).unwrap();
        std::fs::write(project.roster_path("development"), "{}").unwrap();
        git_commit_all(root, "garbage");
        std::fs::write(project.roster_path("development"), &real).unwrap();

        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 1);
        assert_eq!(verified.guard, RollbackGuard::Enforced { highest: 1 });
    }

    #[test]
    fn an_unsigned_huge_version_in_history_is_ignored() {
        // Regression: committing `{"roster_version": u64::MAX}` set the ceiling to u64::MAX
        // and refused every write path forever, because the ceiling is read before any
        // signature check. Only rosters signed by a known maintainer may raise it.
        let (dir, project, _alice) = init_project();
        let root = dir.path();
        git_init(root);
        git_commit_all(root, "v1");

        let real = std::fs::read_to_string(project.roster_path("development")).unwrap();
        let mut poison: serde_json::Value = serde_json::from_str(&real).unwrap();
        poison["roster_version"] = serde_json::json!(u64::MAX);
        poison["signatures"] = serde_json::json!([]);
        std::fs::write(
            project.roster_path("development"),
            serde_json::to_string(&poison).unwrap(),
        )
        .unwrap();
        git_commit_all(root, "poison");
        std::fs::write(project.roster_path("development"), &real).unwrap();

        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 1);
        assert_eq!(verified.guard, RollbackGuard::Enforced { highest: 1 });
    }

    #[test]
    fn a_shallow_clone_verifies_but_reports_no_enforcement() {
        // The `actions/checkout` default. The chain still verifies from the tree; the
        // ceiling cannot be trusted, and that must be reported rather than read as zero.
        let (dir, project, alice) = init_project();
        let root = dir.path();
        git_init(root);
        git_commit_all(root, "v1");
        amend_roster(&project, &alice, "alice", |_| {});
        git_commit_all(root, "v2");

        let clone_parent = tempfile::tempdir().unwrap();
        let shallow = clone_parent.path().join("shallow");
        run_git(
            clone_parent.path(),
            &[
                "clone",
                "-q",
                "--depth",
                "1",
                &format!("file://{}", root.display()),
                shallow.to_str().unwrap(),
            ],
        );

        let cloned = Project::discover(&shallow).unwrap();
        let verified = cloned.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 2, "chain must still verify");
        assert_eq!(verified.guard, RollbackGuard::ShallowRepository);
        assert!(verified.guard.warning().unwrap().contains("fetch-depth"));
    }

    #[test]
    fn supersede_tolerates_a_repeated_append() {
        // A crash between "append to chain.json" and "write keys.json" leaves the chain
        // holding a copy of the roster still in keys.json. Verification must ignore that
        // redundant tail instead of wedging the environment.
        let (_dir, project, alice) = init_project();
        let current = project.load_roster("development").unwrap();
        let mut next = current.amend().unwrap();
        next.sign(&alice, "alice").unwrap();

        // Simulate the crash: the chain advanced, keys.json did not.
        let mut chain = project.load_chain("development").unwrap();
        chain.append(current.clone()).unwrap();
        project.save_chain("development", &chain).unwrap();
        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 1, "redundant tail ignored");

        // Re-running the amendment converges rather than double-appending.
        let vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        project
            .commit_amendment("development", &current, &next, &vault, &alice)
            .unwrap();
        assert_eq!(project.load_chain("development").unwrap().rosters.len(), 1);
        assert_eq!(
            project
                .verify_roster("development")
                .unwrap()
                .roster
                .roster_version,
            2
        );
    }

    /// The roster pair a membership change moves between: bob added to a signed v2.
    /// Persists nothing.
    fn amendment_adding(project: &Project, alice: &Identity, bob: &Identity) -> (Roster, Roster) {
        amended(project, alice, "alice", |m| {
            m.push(member(bob, "bob", Role::Member))
        })
    }

    #[test]
    fn commit_amendment_publishes_the_chain_roster_and_vault_together() {
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        let (current, next) = amendment_adding(&project, &alice, &bob);

        let verified = project.verify_roster("development").unwrap();
        let mut vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        vault.set("API_KEY", "sk-123").unwrap();
        project
            .commit_amendment("development", &current, &next, &vault, &alice)
            .unwrap();

        let verified = project.verify_roster("development").unwrap();
        assert_eq!(verified.roster.roster_version, 2);
        assert_eq!(project.load_chain("development").unwrap().rosters.len(), 1);
        // The vault landed with them, so bob reads it and it is stamped for the new roster.
        let read = project.load_vault("development", &bob, &verified).unwrap();
        assert_eq!(read.vars().get("API_KEY").unwrap(), "sk-123");
        assert_eq!(read.provenance().unwrap().roster_version, 2);
    }

    #[test]
    fn a_refused_vault_leaves_the_roster_and_chain_untouched() {
        // What staging buys: everything that can fail happens while every target still holds
        // its old bytes. An addition used to write `keys.json` first, so a vault the write
        // rules refuse left the roster one version ahead of the vault - a split that needs a
        // `rotate` to repair, produced by a command that did nothing.
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        let (current, next) = amendment_adding(&project, &alice, &bob);

        let verified = project.verify_roster("development").unwrap();
        let mut vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();
        vault.set("LD_PRELOAD", "/tmp/evil.so").unwrap();
        let err = project
            .commit_amendment("development", &current, &next, &vault, &alice)
            .unwrap_err();
        assert!(matches!(err, Error::VaultContent(_)), "got {err:?}");

        assert_eq!(
            project.load_roster("development").unwrap().roster_version,
            1
        );
        assert!(project
            .load_chain("development")
            .unwrap()
            .rosters
            .is_empty());
        assert!(project.verify_roster("development").is_ok());
    }

    #[test]
    fn commit_amendment_converges_after_an_interrupted_chain_write() {
        // The one crash window the publish order still allows: the chain advanced, nothing
        // else did. Re-running must not append a second copy of the same predecessor.
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        let (current, next) = amendment_adding(&project, &alice, &bob);
        let verified = project.verify_roster("development").unwrap();
        let vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();

        let mut chain = project.load_chain("development").unwrap();
        chain.append(current.clone()).unwrap();
        project.save_chain("development", &chain).unwrap();

        project
            .commit_amendment("development", &current, &next, &vault, &alice)
            .unwrap();
        assert_eq!(project.load_chain("development").unwrap().rosters.len(), 1);
        assert_eq!(
            project
                .verify_roster("development")
                .unwrap()
                .roster
                .roster_version,
            2
        );
    }

    #[test]
    fn environment_exists_sees_files_config_does_not_list() {
        let (_dir, project, _id) = init_project();
        assert!(project.environment_exists("development"));
        assert!(!project.environment_exists("production"));
    }

    #[test]
    fn is_dotenv_gitignored_reflects_gitignore() {
        let (_dir, project, _id) = init_project();
        assert!(project.is_dotenv_gitignored());
        std::fs::remove_file(project.root().join(".gitignore")).unwrap();
        assert!(!project.is_dotenv_gitignored());
    }

    #[test]
    fn ensure_dotenv_gitignored_keeps_unreadable_content() {
        // Regression: a `.gitignore` that is not valid UTF-8 made `read_to_string` fail,
        // `unwrap_or_default` turn it into "", and the rewrite delete every existing rule.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        std::fs::write(&path, b"node_modules/\ntarget/\n# caf\xe9\n*.log\n").unwrap();
        let id = Identity::generate().unwrap();

        let err = Project::init(dir.path(), &dev_config(&id.anchor())).unwrap_err();
        assert!(
            format!("{err}").contains(".gitignore"),
            "expected a named .gitignore failure, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap().len(),
            35,
            "the existing .gitignore must be left intact"
        );
    }

    #[test]
    fn resolve_env_rejects_unknown() {
        let (_dir, project, _id) = init_project();
        let config = project.load_config().unwrap();
        assert_eq!(project.resolve_env(None, &config).unwrap(), "development");
        assert!(project.resolve_env(Some("production"), &config).is_err());
    }

    #[test]
    fn load_roster_rejects_a_future_schema_version() {
        let (_dir, project, _id) = init_project();
        let mut roster = project.load_roster("development").unwrap();
        roster.schema_version = crate::roster::SCHEMA_VERSION + 1;
        project.save_roster("development", &roster).unwrap();
        assert!(matches!(
            project.load_roster("development"),
            Err(Error::UnsupportedSchema("roster", 2, 1))
        ));
    }

    #[test]
    fn load_vault_names_the_missing_file() {
        let (_dir, project, id) = init_project();
        let verified = project.verify_roster("development").unwrap();
        std::fs::remove_file(project.vault_path("development")).unwrap();
        let err = project
            .load_vault("development", &id, &verified)
            .unwrap_err();
        assert!(
            format!("{err}").contains("vault.enc"),
            "error must name the file, got {err:?}"
        );
    }

    #[test]
    fn no_merge_in_progress_is_not_a_conflict() {
        // The two are kept apart, because the way out differs: inside a repository the merge
        // can be restored, and outside one there is no index to restore it from.
        let (dir, project, id) = init_project();
        let verified = project.verify_roster("development").unwrap();
        assert!(matches!(
            project.load_vault_conflict("development", &id, &verified),
            Ok(VaultConflict::NoRepository)
        ));

        git_init(dir.path());
        git_commit_all(dir.path(), "init");
        assert!(matches!(
            project.load_vault_conflict("development", &id, &verified),
            Ok(VaultConflict::None)
        ));
    }

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "payload")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_refuses_a_pre_planted_symlink() {
        // Regression: the staging name is predictable and `File::create` follows symlinks,
        // so anyone able to write into `.bitfort/` could redirect a vault write outside the
        // project. `create_new` refuses to open an existing path, link included.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("outside");
        let path = dir.path().join("payload");
        // Pin the sequence number so the staging name is exactly predictable here, the way
        // an attacker watching the directory would predict it.
        let seq = 424_242;
        std::os::unix::fs::symlink(&target, staging_path(&path, seq)).unwrap();

        assert!(write_atomic_seq(&path, b"secret", seq).is_err());
        assert!(!target.exists(), "the write escaped through the symlink");
        assert!(!path.exists(), "no payload should have been written");
        // The planted link is left alone. A `Staged` is built only after `create_new` succeeds,
        // so a refused write never deletes a path this process did not create.
        assert!(
            staging_path(&path, seq).symlink_metadata().is_ok(),
            "the refused write removed a file it did not create"
        );
    }

    #[test]
    fn a_failed_publish_leaves_no_staging_file_behind() {
        // The `Staged` values the publish loop has not reached are dropped, and each removes
        // its own staging file. A leftover would be committed with the rest of `.bitfort`.
        let (_dir, project, alice) = init_project();
        let bob = Identity::generate().unwrap();
        let (current, next) = amendment_adding(&project, &alice, &bob);
        let verified = project.verify_roster("development").unwrap();
        let vault = project
            .load_vault("development", &alice, &verified)
            .unwrap();

        // Make the vault rename fail: a rename over a non-empty directory cannot succeed.
        let vault_path = project.vault_path("development");
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();
        std::fs::write(vault_path.join("occupied"), b"x").unwrap();

        assert!(project
            .commit_amendment("development", &current, &next, &vault, &alice)
            .is_err());

        let leftovers: Vec<_> = std::fs::read_dir(project.env_dir("development"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "staging files left: {leftovers:?}");
    }

    #[test]
    fn write_atomic_concurrent_same_path_writes_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("payload"));
        let a = std::thread::spawn({
            let path = path.clone();
            move || {
                for _ in 0..200 {
                    write_atomic(&path, &[b'a'; 4096]).unwrap();
                }
            }
        });
        let b = std::thread::spawn({
            let path = path.clone();
            move || {
                for _ in 0..200 {
                    write_atomic(&path, &[b'b'; 4096]).unwrap();
                }
            }
        });
        a.join().unwrap();
        b.join().unwrap();

        let final_bytes = std::fs::read(&*path).unwrap();
        assert!(
            final_bytes == vec![b'a'; 4096] || final_bytes == vec![b'b'; 4096],
            "final content is torn"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "payload")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    fn write_atomic_cleans_up_when_the_target_dir_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-subdir").join("payload");
        assert!(write_atomic(&path, b"data").is_err());
        assert!(!path.exists());
    }
}
