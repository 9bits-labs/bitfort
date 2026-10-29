//! Command implementations. Each is a thin orchestration over `bitfort-core`: the
//! crypto, roster, and project logic lives in the core crate (docs/SPEC.md §9.1), so
//! this layer only handles argument shaping, prompting, and user-facing output.

use std::io::Write as _;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;

use bitfort_core::project::{MergeBase, VaultConflict, Verified};
use bitfort_core::vault::{Drift, Provenance, VALUE_SIZE_WARN};
use bitfort_core::{
    clock, config, dotenv, keystore, wordlist, Config, Identity, Invite, Member, Role, Roster,
    Vault,
};

use crate::ui::{outln, Failure, Level, Ui, WRITE_FAILED};

/// `bitfort init`: a guided setup that creates `.bitfort/`, generates/adopts the
/// initializer identity, pins the trust anchor, and writes a signed v1 roster + empty
/// vault. On a terminal it walks the user through their name, the first environment,
/// importing an existing `.env`, and putting the project under git; off a terminal it is
/// fully non-interactive (flag/`$USER` defaults, no prompts, no git) so CI and scripts keep
/// working. `name` is the `--name` override that skips the name prompt.
pub fn init(ui: &Ui, start: Option<&Path>, name: Option<String>) -> Result<()> {
    let root = match start {
        Some(d) => d.to_path_buf(),
        None => std::env::current_dir().context("cannot determine current directory")?,
    };
    // Guard before generating a key or prompting: don't write a fresh identity into the
    // keyring, or walk the user through the wizard, only to refuse because a project exists.
    let bitfort_dir = root.join(bitfort_core::project::DIR_NAME);
    if bitfort_dir.exists() {
        bail!(
            "{} already exists; refusing to re-initialize",
            bitfort_dir.display()
        );
    }

    if ui.interactive() {
        ui.header("Set up BitFort")?;
        ui.blank()?;
    }

    // Name: a non-empty `--name` wins; otherwise prompt (default `$USER`) on a terminal, or
    // take the default silently off one. An empty/whitespace flag is treated as absent, as
    // the pre-wizard `resolve_name` did.
    // This name becomes the first roster member, so the same rule applies as for an invite.
    // A `--name` the rule refuses is an error, because the user can correct it and retry; a
    // typed answer is re-asked instead, like the environment prompt below. Off a terminal
    // `prompt` returns the default, which `resolve_name` has already checked, so this cannot
    // loop.
    let name = match name.filter(|n| !n.trim().is_empty()) {
        Some(n) => {
            let n = n.trim().to_string();
            bitfort_core::roster::validate_member_name(&n)?;
            n
        }
        None => loop {
            let candidate = ui.prompt("Your name?", &resolve_name(None));
            if bitfort_core::roster::validate_member_name(&candidate).is_ok() {
                break candidate;
            }
            ui.status(
                Level::Warn,
                "invalid",
                "use printable ASCII, at most 64 characters",
            )?;
        },
    };
    // First environment: prompt (default `development`), re-asking until it's a valid name.
    // Off a terminal `prompt` returns the default immediately, so this cannot loop.
    let env = loop {
        let candidate = ui.prompt("First environment?", "development");
        if config::is_valid_env_name(&candidate) {
            break candidate;
        }
        ui.status(Level::Warn, "invalid", "use letters, digits, '-' or '_'")?;
    };

    let identity = acquire_identity()?;
    let anchor = identity.anchor();

    let config = Config::new(config::generate_project_id()?, &env, anchor.clone());
    let project = bitfort_core::Project::init(&root, &config)?;

    let mut roster = Roster::new_v1(
        config.project_id.clone(),
        &env,
        vec![Member {
            name: name.clone(),
            enc_pubkey: identity.enc_pubkey(),
            sign_pubkey: identity.sign_pubkey(),
            role: Role::Maintainer,
            added_by: name.clone(),
            added_at: clock::now_rfc3339(),
        }],
    );
    roster.sign(&identity, &name)?;
    project.save_roster(&env, &roster)?;
    project.save_vault(&env, &Vault::new(&env), &roster, &identity)?;

    // Optional guided steps - interactive only; each degrades to nothing off a TTY. Both are
    // best-effort: the project is already on disk, so a failure here warns but never aborts.
    let dotenv_path = root.join(".env");
    let mut imported = false;
    if dotenv_path.is_file()
        && ui.offer(&format!(
            "Found {} - import it into '{env}' now?",
            dotenv_path.display()
        )) == Some(true)
    {
        match import(Some(&root), Some(&env), &dotenv_path, false) {
            Ok(()) => imported = true,
            Err(e) => ui.report(&e),
        }
    }
    let committed = offer_initial_commit(ui, &project);

    // --- summary ---
    ui.blank()?;
    ui.header(&format!("Initialized '{env}' in {}", root.display()))?;
    ui.status(Level::Ok, "maintainer", &name)?;
    ui.status(Level::Ok, "anchor", &anchor)?;
    if let Some(words) = wordlist::anchor_words(&anchor) {
        ui.field("words", &words)?;
    }
    if imported {
        ui.status(
            Level::Ok,
            "imported",
            &format!("secrets from {}", dotenv_path.display()),
        )?;
    }
    if committed {
        ui.status(Level::Ok, "git", "committed .bitfort")?;
    }
    ui.blank()?;
    ui.status(
        Level::Warn,
        "solo",
        "one maintainer - a lost key loses the vault; add a second before relying on it",
    )?;
    ui.blank()?;
    ui.hint("publish the anchor out-of-band (README/Slack) - the one human trust step")?;
    if !committed {
        ui.hint("git add .bitfort && git commit   (pins the anchor in history)")?;
    }
    if !imported && dotenv_path.is_file() {
        ui.hint("import an existing .env:  bitfort import .env")?;
    }
    ui.hint("run your app:  bitfort run -- <cmd>")?;
    Ok(())
}

/// Offer to put the fresh project under version control (interactive only). Inside a repo
/// it offers to commit `.bitfort` + `.gitignore`; outside one it offers `git init` first.
/// Returns whether a commit was made. Best-effort: a git failure is surfaced but the
/// project is already usable, so init still succeeds.
fn offer_initial_commit(ui: &Ui, project: &bitfort_core::Project) -> bool {
    let in_repo = project.in_git_work_tree();
    let question = if in_repo {
        "Commit .bitfort to git now?"
    } else {
        "Initialize a git repo and commit .bitfort now?"
    };
    if ui.offer(question) != Some(true) {
        return false;
    }
    let result = (|| {
        if !in_repo {
            project.init_git()?;
        }
        project.commit_init("bitfort: initialize project")
    })();
    match result {
        Ok(()) => true,
        Err(e) => {
            ui.report(&anyhow!(e));
            false
        }
    }
}

/// `bitfort keygen`: idempotently ensure a local identity exists and print its public
/// keys plus a copy/paste invite blob for a maintainer to add (docs/SPEC.md §5.2).
pub fn keygen(ui: &Ui, name: Option<String>) -> Result<()> {
    let name = resolve_name(name);
    // Refuse here so a rejected name never reaches an invite blob.
    bitfort_core::roster::validate_member_name(&name)?;
    let (identity, created) = match keystore::find_identity()? {
        Some(id) => (id, false),
        None => {
            let id = Identity::generate()?;
            keystore::store_identity(&id)?;
            (id, true)
        }
    };

    let status = if created {
        "generated a new identity (stored in the OS keyring)"
    } else {
        "using your existing local identity"
    };
    ui.status(Level::Ok, "identity", status)?;
    ui.field("fingerprint", &identity.fingerprint())?;
    ui.field("enc key", &identity.enc_pubkey())?;
    ui.field("sign key", &identity.sign_pubkey())?;
    ui.blank()?;
    ui.status(
        Level::Info,
        "invite",
        "send this to a maintainer to be added:",
    )?;
    // The blob is printed verbatim (no styling) so it stays copy-pasteable.
    ui.line(&Invite::from_identity(&identity, name).encode()?)?;
    ui.blank()?;
    ui.hint("they run:  bitfort member add <invite>")?;
    Ok(())
}

/// `bitfort identity new`: mint a fresh identity and print both secrets.
///
/// This is the only command that prints private key material, and it exists because a machine
/// with no keyring - a CI runner, a container - needs `BITFORT_IDENTITY` and
/// `BITFORT_SIGN_IDENTITY` supplied out of band (docs/SPEC.md §3.1), and no other command can
/// produce them. `keygen` cannot: it is idempotent, so on a machine that already holds an
/// identity it returns that one, and it never reveals a secret.
///
/// Three things keep the blast radius small:
/// - the keyring is never touched, so this cannot overwrite the operator's own identity;
/// - it refuses a terminal without `--force`, like `export`, so the secrets do not land in
///   scrollback;
/// - the minted identity is not a member of anything until a maintainer runs `member add`
///   with the invite blob printed alongside it.
pub fn identity_new(ui: &Ui, name: Option<String>, force: bool) -> Result<()> {
    // Before anything is generated: the guard is about where the output goes, not what it is.
    if ui.stdout_is_terminal() && !force {
        // `--name` keeps the invite from colliding with the caller's own roster name, which
        // `member add` refuses after the key is already on disk. The file belongs outside the
        // work tree, because `.gitignore` covers only `.env*`, and `umask 077` gives a new
        // file the 600 mode an identity file requires.
        let redirect = if ui.json() {
            "(umask 077; bitfort identity new --name ci --json > ~/ci.json)"
        } else {
            "(umask 077; bitfort identity new --name ci > ~/ci.key)"
        };
        return Err(Failure::hinted(
            "refusing to print a private identity to a terminal\nthis would leave the key in \
             scrollback; redirect it to a file or a consumer instead",
            format!("{redirect}   (or pass --force)"),
        ));
    }

    let name = resolve_name(name);
    // Refuse before a key exists, so a rejected name costs no minted identity on disk.
    bitfort_core::roster::validate_member_name(&name)?;
    // Deliberately not `keystore::store_identity`: this identity belongs to another machine.
    let identity = Identity::generate()?;
    let (enc, sign) = (identity.enc_secret(), identity.sign_secret());
    let invite = Invite::from_identity(&identity, name).encode()?;

    if ui.json() {
        // Keyed by the variable names, so a caller stores each value under its own name.
        ui.emit_json(&json!({
            (keystore::ENV_ENC): enc.as_str(),
            (keystore::ENV_SIGN): sign.as_str(),
            "invite": invite,
        }))?;
    } else {
        // Printed as `KEY=VALUE` so the pair can be sourced, or split into two CI secrets.
        ui.line(&format!("{}={}", keystore::ENV_ENC, enc.as_str()))?;
        ui.line(&format!("{}={}", keystore::ENV_SIGN, sign.as_str()))?;
        ui.line("")?;
        ui.line("# Send this invite to a maintainer, who runs: bitfort member add <invite>")?;
        ui.line(&format!("# {invite}"))?;
    }

    // To stderr, so the operator still sees it when stdout is redirected into a key file,
    // and so it never lands inside that file.
    eprintln!(
        "warning: this printed a private identity; put it in your CI secret store and delete \
         any file you wrote it to"
    );
    Ok(())
}

/// `bitfort anchor [--share]`: print the project's trust anchor - the hex fingerprint plus
/// its 6-word BIP-39 phrase - so it can be published out-of-band for a fresh clone to verify
/// (docs/SPEC.md §5.1). The hex is the source of truth; the words are the human compare
/// layer. `--share` emits a plain, chrome-free block that pastes cleanly into a README or
/// Slack even from a terminal.
pub fn anchor(ui: &Ui, start: Option<&Path>, share: bool) -> Result<()> {
    let project = discover(start)?;
    let config = project.load_config()?;
    let anchor = &config.trust_anchor_fingerprint;
    let words = wordlist::anchor_words(anchor);

    if ui.json() {
        ui.emit_json(&json!({ "anchor": anchor, "anchor_words": words }))?;
        return Ok(());
    }
    if share {
        // Plain, no styling even on a TTY, so it copy-pastes into a README/Slack cleanly.
        outln!("BitFort trust anchor - verify this matches on a fresh clone:")?;
        outln!("  {anchor}")?;
        if let Some(w) = &words {
            outln!("  {w}")?;
        }
        return Ok(());
    }
    ui.header("Trust anchor")?;
    ui.field("anchor", anchor)?;
    if let Some(w) = &words {
        ui.field("words", w)?;
    }
    ui.blank()?;
    ui.hint("publish this out-of-band (README/Slack) so teammates verify it on a fresh clone")?;
    Ok(())
}

/// Output shape for `bitfort export`.
#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ExportFormat {
    /// `KEY=VALUE` dotenv, the inverse of `import`.
    Dotenv,
    /// `export KEY=VALUE` shell assignments to `eval`/`source`.
    Shell,
    /// A single `{ "KEY": "VALUE" }` JSON object.
    Json,
}

/// `bitfort export [--format] [--force]`: decrypt and print every secret (read path) as
/// dotenv, shell, or JSON. This is the highest-exposure command - the whole vault in
/// plaintext - so it refuses to write to a terminal (where the values would linger in
/// scrollback) unless `--force`; pipe or redirect it instead. It always warns on stderr.
pub fn export(
    ui: &Ui,
    start: Option<&Path>,
    env: Option<&str>,
    format: ExportFormat,
    force: bool,
) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());
    let verified = opened.verified("export")?;

    // The one read path that does not use `Opened::read_vault`: this guard has to run before
    // anything is decrypted, not after.
    // Dumping every secret into terminal scrollback is a footgun; require a pipe or --force.
    if ui.stdout_is_terminal() && !force {
        return Err(Failure::hinted(
            "refusing to print all secrets to a terminal\nthis would expose every value in \
             scrollback; redirect it to a file or a consumer instead",
            "bitfort export > .env   (or pass --force)",
        ));
    }

    let identity = load_identity()?;
    let vault = open_vault(project, env, &identity, &verified, Use::Read)?;
    // Before the warning and the render: this output is `eval`ed or fed to a dotenv loader, so
    // emitting one of these names is the same injection `run` refuses, one step later.
    refuse_process_control_vars(&vault, "export it")?;

    eprintln!(
        "warning: exposing {} plaintext secret(s) from '{env}'",
        vault.vars().len()
    );
    let pairs = || vault.vars().iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let rendered = match format {
        ExportFormat::Dotenv => dotenv::to_dotenv(pairs())?,
        ExportFormat::Shell => dotenv::to_shell(pairs())?,
        ExportFormat::Json => {
            let mut json = serde_json::to_string_pretty(vault.vars())
                .context("failed to serialize secrets as JSON")?;
            json.push('\n');
            json
        }
    };
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .context(WRITE_FAILED)?;
    Ok(())
}

/// `bitfort import <path>`: migrate a dotenv-format file into the vault (write path).
pub fn import(
    start: Option<&Path>,
    env: Option<&str>,
    path: &Path,
    delete_source: bool,
) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    // Write path: refuse to re-encrypt against an unverified roster. Re-use the returned
    // roster for re-encryption so `keys.json` is never read a second, unverified time
    // (closes a verify-then-use window).
    let verified = opened.verified("import")?;

    let identity = load_identity()?;
    let mut vault = open_vault(project, env, &identity, &verified, Use::Rewrite)?;

    let contents =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let pairs = dotenv::parse(&contents)?;
    if pairs.is_empty() {
        bail!("{} contained no assignments", path.display());
    }

    let (mut added, mut updated) = (0usize, 0usize);
    for (key, value) in pairs {
        if vault.vars().contains_key(&key) {
            updated += 1;
        } else {
            added += 1;
        }
        vault.set(&key, value)?;
    }
    warn_oversized(&vault);

    project.save_vault(env, &vault, &verified.roster, &identity)?;

    outln!(
        "Imported {} secret(s) into '{env}' ({added} added, {updated} updated).",
        added + updated
    )?;
    if delete_source {
        std::fs::remove_file(path)
            .with_context(|| format!("imported, but failed to delete {}", path.display()))?;
        outln!("Deleted source file {}.", path.display())?;
    } else {
        outln!(
            "Source file {} still contains plaintext secrets - delete it once you've",
            path.display()
        )?;
        outln!("confirmed the import (or re-run with --delete-source). `.env*` is gitignored.")?;
    }
    Ok(())
}

/// `bitfort set KEY[=VALUE]`: add or update one secret (write path). With the value
/// omitted it comes from a terminal prompt without echo, so it never lands in shell
/// history, or - when stdin is not a terminal - from stdin, which is the headless path:
/// `printf %s "$SECRET" | bitfort set KEY`. Overwriting an existing key is confirmed
/// first (`--yes` to skip), before any value is read.
pub fn set(
    ui: &Ui,
    start: Option<&Path>,
    env: Option<&str>,
    assignment: &str,
    yes: bool,
) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    // Re-use the verified roster for re-encryption (see `import` for the rationale).
    let verified = opened.verified("set")?;

    // Split off the key first; defer reading the value until any overwrite is confirmed,
    // so the user isn't prompted to type a secret we might then decline to store.
    let (key, inline_value) = match assignment.split_once('=') {
        Some((k, v)) => (k.trim().to_string(), Some(v.to_string())),
        None => (assignment.trim().to_string(), None),
    };
    // Both rules run here, before the value is read, so the user is never asked to type a
    // secret that the write would then refuse. `Vault::set` and `Project::save_vault` are the
    // enforcement points; these two calls only move the refusal earlier.
    dotenv::check_key(&key)?;
    refuse_process_control(&key)?;

    let identity = load_identity()?;
    let mut vault = open_vault(project, env, &identity, &verified, Use::Rewrite)?;
    let existed = vault.vars().contains_key(&key);
    // The `--yes` fix line stops at the key: echoing the assignment would leak an inline
    // secret value into the error output (docs/SPEC.md §6 secret hygiene).
    if existed
        && !ui.confirm(
            &format!("Overwrite existing secret `{key}` in '{env}'?"),
            yes,
            &format!("bitfort set {key}=... --yes"),
        )?
    {
        ui.line(&ui.dim("aborted."))?;
        return Ok(());
    }

    let value = match inline_value {
        Some(v) => v,
        None => read_value(ui, &key)?,
    };
    vault.set(&key, value)?;
    warn_oversized(&vault);

    project.save_vault(env, &vault, &verified.roster, &identity)?;

    outln!(
        "{} {key} in '{env}'.",
        if existed { "Updated" } else { "Set" }
    )?;
    Ok(())
}

/// `bitfort verify [--strict]`: check the roster (signature chain, anchor pin, env
/// match, anti-rollback) and print the anchor fingerprint for out-of-band comparison
/// (docs/SPEC.md §5.1). A hard failure (bad chain, rollback, tampering) always exits
/// non-zero. `--strict` additionally fails on best-effort conditions - chiefly running
/// outside a git repo, where anti-rollback and the chain cannot be enforced - so CI can
/// demand full protection (§5.5).
pub fn verify(ui: &Ui, start: Option<&Path>, env: Option<&str>, strict: bool) -> Result<i32> {
    let opened = open(start, env)?;
    let (project, env, config) = (&opened.project, opened.env.as_str(), &opened.config);

    let verified = project.verify_roster(env);
    // The one check that can still be unavailable: anti-rollback needs git history.
    let guard = verified.as_ref().ok().map(|v| v.guard);
    let enforced = guard.is_some_and(|g| g.is_enforced());
    // The roster is only half of what a pull request needs checked: `vault.enc` carries a
    // signature now, and a forged one must be visible on the diff that introduced it, not
    // only later at `run`.
    let vault = VaultState::read(project, env, verified.as_ref().ok());
    // A hard verification failure exits 1, and so does a vault this roster did not authorize.
    // `--strict` adds the case where anti-rollback cannot be enforced (no repository, or a
    // shallow clone). This holds across every output mode.
    let code = i32::from(verified.is_err() || vault.is_failure() || (strict && !enforced));

    if ui.json() {
        let mut obj = json!({
            "environment": env,
            "anchor": config.trust_anchor_fingerprint,
            "anchor_words": wordlist::anchor_words(&config.trust_anchor_fingerprint),
            "rollback_enforced": enforced,
            "strict": strict,
            "exit_code": code,
        });
        merge_roster_json(&mut obj, verified.as_ref());
        if let Ok(v) = &verified {
            if let Some(why) = v.guard.warning() {
                obj["rollback_warning"] = json!(why);
            }
        }
        obj["vault"] = vault.json();
        ui.emit_json(&obj)?;
        return Ok(code);
    }

    if !ui.interactive() {
        // Plain machine/CI output (stable strings a pipeline or gate may match).
        outln!("environment:  {env}")?;
        outln!("trust anchor: {}", config.trust_anchor_fingerprint)?;
        if let Some(words) = wordlist::anchor_words(&config.trust_anchor_fingerprint) {
            outln!("anchor words: {words}")?;
        }
        outln!("(compare the anchor against the value published out-of-band, e.g. the README)")?;
        match &verified {
            Ok(v) => outln!(
                "OK: roster v{} verified, {} member(s).",
                v.roster.roster_version,
                v.roster.members.len()
            )?,
            Err(e) => {
                eprintln!("FAILED: {e}");
                return Ok(code);
            }
        }
        match vault.line() {
            (Level::Fail, why) => eprintln!("FAILED: {why}"),
            (_, msg) => outln!("vault: {msg}")?,
        }
        if let Some(why) = guard.and_then(|g| g.warning()) {
            eprintln!("warning: {why}");
            if strict {
                eprintln!("FAILED: --strict requires git-backed rollback protection");
            }
        }
        return Ok(code);
    }

    ui.header(&format!("bitfort verify · {env}"))?;
    ui.field("anchor", &config.trust_anchor_fingerprint)?;
    if let Some(words) = wordlist::anchor_words(&config.trust_anchor_fingerprint) {
        ui.field("words", &words)?;
    }
    ui.hint("compare the anchor with the value published out-of-band (e.g. the README)")?;
    match &verified {
        Ok(v) => ui.status(
            Level::Ok,
            "roster",
            &format!(
                "v{} verified · {} member(s)",
                v.roster.roster_version,
                v.roster.members.len()
            ),
        )?,
        Err(e) => {
            ui.status(Level::Fail, "roster", &format!("{e}"))?;
            return Ok(code);
        }
    }
    let (level, msg) = vault.line();
    ui.status(level, "vault", &msg)?;
    // The chain verified from `chain.json`. Anti-rollback is the one part that still needs
    // git history, so it is the one part that can be unavailable.
    if let Some(why) = guard.and_then(|g| g.warning()) {
        ui.status(Level::Warn, "rollback", why)?;
        if strict {
            ui.status(
                Level::Fail,
                "strict",
                "requires git-backed rollback protection",
            )?;
        }
    }
    Ok(code)
}

/// `bitfort get KEY`: decrypt and print one value (read path). Guarded: it warns on
/// stderr that it is exposing a plaintext secret, and prints only the value on stdout so
/// it stays pipeable.
pub fn get(start: Option<&Path>, env: Option<&str>, key: &str) -> Result<()> {
    let opened = open(start, env)?;
    let env = opened.env.as_str();
    let vault = opened.read_vault("read a secret")?;

    let value = vault
        .vars()
        .get(key)
        .ok_or_else(|| anyhow!("no secret named `{key}` in '{env}'"))?;
    eprintln!("warning: exposing the plaintext value of {key}");
    outln!("{value}")?;
    Ok(())
}

/// `bitfort unset KEY`: remove a secret and re-encrypt (write path).
pub fn unset(ui: &Ui, start: Option<&Path>, env: Option<&str>, key: &str, yes: bool) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    // Re-use the verified roster for re-encryption (see `set` for the rationale).
    let verified = opened.verified("unset")?;

    let identity = load_identity()?;
    let mut vault = open_vault(project, env, &identity, &verified, Use::Rewrite)?;
    // Reject an absent key before asking to confirm: there is nothing to remove.
    if !vault.vars().contains_key(key) {
        bail!("no secret named `{key}` in '{env}'");
    }
    if !ui.confirm(
        &format!("Remove secret `{key}` from '{env}'?"),
        yes,
        &format!("bitfort unset {key} --yes"),
    )? {
        ui.line(&ui.dim("aborted."))?;
        return Ok(());
    }
    vault.unset(key);
    project.save_vault(env, &vault, &verified.roster, &identity)?;

    outln!("Removed {key} from '{env}'.")?;
    Ok(())
}

/// `bitfort list`: print the vault's keys, never values (read path). On a terminal it
/// shows a titled, two-column table; piped (or in CI) it stays one key per line with no
/// chrome, because scripts depend on that shape.
pub fn list(ui: &Ui, start: Option<&Path>, env: Option<&str>) -> Result<()> {
    let opened = open(start, env)?;
    let env = opened.env.as_str();
    let vault = opened.read_vault("list secrets")?;

    if ui.json() {
        ui.emit_json(&json!({
            "environment": env,
            "keys": vault.vars().keys().collect::<Vec<_>>(),
        }))?;
        return Ok(());
    }

    if !ui.interactive() {
        if vault.vars().is_empty() {
            outln!("No secrets in '{env}'.")?;
        } else {
            for key in vault.vars().keys() {
                outln!("{key}")?;
            }
        }
        return Ok(());
    }

    if vault.vars().is_empty() {
        ui.line(&ui.dim(&format!("No secrets in '{env}'.")))?;
        return Ok(());
    }

    ui.line(&format!(
        "{}   {}",
        ui.bold(&format!("SECRETS · {env}")),
        ui.dim(&format!("{} keys", vault.vars().len()))
    ))?;
    ui.blank()?;
    let keys: Vec<&String> = vault.vars().keys().collect();
    let colw = keys.iter().map(|k| k.chars().count()).max().unwrap_or(0) + 2;
    let half = keys.len().div_ceil(2);
    for i in 0..half {
        match keys.get(half + i) {
            Some(right) => ui.line(&format!("  {}{}{right}", keys[i], pad(keys[i], colw)))?,
            None => ui.line(&format!("  {}", keys[i]))?,
        }
    }
    Ok(())
}

/// `bitfort run [--clean] -- <cmd>`: decrypt, inject secrets, and run the child,
/// propagating its exit code and forwarding signals (read path; docs/SPEC.md §7).
pub fn run(
    start: Option<&Path>,
    env: Option<&str>,
    clean: bool,
    command: &[String],
) -> Result<i32> {
    let opened = open(start, env)?;
    let vault = opened.read_vault("run")?;
    refuse_process_control_vars(&vault, "inject it into the child")?;

    crate::run::exec(vault.into_vars(), clean, command)
}

/// `bitfort env add <name>`: create a new environment - its own signed v1 roster and
/// empty vault - rooted at the same trust anchor (docs/SPEC.md §4.1, §5.1). Because a
/// new env's v1 must be self-signed by the pinned anchor, only the anchor holder can
/// create one.
pub fn env_add(start: Option<&Path>, name: &str) -> Result<()> {
    let project = discover(start)?;
    let mut config = project.load_config()?;
    // Validate before any file I/O; `add_env` re-checks as the authoritative core guard.
    config.check_env_addable(name)?;
    // The config list is not the truth. A merge that drops an `environments` entry leaves the
    // roster, chain, and vault on disk, and writing a fresh v1 over them destroys the
    // environment: its members lose access and every later command refuses the downgrade.
    if project.environment_exists(name) {
        bail!(
            "'{name}' already has files under {}\nIt is missing from config.toml - restore \
             the entry rather than re-creating the environment.",
            project.env_dir(name).display()
        );
    }

    let identity = load_identity()?;
    // v1 verification requires a maintainer whose two-key anchor equals the pinned anchor
    // (§5.1); only that identity can produce a verifiable roster for a fresh environment.
    if identity.anchor() != config.trust_anchor_fingerprint {
        bail!(
            "only the trust-anchor holder can create a new environment\n  your anchor:   {}\n  pinned anchor: {}",
            identity.anchor(),
            config.trust_anchor_fingerprint
        );
    }

    // Reuse the holder's existing display name so it stays consistent across environments.
    let holder_name =
        anchor_member_name(&project, &config, &identity).unwrap_or_else(|| resolve_name(None));
    // This name becomes the sole member of a fresh signed roster, so the same rule applies as
    // for an invite. A name reused from an older environment can predate the rule, so the
    // message says where it came from: the repair is in that roster, not in this command.
    bitfort_core::roster::validate_member_name(&holder_name).map_err(|e| {
        anyhow!(
            "{e}\nthe name comes from an existing environment's roster, or from $USER; correct \
             it there, then create the environment"
        )
    })?;
    let mut roster = Roster::new_v1(
        config.project_id.clone(),
        name,
        vec![Member {
            name: holder_name.clone(),
            enc_pubkey: identity.enc_pubkey(),
            sign_pubkey: identity.sign_pubkey(),
            role: Role::Maintainer,
            added_by: holder_name.clone(),
            added_at: clock::now_rfc3339(),
        }],
    );
    roster.sign(&identity, &holder_name)?;

    // Write the env's files first, then record it in config: an orphan env dir is inert
    // (resolve_env rejects anything not in config), but a config entry with no files would
    // break every command that touches the env.
    project.save_roster(name, &roster)?;
    project.save_vault(name, &Vault::new(name), &roster, &identity)?;
    config.add_env(name)?;
    project.save_config(&config)?;

    outln!("Created environment '{name}' with maintainer {holder_name}.")?;
    outln!("Add members to it with `bitfort member add <invite> --env {name}`.")?;
    Ok(())
}

/// `bitfort env list`: show every environment with its verification status (read path).
/// Terminal: a table with a default marker and colored status. Piped: the stable
/// `{env}{ (default)}  {status}` line per environment.
pub fn env_list(ui: &Ui, start: Option<&Path>) -> Result<()> {
    const NAME_W: usize = 16;
    const ROSTER_W: usize = 8;

    let project = discover(start)?;
    let config = project.load_config()?;

    if ui.json() {
        let envs: Vec<_> = config
            .environments
            .iter()
            .map(|env| {
                let mut o = json!({ "name": env, "default": *env == config.default_env });
                let verified = project.verify_roster(env);
                merge_roster_json(&mut o, verified.as_ref());
                if let Ok(v) = &verified {
                    o["rollback_enforced"] = json!(v.guard.is_enforced());
                }
                o
            })
            .collect();
        ui.emit_json(&json!({ "environments": envs }))?;
        return Ok(());
    }

    if !ui.interactive() {
        for env in &config.environments {
            let marker = if *env == config.default_env {
                " (default)"
            } else {
                ""
            };
            let status = match project.verify_roster(env) {
                Ok(v) => format!("verified, {} member(s)", v.roster.members.len()),
                Err(e) => format!("FAILED: {e}"),
            };
            outln!("{env}{marker}  {status}")?;
        }
        return Ok(());
    }

    ui.line(&ui.bold("ENVIRONMENTS"))?;
    ui.blank()?;
    ui.line(&ui.dim(&format!(
        "  {:<nw$} {:<rw$} STATUS",
        "NAME",
        "ROSTER",
        nw = NAME_W,
        rw = ROSTER_W
    )))?;
    for env in &config.environments {
        let default = *env == config.default_env;
        let name_plain = if default {
            format!("{env} *")
        } else {
            env.clone()
        };
        let name = if default {
            format!("{env} {}", ui.dim("*"))
        } else {
            env.clone()
        };
        let (level, roster_col, status) = match project.verify_roster(env) {
            Ok(v) => (
                Level::Ok,
                format!("v{}", v.roster.roster_version),
                format!("verified · {} member(s)", v.roster.members.len()),
            ),
            Err(_) => (Level::Fail, "-".to_string(), "unverified".to_string()),
        };
        ui.line(&format!(
            "  {name}{} {roster_col}{} {} {status}",
            pad(&name_plain, NAME_W),
            pad(&roster_col, ROSTER_W),
            ui.mark(level),
        ))?;
    }
    Ok(())
}

/// `bitfort member add <invite>`: a maintainer adds the identity from an invite blob to
/// the target env, bumps + re-signs the roster, and re-encrypts the vault so the new
/// member becomes a recipient (docs/SPEC.md §5.2). Write path.
pub fn member_add(
    start: Option<&Path>,
    env: Option<&str>,
    invite_blob: &str,
    maintainer: bool,
    name_override: Option<String>,
) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    let (identity, verified) = authorize_maintainer(&opened, "change membership")?;
    let current = &verified.roster;

    let invite = Invite::decode(invite_blob)?;
    // Untrusted input, pasted from a chat message. Reject malformed key material now, before
    // any file is written, so a bad key cannot leave the roster one version ahead of the vault.
    invite.validate_keys()?;
    // `Invite::decode` already checked the name inside the blob; this covers the override,
    // which reaches the signed roster by the same path.
    let name = name_override.unwrap_or_else(|| invite.name.clone());
    let name = name.trim().to_string();
    bitfort_core::roster::validate_member_name(&name)?;
    // Reject a member that would collide on identity (same signing key) or on name (which
    // `member rm` addresses by), either of which makes the roster ambiguous.
    if current.member_by_sign_pubkey(&invite.sign_pubkey).is_some() {
        bail!("that identity is already a member of '{env}'");
    }
    // Case-insensitively: `member rm` takes a name, and two members whose names differ only
    // in case read as one row to whoever runs it, so the wrong seat can be revoked.
    if let Some(existing) = current
        .members
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(&name))
    {
        bail!(
            "a member named '{}' already exists in '{env}'; pass --name to disambiguate",
            bitfort_core::roster::display_name(&existing.name)
        );
    }
    // And on the *encryption* key. Only the signing key was checked, so one decryption key
    // could hold two seats under different names - and `member rm` of one seat then left the
    // vault readable by the other, silently failing to revoke.
    if let Some(existing) = current
        .members
        .iter()
        .find(|m| m.enc_pubkey == invite.enc_pubkey)
    {
        bail!(
            "that encryption key is already in '{env}' as '{}'\nAdding it twice would make \
             `member rm` unable to revoke it.",
            bitfort_core::roster::display_name(&existing.name)
        );
    }

    // Sanitized, not validated: the acting name comes from the roster on disk, which an older
    // build may have written before the rule existed. Refusing it would leave that team unable
    // to change membership at all, while copying it raw would carry a forged row into the new
    // signed roster.
    let signer_name = bitfort_core::roster::display_name(&acting_member_name(current, &identity));
    let mut next = current.amend()?;
    next.members.push(Member {
        name: name.clone(),
        enc_pubkey: invite.enc_pubkey,
        sign_pubkey: invite.sign_pubkey,
        role: if maintainer {
            Role::Maintainer
        } else {
            Role::Member
        },
        added_by: signer_name.clone(),
        added_at: clock::now_rfc3339(),
    });
    next.sign(&identity, &signer_name)?;

    reencrypt_to_new_roster(project, env, &identity, &verified, &next)?;

    let role = if maintainer { "maintainer" } else { "member" };
    outln!(
        "Added {name} as {role} to '{env}' (roster v{}).",
        next.roster_version
    )?;
    outln!("Commit the change and open a PR so reviewers see the signed roster bump.")?;
    Ok(())
}

/// `bitfort member rm <name>`: a maintainer removes a member, bumps + re-signs the
/// roster, and re-encrypts so the removed key is no longer a recipient. Write path.
pub fn member_rm(
    ui: &Ui,
    start: Option<&Path>,
    env: Option<&str>,
    name: &str,
    yes: bool,
) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    let (identity, verified) = authorize_maintainer(&opened, "change membership")?;
    let current = &verified.roster;

    // Every message below echoes the argument, and a name typed here, or copied out of an
    // older roster, can carry an escape sequence. The lookup still compares the raw bytes.
    let shown = bitfort_core::roster::display_name(name);
    let target = current
        .members
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| anyhow!("no member named '{shown}' in '{env}'"))?;
    // Refuse to strip the last maintainer: a roster with none can never authorize a
    // successor and permanently bricks the chain (docs/SPEC.md §5.4). `verify` enforces
    // this too, but failing here gives a clearer message before any write.
    if target.role == Role::Maintainer && current.maintainers().count() == 1 {
        // Not "promote another": there is no command that changes an existing member's role,
        // so that advice was a dead end. A second maintainer can only arrive as a new member.
        bail!(
            "'{shown}' is the only maintainer of '{env}'; add a second one first with \
             `bitfort member add <invite> --maintainer`, then remove this one"
        );
    }
    // Removing yourself cannot work: the re-encrypted vault must be signed by a member of the
    // roster it is written for, and after this change you are not one. Revocation is someone
    // else's action anyway - a departing member should not be the last writer of the vault.
    if target.sign_pubkey == identity.sign_pubkey() {
        bail!(
            "'{shown}' is your own identity; a member cannot remove themselves from '{env}'.\n\
             Ask another maintainer to run this, so the re-encrypted vault is signed by \
             someone who stays."
        );
    }

    // The hint has to be runnable. A sanitized name does not match the roster entry, so where
    // the stored name is one the rule refuses, the hint names the flag instead of the member.
    let try_cmd = if bitfort_core::roster::validate_member_name(name).is_ok() {
        format!("bitfort member rm {name} --yes")
    } else {
        "bitfort member rm <name> --yes".to_string()
    };
    if !ui.confirm(
        &format!("Remove member '{shown}' from '{env}' and re-encrypt without their key?"),
        yes,
        &try_cmd,
    )? {
        ui.line(&ui.dim("aborted."))?;
        return Ok(());
    }

    // Sanitized for the same reason as in `member_add`: an older roster's name must not travel
    // into the roster this command signs.
    let signer_name = bitfort_core::roster::display_name(&acting_member_name(current, &identity));
    let mut next = current.amend()?;
    next.members.retain(|m| m.name != name);
    next.sign(&identity, &signer_name)?;

    reencrypt_to_new_roster(project, env, &identity, &verified, &next)?;

    outln!(
        "Removed {shown} from '{env}' (roster v{}).",
        next.roster_version
    )?;
    outln!(
        "The vault is re-encrypted without their key, but they may retain previously seen \
         values - run `bitfort rotate` and change any secrets you consider compromised."
    )?;
    Ok(())
}

/// `bitfort member list`: show the target env's roster and verification status (read
/// path). Terminal: a table with roles colored (maintainer bold, member dim), the local
/// identity marked `(you)`, and the verification state in the title. Piped: the stable
/// `{fingerprint}  {role}  {name}` line per member.
pub fn member_list(ui: &Ui, start: Option<&Path>, env: Option<&str>) -> Result<()> {
    const NAME_W: usize = 18;
    const ROLE_W: usize = 12;

    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    // Verify once and reuse: for the stderr warning, the title status, and (on success)
    // the member list itself - avoiding a second verify plus a redundant roster load.
    let verified = project.verify_roster(env);
    if let Err(e) = &verified {
        // Under `--json` the failure is carried in the payload (`verified:false` + `error`),
        // so a plain-text stderr line would just be inconsistent noise; skip it there.
        if !ui.json() {
            eprintln!("warning: roster verification failed: {e}");
        }
    }
    let roster = match &verified {
        Ok(v) => v.roster.clone(),
        Err(_) => project.load_roster(env)?,
    };

    if ui.json() {
        let me = keystore::load_identity().ok().map(|id| id.sign_pubkey());
        let members: Vec<_> = roster
            .members
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "role": format!("{:?}", m.role).to_lowercase(),
                    "fingerprint": bitfort_core::fingerprint_of(&m.enc_pubkey),
                    "you": me.as_ref().is_some_and(|k| *k == m.sign_pubkey),
                })
            })
            .collect();
        let mut obj = json!({ "environment": env, "members": members });
        merge_roster_json(&mut obj, verified.as_ref());
        ui.emit_json(&obj)?;
        return Ok(());
    }

    if !ui.interactive() {
        for m in &roster.members {
            // Sanitized at the display boundary: a roster written by an older build can hold a
            // newline, which prints as a row nobody added, or an escape that repaints the
            // terminal. anstream is no help here: it strips escapes off a TTY but never a
            // newline, and `CLICOLOR_FORCE` restores pass-through into a pipe.
            ui.line(&format!(
                "{}  {:<10}  {}",
                bitfort_core::fingerprint_of(&m.enc_pubkey),
                format!("{:?}", m.role).to_lowercase(),
                bitfort_core::roster::display_name(&m.name)
            ))?;
        }
        return Ok(());
    }

    let status = match &verified {
        Ok(v) => format!(
            "{}  {} {}",
            ui.dim(&format!("v{}", v.roster.roster_version)),
            ui.mark(Level::Ok),
            ui.styled(Level::Ok, "verified")
        ),
        Err(_) => format!(
            "{} {}",
            ui.mark(Level::Fail),
            ui.styled(Level::Fail, "unverified")
        ),
    };
    ui.line(&format!(
        "{}   {status}",
        ui.bold(&format!("ROSTER · {env}"))
    ))?;
    ui.blank()?;
    ui.line(&ui.dim(&format!(
        "  {:<nw$} {:<rw$} KEY FINGERPRINT",
        "NAME",
        "ROLE",
        nw = NAME_W,
        rw = ROLE_W
    )))?;

    // Mark the local identity, when one is available, without failing the listing if not.
    let me = keystore::load_identity().ok().map(|id| id.sign_pubkey());
    for m in &roster.members {
        let is_me = me.as_ref().is_some_and(|k| *k == m.sign_pubkey);
        // The table goes to a real terminal, where nothing strips an escape byte, so the
        // sanitizer is what keeps an older roster's name from repainting the screen.
        let safe = bitfort_core::roster::display_name(&m.name);
        let name_plain = if is_me {
            format!("{safe} (you)")
        } else {
            safe.clone()
        };
        let name = if is_me {
            format!("{safe} {}", ui.dim("(you)"))
        } else {
            safe.clone()
        };
        let role_str = format!("{:?}", m.role).to_lowercase();
        let role = match m.role {
            Role::Maintainer => ui.bold(&role_str),
            Role::Member => ui.dim(&role_str),
        };
        let fp = ui.dim(&bitfort_core::fingerprint_of(&m.enc_pubkey));
        ui.line(&format!(
            "  {name}{} {role}{} {fp}",
            pad(&name_plain, NAME_W),
            pad(&role_str, ROLE_W)
        ))?;
    }
    Ok(())
}

/// `bitfort rotate`: re-encrypt the vault to the current roster with fresh `age`
/// ciphertext and stamp `rotated_at` (docs/SPEC.md §8). Write path. It cannot change the
/// secret *values* themselves - that is a human step at each credential's source.
pub fn rotate(start: Option<&Path>, env: Option<&str>) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());
    let mut config = opened.config.clone();

    let verified = opened.verified("rotate")?;
    let identity = load_identity()?;
    // The one command that may read a vault older than the current roster: re-signing it is
    // exactly what this command is for, and it is the documented repair for an interrupted
    // membership change. It warns before it does so.
    let vault = open_vault(project, env, &identity, &verified, Use::Resign)?;

    // Re-encrypting produces a fresh file key and recipient stanzas for the current
    // roster, superseding any prior ciphertext. It also re-signs the payload at the current
    // `roster_version`, which is what re-syncs a vault left behind by an interrupted
    // membership change.
    project.save_vault(env, &vault, &verified.roster, &identity)?;
    config.rotated_at = Some(clock::now_rfc3339());
    project.save_config(&config)?;

    outln!(
        "Re-encrypted '{env}' vault to the current roster ({} member(s)).",
        verified.roster.members.len()
    )?;
    outln!(
        "This refreshes the ciphertext only. To invalidate values a departed member saw, \
         change the real credentials at their source and `bitfort set` the new values."
    )?;
    Ok(())
}

/// Which side of a merge conflict `resolve` keeps for a key both sides changed.
///
/// One value rather than a `--ours`/`--theirs` pair of bools: `(true, true)` is representable
/// there, and it fell into the "neither was given" arm, so only clap's `conflicts_with` kept
/// the two flags apart.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Ours,
    Theirs,
}

/// `bitfort resolve`: after a git merge/rebase leaves `vault.enc` conflicted, merge the two
/// sides against their common ancestor and re-encrypt one clean vault (docs/SPEC.md §4.5).
/// Disjoint edits merge automatically; a key changed on both sides needs `--ours` or
/// `--theirs`. Write path.
///
/// All three inputs come from git's index, never from the markers in the file - see
/// [`bitfort_core::Project::load_vault_conflict`] for why. So this command resolves the
/// conflict *git* has, and refuses when git has none, however the working file looks.
pub fn resolve(start: Option<&Path>, env: Option<&str>, side: Option<Side>) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env) = (&opened.project, opened.env.as_str());

    let verified = opened.verified("resolve")?;
    let identity = load_identity()?;

    let (base, ours, theirs) = match project.load_vault_conflict(env, &identity, &verified)? {
        VaultConflict::Sides { base, ours, theirs } => (base, ours, theirs),
        VaultConflict::NoRepository | VaultConflict::None => {
            return no_conflict_to_resolve(project, env)
        }
        VaultConflict::Incomplete {
            ancestor,
            ours,
            theirs,
        } => return Err(incomplete_conflict(env, ancestor, ours, theirs)),
    };

    // Git keeps the unmerged entry until the path is staged, so a second `resolve` reads the
    // same stages and would rebuild the vault from them - discarding every `set` made since
    // the first one, silently. The merged file has no markers, and that is the difference: it
    // means this conflict has already been settled in the working tree.
    if !project.vault_has_conflict_markers(env)? {
        outln!(
            "The '{env}' vault has already been resolved; leaving it alone.\nStage it to clear \
             the merge."
        )?;
        return Ok(());
    }

    // Both sides get the full check - signature, signer, project, environment, and version -
    // before anything is merged. A merge is otherwise the laundering path around every other
    // refusal: the output is re-signed at the current roster version, so a side this command
    // accepts becomes a vault every later read trusts.
    check_drift(&ours, &verified.roster, env, Use::Rewrite)
        .with_context(|| format!("our side of the '{env}' conflict cannot be merged"))?;
    check_drift(&theirs, &verified.roster, env, Use::Rewrite)
        .with_context(|| format!("their side of the '{env}' conflict cannot be merged"))?;
    let base = merge_base(base, &verified, env)?;

    let mut outcome = bitfort_core::resolve::merge_vars(
        base.as_ref().map(Vault::vars),
        ours.vars(),
        theirs.vars(),
    );
    if !outcome.conflicts.is_empty() {
        match side {
            Some(Side::Ours) => {} // `merged` already holds our side for conflicts
            Some(Side::Theirs) => {
                for c in &outcome.conflicts {
                    if let Some(value) = &c.theirs {
                        outcome.merged.insert(c.key.clone(), value.clone());
                    } else {
                        // Their side deleted it, so taking their side removes it.
                        outcome.merged.remove(&c.key);
                    }
                }
            }
            None => {
                eprintln!("Both sides changed these keys - re-run with --ours or --theirs:");
                for c in &outcome.conflicts {
                    eprintln!("  {} ({})", c.key, conflict_shape(c));
                }
                bail!("unresolved conflicting keys in '{env}'");
            }
        }
    }

    let vault = Vault::with_vars(env, outcome.merged)?;
    warn_oversized(&vault);
    project.save_vault(env, &vault, &verified.roster, &identity)?;

    outln!(
        "Resolved '{env}' vault: {} secret(s), {} conflict(s) settled.",
        vault.vars().len(),
        outcome.conflicts.len()
    )?;
    report_merge_effect(&ours, &vault)
}

/// Name every secret the merge added to our side, and every one it took away.
///
/// This is what makes a resurrection visible, and it does not depend on trusting the common
/// ancestor. A three-way merge is only as good as its ancestor, and whoever can push chooses
/// the branch point and therefore the ancestor: branching before a secret was first set makes
/// their side read as *adding* it, which is an ordinary merge with no conflict and no warning.
/// The tool cannot tell that from a teammate legitimately adding the same name. What it can do
/// is say which names changed hands, so the user who withdrew one sees it come back.
///
/// Names only. Counts alone read as success, and values would put plaintext on the terminal.
fn report_merge_effect(ours: &Vault, merged: &Vault) -> Result<()> {
    let names = |from: &Vault, missing_in: &Vault| -> Vec<String> {
        from.vars()
            .keys()
            .filter(|k| !missing_in.vars().contains_key(*k))
            .cloned()
            .collect()
    };
    for (label, keys) in [
        ("added by the other branch", names(merged, ours)),
        ("removed", names(ours, merged)),
    ] {
        if !keys.is_empty() {
            outln!("  {label}: {}", keys.join(", "))?;
        }
    }
    Ok(())
}

/// `bitfort status`: a one-screen readout of the environment's security posture -
/// roster verification, vault size, and git/gitignore state - plus the
/// single most useful next action. Read path: it verifies and reports but never writes
/// (docs/SPEC.md §5.5). All output degrades to plain ASCII off a TTY, so an MCP host or
/// script consuming it never sees escape codes.
pub fn status(ui: &Ui, start: Option<&Path>, env: Option<&str>) -> Result<()> {
    let opened = open(start, env)?;
    let (project, env, config) = (&opened.project, opened.env.as_str(), &opened.config);

    // Gather every posture fact once, up front, so the human readout and the `--json`
    // payload render from the same source (and `verify_roster`, the load-bearing and
    // expensive call, runs a single time).
    let roster = project.verify_roster(env);

    // The same classification `verify` gates on, so the readout and the gate can never
    // disagree about the same file.
    let vault_state = VaultState::read(project, env, roster.as_ref().ok());

    let guard = roster.as_ref().ok().map(|v| v.guard);
    let rollback_warning = guard.and_then(|g| g.warning());
    let gitignored = project.is_dotenv_gitignored();

    // The single highest-priority next action, worst posture first. Each source answers for
    // itself - `VaultState::next_step` sits beside the `match` tables the compiler already
    // checks - so a new state cannot be added here and forgotten. It was forgotten: this ran
    // as a chain of `matches!` arms, `Unreadable` had no arm, and a deleted vault printed its
    // failure line and then "all set".
    let next_step = if roster.is_err() {
        "roster does not verify - run `bitfort verify` and confirm the anchor matches the value published out-of-band"
    } else {
        vault_state
            .next_step()
            .or_else(|| guard.and_then(|g| g.unavailable()).map(|u| u.fix))
            .or_else(|| {
                (!gitignored).then_some(
                    "`.env*` is not gitignored - add it so a plaintext dotenv can't be committed",
                )
            })
            .unwrap_or("all set - inject secrets into a process with `bitfort run -- <cmd>`")
    };

    if ui.json() {
        let mut roster_json = json!({});
        merge_roster_json(&mut roster_json, roster.as_ref());
        ui.emit_json(&json!({
            "environment": env,
            "anchor": config.trust_anchor_fingerprint,
            "anchor_words": wordlist::anchor_words(&config.trust_anchor_fingerprint),
            "roster": roster_json,
            "vault": vault_state.json(),
            "rollback": {
                "enforced": guard.is_some_and(|g| g.is_enforced()),
                "warning": rollback_warning,
            },
            "dotenv_gitignored": gitignored,
            "next_step": next_step,
        }))?;
        return Ok(());
    }

    ui.header(&format!("BitFort · {env}"))?;
    ui.field("anchor", &config.trust_anchor_fingerprint)?;
    if let Some(words) = wordlist::anchor_words(&config.trust_anchor_fingerprint) {
        ui.field("words", &words)?;
    }
    match &roster {
        Ok(v) => ui.status(
            Level::Ok,
            "roster",
            &format!(
                "v{} verified · {} member(s)",
                v.roster.roster_version,
                v.roster.members.len()
            ),
        )?,
        Err(e) => ui.status(Level::Fail, "roster", &format!("unverified: {e}"))?,
    }
    let (vault_level, vault_msg) = vault_state.line();
    ui.status(vault_level, "vault", &vault_msg)?;
    let (rollback_level, rollback_msg) = match rollback_warning {
        Some(why) => (Level::Warn, why),
        None if roster.is_err() => (Level::Info, "not checked - the roster does not verify"),
        None => (Level::Ok, "enforced against committed history"),
    };
    ui.status(rollback_level, "rollback", rollback_msg)?;
    let (env_level, env_msg) = if gitignored {
        (Level::Ok, "gitignored")
    } else {
        (Level::Warn, "not gitignored")
    };
    ui.status(env_level, ".env", env_msg)?;

    ui.blank()?;
    ui.hint(next_step)?;
    Ok(())
}

/// What could be established about `vault.enc`: what it holds and who wrote it, or why not.
///
/// One classification behind two readouts. `status` reports posture and `verify` gates a pull
/// request, but they must agree about the same file - two classifiers would let `verify` pass
/// where `status` fails.
enum VaultState {
    Unlocked {
        secrets: usize,
        provenance: Option<Provenance>,
    },
    /// Readable and validly signed, but written for a different roster than `keys.json`.
    /// Both directions are failures, and [`Drift`] carries which one.
    Drifted(Drift),
    /// Readable and validly signed, but holding a variable that decides how a process runs, so
    /// `run`, `export` and `resolve` all refuse it. Carries the offending name.
    ProcessControl(String),
    /// This identity holds no seat in this environment.
    Locked,
    /// The file opened, but this roster did not authorize its contents.
    Unauthentic(String),
    /// The file is authentic, but its ciphertext is addressed to a different number of keys
    /// than the roster it was written for has members - somebody with a seat wrote a file
    /// somebody without one can open.
    WrongAudience(String),
    /// The file is missing or damaged - not a key problem.
    Unreadable(String),
    NoIdentity,
    NoRoster,
}

impl VaultState {
    /// Read and classify the environment's vault against an already-verified roster.
    fn read(project: &bitfort_core::Project, env: &str, roster: Option<&Verified>) -> Self {
        // Without a verified roster there is nothing to authenticate the payload against, so
        // stop before touching the keyring.
        let Some(verified) = roster else {
            return Self::NoRoster;
        };
        let Ok(identity) = keystore::load_identity() else {
            return Self::NoIdentity;
        };
        match project.load_vault(env, &identity, verified) {
            Ok(vault) => {
                // Ahead of drift in this readout: both are failures and both are refused, but
                // this one names a value someone put in the vault, which is the more specific
                // thing to act on. The gate has to see it either way (docs/SPEC.md §5.5).
                if let Some(key) = vault.process_control_key() {
                    return Self::ProcessControl(key.clone());
                }
                match vault.drift(&verified.roster) {
                    Drift::Current => Self::Unlocked {
                        secrets: vault.vars().len(),
                        provenance: vault.provenance().cloned(),
                    },
                    drift => Self::Drifted(drift),
                }
            }
            Err(bitfort_core::Error::VaultOrigin(why)) => Self::Unauthentic(why),
            // Authentic author, wrong audience. Kept apart from `Unauthentic` because the two
            // call for different actions: distrust the values, against remove the extra key.
            Err(bitfort_core::Error::VaultAudience(why)) => Self::WrongAudience(why),
            // Only a missing seat is benign. A missing or damaged file is a failure, and
            // reporting it as a key problem would blame the wrong thing.
            Err(bitfort_core::Error::NotARecipient) => Self::Locked,
            Err(e) => Self::Unreadable(e.to_string()),
        }
    }

    /// Whether this state must fail `verify`. The gate reports exactly what the read paths
    /// would refuse, so every drifted vault counts: both directions are refused now.
    fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::Unauthentic(_)
                | Self::WrongAudience(_)
                | Self::Unreadable(_)
                | Self::ProcessControl(_)
                | Self::Drifted(Drift::Behind { .. } | Drift::Ahead { .. })
        )
    }

    /// The one-line readout: severity and message, shared by `status` and `verify`.
    fn line(&self) -> (Level, String) {
        match self {
            Self::Unlocked {
                secrets,
                provenance,
            } => {
                let mut msg = format!("{secrets} secret(s)");
                // The signature is inside the ciphertext, where no diff shows it. This line is
                // where a reviewer sees who signed what they are about to trust.
                if let Some(p) = provenance {
                    msg.push_str(&format!(
                        " · signed by {} for roster v{} on {}",
                        bitfort_core::roster::display_name(&p.signer),
                        p.roster_version,
                        p.written_at
                    ));
                }
                (Level::Ok, msg)
            }
            Self::Drifted(Drift::Behind { vault, roster }) => (
                Level::Fail,
                format!(
                    "written for roster v{vault}, but keys.json is v{roster} - refused by \
                     every read path"
                ),
            ),
            Self::Drifted(Drift::Ahead { vault, roster }) => (
                Level::Fail,
                format!(
                    "written for roster v{vault}, but keys.json is v{roster} - keys.json is \
                     older than the vault, so it has been rolled back or replaced"
                ),
            ),
            // `Current` never reaches here: it is classified as `Unlocked`.
            Self::Drifted(Drift::Current) => (Level::Ok, "current".to_string()),
            Self::Locked => (
                Level::Warn,
                "locked - this identity holds no seat here".to_string(),
            ),
            Self::ProcessControl(key) => (
                Level::Fail,
                format!(
                    "holds `{key}`, which controls how a process runs - refused by `run`, \
                     `export` and `resolve`"
                ),
            ),
            Self::Unauthentic(why) => (Level::Fail, why.clone()),
            Self::WrongAudience(why) => (Level::Fail, why.clone()),
            Self::Unreadable(why) => (Level::Fail, format!("unreadable - {why}")),
            Self::NoIdentity => (
                Level::Warn,
                "locked - no local identity (run `bitfort keygen`)".to_string(),
            ),
            Self::NoRoster => (
                Level::Info,
                "not read - the roster does not verify, so the vault cannot be authenticated"
                    .to_string(),
            ),
        }
    }

    /// The single next action this state calls for, or `None` when the vault is healthy and
    /// the caller should look at the next source of advice. A `match`, not a chain, so a new
    /// variant fails to compile until it is answered here too.
    fn next_step(&self) -> Option<&'static str> {
        match self {
            Self::Unauthentic(_) => Some(
                "the vault was not written by a member of this roster - restore it from git history and treat every value in it as compromised",
            ),
            Self::WrongAudience(_) => Some(
                "the vault is encrypted to a key its roster does not list - somebody with a seat addressed it to somebody without one; treat every value in it as compromised and rotate the credentials",
            ),
            Self::ProcessControl(_) => Some(
                "the vault holds a variable that controls how a process runs - `bitfort run` and `bitfort export` refuse it; remove it with `bitfort unset`",
            ),
            Self::Unreadable(_) => Some(
                "the vault is missing or damaged - restore it from git history; `bitfort verify` fails on this state too",
            ),
            Self::Drifted(Drift::Behind { .. }) => Some(
                "the vault predates the current roster - re-sign it with `bitfort rotate` once you have checked what it holds, or restore the vault you want from git history first",
            ),
            Self::Drifted(Drift::Ahead { .. }) => Some(
                "keys.json is older than the vault - check out `.bitfort` whole, at one revision, so the roster, the chain and the vault come from the same commit",
            ),
            // Nothing to fix, or nothing this readout can fix: a missing local identity and an
            // unverified roster are already reported by their own lines.
            Self::Unlocked { .. } | Self::Drifted(Drift::Current) => None,
            Self::Locked | Self::NoIdentity | Self::NoRoster => None,
        }
    }

    /// The `--json` payload, one shape for both commands.
    fn json(&self) -> serde_json::Value {
        match self {
            Self::Unlocked {
                secrets,
                provenance,
            } => json!({
                "unlocked": true,
                "secrets": secrets,
                "written_by": provenance.as_ref().map(|p| &p.signer),
                "written_at": provenance.as_ref().map(|p| &p.written_at),
                "roster_version": provenance.as_ref().map(|p| p.roster_version),
            }),
            Self::Drifted(Drift::Behind { vault, roster } | Drift::Ahead { vault, roster }) => {
                json!({
                    "unlocked": false,
                    "reason": "drifted",
                    "roster_version": vault,
                    "current_roster_version": roster,
                })
            }
            Self::Drifted(Drift::Current) => json!({ "unlocked": false, "reason": "current" }),
            Self::Locked => json!({ "unlocked": false, "reason": "locked" }),
            Self::ProcessControl(key) => {
                json!({ "unlocked": false, "reason": "process-control", "key": key })
            }
            Self::Unauthentic(why) => {
                json!({ "unlocked": false, "reason": "unauthentic", "error": why })
            }
            Self::WrongAudience(why) => {
                json!({ "unlocked": false, "reason": "wrong-audience", "error": why })
            }
            Self::Unreadable(why) => {
                json!({ "unlocked": false, "reason": "unreadable", "error": why })
            }
            Self::NoIdentity => json!({ "unlocked": false, "reason": "no-identity" }),
            Self::NoRoster => json!({ "unlocked": false, "reason": "unverified-roster" }),
        }
    }
}

// --- helpers ---------------------------------------------------------------

/// Merge the roster half of a `--json` payload into `obj`, in the one shape every command
/// emits it.
///
/// `member_count` is a count everywhere; `members` is reserved for the array `member list`
/// emits. The two used to share the key `members`, so a consumer reading it had to know which
/// command produced the payload.
fn merge_roster_json(
    obj: &mut serde_json::Value,
    verified: Result<&Verified, &bitfort_core::Error>,
) {
    obj["verified"] = json!(verified.is_ok());
    match verified {
        Ok(v) => {
            obj["roster_version"] = json!(v.roster.roster_version);
            obj["member_count"] = json!(v.roster.members.len());
        }
        Err(e) => obj["error"] = json!(e.to_string()),
    }
}

/// The three things every project command resolves before it can do anything: the project,
/// its config, and the target environment. Extracted because the prologue appeared at
/// seventeen call sites and the verify-or-refuse clause at five, differing only in a verb.
struct Opened {
    project: bitfort_core::Project,
    config: Config,
    env: String,
}

/// Locate the project and resolve the target environment.
fn open(start: Option<&Path>, env: Option<&str>) -> Result<Opened> {
    let project = discover(start)?;
    let config = project.load_config()?;
    let env = project.resolve_env(env, &config)?;
    Ok(Opened {
        project,
        config,
        env,
    })
}

impl Opened {
    /// Verify the roster, refusing on failure, and report an anti-rollback witness that could
    /// not run here. `action` names what is being refused.
    ///
    /// Every path verifies now, reads included. The old design warned and continued on read
    /// paths because the chain was reconstructed from git history, which is unavailable in a
    /// shallow clone or outside a repository. The chain lives in `chain.json` now, so
    /// verification always works and there is nothing left to degrade to - and a read path
    /// that continues past a failed roster is exactly how a forged roster reaches `run`.
    ///
    /// The rollback warning belongs here rather than at the read paths: `set`, `import`,
    /// `rotate`, `resolve` and the membership commands all change the roster or the vault in a
    /// shallow clone, and they used to do it with no word that anti-rollback was off.
    fn verified(&self, action: &str) -> Result<Verified> {
        let verified = self
            .project
            .verify_roster(&self.env)
            .with_context(|| format!("roster verification failed; refusing to {action}"))?;
        if let Some(why) = verified.guard.warning() {
            eprintln!("warning: {why}");
        }
        Ok(verified)
    }

    /// The whole prologue of a read command: verify the roster, load the identity, and open
    /// the vault against that roster. `run`, `get`, `list` and `export` differ only in the
    /// verb they name when refusing.
    fn read_vault(&self, action: &str) -> Result<Vault> {
        let verified = self.verified(action)?;
        let identity = load_identity()?;
        open_vault(&self.project, &self.env, &identity, &verified, Use::Read)
    }
}

/// What a caller is about to do with a vault, which decides how it must treat a vault whose
/// `roster_version` is not the roster's (see [`Drift`] for what the two directions mean).
#[derive(Clone, Copy, PartialEq)]
enum Use {
    /// Decrypt and stop, re-encrypting nothing: `run`, `get`, `list`, `export`.
    Read,
    /// Re-encrypt through this roster, or through one derived from it: `set`, `unset`,
    /// `import`, `resolve`, and both membership commands. A vault ahead of `keys.json` is
    /// refused for all of them, because the roster they would re-encrypt to is built from a
    /// `keys.json` that is not the newest one this environment has had.
    Rewrite,
    /// Deliberately re-sign an older vault against this roster. `rotate`, and only `rotate`.
    Resign,
    /// Read as the common ancestor of a merge, contributing no value to what is written:
    /// `resolve`, and only `resolve`. Its own cell because an ancestor is *expected* to
    /// predate a membership change, so the refusal the other three apply to a vault behind
    /// the roster would wedge every merge that spans one.
    Ancestor,
}

/// Apply the drift policy for `intent` to an already-decrypted vault, warning or refusing.
///
/// One definition, called by every path - the one that reads `vault.enc` from disk and the
/// one that takes a side out of a merge conflict. `resolve` is where a second copy would
/// cost the most: its output is re-signed at the current version, so a side it accepts
/// becomes a vault every later read trusts.
fn check_drift(vault: &Vault, roster: &Roster, env: &str, intent: Use) -> Result<()> {
    // Matched as a pair rather than as guarded arms over the drift alone. The policy is a
    // table of four intents against three drift states, and written as guards the cells that
    // fell through to a catch-all were invisible - a reader had to simulate the arm order to
    // learn what `Ahead` + `Resign` did. Every cell is named here, so adding a fifth intent
    // does not compile until each one has been decided.
    match (vault.drift(roster), intent) {
        (Drift::Current, _) => Ok(()),

        // An ancestor behind the roster is the ordinary case, not a fault: it precedes both
        // sides of the merge, so it precedes any membership change between them. Accepting it
        // is safe for the reason the intent exists - no value in the merged result comes from
        // the ancestor, only the knowledge of which keys existed before the branches diverged.
        (Drift::Behind { .. }, Use::Ancestor) => Ok(()),

        // Older than the roster: an amendment publishes `keys.json` before `vault.enc`, so
        // this is the state a crash between them leaves - and it is also what an older vault
        // restored by hand looks like, which may hold values a removed member knows. A
        // deliberate re-sign is the repair for both, and it says so first.
        (
            Drift::Behind {
                vault: from,
                roster: to,
            },
            Use::Resign,
        ) => {
            eprintln!(
                "warning: re-signing the '{env}' vault from roster v{from} to v{to}; check that \
                 it does not hold values a removed member knows"
            );
            // Naming the writer matters most when they are the member who was removed, which is
            // exactly what a crash inside `member rm` leaves: their file is authentic for the
            // roster it names, and `rotate` is about to adopt its contents.
            if let Some(p) = vault.provenance() {
                if roster.member_by_sign_pubkey(&p.sign_pubkey).is_none() {
                    eprintln!(
                        "warning: it was written by '{}', who is not in roster v{to}",
                        bitfort_core::roster::display_name(&p.signer)
                    );
                }
            }
            Ok(())
        }
        (Drift::Behind { vault, roster }, Use::Read | Use::Rewrite) => Err(Failure::hinted(
            format!(
                "the '{env}' vault was written for roster v{vault}, but keys.json is \
                 v{roster}.\nIt predates a membership change, so it may hold values a removed \
                 member knows, and it is refused. Re-signing it against the current roster \
                 completes an interrupted change; if the vault you want is a different one, \
                 restore it from git history first."
            ),
            "bitfort rotate",
        )),

        // Newer than the roster, which no write path produces: `keys.json` is not the newest
        // roster this environment has had, so it was rolled back, checked out at an older
        // revision, or substituted. Reads refuse it too, and that is the point - a roster
        // downgrade is what the anti-rollback ceiling exists to catch, and outside a git
        // repository or in a shallow clone the ceiling cannot run. A vault stamped for a
        // version `keys.json` does not have is the only local evidence left, so serving its
        // values would hand a removed member's file to `run`. `Resign` is refused with the
        // rest: `rotate` re-encrypts to the roster on disk, which is the rolled-back one. So
        // is `Ancestor`: no real merge produces an ancestor newer than both its sides, so this
        // is the downgrade signal rather than an ordinary old file, and the ancestor decides
        // which side of the merge wins.
        (Drift::Ahead { vault, roster }, _) => Err(Failure::hinted(
            format!(
                "the '{env}' vault was written for roster v{vault}, but keys.json is \
                 v{roster}.\nkeys.json is older than the vault, so it has been rolled back, \
                 checked out at an older revision, or replaced - and a roster that old may \
                 still list a member v{vault} removed. Check out `.bitfort` whole, at one \
                 revision, so keys.json, chain.json and vault.enc come from the same commit. \
                 Do not `rotate`: it re-encrypts to the roster on disk."
            ),
            "git checkout HEAD -- .bitfort",
        )),
    }
}

/// Report that git has no conflict for this vault, and refuse when the file says otherwise.
///
/// The two states read the same on disk and mean opposite things. A clean vault is simply
/// nothing to do. A vault carrying conflict markers that git has no unmerged entry for is a
/// merge state that was dropped (`git add` on the path, or a committed merge) or that never
/// came from a merge at all - and the inputs `resolve` needs are gone with it. Merging what
/// the file holds is what this command no longer does, because those bytes are chosen by
/// whoever wrote them, so the only honest answer is to refuse and name the way back.
fn no_conflict_to_resolve(project: &bitfort_core::Project, env: &str) -> Result<()> {
    if !project.vault_has_conflict_markers(env)? {
        outln!("No merge conflict in the '{env}' vault; nothing to resolve.")?;
        return Ok(());
    }
    // Outside a repository there is no index to restore a merge from, so `git checkout
    // --merge` would be the wrong thing to name.
    if !project.in_git_work_tree() {
        return Err(Failure::hinted(
            format!(
                "the '{env}' vault carries conflict markers, but this project is not in a git \
                 repository.\nA merge is resolved from what git recorded for it, never from the \
                 markers in the file, so there is nothing here to merge. Take the copy you want \
                 from wherever this file came from."
            ),
            "age -d -i <your key> vault.enc",
        ));
    }
    Err(Failure::hinted(
        format!(
            "the '{env}' vault carries conflict markers, but git has no conflict for it.\nA \
             merge is resolved from what git recorded for it, never from the markers in the \
             file, so there is nothing here to merge. Restoring the conflict brings back the \
             two sides and their common ancestor; if the merge was already committed, redo it."
        ),
        "git checkout --merge -- <path to vault.enc>",
    ))
}

/// Refuse a conflict git holds that does not have two versions to merge, naming what it does
/// hold and the git command that settles it.
///
/// Every shape here needs a decision the merge cannot make: whether the environment still
/// exists. And the "keep it" command is `git add`, not `git checkout --ours` - in a
/// modify/delete conflict the surviving side is already in the working tree, so a checkout is
/// a no-op that leaves the path unmerged and the next `git commit` refusing.
fn incomplete_conflict(env: &str, ancestor: bool, ours: bool, theirs: bool) -> anyhow::Error {
    let what = match (ancestor, ours, theirs) {
        (true, true, false) => "it was deleted on their branch and changed on ours",
        (true, false, true) => "it was deleted on our branch and changed on theirs",
        (true, false, false) => "both branches deleted it, or renamed it apart",
        (false, true, false) => "only our branch has one",
        (false, false, true) => "only their branch has one",
        // `load_vault_conflict` builds this only from an unmerged entry that is missing a
        // side, so every reachable shape is named above.
        _ => "git holds only part of it",
    };
    // With no copy on either side there is nothing to stage, so `git rm` is the only move.
    let (decision, hint) = match (ours, theirs) {
        (false, false) => (
            "Accept the deletion with `git rm`, then commit the merge.".to_string(),
            "git rm <path to vault.enc>",
        ),
        _ => (
            format!(
                "Decide whether the environment still exists. Keep {} copy by staging it with \
                 the command below, or accept the deletion with `git rm`, then commit the merge.",
                if ours { "our" } else { "their" }
            ),
            "git add <path to vault.enc>",
        ),
    };
    Failure::hinted(
        format!("there are not two versions of the '{env}' vault to merge: {what}.\n{decision}"),
        hint,
    )
}

/// Apply this layer's policy to the common ancestor core authenticated, and warn when there
/// is none to merge against.
///
/// Both no-ancestor cases warn, and neither is safe. It is tempting to read an add/add
/// conflict as harmless - both branches created the vault, so what could have been deleted
/// between them? - and that reading is wrong. Git reports no stage 1 when the *merge base
/// commit* does not hold the path, which is what any branch taken before the vault existed
/// produces. Its side can still carry a vault restored from history, and the two-way union
/// then brings back a secret the other branch withdrew (finding 1.7). Reproduced.
fn merge_base(base: MergeBase, verified: &Verified, env: &str) -> Result<Option<Vault>> {
    let union = "so both sides are merged whole, and a secret `unset` on one branch can come \
                 back. Check the summary below against what you expect to be in this \
                 environment";
    match base {
        MergeBase::Found(vault) => {
            check_drift(&vault, &verified.roster, env, Use::Ancestor).with_context(|| {
                format!("the common ancestor of the '{env}' conflict cannot be merged against")
            })?;
            Ok(Some(*vault))
        }
        MergeBase::Absent => {
            eprintln!(
                "warning: the two branches have no common version of the '{env}' vault - one of \
                 them starts before the vault existed - {union}."
            );
            Ok(None)
        }
        MergeBase::Unusable(why) => {
            eprintln!(
                "warning: the common ancestor of the '{env}' vault cannot be read ({why}), {union}."
            );
            Ok(None)
        }
    }
}

/// How a conflicting key differs, for the list a user must choose a side from. Says which
/// side deleted it, and quotes no value.
fn conflict_shape(conflict: &bitfort_core::resolve::Conflict) -> &'static str {
    match (conflict.ours.is_some(), conflict.theirs.is_some()) {
        (false, true) => "deleted here, changed on theirs",
        (true, false) => "changed here, deleted on theirs",
        // Both present is the ordinary case; both absent agrees, so the merge never reports it.
        _ => "changed on both sides",
    }
}

/// Read the environment's vault, authenticate it against `verified`, and apply the drift
/// policy for `intent`.
fn open_vault(
    project: &bitfort_core::Project,
    env: &str,
    identity: &Identity,
    verified: &Verified,
    intent: Use,
) -> Result<Vault> {
    let vault = project.load_vault(env, identity, verified)?;
    check_drift(&vault, &verified.roster, env, intent)?;
    Ok(vault)
}

fn discover(start: Option<&Path>) -> Result<bitfort_core::Project> {
    let start = match start {
        Some(d) => d.to_path_buf(),
        None => std::env::current_dir().context("cannot determine current directory")?,
    };
    bitfort_core::Project::discover(&start).map_err(|e| {
        // `bitfort init` fixes a missing project, not an unresolvable `--dir`; withhold the
        // hint when the start path itself doesn't exist so we don't suggest the wrong fix.
        if start.exists() {
            Failure::hinted(e.to_string(), "bitfort init")
        } else {
            e.into()
        }
    })
}

/// Load the identity for read/write paths, adding a hint about the headless path when
/// none is configured (docs/SPEC.md §3.1).
fn load_identity() -> Result<Identity> {
    keystore::load_identity().map_err(|e| {
        Failure::hinted(
            format!(
                "no identity available: {e}\nA local key is needed here; in CI/headless set \
                 BITFORT_IDENTITY and BITFORT_SIGN_IDENTITY."
            ),
            "bitfort keygen",
        )
    })
}

/// Adopt the existing identity if one is configured, else generate and store a new one.
/// A keyring backend failure (e.g. no Secret Service on a headless box) is surfaced with
/// the headless-path hint rather than a raw error (docs/SPEC.md §3.1).
fn acquire_identity() -> Result<Identity> {
    match keystore::find_identity() {
        Ok(Some(id)) => Ok(id),
        Ok(None) => {
            let id = Identity::generate()?;
            keystore::store_identity(&id)?;
            Ok(id)
        }
        Err(e) => Err(anyhow!(
            "{e}\nNo usable identity source. On a headless box set BITFORT_IDENTITY and \
             BITFORT_SIGN_IDENTITY; on a dev machine ensure the OS keyring is available."
        )),
    }
}

/// Verify the target env's roster and confirm the local identity is a maintainer in it -
/// the shared precondition for every roster-mutating command (docs/SPEC.md §5.2-§5.4).
/// Returns the local identity and the verified current roster.
fn authorize_maintainer(opened: &Opened, action: &str) -> Result<(Identity, Verified)> {
    let current = opened.verified(action)?;
    let identity = load_identity()?;
    let sign_pubkey = identity.sign_pubkey();
    let is_maintainer = current
        .roster
        .member_by_sign_pubkey(&sign_pubkey)
        .is_some_and(|m| m.role == Role::Maintainer);
    if !is_maintainer {
        bail!(
            "only a maintainer of '{}' can change its membership",
            opened.env
        );
    }
    Ok((identity, current))
}

/// The display name the acting identity uses in the current roster (for the signature and
/// `added_by`), falling back to `$USER` if somehow absent.
fn acting_member_name(current: &Roster, identity: &Identity) -> String {
    let sign_pubkey = identity.sign_pubkey();
    current
        .member_by_sign_pubkey(&sign_pubkey)
        .map(|m| m.name.clone())
        .unwrap_or_else(|| resolve_name(None))
}

/// Persist a roster amendment: record the superseded roster in the chain, write the new
/// roster, and re-encrypt the vault to it. The vault is decrypted with `identity` (a current
/// recipient) and re-encrypted to `next`, so added members gain access and removed ones lose
/// it.
///
/// All three files land through one staged write, which is also where the order and the
/// crash-window reasoning live: see `Project::commit_amendment`.
///
/// `Invite::validate_keys` rejects malformed key material before any of it, so a bad
/// `enc_pubkey` fails while every file still holds its old bytes.
fn reencrypt_to_new_roster(
    project: &bitfort_core::Project,
    env: &str,
    identity: &Identity,
    current: &Verified,
    next: &Roster,
) -> Result<()> {
    // The vault on disk was written for `current`, so it authenticates against that roster;
    // it is re-signed for `next` on the way back out. Every membership command re-encrypts,
    // so every one of them treats a vault that is not `current`'s the same way.
    let vault = open_vault(project, env, identity, current, Use::Rewrite)?;
    project.commit_amendment(env, &current.roster, next, &vault, identity)?;
    Ok(())
}

/// The display name the anchor holder already uses in an existing environment (matched
/// by signing key), so new environments reuse it instead of re-deriving from `$USER`.
fn anchor_member_name(
    project: &bitfort_core::Project,
    config: &Config,
    identity: &Identity,
) -> Option<String> {
    let sign_pubkey = identity.sign_pubkey();
    for env in &config.environments {
        if let Ok(roster) = project.load_roster(env) {
            if let Some(m) = roster.member_by_sign_pubkey(&sign_pubkey) {
                return Some(m.name.clone());
            }
        }
    }
    None
}

fn resolve_name(explicit: Option<String>) -> String {
    // Filter each source as it is tried. Filtering only the final Option let a set-but-empty
    // `USER` win the `or_else` chain and then fall straight through to "owner", never
    // reaching `USERNAME`.
    let usable = |s: String| {
        let trimmed = s.trim().to_string();
        Some(trimmed).filter(|t| !t.is_empty())
    };
    // A derived default is not something the user typed, so a `$USER` the name rule refuses
    // falls through to the next source instead of failing the command. An explicit `--name`
    // is returned as given, and the caller refuses it, because there the user can fix it.
    let derived = |var: &str| {
        std::env::var(var)
            .ok()
            .and_then(usable)
            .filter(|n| bitfort_core::roster::validate_member_name(n).is_ok())
    };
    explicit
        .and_then(usable)
        .or_else(|| derived("USER"))
        .or_else(|| derived("USERNAME"))
        .unwrap_or_else(|| "owner".to_string())
}

/// Spaces to pad `plain`'s visible width out to `width`. Used for table columns whose
/// rendered cells may carry ANSI color, which would make `{:<width$}` misalign.
fn pad(plain: &str, width: usize) -> String {
    " ".repeat(width.saturating_sub(plain.chars().count()))
}

/// Refuse to *store* a variable that decides how a process runs (docs/SPEC.md §7), for `set`
/// and `import`. The earlier, friendlier half of the rule: a name that could never be used
/// does not reach the vault in the first place.
fn refuse_process_control(key: &str) -> Result<()> {
    if !bitfort_core::vault::is_process_control_key(key) {
        return Ok(());
    }
    Err(anyhow!(
        "`{key}` controls how a process runs, not what it reads, so the vault will not hold \
         it.\nAnyone who can write the vault could otherwise run their own code in every \
         teammate's `bitfort run`. Set it in the environment you launch bitfort from instead."
    ))
}

/// Refuse to *use* a vault that already holds such a variable, for every command that turns
/// vault contents into a process environment. `action` names what is refused.
///
/// `set` and `import` cannot store one, so reaching this takes a member writing the payload
/// through `bitfort-core` directly - which is the attacker the rule exists for, since a
/// signature identifies a vault's author and does not license that author to run code on a
/// teammate's machine. Three commands qualify, not one: `run` injects the values into a child,
/// `export` emits text that `eval` or a dotenv loader turns into the same environment a step
/// later, and `resolve` would re-sign such a name out of a hostile conflict side under the
/// local identity, making it look authentic from then on.
///
/// `bitfort-core` still *stores* the name deliberately, so a vault holding one stays readable
/// and `list` and `status` can show what has to be removed.
fn refuse_process_control_vars(vault: &Vault, action: &str) -> Result<()> {
    let Some(key) = vault.process_control_key() else {
        return Ok(());
    };
    Err(Failure::hinted(
        format!(
            "the vault holds `{key}`, which controls how a process runs rather than what it \
             reads.\nWhoever wrote it could otherwise run their own code wherever these values \
             land, so bitfort refuses to {action}. Remove it from the vault; if the process \
             really needs it, set it in the environment you launch bitfort from."
        ),
        format!("bitfort unset {key}"),
    ))
}

/// Read the value for `key` when the assignment carried none.
///
/// On a terminal, prompt without echo through `/dev/tty` - gated on stdin rather than on
/// [`Ui::can_prompt`], because the prompt does not use stdout and stays correct under
/// `bitfort set KEY > file`. Off a terminal, take the value from stdin: without this there
/// is no headless way to set a secret except putting it in argv, where the whole machine can
/// read it out of the process list. `rpassword` would fail there anyway, with
/// `Device not configured` on a host with no controlling terminal, or by ignoring the
/// redirect and reading the terminal on a host that has one.
///
/// Everything stdin holds is the value, minus one trailing newline, so a multi-line secret
/// survives and `echo "$SECRET" | bitfort set KEY` does not store the shell's newline.
fn read_value(ui: &Ui, key: &str) -> Result<String> {
    if ui.stdin_is_terminal() {
        return rpassword::prompt_password(format!("Value for {key}: "))
            .context("failed to read value");
    }
    use std::io::Read as _;

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("failed to read the value from stdin")?;
    // The line ending comes off before the emptiness test, not after: `echo |` and
    // `echo "$UNSET" |` both send exactly "\n", and that is the same mistake as sending
    // nothing. `\r` is only part of the ending when a `\n` followed it; a lone trailing
    // `\r` belongs to the value.
    let value = match buf.strip_suffix('\n') {
        Some(line) => line.strip_suffix('\r').unwrap_or(line),
        None => buf.as_str(),
    };
    if value.is_empty() {
        // Naming the key is safe; naming what stdin held is not.
        return Err(Failure::hinted(
            format!(
                "no value for `{key}` on stdin\nstdin is not a terminal, so the value has to \
                 be piped in; write `bitfort set {key}=` to store an empty one"
            ),
            format!("printf %s \"$SECRET\" | bitfort set {key}"),
        ));
    }
    Ok(value.to_string())
}

fn warn_oversized(vault: &Vault) {
    for key in vault.oversized_keys() {
        eprintln!(
            "warning: {key} exceeds {} KiB; oversized values can exceed OS env limits at spawn",
            VALUE_SIZE_WARN / 1024
        );
    }
}
