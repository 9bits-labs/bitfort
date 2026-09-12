//! The encrypted secret store. A [`Vault`] is a set of key/value secrets for one
//! environment, serialized as JCS-canonical JSON and encrypted with `age` to every
//! member's recipient, then ASCII-armored so Git renders text diffs. See docs/SPEC.md §4.4.
//!
//! **The payload is signed, and the signature lives inside the ciphertext.** Encryption
//! alone authenticates nothing here: every `enc_pubkey` in `keys.json` is public and
//! committed, so anyone with repo write access can encrypt a file to the whole roster and
//! overwrite `vault.enc` with it. Without a signature that forgery decrypts cleanly and
//! `run` injects the attacker's values (`LD_PRELOAD`, `NODE_OPTIONS`, ...) into the child.
//! [`Vault::decrypt`] therefore verifies the payload signature against the verified roster
//! and refuses a vault no member of that roster wrote.
//!
//! Sign-then-encrypt, in one payload rather than a sibling file: a vault without a
//! signature is not representable on disk, so the format fails closed by construction. The
//! file stays a plain `age` document, so `age -d -i <key> vault.enc` remains the break-glass
//! path.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::chain::Chain;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::roster::{Roster, Signature};

/// Current on-disk payload schema.
pub const SCHEMA_VERSION: u32 = 1;

/// Domain-separation tag prepended to the JCS bytes before signing, so a vault signature
/// can never be confused with a signature over a roster or any other BitFort payload.
const SIGNING_DOMAIN: &[u8] = b"bitfort-vault-v1\n";

/// Values larger than this (bytes) are flagged by callers; oversized env vars can
/// exceed the OS `ARG_MAX`/env limits when spawning the child (docs/SPEC.md §4.4).
pub const VALUE_SIZE_WARN: usize = 512 * 1024;

/// Variable names that decide what a process *runs* rather than what it reads, matched
/// exactly.
const PROCESS_CONTROL_NAMES: &[&str] = &["PATH", "NODE_OPTIONS", "PYTHONPATH", "PERL5LIB"];

/// The same, matched as a prefix: the dynamic loaders (`LD_PRELOAD`, `LD_AUDIT`,
/// `DYLD_INSERT_LIBRARIES`, ...), git's configuration (`GIT_CONFIG_*` reaches
/// `core.hooksPath`, which runs a planted hook), and bitfort's own identity source.
const PROCESS_CONTROL_PREFIXES: &[&str] = &["LD_", "DYLD_", "GIT_", "BITFORT_"];

/// Whether `key` names a variable that controls how a process runs: the loader, the
/// interpreter's option and module paths, program resolution itself, git's configuration, or
/// bitfort's identity source.
///
/// A vault is authenticated but not trusted this far. Its signature says a roster member
/// wrote the file; it does not say that any member may execute code on every teammate's
/// machine the next time they run `bitfort run`. `set` and `import` refuse to store these
/// names and `run` refuses to inject one, which bounds what a compromised member gains -
/// something a signature alone does not do (docs/SPEC.md §7).
///
/// This is a bound, not a sandbox: an interpreter has other hooks, and a child that reads a
/// secret and passes it on is outside anyone's reach. The list names the variables that turn
/// a secret store into remote code execution.
pub fn is_process_control_key(key: &str) -> bool {
    PROCESS_CONTROL_NAMES.contains(&key)
        || PROCESS_CONTROL_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// Who wrote a decrypted payload, against which roster, and when. Read off the verified
/// signature, so every field is authenticated: `signer` is the name that key carries in the
/// roster, not the display name the payload claims (which sits outside the signed bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub signer: String,
    pub sign_pubkey: String,
    pub roster_version: u64,
    pub written_at: String,
}

/// How a vault's `roster_version` stands against the roster on disk.
///
/// The two files are written atomically but not together, so an interrupted membership
/// change leaves them one version apart - and the two directions mean opposite things. This
/// is the single definition every front end compares against; the response to each case is
/// a policy decision the caller makes (docs/SPEC.md §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drift {
    /// The vault was written for exactly this roster.
    Current,
    /// Older than the roster: it predates a membership change, so it can hold values a
    /// removed member knows. Only a deliberate re-sign (`rotate`) should accept it.
    Behind { vault: u64, roster: u64 },
    /// Newer than the roster: `keys.json` is not the newest roster this vault has seen, so it
    /// was rolled back, checked out at an older revision, or substituted. No write path
    /// produces this state - an amendment publishes the roster before the vault - so it is
    /// read as a mismatch to repair, not as a step that did not finish. Safe to read; never
    /// safe to re-encrypt through the older roster, which may still list a member the newer
    /// one removed.
    Ahead { vault: u64, roster: u64 },
}

/// The decrypted contents of a `vault.enc`. The secrets are a `BTreeMap` so serialization
/// order is deterministic and diffs stay stable.
///
/// The map is private and every way into it validates the name (see [`Vault::set`]). Front
/// ends render these names into shell and dotenv text, so a name that is not an environment
/// variable name is a command in disguise (finding 1.3); one chokepoint here is what stops a
/// second front end, or a merge that unions two decrypted maps, from re-deriving the rule and
/// getting it wrong.
#[derive(Clone, PartialEq, Eq)]
pub struct Vault {
    pub env: String,
    vars: BTreeMap<String, String>,
    provenance: Option<Provenance>,
    /// Process-control names this vault already carried when it was decrypted.
    ///
    /// `decrypt` accepts such a name on purpose, so `list` and `status` can show the user what
    /// to remove (invariant 6). Removing it means writing the vault back, and the write guard
    /// refuses a process-control name - so with two of them present, every `unset` was refused
    /// because of the *other* one and the vault could never be repaired. Recording what was
    /// already there lets the guard refuse only names a write would *add*.
    admitted: BTreeSet<String>,
}

/// Names only. A derived `Debug` puts every secret into whatever prints it - a panic
/// message, a log line, a `dbg!` left behind - which invariant 6 forbids.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("env", &self.env)
            .field("vars", &self.vars.keys().collect::<Vec<_>>())
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// The on-disk payload: everything in [`Vault`] plus the context it is bound to and the
/// signature over all of it. Private, and the only serialized form, so no code path can
/// write a vault that carries no signature.
///
/// The borrowed fields are what let `encrypt` serialize a vault without copying every secret
/// into a second plaintext buffer; `decrypt` deserializes them as owned.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    schema_version: u32,
    project_id: Cow<'a, str>,
    env: Cow<'a, str>,
    roster_version: u64,
    vars: Cow<'a, BTreeMap<String, String>>,
    written_at: Cow<'a, str>,
    signature: Signature,
}

/// The subset of the payload that is signed: everything except `signature`. Serialized via
/// JCS, so the field order here is irrelevant.
///
/// `project_id` and `env` bind the payload to one environment of one project, which is what
/// stops a vault being replayed across either. `roster_version` names the roster it was
/// encrypted to, so a reader can see a vault and a roster that have drifted apart.
#[derive(Serialize)]
struct SigningView<'a> {
    schema_version: u32,
    project_id: &'a str,
    env: &'a str,
    roster_version: u64,
    vars: &'a BTreeMap<String, String>,
    written_at: &'a str,
}

impl Document<'_> {
    /// This document's signing view, so the bytes are built one way whether they are about to
    /// be signed or about to be verified. `signature` is not in it - which is also why a
    /// document may be signed after it is built, from exactly the fields that get written.
    fn signing_view(&self) -> SigningView<'_> {
        SigningView {
            schema_version: self.schema_version,
            project_id: &self.project_id,
            env: &self.env,
            roster_version: self.roster_version,
            vars: &self.vars,
            written_at: &self.written_at,
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        crate::roster::signing_bytes(SIGNING_DOMAIN, &self.signing_view())
    }
}

/// Encrypt `plaintext` to `recipients` as an ASCII-armored `age` document.
fn armor_encrypt(plaintext: &[u8], recipients: &[age::x25519::Recipient]) -> Result<String> {
    if recipients.is_empty() {
        return Err(Error::Encrypt("no recipients".into()));
    }
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
            .map_err(Error::encrypt)?;

    let mut armored =
        ArmoredWriter::wrap_output(Vec::new(), Format::AsciiArmor).map_err(Error::encrypt)?;
    let mut writer = encryptor
        .wrap_output(&mut armored)
        .map_err(Error::encrypt)?;
    writer.write_all(plaintext).map_err(Error::encrypt)?;
    writer.finish().map_err(Error::encrypt)?;
    let out = armored.finish().map_err(Error::encrypt)?;

    String::from_utf8(out).map_err(Error::encrypt)
}

/// Decrypt an armored `age` document with `identity`, returning its plaintext bytes.
///
/// The buffer is wrapped so it is zeroized when the caller drops it: it holds every secret
/// in the environment, and leaving it in freed heap is how a canary from a decrypted vault
/// turned up in a core dump of the parent (invariant 6).
fn armor_decrypt(armored: &str, identity: &Identity) -> Result<Zeroizing<Vec<u8>>> {
    let reader = ArmoredReader::new(armored.as_bytes());
    let decryptor = age::Decryptor::new(reader).map_err(Error::decrypt)?;
    let mut stream = decryptor
        .decrypt(std::iter::once(
            identity.age_identity() as &dyn age::Identity
        ))
        // "You hold no seat here" and "this file is damaged" have different fixes, so they
        // get different errors rather than one opaque decryption failure.
        .map_err(|e| match e {
            age::DecryptError::NoMatchingKeys => Error::NotARecipient,
            other => Error::decrypt(other),
        })?;

    // Sized up front: `read_to_end` on an empty `Vec` grows by doubling, and every
    // intermediate buffer it abandons keeps a copy of the plaintext in freed heap that
    // `Zeroizing` never sees. The armored form is base64 plus headers, so it is always the
    // larger of the two and one allocation covers the read.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(armored.len()));
    stream.read_to_end(&mut plaintext).map_err(Error::decrypt)?;
    Ok(plaintext)
}

/// How many keys an armored `age` document was encrypted to.
///
/// The header is plain ASCII: one `-> <type> <args>` stanza per recipient, then a `--- <mac>`
/// line the binary body follows. Counting those stanzas is the only thing the file says about
/// its audience - an X25519 stanza carries an ephemeral share, not the recipient's public key,
/// so *which* keys can open it is not recoverable, and `age` exposes no API for either.
///
/// Every stanza counts except the "grease": a randomly tagged decoy every age header carries
/// to keep parsers from ossifying, whose tag always ends in `-grease`. Counting only `X25519`
/// would miss the attack this exists to catch, because `age` ignores a stanza type it does not
/// know rather than refusing the file - so a member could add an `ssh-ed25519` recipient, keep
/// the X25519 count right, and hand the vault to somebody with no seat. No usable type ends in
/// `-grease`, so nothing readable can hide behind that suffix.
fn recipient_count(armored: &str) -> Result<usize> {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(ArmoredReader::new(armored.as_bytes()));
    let mut line = String::new();
    let mut count = 0usize;
    loop {
        line.clear();
        // Stops at the MAC line, so this never reads into the binary body. Stanza bodies are
        // base64, so no body line can be read as a stanza header.
        if reader.read_line(&mut line).map_err(Error::decrypt)? == 0 {
            return Err(Error::Decrypt("truncated age header".into()));
        }
        if line.starts_with("---") {
            return Ok(count);
        }
        if let Some(rest) = line.strip_prefix("-> ") {
            let tag = rest.split(' ').next().unwrap_or("").trim_end();
            if !tag.ends_with("-grease") {
                count += 1;
            }
        }
    }
}

impl Vault {
    /// A new empty vault for `env`, not yet written anywhere and so carrying no provenance.
    pub fn new(env: impl Into<String>) -> Self {
        Self {
            env: env.into(),
            vars: BTreeMap::new(),
            provenance: None,
            admitted: BTreeSet::new(),
        }
    }

    /// A new vault for `env` holding `vars`, refusing the whole map if any name is not an
    /// environment variable name - the way `resolve` builds one from a merge of two decrypted
    /// vaults. Built in one step, so there is no moment where the map is in but unchecked.
    pub fn with_vars(env: impl Into<String>, vars: BTreeMap<String, String>) -> Result<Self> {
        for (key, value) in &vars {
            crate::dotenv::check_key(key)?;
            crate::dotenv::check_value(key, value)?;
        }
        Ok(Self {
            env: env.into(),
            vars,
            provenance: None,
            admitted: BTreeSet::new(),
        })
    }

    /// Who last wrote this vault, from the verified signature. `None` for a vault built in
    /// memory that has not been through [`Vault::decrypt`].
    pub fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }

    /// This vault's secrets, by name.
    pub fn vars(&self) -> &BTreeMap<String, String> {
        &self.vars
    }

    /// Take the secrets out, for a caller that owns them from here on - `run`, which hands
    /// them to the child and then zeroizes its copy.
    pub fn into_vars(self) -> BTreeMap<String, String> {
        self.vars
    }

    /// Set (or overwrite) a secret, refusing a name that is not an environment variable name.
    pub fn set(&mut self, key: &str, value: impl Into<String>) -> Result<()> {
        crate::dotenv::check_key(key)?;
        let value = value.into();
        crate::dotenv::check_value(key, &value)?;
        self.vars.insert(key.to_string(), value);
        Ok(())
    }

    /// Remove a secret, returning the old value if present.
    pub fn unset(&mut self, key: &str) -> Option<String> {
        self.vars.remove(key)
    }

    /// The first name here that decides how a process runs, if any.
    ///
    /// One finder behind every *read*-side use of the rule: the refusal `run` and `export`
    /// raise before turning these values into an environment, and the state `status` and
    /// `verify` report. Two would let the CI gate pass a vault the commands refuse.
    pub fn process_control_key(&self) -> Option<&String> {
        self.vars.keys().find(|k| is_process_control_key(k))
    }

    /// The first process-control name this vault did **not** already carry when it was
    /// decrypted - that is, one a write would introduce.
    ///
    /// This is the write-side rule, used by
    /// [`Project::save_vault`](crate::project::Project::save_vault). It still refuses every
    /// path that would put such a name into a vault, because a vault built in memory admits
    /// nothing; what it no longer refuses is writing back a vault that already held one, which
    /// is exactly what removing it requires.
    pub fn introduced_process_control_key(&self) -> Option<&String> {
        self.vars
            .keys()
            .find(|k| is_process_control_key(k) && !self.admitted.contains(*k))
    }

    /// Keys whose value exceeds [`VALUE_SIZE_WARN`], for the caller to warn about.
    pub fn oversized_keys(&self) -> Vec<&str> {
        self.vars
            .iter()
            .filter(|(_, v)| v.len() > VALUE_SIZE_WARN)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Sign the payload as `identity` and encrypt it to every member of `roster`, returning
    /// an ASCII-armored `age` document.
    ///
    /// `identity` must hold a signing key listed in `roster`: only a member may author a
    /// vault, and [`Vault::decrypt`] enforces the same rule on the way back in. The payload
    /// records the roster's `project_id` and `roster_version`, binding the ciphertext to the
    /// environment and roster it was written for.
    ///
    /// Callers must verify `roster` first (see [`crate::project::Project::verify_roster`]);
    /// encrypting to an unverified roster is what sends secrets to a rogue key.
    pub fn encrypt(&self, roster: &Roster, identity: &Identity) -> Result<String> {
        if self.env != roster.env {
            return Err(Error::Encrypt(format!(
                "env mismatch: vault is for '{}', roster is for '{}'",
                self.env, roster.env
            )));
        }
        let sign_pubkey = identity.sign_pubkey();
        let member = roster.member_by_sign_pubkey(&sign_pubkey).ok_or_else(|| {
            Error::Encrypt(format!(
                "this identity is not a member of the '{}' roster; refusing to write a vault \
                 nobody in it signed",
                roster.env
            ))
        })?;

        // Build the document first and sign it second, from its own signing view. The bytes
        // that get signed are then literally the ones that get written, rather than a second
        // copy of the same six fields that a later edit could let drift (invariant 4). The
        // placeholder never reaches the signature: `signing_view` does not include it.
        let mut document = Document {
            schema_version: SCHEMA_VERSION,
            project_id: Cow::Borrowed(&roster.project_id),
            env: Cow::Borrowed(&self.env),
            roster_version: roster.roster_version,
            vars: Cow::Borrowed(&self.vars),
            written_at: Cow::Owned(crate::clock::now_rfc3339()),
            signature: Signature::placeholder(),
        };
        document.signature =
            Signature::create(identity, member.name.clone(), &document.signing_bytes()?);

        // Zeroized on drop for the same reason as the decrypt buffer: this is the whole
        // environment in plaintext, one serialization step before it becomes ciphertext.
        let plaintext = Zeroizing::new(serde_jcs::to_vec(&document).map_err(Error::serde)?);
        armor_encrypt(&plaintext, &roster.recipients()?)
    }

    /// Decrypt an armored `age` document with `identity` and authenticate its origin against
    /// the roster it was written for - `current` if it names that version, otherwise the link
    /// `chain` holds for the version it names. The caller must have verified both.
    ///
    /// Decryption alone proves only that this identity is a recipient - nothing about who
    /// produced the file. Five checks follow it, and every one refuses rather than warns:
    /// the payload's `env` must match the directory it was loaded from and its `project_id`
    /// the roster's, so a vault cannot be replayed across environments or projects; the
    /// signature must verify over the payload's signing bytes, so the `vars` are exactly what
    /// the signer wrote; the signing key must belong to a member of that roster, so a file
    /// written by anyone else - including someone with repo write access and no key at all -
    /// is refused; and the ciphertext must be addressed to as many keys as that roster has
    /// members, so a member cannot quietly add an outside key to the audience.
    ///
    /// **Authenticating against the roster the payload names, not always the current one**, is
    /// what keeps an authentic older vault readable. A vault written before a membership change
    /// was signed by a member of the roster of that moment, and the member who signed it may be
    /// the one that change removed - which is exactly what a crash between the roster write and
    /// the vault write leaves behind. Looking that signer up in today's `keys.json` would call
    /// an authentic file a forgery and leave the environment with no repair. Staleness is a
    /// separate question, answered by [`Drift`] and refused by the caller everywhere except
    /// `rotate`, which exists to re-sign such a vault.
    pub fn decrypt(
        armored: &str,
        identity: &Identity,
        current: &Roster,
        chain: &Chain,
        expected_env: &str,
    ) -> Result<Self> {
        let plaintext = armor_decrypt(armored, identity)?;
        let document: Document = serde_json::from_slice(&plaintext).map_err(Error::serde)?;
        crate::error::check_schema("vault", document.schema_version, SCHEMA_VERSION)?;
        if document.env != expected_env {
            return Err(Error::VaultOrigin(format!(
                "env mismatch: vault says '{}', loaded from '{}'",
                document.env, expected_env
            )));
        }
        if document.project_id != current.project_id {
            return Err(Error::VaultOrigin(format!(
                "project mismatch: vault says '{}', this project is '{}'",
                document.project_id, current.project_id
            )));
        }

        // The roster the payload was written for, when this environment has a record of it.
        // `None` means it names a version neither `keys.json` nor the chain holds, which no
        // write path produces: `keys.json` has been rolled back, or the payload is lying. The
        // signer is then checked against the current roster, the strictest answer available,
        // and the audience is not checked at all - there is no member count to compare with,
        // and accusing such a file of the wrong fault would hide the real one. Every caller
        // refuses it anyway on the drift it reports.
        let written_for = if document.roster_version == current.roster_version {
            Some(current)
        } else {
            chain.roster_at(document.roster_version)
        };
        let roster = written_for.unwrap_or(current);

        // The name comes from the roster, not from the payload: `signature.signer` is a
        // display field outside the signed bytes, so only the key it names is trustworthy.
        let member = roster
            .member_by_sign_pubkey(&document.signature.sign_pubkey)
            .ok_or_else(|| {
                Error::VaultOrigin(format!(
                    "the '{expected_env}' vault was signed by a key that is not in roster v{}, \
                     the one it was written for; refusing it. Someone with repo write access can \
                     encrypt to a roster's public keys, so an unrecognized signer means a forged \
                     vault.",
                    roster.roster_version
                ))
            })?;
        if !document.signature.verifies(&document.signing_bytes()?) {
            return Err(Error::VaultOrigin(format!(
                "the '{expected_env}' vault's signature does not verify; its contents were \
                 modified after '{}' signed it",
                crate::roster::display_name(&member.name)
            )));
        }
        // The audience: the ciphertext must open for that roster and for nobody else. A member
        // can sign a payload the roster accepts and still encrypt it to their own extra key,
        // handing every value to somebody with no seat - the signature says who wrote the file,
        // not who can read it. Only the size of the audience is checkable; see
        // [`recipient_count`] for what the file does and does not say about who can open it.
        if let Some(roster) = written_for {
            let audience = recipient_count(armored)?;
            if audience != roster.members.len() {
                return Err(Error::VaultAudience(format!(
                    "the '{expected_env}' vault is encrypted to {audience} key(s), but roster \
                     v{} - the one it was written for - has {} member(s). Whoever wrote it \
                     addressed the ciphertext to somebody that roster does not list.",
                    roster.roster_version,
                    roster.members.len()
                )));
            }
        }

        // Last, because a name this shape means an authorized writer produced bad content,
        // which is a different report from a forgery - and checking it before the signature
        // would let an unauthenticated payload choose which error the user sees.
        for key in document.vars.keys() {
            crate::dotenv::check_key(key)?;
        }

        let vars = document.vars.into_owned();
        let admitted = vars
            .keys()
            .filter(|k| is_process_control_key(k))
            .cloned()
            .collect();

        Ok(Self {
            env: document.env.into_owned(),
            vars,
            admitted,
            provenance: Some(Provenance {
                signer: member.name.clone(),
                sign_pubkey: document.signature.sign_pubkey,
                roster_version: document.roster_version,
                written_at: document.written_at.into_owned(),
            }),
        })
    }

    /// How this vault's `roster_version` stands against `roster`. A vault built in memory has
    /// nothing to compare, so it reports [`Drift::Current`] - it has not been written yet,
    /// and `encrypt` stamps it with the roster it is written for.
    pub fn drift(&self, roster: &Roster) -> Drift {
        let Some(p) = self.provenance() else {
            return Drift::Current;
        };
        let (vault, current) = (p.roster_version, roster.roster_version);
        match vault.cmp(&current) {
            std::cmp::Ordering::Equal => Drift::Current,
            std::cmp::Ordering::Less => Drift::Behind {
                vault,
                roster: current,
            },
            std::cmp::Ordering::Greater => Drift::Ahead {
                vault,
                roster: current,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{Member, Role};

    fn sample() -> Vault {
        let mut v = Vault::new("development");
        v.set("DATABASE_URL", "postgres://localhost/app").unwrap();
        v.set("API_KEY", "sk-test-123").unwrap();
        v
    }

    /// Exactly at the limit, and one byte over. The boundary is `>`, so a value of exactly
    /// `VALUE_SIZE_WARN` bytes is not reported: the warning is about exceeding the limit.
    #[test]
    fn oversized_keys_reports_only_values_past_the_limit() {
        let mut v = Vault::new("development");
        v.set("SMALL", "x").unwrap();
        v.set("AT_LIMIT", "x".repeat(VALUE_SIZE_WARN)).unwrap();
        v.set("OVER_LIMIT", "x".repeat(VALUE_SIZE_WARN + 1))
            .unwrap();

        assert_eq!(v.oversized_keys(), vec!["OVER_LIMIT"]);
    }

    #[test]
    fn oversized_keys_is_empty_for_ordinary_values() {
        assert!(sample().oversized_keys().is_empty());
    }

    /// Several oversized values are all reported, in the map's sorted order, so the caller
    /// warns about each one rather than only the first.
    #[test]
    fn oversized_keys_reports_every_offender() {
        let mut v = Vault::new("development");
        for key in ["ZED", "ALPHA"] {
            v.set(key, "x".repeat(VALUE_SIZE_WARN + 1)).unwrap();
        }
        assert_eq!(v.oversized_keys(), vec!["ALPHA", "ZED"]);
    }

    /// A NUL cannot go into a process environment, so it is refused where a vault is
    /// written rather than at every later `run`, which would fail to spawn anything at all.
    #[test]
    fn a_value_holding_a_nul_is_refused_on_the_write_side() {
        let mut v = Vault::new("development");
        let err = v.set("TOKEN", "a\0b").unwrap_err();
        assert!(
            format!("{err}").contains("NUL"),
            "unexpected message: {err}"
        );
        assert!(
            !format!("{err}").contains("a\0b"),
            "the value was quoted back"
        );
        assert!(
            !v.vars().contains_key("TOKEN"),
            "the value was stored anyway"
        );

        let vars = BTreeMap::from([("TOKEN".to_string(), "a\0b".to_string())]);
        assert!(Vault::with_vars("development", vars).is_err());
    }

    fn member(id: &Identity, name: &str) -> Member {
        Member {
            name: name.to_string(),
            enc_pubkey: id.enc_pubkey(),
            sign_pubkey: id.sign_pubkey(),
            role: Role::Maintainer,
            added_by: "test".to_string(),
            added_at: "2026-07-03T00:00:00Z".to_string(),
        }
    }

    /// A roster for `proj-1`/`development` holding every given identity.
    fn roster(members: &[(&Identity, &str)]) -> Roster {
        Roster::new_v1(
            "proj-1",
            "development",
            members.iter().map(|(id, name)| member(id, name)).collect(),
        )
    }

    /// [`Vault::decrypt`] against `current` with an empty chain: the shape of a project still
    /// at v1, which is what all but the drift tests need.
    fn open(armored: &str, identity: &Identity, current: &Roster, env: &str) -> Result<Vault> {
        Vault::decrypt(armored, identity, current, &Chain::new(), env)
    }

    /// Decrypt to the raw payload, for tests that forge one field of it.
    fn document_of(armored: &str, identity: &Identity) -> Document<'static> {
        let plaintext = armor_decrypt(armored, identity).unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    fn reseal(document: &Document, recipients: &[age::x25519::Recipient]) -> String {
        armor_encrypt(&serde_jcs::to_vec(document).unwrap(), recipients).unwrap()
    }

    #[test]
    fn roundtrips_to_the_intended_recipient() {
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let vault = sample();

        let armored = vault.encrypt(&r, &alice).unwrap();
        assert!(armored.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let out = open(&armored, &alice, &r, "development").unwrap();
        assert_eq!(out.vars, vault.vars);
        let p = out.provenance().unwrap();
        assert_eq!(p.signer, "alice");
        assert_eq!(p.sign_pubkey, alice.sign_pubkey());
        assert_eq!(p.roster_version, 1);
        assert!(p.written_at.ends_with('Z'));
    }

    #[test]
    fn a_non_recipient_cannot_decrypt() {
        let alice = Identity::generate().unwrap();
        let outsider = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);

        let armored = sample().encrypt(&r, &alice).unwrap();
        assert!(matches!(
            open(&armored, &outsider, &r, "development"),
            Err(Error::NotARecipient)
        ));
    }

    #[test]
    fn every_listed_recipient_can_decrypt() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice"), (&bob, "bob")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        for id in [&alice, &bob] {
            let out = open(&armored, id, &r, "development").unwrap();
            assert_eq!(out.vars, sample().vars);
        }
    }

    #[test]
    fn decrypt_env_mismatch_is_rejected() {
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();
        assert!(open(&armored, &alice, &r, "production").is_err());
    }

    #[test]
    fn decrypt_project_mismatch_is_rejected() {
        // A vault lifted from another project decrypts fine for a shared identity; only the
        // project binding catches it.
        let alice = Identity::generate().unwrap();
        let mine = roster(&[(&alice, "alice")]);
        let mut theirs = mine.clone();
        theirs.project_id = "proj-2".into();

        let armored = sample().encrypt(&theirs, &alice).unwrap();
        let err = open(&armored, &alice, &mine, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultOrigin(m) if m.contains("project mismatch")),
            "expected a project rejection, got {err:?}"
        );
    }

    #[test]
    fn a_forged_vault_from_a_non_member_is_rejected() {
        // Finding 1.2: every `enc_pubkey` is public, so an attacker with repo write access
        // and no member key can encrypt a payload to the whole roster and overwrite
        // `vault.enc`. Without origin authentication `run` injects their values.
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let real = roster(&[(&alice, "alice")]);
        // Mallory's own roster: alice as a recipient so she can still decrypt, mallory added
        // so his signature is accepted by his own copy of `encrypt`.
        let forged_roster = roster(&[(&alice, "alice"), (&mallory, "mallory")]);

        let mut forged = Vault::new("development");
        forged.set("LD_PRELOAD", "/tmp/evil.so").unwrap();
        let armored = forged.encrypt(&forged_roster, &mallory).unwrap();

        let err = open(&armored, &alice, &real, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultOrigin(m) if m.contains("not in roster v1")),
            "expected an unknown-signer rejection, got {err:?}"
        );
    }

    #[test]
    fn a_vault_encrypted_to_an_extra_key_is_rejected() {
        // A member is authorized to write the vault, not to choose who else can read it. Bob
        // re-encrypts the real contents to the roster plus his own outside key: the payload is
        // his to sign, the values are correct, and every other check passes. Only the size of
        // the audience shows that somebody with no seat can open the file.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let outsider = Identity::generate().unwrap();
        let real = roster(&[(&alice, "alice"), (&bob, "bob")]);

        let mut widened = real.clone();
        widened.members.push(member(&outsider, "outsider@nowhere"));
        let armored = sample().encrypt(&widened, &bob).unwrap();

        let err = open(&armored, &alice, &real, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultAudience(m) if m.contains("3 key(s)")),
            "expected an audience rejection, got {err:?}"
        );
        // And the outsider really could read it, which is what the check is for.
        assert!(open(&armored, &outsider, &widened, "development").is_ok());
    }

    #[test]
    fn an_extra_recipient_of_another_type_is_counted_too() {
        // Counting only `X25519` stanzas would miss the attack: `age` ignores a recipient type
        // it does not know rather than refusing the file, so an `ssh-ed25519` stanza would keep
        // the X25519 count right and still hand the vault to somebody with no seat. Only the
        // grease stanza - always tagged `*-grease` - is excluded.
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();
        assert_eq!(
            recipient_count(&armored).unwrap(),
            1,
            "a real one-member vault counts one, grease excluded"
        );

        // Hand-built, because the stanza lines are inside the armor. `age` reads an unarmored
        // document too, so the parser sees exactly these bytes.
        let smuggled = "age-encryption.org/v1\n\
             -> X25519 QUFBQQ\n\
             QkJCQg\n\
             -> ssh-ed25519 Q0ND REREUkg\n\
             RUVFRQ\n\
             -> 8wKYx-grease 5{WI\n\
             RkZGRg\n\
             --- TUFD\n";
        assert_eq!(recipient_count(smuggled).unwrap(), 2);
    }

    #[test]
    fn a_vault_is_checked_against_the_roster_it_names_not_the_current_one() {
        // A vault written before a membership change was signed by a member of the roster of
        // that moment, and encrypted to that roster's member list. Both are checked against the
        // chain link it names: bob signed this one and was then removed, which is what a crash
        // between the roster write and the vault write leaves behind. Refusing it would leave
        // the environment with no repair, since `rotate` has to read it to re-sign it.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let v1 = roster(&[(&alice, "alice"), (&bob, "bob")]);
        let armored = sample().encrypt(&v1, &bob).unwrap();

        let mut chain = Chain::new();
        chain.append(v1).unwrap();
        let mut v2 = roster(&[(&alice, "alice")]);
        v2.roster_version = 2;

        let vault = Vault::decrypt(&armored, &alice, &v2, &chain, "development").unwrap();
        assert_eq!(vault.provenance().unwrap().signer, "bob");
        assert_eq!(
            vault.drift(&v2),
            Drift::Behind {
                vault: 1,
                roster: 2
            }
        );
        // Without the link there is nothing better to check against, so it falls back to the
        // current roster and refuses - bob is not in v2.
        assert!(open(&armored, &alice, &v2, "development").is_err());
    }

    #[test]
    fn a_signature_from_a_removed_member_is_rejected() {
        // The same check catches a stale vault: bob wrote it, then bob was removed.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let with_bob = roster(&[(&alice, "alice"), (&bob, "bob")]);
        let armored = sample().encrypt(&with_bob, &bob).unwrap();

        let without_bob = roster(&[(&alice, "alice")]);
        assert!(open(&armored, &alice, &without_bob, "development").is_err());
    }

    #[test]
    fn tampered_vars_break_the_signature() {
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        let mut document = document_of(&armored, &alice);
        document
            .vars
            .to_mut()
            .insert("API_KEY".into(), "sk-attacker".to_string());
        let tampered = reseal(&document, &r.recipients().unwrap());

        let err = open(&tampered, &alice, &r, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultOrigin(m) if m.contains("does not verify")),
            "expected a signature rejection, got {err:?}"
        );
    }

    #[test]
    fn a_rewritten_signer_name_does_not_change_who_signed() {
        // `signature.signer` sits outside the signed bytes, so it is malleable. Provenance
        // must report the name the signing key holds in the roster, not the payload's claim.
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        let mut document = document_of(&armored, &alice);
        document.signature.signer = "mallory".into();
        let renamed = reseal(&document, &r.recipients().unwrap());

        let out = open(&renamed, &alice, &r, "development").unwrap();
        assert_eq!(out.provenance().unwrap().signer, "alice");
    }

    #[test]
    fn a_future_schema_version_is_rejected_on_decrypt() {
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        let mut document = document_of(&armored, &alice);
        document.schema_version = SCHEMA_VERSION + 1;
        let future = reseal(&document, &r.recipients().unwrap());

        assert!(matches!(
            open(&future, &alice, &r, "development"),
            Err(Error::UnsupportedSchema("vault", 2, 1))
        ));
    }

    #[test]
    fn a_schema_version_rewrite_breaks_the_signature() {
        // `schema_version` is inside the signing view, so it cannot be edited quietly even
        // within the range this build accepts.
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        let mut document = document_of(&armored, &alice);
        document.schema_version = 0;
        let rewritten = reseal(&document, &r.recipients().unwrap());

        let err = open(&rewritten, &alice, &r, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultOrigin(m) if m.contains("does not verify")),
            "expected a signature rejection, got {err:?}"
        );
    }

    #[test]
    fn encrypting_as_a_non_member_is_rejected() {
        let alice = Identity::generate().unwrap();
        let outsider = Identity::generate().unwrap();
        let err = sample()
            .encrypt(&roster(&[(&alice, "alice")]), &outsider)
            .unwrap_err();
        assert!(
            matches!(&err, Error::Encrypt(m) if m.contains("not a member")),
            "expected a membership rejection, got {err:?}"
        );
    }

    #[test]
    fn encrypting_against_another_environments_roster_is_rejected() {
        let alice = Identity::generate().unwrap();
        let mut production = roster(&[(&alice, "alice")]);
        production.env = "production".into();
        let err = sample().encrypt(&production, &alice).unwrap_err();
        assert!(
            matches!(&err, Error::Encrypt(m) if m.contains("env mismatch")),
            "expected an env rejection, got {err:?}"
        );
    }

    #[test]
    fn a_name_that_is_not_an_env_var_name_is_refused_on_the_way_in() {
        // Finding 1.3: `export --format shell` emits the name verbatim, so this one is a
        // second command under the documented `eval "$(bitfort export --format shell)"`.
        let mut v = Vault::new("development");
        let err = v.set("BAD; touch /tmp/PWNED #", "boom").unwrap_err();
        assert!(
            matches!(&err, Error::VaultContent(m) if m.contains("BAD; touch")),
            "expected a name rejection, got {err:?}"
        );
        assert!(v.vars().is_empty(), "the rejected name must not be stored");

        // `resolve` builds a vault from a union of two decrypted maps, so `with_vars` is the
        // second way in and applies the same rule.
        let merged = BTreeMap::from([("9lives".to_string(), "x".to_string())]);
        assert!(matches!(
            Vault::with_vars("development", merged),
            Err(Error::VaultContent(_))
        ));
    }

    #[test]
    fn a_signed_payload_with_a_crafted_name_is_refused_on_decrypt() {
        // The CLI refuses such a name before it is stored, so producing one takes a member
        // writing the payload by hand. That is exactly why the check is at this boundary too,
        // and why it runs after the signature: the report names bad content, not a forgery.
        let alice = Identity::generate().unwrap();
        let r = roster(&[(&alice, "alice")]);
        let armored = sample().encrypt(&r, &alice).unwrap();

        let mut document = document_of(&armored, &alice);
        document
            .vars
            .to_mut()
            .insert("BAD; touch /tmp/PWNED #".into(), "boom".into());
        let bytes = document.signing_bytes().unwrap();
        document.signature = Signature::create(&alice, "alice".to_string(), &bytes);
        let crafted = reseal(&document, &r.recipients().unwrap());

        let err = open(&crafted, &alice, &r, "development").unwrap_err();
        assert!(
            matches!(&err, Error::VaultContent(m) if m.contains("not a valid environment variable name")),
            "expected a content rejection, got {err:?}"
        );
    }

    #[test]
    fn debug_prints_names_but_no_values() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("API_KEY"), "names are useful: {rendered}");
        assert!(
            !rendered.contains("sk-test-123"),
            "value leaked: {rendered}"
        );
        assert!(
            !rendered.contains("postgres://localhost/app"),
            "value leaked: {rendered}"
        );
    }

    #[test]
    fn process_control_names_are_recognized() {
        for key in [
            "PATH",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PERL5LIB",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "GIT_CONFIG_GLOBAL",
            "BITFORT_IDENTITY",
        ] {
            assert!(is_process_control_key(key), "{key} should be refused");
        }
        // Ordinary secrets that only look close: the prefixes need their underscore.
        for key in ["DATABASE_URL", "GITHUB_TOKEN", "PATHOLOGY", "NODE_ENV"] {
            assert!(!is_process_control_key(key), "{key} should be allowed");
        }
    }

    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let alice = Identity::generate().unwrap();
        let armored = sample()
            .encrypt(&roster(&[(&alice, "alice")]), &alice)
            .unwrap();
        assert!(!armored.contains("postgres://localhost/app"));
        assert!(!armored.contains("sk-test-123"));
    }
}
