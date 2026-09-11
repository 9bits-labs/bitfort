//! The signed team roster (`keys.json`). A roster lists the public identities
//! authorized for one environment. Changes are signed with Ed25519 over an
//! RFC 8785 (JCS) canonicalization with a domain tag, and verified against a
//! maintainer chain rooted at the pinned trust anchor. See docs/SPEC.md §4.3, §5.

use std::collections::HashSet;

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::identity::{anchor_of, Identity, B64, SIGN_PUBKEY_PREFIX};

/// Current `keys.json` schema (mirrors `config`/`vault`; checked on every load).
pub const SCHEMA_VERSION: u32 = 1;
/// Domain-separation tag prepended to the JCS bytes before signing, so a roster
/// signature can never be confused with a signature over any other BitFort payload.
const SIGNING_DOMAIN: &[u8] = b"bitfort-roster-v1\n";

/// A member's authority within an environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Member,
    Maintainer,
}

/// One authorized identity (public keys only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub name: String,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
    pub role: Role,
    pub added_by: String,
    pub added_at: String,
}

/// A detached Ed25519 signature over a payload's signing bytes. One shape for both signed
/// payloads - the roster (`keys.json`) and the vault - so there is a single signature idiom
/// on disk and a single verification routine behind it.
///
/// `signer` is a display name only. It sits outside the signing bytes, so a tamperer can
/// rewrite it; `sign_pubkey` is what verification uses, and callers that display an author
/// resolve the name from the verified roster instead of trusting this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub signer: String,
    pub sign_pubkey: String,
    pub signature: String,
}

/// The signing bytes for any BitFort payload: a domain-separation tag followed by the RFC
/// 8785 (JCS) canonicalization of `view`.
///
/// One function, because invariant 4 makes these bytes load-bearing: a payload that builds
/// them even slightly differently verifies against nothing, silently. The roster and the
/// vault pass their own tag and their own signing view.
pub(crate) fn signing_bytes(domain: &[u8], view: &impl Serialize) -> Result<Vec<u8>> {
    let canonical = serde_jcs::to_vec(view).map_err(Error::serde)?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

impl Signature {
    /// An empty signature, for a payload that is built before it is signed. It verifies
    /// against nothing, and [`Signature::create`] overwrites it in the same expression that
    /// builds the bytes it covers.
    pub(crate) fn placeholder() -> Self {
        Self {
            signer: String::new(),
            sign_pubkey: String::new(),
            signature: String::new(),
        }
    }

    /// Sign `signing_bytes` with `identity`, labelled with the signer's display name.
    pub(crate) fn create(
        identity: &Identity,
        signer: impl Into<String>,
        signing_bytes: &[u8],
    ) -> Self {
        Self {
            signer: signer.into(),
            sign_pubkey: identity.sign_pubkey(),
            signature: B64.encode(identity.sign(signing_bytes).to_bytes()),
        }
    }

    /// Whether this signature verifies over `signing_bytes`. Any parse failure means "does
    /// not verify" (never a panic), so malformed key or signature material cannot bypass
    /// the check.
    pub(crate) fn verifies(&self, signing_bytes: &[u8]) -> bool {
        let Ok(vk) = verifying_key(&self.sign_pubkey) else {
            return false;
        };
        let Ok(raw) = B64.decode(&self.signature) else {
            return false;
        };
        let Ok(arr) = <[u8; 64]>::try_from(raw.as_slice()) else {
            return false;
        };
        vk.verify_strict(signing_bytes, &ed25519_dalek::Signature::from_bytes(&arr))
            .is_ok()
    }
}

/// The `keys.json` document for one environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    pub schema_version: u32,
    pub project_id: String,
    pub env: String,
    pub roster_version: u64,
    /// Hex SHA-256 of the predecessor's [`Roster::signing_bytes`], or `None` at version 1.
    /// This is what makes the chain in `chain.json` tamper-evident: a link cannot be
    /// swapped or dropped without breaking the successor's digest (docs/SPEC.md §4.3).
    pub prev_digest: Option<String>,
    pub members: Vec<Member>,
    #[serde(default)]
    pub signatures: Vec<Signature>,
}

/// The subset of the roster that is actually signed. Serialized via JCS; the field
/// order here is irrelevant because JCS sorts object keys.
///
/// `schema_version` is inside the signed set: leaving it out let a repo-write attacker
/// rewrite it while keeping the signature valid. `prev_digest` is always serialized, as
/// `null` at version 1 - never elided by `skip_serializing_if`, because signing bytes that
/// depend on whether a field is present are not deterministic (invariant 4).
#[derive(Serialize)]
struct SigningView<'a> {
    schema_version: u32,
    project_id: &'a str,
    env: &'a str,
    roster_version: u64,
    prev_digest: Option<&'a str>,
    members: &'a [Member],
}

impl Roster {
    /// Create an unsigned version-1 roster. The caller signs it with the initializer's
    /// identity via [`Roster::sign`]; that identity's anchor becomes the pinned root.
    pub fn new_v1(
        project_id: impl Into<String>,
        env: impl Into<String>,
        initial_members: Vec<Member>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            project_id: project_id.into(),
            env: env.into(),
            roster_version: 1,
            prev_digest: None,
            members: initial_members,
            signatures: Vec::new(),
        }
    }

    /// Parse a roster from its JSON bytes, rejecting a `schema_version` newer than this
    /// build understands. The single deserialization chokepoint for `keys.json`, mirroring
    /// [`crate::config::Config::from_toml`] and [`crate::vault::Vault::decrypt`], so every
    /// load path validates the schema without repeating the check.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let roster: Roster = serde_json::from_slice(bytes).map_err(Error::serde)?;
        crate::error::check_schema("roster", roster.schema_version, SCHEMA_VERSION)?;
        Ok(roster)
    }

    /// The exact bytes signed and verified: domain tag followed by JCS of the
    /// signing view (everything except `signatures`).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(
            SIGNING_DOMAIN,
            &SigningView {
                schema_version: self.schema_version,
                project_id: &self.project_id,
                env: &self.env,
                roster_version: self.roster_version,
                prev_digest: self.prev_digest.as_deref(),
                members: &self.members,
            },
        )
    }

    /// Hex SHA-256 of this roster's signing bytes - the value a successor pins in its
    /// `prev_digest`. Two rosters share a digest only if they sign identical bytes.
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.signing_bytes()?)))
    }

    /// Append a signature from `identity`. Does not remove existing signatures.
    pub fn sign(&mut self, identity: &Identity, signer_name: impl Into<String>) -> Result<()> {
        let bytes = self.signing_bytes()?;
        self.signatures
            .push(Signature::create(identity, signer_name, &bytes));
        Ok(())
    }

    /// Begin an amendment: a clone at the next `roster_version`, pinning this roster as its
    /// predecessor and clearing the stale signatures, ready for the caller to edit `members`
    /// and re-sign. Bumping the version, pinning the digest, and dropping old signatures
    /// together keep a mutation from ever producing a roster that reuses a version, skips a
    /// predecessor, or carries a signature over different bytes (docs/SPEC.md §5.2).
    pub fn amend(&self) -> Result<Roster> {
        Ok(Roster {
            roster_version: self.roster_version.checked_add(1).ok_or_else(|| {
                Error::Verification("roster version would overflow; cannot amend".into())
            })?,
            prev_digest: Some(self.digest()?),
            signatures: Vec::new(),
            ..self.clone()
        })
    }

    /// Maintainer members.
    pub fn maintainers(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.role == Role::Maintainer)
    }

    /// The member holding this signing public key, if any. The canonical "who is this
    /// identity in the roster" lookup, so callers don't re-scan `members` by hand.
    pub fn member_by_sign_pubkey(&self, sign_pubkey: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.sign_pubkey == sign_pubkey)
    }

    /// Parse every member's `enc_pubkey` into an `age` recipient, for encrypting the
    /// vault to the whole roster. A single malformed key fails the batch rather than
    /// silently dropping a recipient (which would lock that member out).
    pub fn recipients(&self) -> Result<Vec<age::x25519::Recipient>> {
        self.members
            .iter()
            .map(|m| {
                m.enc_pubkey
                    .parse::<age::x25519::Recipient>()
                    .map_err(|e: &str| {
                        Error::InvalidKey(format!("member '{}' enc_pubkey: {e}", m.name))
                    })
            })
            .collect()
    }

    /// Whether any signature on this roster verifies under a key in `keys`.
    ///
    /// This is not roster verification - it answers only "did one of these keys sign these
    /// bytes". The anti-rollback ceiling uses it to decide whether a committed revision is
    /// worth counting, without reconstructing a chain for a version it may have no
    /// predecessors for (see [`crate::project`]).
    pub fn is_signed_by_any(&self, keys: &HashSet<String>) -> Result<bool> {
        let bytes = self.signing_bytes()?;
        Ok(self
            .signatures
            .iter()
            .any(|s| keys.contains(&s.sign_pubkey) && s.verifies(&bytes)))
    }

    /// Verify this roster.
    ///
    /// - `previous`: the immediately-preceding valid roster (`None` when verifying
    ///   version 1). Must be exactly `roster_version - 1`.
    /// - `anchor_fingerprint`: the pinned trust anchor (docs/SPEC.md §5.1).
    /// - `highest_known_version`: the greatest `roster_version` seen in Git history for
    ///   this file (0 if unknown); a lower current version is a rejected downgrade.
    /// - `expected_env`: the environment directory this roster was loaded from.
    pub fn verify(
        &self,
        previous: Option<&Roster>,
        anchor_fingerprint: &str,
        highest_known_version: u64,
        expected_env: &str,
    ) -> Result<()> {
        if self.env != expected_env {
            return Err(Error::Verification(format!(
                "env mismatch: roster says '{}', loaded from '{}'",
                self.env, expected_env
            )));
        }

        // Versions start at 1, so 0 is not a roster this chain can ever hold. Refused by name
        // rather than left to fall through the adjacency check, which would report it as a
        // missing predecessor and send the reader looking for the wrong problem.
        if self.roster_version == 0 {
            return Err(Error::Verification(
                "roster version 0 is not valid; versions start at 1".into(),
            ));
        }

        // Anti-rollback: never accept a roster older than one we have already seen.
        if self.roster_version < highest_known_version {
            return Err(Error::Verification(format!(
                "downgrade rejected: version {} is below the highest seen version {}",
                self.roster_version, highest_known_version
            )));
        }

        // A roster with no maintainers can never authorize a successor, permanently
        // bricking the chain; refuse to accept one in the first place.
        if self.maintainers().next().is_none() {
            return Err(Error::Verification("roster has no maintainers".into()));
        }

        // The set of signing keys allowed to authorize *this* roster.
        let authorized: HashSet<&str> = if self.roster_version == 1 {
            // Bootstrapping: v1 must be self-signed by a maintainer whose identity anchor
            // (both public keys) equals the pinned anchor. Binding the signing key is what
            // stops a repo-write attacker from copying the public enc key and pairing it
            // with their own signing key.
            if self.prev_digest.is_some() {
                return Err(Error::Verification(
                    "version 1 must not pin a predecessor digest".into(),
                ));
            }
            let anchored: HashSet<&str> = self
                .maintainers()
                .filter(|m| anchor_of(&m.enc_pubkey, &m.sign_pubkey) == anchor_fingerprint)
                .map(|m| m.sign_pubkey.as_str())
                .collect();
            if anchored.is_empty() {
                return Err(Error::Verification(
                    "version 1 has no maintainer matching the trust anchor".into(),
                ));
            }
            anchored
        } else {
            // Forward chain: authority comes from the immediately-preceding roster's
            // maintainers. Strict adjacency forces callers to walk the chain one link at
            // a time, so a stale older snapshot can't resurrect a removed maintainer.
            let prev = previous.ok_or_else(|| {
                Error::Verification("missing previous roster for version > 1".into())
            })?;
            if prev.project_id != self.project_id || prev.env != self.env {
                return Err(Error::Verification(
                    "previous roster is for a different project/environment".into(),
                ));
            }
            // Subtract on this side rather than adding on the other: a `previous` at
            // `u64::MAX` is reachable through the public API, and `prev.roster_version + 1`
            // panics on it in a debug build.
            if self.roster_version.checked_sub(1) != Some(prev.roster_version) {
                return Err(Error::Verification(format!(
                    "previous roster must be version {}, got {}",
                    self.roster_version.saturating_sub(1),
                    prev.roster_version
                )));
            }
            // Pin the predecessor by content, not just by version. Adjacency alone lets a
            // repo-write attacker substitute a different, differently-signed v(N-1) into the
            // chain file; the digest makes that substitution break this link.
            let pinned = self.prev_digest.as_deref().ok_or_else(|| {
                Error::Verification(format!(
                    "roster v{} does not pin its predecessor's digest",
                    self.roster_version
                ))
            })?;
            if pinned != prev.digest()? {
                return Err(Error::Verification(format!(
                    "roster v{} pins a different v{} than the chain holds",
                    self.roster_version, prev.roster_version
                )));
            }
            prev.maintainers().map(|m| m.sign_pubkey.as_str()).collect()
        };

        let bytes = self.signing_bytes()?;
        let ok = self
            .signatures
            .iter()
            .any(|s| authorized.contains(s.sign_pubkey.as_str()) && s.verifies(&bytes));
        if ok {
            Ok(())
        } else {
            Err(Error::Verification(
                "no valid signature from an authorized maintainer".into(),
            ))
        }
    }
}

pub(crate) fn verifying_key(sign_pubkey: &str) -> Result<VerifyingKey> {
    let b64 = sign_pubkey
        .strip_prefix(SIGN_PUBKEY_PREFIX)
        .ok_or_else(|| {
            Error::InvalidKey(format!("signing key missing '{SIGN_PUBKEY_PREFIX}' prefix"))
        })?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| Error::InvalidKey(format!("signing key: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKey("signing key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::InvalidKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &Identity, name: &str, role: Role) -> Member {
        Member {
            name: name.to_string(),
            enc_pubkey: id.enc_pubkey(),
            sign_pubkey: id.sign_pubkey(),
            role,
            added_by: "test".to_string(),
            added_at: "2026-07-03T00:00:00Z".to_string(),
        }
    }

    /// Build a signed v1 roster and return it alongside the pinned anchor.
    fn anchored_v1(alice: &Identity) -> (Roster, String) {
        let mut r = Roster::new_v1(
            "proj-1",
            "development",
            vec![member(alice, "alice", Role::Maintainer)],
        );
        r.sign(alice, "alice").unwrap();
        (r, alice.anchor())
    }

    #[test]
    fn from_json_roundtrips_and_rejects_a_future_schema() {
        let alice = Identity::generate().unwrap();
        let (roster, _anchor) = anchored_v1(&alice);

        let bytes = serde_json::to_vec(&roster).unwrap();
        assert_eq!(Roster::from_json(&bytes).unwrap(), roster);

        let mut future = roster;
        future.schema_version = SCHEMA_VERSION + 1;
        let bytes = serde_json::to_vec(&future).unwrap();
        assert!(matches!(
            Roster::from_json(&bytes),
            Err(Error::UnsupportedSchema("roster", 2, 1))
        ));
    }

    #[test]
    fn member_by_sign_pubkey_finds_and_misses() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let r = Roster::new_v1(
            "proj-1",
            "development",
            vec![
                member(&alice, "alice", Role::Maintainer),
                member(&bob, "bob", Role::Member),
            ],
        );
        assert_eq!(
            r.member_by_sign_pubkey(&bob.sign_pubkey())
                .map(|m| m.name.as_str()),
            Some("bob")
        );
        assert!(r.member_by_sign_pubkey(&stranger.sign_pubkey()).is_none());
    }

    #[test]
    fn valid_v1_verifies() {
        let alice = Identity::generate().unwrap();
        let (r, anchor) = anchored_v1(&alice);
        assert!(r.verify(None, &anchor, 1, "development").is_ok());
    }

    #[test]
    fn v1_not_matching_anchor_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (r, _) = anchored_v1(&alice);
        assert!(r
            .verify(None, "bf1:deadbeefdeadbeef", 1, "development")
            .is_err());
    }

    #[test]
    fn forged_v1_with_copied_enc_key_but_attacker_sign_key_is_rejected() {
        // Security finding #1: an attacker copies the real anchor's public enc key,
        // pairs it with their own signing key, and self-signs. Must NOT verify.
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let anchor = alice.anchor();

        let forged_member = Member {
            enc_pubkey: alice.enc_pubkey(), // public, copied
            sign_pubkey: mallory.sign_pubkey(),
            ..member(&mallory, "alice", Role::Maintainer)
        };
        let mut forged = Roster::new_v1("proj-1", "development", vec![forged_member]);
        forged.sign(&mallory, "mallory").unwrap();

        assert!(forged.verify(None, &anchor, 1, "development").is_err());
    }

    #[test]
    fn extreme_versions_are_refused_rather_than_overflowing() {
        // API hardening: `Roster` is public, so a caller can build these shapes. The version
        // arithmetic used to be unchecked, and both cases panicked in a debug build.
        let alice = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);

        let mut last = v1.clone();
        last.roster_version = u64::MAX;
        assert!(last.amend().is_err(), "amending v{} must refuse", u64::MAX);

        let mut v2 = v1.amend().unwrap();
        v2.sign(&alice, "alice").unwrap();
        assert!(v2.verify(Some(&last), &anchor, 0, "development").is_err());

        let mut zero = v1;
        zero.roster_version = 0;
        assert!(zero.verify(None, &anchor, 0, "development").is_err());
    }

    #[test]
    fn env_mismatch_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (r, anchor) = anchored_v1(&alice);
        assert!(r.verify(None, &anchor, 1, "production").is_err());
    }

    #[test]
    fn v2_signed_by_existing_maintainer_verifies() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);

        let mut v2 = v1.amend().unwrap();
        v2.members.push(member(&bob, "bob", Role::Member));
        v2.sign(&alice, "alice").unwrap();

        assert!(v2.verify(Some(&v1), &anchor, 2, "development").is_ok());
    }

    #[test]
    fn rogue_self_added_maintainer_is_rejected() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);

        let mut rogue = v1.amend().unwrap();
        rogue
            .members
            .push(member(&mallory, "mallory", Role::Maintainer));
        rogue.sign(&mallory, "mallory").unwrap();

        assert!(rogue.verify(Some(&v1), &anchor, 2, "development").is_err());
    }

    #[test]
    fn rollback_to_older_version_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);
        let err = v1.verify(None, &anchor, 2, "development").unwrap_err();
        assert!(matches!(err, Error::Verification(m) if m.contains("downgrade")));
    }

    #[test]
    fn non_adjacent_previous_is_rejected() {
        // Security finding #2: verifying v3 against a stale v1 (not v2) must be refused,
        // so a removed maintainer can't be resurrected via an old snapshot.
        let alice = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);
        let mut v3 = v1.amend().unwrap().amend().unwrap();
        v3.sign(&alice, "alice").unwrap();
        assert!(v3.verify(Some(&v1), &anchor, 3, "development").is_err());
    }

    #[test]
    fn removing_all_maintainers_is_rejected() {
        // Security finding #3: a validly-signed version that leaves zero maintainers
        // would brick the chain forever; refuse it.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);
        let mut v2 = v1.amend().unwrap();
        v2.members = vec![member(&bob, "bob", Role::Member)];
        v2.sign(&alice, "alice").unwrap();
        assert!(v2.verify(Some(&v1), &anchor, 2, "development").is_err());
    }

    #[test]
    fn tampered_members_break_the_signature() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (mut r, anchor) = anchored_v1(&alice);
        r.members.push(member(&bob, "bob", Role::Member));
        assert!(r.verify(None, &anchor, 1, "development").is_err());
    }

    #[test]
    fn amend_bumps_version_pins_the_predecessor_and_drops_signatures() {
        let alice = Identity::generate().unwrap();
        let (v1, _anchor) = anchored_v1(&alice);
        assert!(!v1.signatures.is_empty());
        assert_eq!(v1.prev_digest, None, "v1 pins nothing");

        let next = v1.amend().unwrap();
        assert_eq!(next.roster_version, 2);
        assert!(next.signatures.is_empty());
        assert_eq!(next.prev_digest, Some(v1.digest().unwrap()));
        assert_eq!(next.members, v1.members);
        assert_eq!(next.project_id, v1.project_id);
    }

    #[test]
    fn missing_previous_for_v2_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);
        let mut v2 = v1.amend().unwrap();
        v2.sign(&alice, "alice").unwrap();
        assert!(v2.verify(None, &anchor, 2, "development").is_err());
    }

    #[test]
    fn a_v2_without_a_prev_digest_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (v1, anchor) = anchored_v1(&alice);
        let mut v2 = v1.amend().unwrap();
        v2.prev_digest = None;
        v2.sign(&alice, "alice").unwrap();
        let err = v2.verify(Some(&v1), &anchor, 0, "development").unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("does not pin")),
            "expected a missing-digest rejection, got {err:?}"
        );
    }

    #[test]
    fn a_v1_carrying_a_prev_digest_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (mut v1, anchor) = anchored_v1(&alice);
        v1.prev_digest = Some("00".repeat(32));
        v1.signatures.clear();
        v1.sign(&alice, "alice").unwrap();
        let err = v1.verify(None, &anchor, 0, "development").unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("must not pin")),
            "expected a spurious-digest rejection, got {err:?}"
        );
    }

    #[test]
    fn schema_version_is_covered_by_the_signature() {
        // Regression: `schema_version` sat outside the signing view, so a repo-write
        // attacker could rewrite it and keep the signature valid.
        let alice = Identity::generate().unwrap();
        let (mut r, anchor) = anchored_v1(&alice);
        r.schema_version = 0;
        assert!(r.verify(None, &anchor, 0, "development").is_err());
    }

    #[test]
    fn is_signed_by_any_matches_only_the_listed_keys() {
        let alice = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let (r, _anchor) = anchored_v1(&alice);

        assert!(r
            .is_signed_by_any(&HashSet::from([alice.sign_pubkey()]))
            .unwrap());
        assert!(!r
            .is_signed_by_any(&HashSet::from([stranger.sign_pubkey()]))
            .unwrap());
        assert!(!r.is_signed_by_any(&HashSet::new()).unwrap());
    }

    #[test]
    fn is_signed_by_any_rejects_a_forged_signature_from_a_listed_key() {
        // The key is authorized, but the signature does not verify over these bytes.
        let alice = Identity::generate().unwrap();
        let (mut r, _anchor) = anchored_v1(&alice);
        r.members[0].name = "renamed after signing".into();
        assert!(!r
            .is_signed_by_any(&HashSet::from([alice.sign_pubkey()]))
            .unwrap());
    }
}
