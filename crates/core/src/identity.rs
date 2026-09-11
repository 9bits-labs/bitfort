//! A BitFort identity: an X25519 encryption keypair (an `age` recipient/identity)
//! plus an Ed25519 signing keypair used to sign roster changes. See docs/SPEC.md §3.
//!
//! Both private keys zeroize on drop (`age::x25519::Identity` wraps a `StaticSecret`,
//! and `ed25519_dalek::SigningKey` zeroizes under its default `zeroize` feature). The
//! secret *export* accessors return [`Zeroizing<String>`] so callers don't leave bare
//! copies of key material in freed heap memory.

use age::secrecy::ExposeSecret;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

pub(crate) const SIGN_PUBKEY_PREFIX: &str = "ed25519:";
pub(crate) const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A locally-held identity. The private halves never leave the process except via
/// [`Identity::enc_secret`] / [`Identity::sign_secret`], which callers persist only to
/// the OS keyring or an out-of-band `BITFORT_IDENTITY` (see docs/SPEC.md §3.1).
pub struct Identity {
    enc: age::x25519::Identity,
    sign: SigningKey,
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let enc = age::x25519::Identity::generate();

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Random(e.to_string()))?;
        let sign = SigningKey::from_bytes(&seed);
        seed.zeroize();

        Ok(Self { enc, sign })
    }

    /// Reconstruct an identity from its two secret strings (the keyring / env form).
    pub fn from_secret_strings(enc: &str, sign: &str) -> Result<Self> {
        let enc: age::x25519::Identity = enc
            .trim()
            .parse()
            .map_err(|e: &str| Error::InvalidKey(format!("encryption key: {e}")))?;

        // Zeroizing so the decoded secret is scrubbed on every exit path, including the
        // length-mismatch error below.
        let bytes = Zeroizing::new(
            B64.decode(sign.trim())
                .map_err(|e| Error::InvalidKey(format!("signing key: {e}")))?,
        );
        let mut seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("signing key must be 32 bytes".into()))?;
        let sign = SigningKey::from_bytes(&seed);
        seed.zeroize();

        Ok(Self { enc, sign })
    }

    /// The `age` recipient used to encrypt vaults to this identity.
    pub fn recipient(&self) -> age::x25519::Recipient {
        self.enc.to_public()
    }

    /// Public encryption key as an `age1...` string (goes in the roster).
    pub fn enc_pubkey(&self) -> String {
        self.recipient().to_string()
    }

    /// Public signing key as `ed25519:<base64>` (goes in the roster).
    pub fn sign_pubkey(&self) -> String {
        format!(
            "{SIGN_PUBKEY_PREFIX}{}",
            B64.encode(self.sign.verifying_key().to_bytes())
        )
    }

    /// Stable short fingerprint of the encryption public key, e.g. `bf1:9c2a1f...`.
    /// Used for display and keyring-account naming (docs/SPEC.md §3.1). This is NOT the
    /// trust anchor; use [`Identity::anchor`] for that.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.enc_pubkey())
    }

    /// The trust-anchor fingerprint, binding BOTH public keys of the identity
    /// (docs/SPEC.md §5.1). Binding the signing key is what makes the anchor
    /// unforgeable: a valid v1 signature requires the matching signing *private* key,
    /// which a repo-write attacker copying public keys does not have.
    pub fn anchor(&self) -> String {
        anchor_of(&self.enc_pubkey(), &self.sign_pubkey())
    }

    /// Secret encryption key string (`AGE-SECRET-KEY-1...`). Persist only to the keyring.
    pub fn enc_secret(&self) -> Zeroizing<String> {
        Zeroizing::new(self.enc.to_string().expose_secret().to_string())
    }

    /// Secret signing key as base64. Persist only to the keyring.
    pub fn sign_secret(&self) -> Zeroizing<String> {
        let mut raw = self.sign.to_bytes();
        let encoded = Zeroizing::new(B64.encode(raw));
        raw.zeroize();
        encoded
    }

    /// Sign a message with the Ed25519 signing key.
    pub fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature {
        self.sign.sign(msg)
    }

    /// Borrow the `age` identity for decryption.
    pub(crate) fn age_identity(&self) -> &age::x25519::Identity {
        &self.enc
    }
}

/// Compute the display fingerprint of an `age1...` encryption public key.
pub fn fingerprint_of(enc_pubkey: &str) -> String {
    let digest = Sha256::digest(enc_pubkey.as_bytes());
    format!("bf1:{}", hex::encode(&digest[..8]))
}

/// Compute the trust anchor over an identity's encryption and signing public keys.
/// The separator prevents concatenation ambiguity between the two fields.
pub fn anchor_of(enc_pubkey: &str, sign_pubkey: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(enc_pubkey.as_bytes());
    hasher.update(b"|");
    hasher.update(sign_pubkey.as_bytes());
    format!("bf1:{}", hex::encode(&hasher.finalize()[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_distinct_wellformed_keys() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();

        assert!(a.enc_pubkey().starts_with("age1"));
        assert!(a.sign_pubkey().starts_with("ed25519:"));
        assert!(a.fingerprint().starts_with("bf1:"));
        assert!(a.anchor().starts_with("bf1:"));
        assert_ne!(a.enc_pubkey(), b.enc_pubkey());
        assert_ne!(a.sign_pubkey(), b.sign_pubkey());
        assert_ne!(a.anchor(), b.anchor());
    }

    #[test]
    fn anchor_binds_both_keys() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        // Swapping in a different signing key must change the anchor, even with the
        // same encryption key (the core of security finding #1).
        assert_ne!(
            anchor_of(&a.enc_pubkey(), &a.sign_pubkey()),
            anchor_of(&a.enc_pubkey(), &b.sign_pubkey())
        );
    }

    #[test]
    fn secret_string_roundtrip_preserves_identity() {
        let id = Identity::generate().unwrap();
        let restored = Identity::from_secret_strings(&id.enc_secret(), &id.sign_secret()).unwrap();

        assert_eq!(id.enc_pubkey(), restored.enc_pubkey());
        assert_eq!(id.sign_pubkey(), restored.sign_pubkey());
        assert_eq!(id.anchor(), restored.anchor());
    }

    #[test]
    fn signatures_verify_and_survive_roundtrip() {
        let id = Identity::generate().unwrap();
        let restored = Identity::from_secret_strings(&id.enc_secret(), &id.sign_secret()).unwrap();
        let msg = b"bitfort-roster-v1\npayload";

        let sig = restored.sign(msg);
        let vk = id.sign.verifying_key();
        assert!(vk.verify_strict(msg, &sig).is_ok());
    }

    #[test]
    fn malformed_secret_strings_are_rejected() {
        assert!(Identity::from_secret_strings("not-an-age-key", "AAAA").is_err());
        let id = Identity::generate().unwrap();
        assert!(Identity::from_secret_strings(&id.enc_secret(), "!!!not-base64").is_err());
        // Well-formed base64 but wrong length must be rejected (and zeroized).
        assert!(Identity::from_secret_strings(&id.enc_secret(), "QQ==").is_err());
    }
}
