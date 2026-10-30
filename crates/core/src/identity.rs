//! A BitFort identity: an X25519 encryption keypair (an `age` recipient/identity)
//! plus an Ed25519 signing keypair used to sign roster changes. See docs/SPEC.md §3.
//!
//! Both private keys zeroize on drop (`age::x25519::Identity` wraps a `StaticSecret`,
//! and `ed25519_dalek::SigningKey` zeroizes under its default `zeroize` feature). The
//! secret *export* accessors return [`Zeroizing<String>`] so callers don't leave bare
//! copies of key material in freed heap memory.

use age::secrecy::ExposeSecret;
use base64::{DecodeError, DecodeSliceError, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keystore::{ENV_ENC, ENV_SIGN};

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

    /// Reconstruct an identity from its two secret strings (the keyring / env form). An error
    /// names the variable that holds the bad secret, so it does not read like an error in a
    /// roster key.
    pub fn from_secret_strings(enc: &str, sign: &str) -> Result<Self> {
        let enc: age::x25519::Identity = enc
            .trim()
            .parse()
            .map_err(|e: &str| Error::InvalidKey(format!("{ENV_ENC}: {e}")))?;

        // Decoded into a stack buffer that is wiped on every exit path. `decode` puts the seed
        // in a heap block of its own and frees it unwiped when the key fails part way. The
        // decoder's own message quotes a byte of the key, so each kind of error gets a fixed
        // text instead, with the position of the bad character counted from 1 (invariant 6).
        // The decoder counts bytes from the end of the leading whitespace that `trim` removes,
        // and the user counts characters from the start of the value. Every byte before the
        // bad one is a base64 symbol, so only the whitespace can hold a multi-byte character.
        let lead = sign.chars().take_while(|c| c.is_whitespace()).count();
        let invalid =
            |why: &str| Error::InvalidKey(format!("{ENV_SIGN} is not valid base64: {why}"));
        let mut seed = Zeroizing::new([0u8; 32]);
        match B64.decode_slice(sign.trim(), seed.as_mut_slice()) {
            Ok(32) => Ok(Self {
                enc,
                sign: SigningKey::from_bytes(&seed),
            }),
            Ok(_) | Err(DecodeSliceError::OutputSliceTooSmall) => Err(Error::InvalidKey(format!(
                "{ENV_SIGN} must decode to 32 bytes"
            ))),
            Err(DecodeSliceError::DecodeError(
                DecodeError::InvalidByte(at, _) | DecodeError::InvalidLastSymbol(at, _),
            )) => Err(invalid(&format!("character {} is wrong", lead + at + 1))),
            Err(DecodeSliceError::DecodeError(DecodeError::InvalidLength(_))) => {
                Err(invalid("it has the wrong length; it may be cut short"))
            }
            Err(DecodeSliceError::DecodeError(DecodeError::InvalidPadding)) => {
                Err(invalid("the `=` padding at its end is wrong or missing"))
            }
        }
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

    /// The decoder's own error quotes a byte of the input and its offset. The two low bits of
    /// the last symbol are always zero, so a one-bit typo there gives away the real key
    /// character. Each kind of error gets a fixed text that says what is wrong, and where,
    /// without quoting the key (invariant 6). The text names the variable: a roster's public
    /// signing key fails with "signing key ..." texts, so a bare "signing key" sends the user
    /// to `keys.json` instead of to their own identity.
    #[test]
    fn a_malformed_signing_key_is_named_and_not_quoted() {
        let id = Identity::generate().unwrap();
        let (enc, sign) = (id.enc_secret(), id.sign_secret());
        let invalid =
            |why: &str| format!("invalid key material: {ENV_SIGN} is not valid base64: {why}");
        let wrong_size = format!("invalid key material: {ENV_SIGN} must decode to 32 bytes");
        let cases = [
            // Offset 42 is the last data symbol; `B` (value 1) sets a low bit there.
            (
                format!("{}B{}", &sign[..42], &sign[43..]),
                invalid("character 43 is wrong"),
            ),
            (
                format!("{}!{}", &sign[..10], &sign[11..]),
                invalid("character 11 is wrong"),
            ),
            (
                format!("{}={}", &sign[..10], &sign[11..]),
                invalid("character 11 is wrong"),
            ),
            // Leading whitespace counts, in characters: a no-break space is two bytes.
            (
                format!("\u{a0} {}!{}", &sign[..10], &sign[11..]),
                invalid("character 13 is wrong"),
            ),
            // Cut short: without the trailing `=`, and with one symbol in the last quad.
            (
                sign[..43].to_string(),
                invalid("the `=` padding at its end is wrong or missing"),
            ),
            (
                sign[..41].to_string(),
                invalid("it has the wrong length; it may be cut short"),
            ),
            // Well-formed base64 of the wrong length, rejected (and zeroized) after decoding.
            ("QQ==".to_string(), wrong_size.clone()),
            // Too long: refused before the decoder writes past the 32-byte buffer, also when
            // the extra characters make the padding or the length wrong.
            (format!("{}A", sign.as_str()), wrong_size.clone()),
            (format!("{}AA", &sign[..43]), wrong_size.clone()),
            (format!("{}AAAA", &sign[..43]), wrong_size),
        ];
        for (bad, expected) in cases {
            let err = Identity::from_secret_strings(&enc, &bad).err().unwrap();
            assert_eq!(err.to_string(), expected);
        }
    }

    /// A malformed encryption key names its variable too. The `age` parser's error is a fixed
    /// text, so it is passed on.
    #[test]
    fn a_malformed_encryption_key_is_named() {
        let id = Identity::generate().unwrap();
        let err = Identity::from_secret_strings("not-an-age-key", &id.sign_secret())
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.starts_with(&format!("invalid key material: {ENV_ENC}: ")),
            "{err}"
        );
    }
}
