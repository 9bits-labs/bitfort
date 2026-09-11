//! Error type for `bitfort-core`.

use thiserror::Error;

/// Errors produced by the crypto, roster, and vault engine.
#[derive(Debug, Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("random source failed: {0}")]
    Random(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("encryption failed: {0}")]
    Encrypt(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    /// The file is a well-formed `age` document, but this identity is not one of its
    /// recipients. Kept apart from [`Error::Decrypt`] so callers can tell "you have no seat
    /// here" from "this file is damaged", which read very differently to a user.
    #[error("this identity is not a recipient of this vault")]
    NotARecipient,

    #[error("serialization failed: {0}")]
    Serde(String),

    /// Roster failed verification (bad signature chain, downgrade, or env mismatch).
    #[error("roster verification failed: {0}")]
    Verification(String),

    /// A vault decrypted, but nothing authorized to write it produced those bytes: the
    /// payload signature is bad, its signer is not in the roster, or it belongs to another
    /// project or environment. Distinct from [`Error::Decrypt`], which means the local
    /// identity could not open the file at all - the two have different fixes.
    #[error("vault authentication failed: {0}")]
    VaultOrigin(String),

    /// A vault decrypted and was signed by a member of the roster it names, but its
    /// ciphertext is addressed to a different number of keys than that roster has members.
    /// Distinct from [`Error::VaultOrigin`] because the author is authentic and the fix is
    /// different: somebody with a seat wrote a file somebody without one can open.
    #[error("vault audience rejected: {0}")]
    VaultAudience(String),

    /// A vault decrypted and authenticated, but its contents are not usable as an
    /// environment: a secret's name is not an environment variable name. Distinct from
    /// [`Error::VaultOrigin`] because the signature is fine - an authorized writer produced
    /// these bytes, so the fix is to correct the vault, not to distrust its author.
    #[error("vault content rejected: {0}")]
    VaultContent(String),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("git error: {0}")]
    Git(String),

    /// A `.bitfort/` project could not be located, or its layout is malformed.
    #[error("{0}")]
    Project(String),

    /// `config.toml` is missing, unparseable, or internally inconsistent.
    #[error("config error: {0}")]
    Config(String),

    /// An on-disk payload's format version is newer than this build understands.
    #[error(
        "unsupported {0} schema v{1}: this bitfort reads up to v{2}. Upgrade bitfort to open this project."
    )]
    UnsupportedSchema(&'static str, u32, u32),
}

/// Reject an on-disk payload whose format version is newer than this build understands.
/// `found <= supported` passes (current, and any older format we still read); a newer
/// version fails closed rather than silently misparsing a format from the future. `kind`
/// names the payload for the message ("config", "roster", "vault"). This is the migration
/// chokepoint: when a format bumps, its `SCHEMA_VERSION` rises and old builds refuse it here.
pub(crate) fn check_schema(kind: &'static str, found: u32, supported: u32) -> Result<()> {
    if found > supported {
        return Err(Error::UnsupportedSchema(kind, found, supported));
    }
    Ok(())
}

impl Error {
    pub(crate) fn encrypt(e: impl std::fmt::Display) -> Self {
        Self::Encrypt(e.to_string())
    }
    pub(crate) fn decrypt(e: impl std::fmt::Display) -> Self {
        Self::Decrypt(e.to_string())
    }
    pub(crate) fn serde(e: impl std::fmt::Display) -> Self {
        Self::Serde(e.to_string())
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
