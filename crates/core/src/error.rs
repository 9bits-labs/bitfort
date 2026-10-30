//! Error type for `bitfort-core`.

use thiserror::Error;

/// Errors produced by the crypto, roster, and vault engine.
#[derive(Debug, Error)]
pub enum Error {
    /// Not `#[from]`: that also makes the i/o error the source, and the message already prints
    /// it, so a printer that walks the cause chain showed it twice. [`From`] is below.
    #[error("i/o error: {0}")]
    Io(std::io::Error),

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

    /// A member display name is not printable text. The name travels inside the signed
    /// roster and is printed back by `member list`, so a control character (a newline above
    /// all) renders one member as two rows, and a bidi or zero-width character reorders what
    /// a reviewer reads.
    #[error("invalid member name: {0}")]
    MemberName(String),

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

    /// A dotenv line, at this 1-based number, has no `=`. Kept apart from [`Error::Config`]
    /// because it is the line a multi-line value leaves behind, so `import` can name the fix
    /// for that case alone. The line itself is withheld: it may be secret material.
    #[error("line {0}: expected KEY=VALUE (the line is withheld: it may be secret material)")]
    NotAnAssignment(usize),

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

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The message carries the i/o error, so the error has no source to print it again.
    #[test]
    fn an_io_error_prints_its_cause_once() {
        let err = Error::from(std::io::Error::other("gone"));
        assert_eq!(err.to_string(), "i/o error: gone");
        assert!(std::error::Error::source(&err).is_none());
    }
}
