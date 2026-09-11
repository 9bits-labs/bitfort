//! Identity source resolution (docs/SPEC.md §3.1). On a developer machine the
//! identity lives in the OS keyring; in headless/CI environments it is supplied
//! out-of-band via `BITFORT_IDENTITY` (+ `BITFORT_SIGN_IDENTITY`) or a file named
//! by `BITFORT_IDENTITY_FILE`.
//!
//! Resolution order: env vars, then env-named file, then keyring.

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::Identity;

/// Secret encryption key (age identity string).
pub const ENV_ENC: &str = "BITFORT_IDENTITY";
/// Secret signing key (base64 Ed25519 seed).
pub const ENV_SIGN: &str = "BITFORT_SIGN_IDENTITY";
/// Path to a file containing the two variables above.
pub const ENV_FILE: &str = "BITFORT_IDENTITY_FILE";

/// Keyring service name. The local identity is stored as a single item under one
/// account (both secrets together), so loading it costs one keychain access - and, on
/// macOS, one authorization prompt - instead of one per secret.
pub const KEYRING_SERVICE: &str = "bitfort";
const IDENTITY_ACCOUNT: &str = "identity";

/// Like [`load_identity`], but distinguishes "no identity is configured anywhere"
/// (`Ok(None)`) from a real failure (`Err`). Used by `init`/`keygen`, which generate a
/// fresh identity only when none exists. A misconfigured env source (e.g. `BITFORT_IDENTITY`
/// set but malformed, or `BITFORT_SIGN_IDENTITY` missing) is a hard error, not "none" -
/// otherwise a typo would silently mint a second identity instead of surfacing the mistake.
pub fn find_identity() -> Result<Option<Identity>> {
    if std::env::var_os(ENV_ENC).is_some() || std::env::var_os(ENV_FILE).is_some() {
        return load_identity().map(Some);
    }
    match keyring_get_opt(IDENTITY_ACCOUNT)? {
        None => Ok(None),
        // Wrap the returned blob so the plaintext secrets it holds are zeroized on drop.
        Some(blob) => build_identity(&Zeroizing::new(blob)).map(Some),
    }
}

/// Load the local identity, trying each source in precedence order.
pub fn load_identity() -> Result<Identity> {
    // `var_os` so a present-but-non-UTF-8 value is a clear error instead of silently
    // falling through to a different source (security review #3).
    if let Some(raw_enc) = std::env::var_os(ENV_ENC) {
        let enc = Zeroizing::new(
            raw_enc
                .into_string()
                .map_err(|_| Error::InvalidKey(format!("{ENV_ENC} is set but not valid UTF-8")))?,
        );
        let raw_sign = std::env::var_os(ENV_SIGN).ok_or_else(|| {
            Error::InvalidKey(format!("{ENV_SIGN} must be set when {ENV_ENC} is set"))
        })?;
        let sign =
            Zeroizing::new(raw_sign.into_string().map_err(|_| {
                Error::InvalidKey(format!("{ENV_SIGN} is set but not valid UTF-8"))
            })?);
        return Identity::from_secret_strings(&enc, &sign);
    }
    if let Some(path) = std::env::var_os(ENV_FILE) {
        return load_identity_file(Path::new(&path));
    }
    load_from_keyring()
}

/// Load an identity from a `BITFORT_IDENTITY_FILE`-style file.
pub fn load_identity_file(path: &Path) -> Result<Identity> {
    // Refuse group/world-accessible key files, ssh/gpg-style (security review #5).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::InvalidKey(format!(
                "identity file {} is group/world accessible (mode {:o}); run: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            )));
        }
    }
    let contents = Zeroizing::new(std::fs::read_to_string(path)?);
    let (enc, sign) = parse_identity_file(&contents)?;
    Identity::from_secret_strings(&enc, &sign)
}

/// Parse the two key variables out of a dotenv-style identity file. Blank lines and
/// `#` comments are ignored; unknown keys are skipped.
fn parse_identity_file(contents: &str) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let mut enc = None;
    let mut sign = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            ENV_ENC => enc = Some(Zeroizing::new(value.to_string())),
            ENV_SIGN => sign = Some(Zeroizing::new(value.to_string())),
            _ => {}
        }
    }
    let enc =
        enc.ok_or_else(|| Error::InvalidKey(format!("{ENV_ENC} missing in identity file")))?;
    let sign =
        sign.ok_or_else(|| Error::InvalidKey(format!("{ENV_SIGN} missing in identity file")))?;
    Ok((enc, sign))
}

/// Persist an identity to the OS keyring as a single item under [`IDENTITY_ACCOUNT`].
/// Storing overwrites that one item, so a rotation replaces the previous secret in place
/// and never leaves stale private key material behind (security review #4).
pub fn store_identity(identity: &Identity) -> Result<()> {
    keyring_set(IDENTITY_ACCOUNT, serialize_identity(identity).as_str())
}

fn load_from_keyring() -> Result<Identity> {
    // Wrap the returned blob so the plaintext secrets it holds are zeroized on drop.
    let blob = Zeroizing::new(keyring_get(IDENTITY_ACCOUNT)?);
    build_identity(&blob)
}

/// Rebuild an identity from a stored blob, reusing the identity-file parser so the
/// serialization format lives in exactly one place.
fn build_identity(blob: &str) -> Result<Identity> {
    let (enc, sign) = parse_identity_file(blob)?;
    Identity::from_secret_strings(&enc, &sign)
}

/// Serialize both secrets into one blob (the identity-file format). Zeroized on drop so
/// the plaintext does not linger after it is handed to the keyring.
fn serialize_identity(identity: &Identity) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{ENV_ENC}={}\n{ENV_SIGN}={}\n",
        identity.enc_secret().as_str(),
        identity.sign_secret().as_str()
    ))
}

/// Remove the local identity from the keyring.
pub fn delete_identity() -> Result<()> {
    keyring_delete(IDENTITY_ACCOUNT)
}

fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, account).map_err(|e| Error::Keyring(e.to_string()))
}

fn keyring_delete(account: &str) -> Result<()> {
    entry(account)?
        .delete_credential()
        .map_err(|e| Error::Keyring(e.to_string()))
}

fn keyring_set(account: &str, secret: &str) -> Result<()> {
    entry(account)?
        .set_password(secret)
        .map_err(|e| Error::Keyring(e.to_string()))
}

fn keyring_get(account: &str) -> Result<String> {
    entry(account)?
        .get_password()
        .map_err(|e| Error::Keyring(e.to_string()))
}

/// Fetch a keyring entry, mapping a genuinely-absent entry to `Ok(None)` while still
/// surfacing backend failures (locked keyring, no Secret Service) as errors.
fn keyring_get_opt(account: &str) -> Result<Option<String>> {
    match entry(account)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::Keyring(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_a_wellformed_identity_file() {
        let id = Identity::generate().unwrap();
        let contents = format!(
            "# bitfort identity\n{ENV_ENC}={}\n\n{ENV_SIGN}=\"{}\"\n",
            id.enc_secret().as_str(),
            id.sign_secret().as_str(),
        );
        let (enc, sign) = parse_identity_file(&contents).unwrap();
        assert_eq!(enc.as_str(), id.enc_secret().as_str());
        assert_eq!(sign.as_str(), id.sign_secret().as_str());
    }

    #[test]
    fn identity_file_missing_sign_is_rejected() {
        let id = Identity::generate().unwrap();
        let contents = format!("{ENV_ENC}={}\n", id.enc_secret().as_str());
        assert!(parse_identity_file(&contents).is_err());
    }

    #[test]
    fn load_identity_file_reconstructs_the_identity() {
        let id = Identity::generate().unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "{ENV_ENC}={}\n{ENV_SIGN}={}\n",
            id.enc_secret().as_str(),
            id.sign_secret().as_str()
        )
        .unwrap();

        let loaded = load_identity_file(file.path()).unwrap();
        assert_eq!(loaded.enc_pubkey(), id.enc_pubkey());
        assert_eq!(loaded.anchor(), id.anchor());
    }

    #[test]
    fn missing_identity_file_errors() {
        assert!(load_identity_file(Path::new("/nonexistent/bitfort/id")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_identity_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let id = Identity::generate().unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            format!(
                "{ENV_ENC}={}\n{ENV_SIGN}={}\n",
                id.enc_secret().as_str(),
                id.sign_secret().as_str()
            ),
        )
        .unwrap();

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_identity_file(file.path()).is_err());

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_identity_file(file.path()).is_ok());
    }

    #[test]
    fn identity_blob_roundtrips_through_the_stored_format() {
        // The serialized keyring blob must reconstruct the exact identity. Pure (no
        // keychain), so it runs in the normal suite and pins the store/load format.
        let id = Identity::generate().unwrap();
        let blob = serialize_identity(&id);
        let back = build_identity(blob.as_str()).unwrap();
        assert_eq!(back.enc_pubkey(), id.enc_pubkey());
        assert_eq!(back.sign_pubkey(), id.sign_pubkey());
        assert_eq!(back.anchor(), id.anchor());
    }

    // Exercises the real OS keyring; skipped by default so `cargo test` stays hermetic
    // and does not touch the developer's keychain. Run with:
    //   cargo test -p bitfort-core -- --ignored --test-threads=1 keyring
    #[test]
    #[ignore]
    fn keyring_roundtrip() {
        let id = Identity::generate().unwrap();
        store_identity(&id).unwrap();
        assert_eq!(load_from_keyring().unwrap().anchor(), id.anchor());

        // Rotation overwrites the one item in place; no stale material to clean up.
        let rotated = Identity::generate().unwrap();
        store_identity(&rotated).unwrap();
        assert_eq!(
            load_from_keyring().unwrap().enc_pubkey(),
            rotated.enc_pubkey()
        );

        delete_identity().unwrap();
        assert!(load_from_keyring().is_err());
    }
}
