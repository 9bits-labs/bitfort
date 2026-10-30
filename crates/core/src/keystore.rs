//! Identity source resolution (docs/SPEC.md §3.1). On a developer machine the
//! identity lives in the OS keyring; in headless/CI environments it is supplied
//! out-of-band via `BITFORT_IDENTITY` (+ `BITFORT_SIGN_IDENTITY`) or a file named
//! by `BITFORT_IDENTITY_FILE`.
//!
//! Resolution order: env vars, then env-named file, then keyring.

use std::ffi::OsString;
use std::path::Path;

use zeroize::Zeroizing;

use crate::dotenv;
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
/// set but malformed, or one of the pair set without the other) is a hard error, not "none" -
/// otherwise a typo would silently mint a second identity instead of surfacing the mistake.
pub fn find_identity() -> Result<Option<Identity>> {
    if let Some(identity) = identity_from_env(|var| std::env::var_os(var))? {
        return Ok(Some(identity));
    }
    match keyring_get_opt(IDENTITY_ACCOUNT)? {
        None => Ok(None),
        // Wrap the returned blob so the plaintext secrets it holds are zeroized on drop.
        Some(blob) => build_identity(&Zeroizing::new(blob)).map(Some),
    }
}

/// Load the local identity, trying each source in precedence order.
pub fn load_identity() -> Result<Identity> {
    match identity_from_env(|var| std::env::var_os(var))? {
        Some(identity) => Ok(identity),
        None => load_from_keyring(),
    }
}

/// The env sources, in precedence order: the variable pair, then the file named by
/// [`ENV_FILE`]. `None` means neither is configured and the caller goes on to the keyring.
/// [`find_identity`] and [`load_identity`] both resolve through here, so they cannot disagree
/// on what counts as configured.
///
/// Half a pair is an error, whichever half it is, and it is raised before the file is read, so
/// the stray half is never ignored in favor of another source.
///
/// `var` reads one variable: `std::env::var_os` in use, a fixed list in the tests, so the
/// rules are tested without changing the process environment and without the keyring.
fn identity_from_env(var: impl Fn(&str) -> Option<OsString>) -> Result<Option<Identity>> {
    // `var_os` so a present-but-non-UTF-8 value is a clear error instead of silently
    // falling through to a different source (security review #3).
    let secret = |raw: OsString, var: &str| {
        raw.into_string()
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidKey(format!("{var} is set but not valid UTF-8")))
    };
    match (var(ENV_ENC), var(ENV_SIGN)) {
        (Some(enc), Some(sign)) => {
            let (enc, sign) = (secret(enc, ENV_ENC)?, secret(sign, ENV_SIGN)?);
            Identity::from_secret_strings(&enc, &sign).map(Some)
        }
        (Some(_), None) => Err(Error::InvalidKey(format!(
            "{ENV_SIGN} must be set when {ENV_ENC} is set"
        ))),
        (None, Some(_)) => Err(Error::InvalidKey(format!(
            "{ENV_ENC} must be set when {ENV_SIGN} is set"
        ))),
        (None, None) => match var(ENV_FILE) {
            Some(path) => load_identity_file(Path::new(&path)).map(Some),
            None => Ok(None),
        },
    }
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
    identity_from_text(&contents, &format!("identity file {}", path.display()))
}

/// Build an identity from the text of an identity file or a keyring entry. A key error starts
/// with `origin`: the variable it names is not set in the environment, so the name alone
/// would send the user to the wrong place.
fn identity_from_text(contents: &str, origin: &str) -> Result<Identity> {
    let (enc, sign) = parse_identity_file(contents, origin)?;
    Identity::from_secret_strings(&enc, &sign).map_err(|e| match e {
        Error::InvalidKey(m) => Error::InvalidKey(format!("{origin}: {m}")),
        e => e,
    })
}

/// Parse the two key variables out of a dotenv-style identity file, with the parser `import`
/// uses, so a file a shell can source (`export` prefixes, single quotes) reads the same here.
/// Unknown keys are skipped. `origin` names the text's source in an error, because a parse
/// error alone gives only a line number.
fn parse_identity_file(
    contents: &str,
    origin: &str,
) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let mut enc = None;
    let mut sign = None;
    let pairs = dotenv::parse(contents).map_err(|e| Error::InvalidKey(format!("{origin}: {e}")))?;
    for (key, value) in pairs {
        match key.as_str() {
            ENV_ENC => enc = Some(value),
            ENV_SIGN => sign = Some(value),
            _ => {}
        }
    }
    let enc = enc.ok_or_else(|| Error::InvalidKey(format!("{ENV_ENC} missing in {origin}")))?;
    let sign = sign.ok_or_else(|| Error::InvalidKey(format!("{ENV_SIGN} missing in {origin}")))?;
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
    identity_from_text(blob, "the keyring entry")
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
        let (enc, sign) = parse_identity_file(&contents, "identity file").unwrap();
        assert_eq!(enc.as_str(), id.enc_secret().as_str());
        assert_eq!(sign.as_str(), id.sign_secret().as_str());
    }

    /// A file a shell can source parses to the same values: an `export` prefix and a
    /// single-quoted value used to fail, the first as a missing key and the second as a key
    /// with the quotes still on it.
    #[test]
    fn parses_an_identity_file_in_shell_syntax() {
        let id = Identity::generate().unwrap();
        let contents = format!(
            "export {ENV_ENC}={}\n{ENV_SIGN}='{}'\n",
            id.enc_secret().as_str(),
            id.sign_secret().as_str(),
        );
        let (enc, sign) = parse_identity_file(&contents, "identity file").unwrap();
        assert_eq!(enc.as_str(), id.enc_secret().as_str());
        assert_eq!(sign.as_str(), id.sign_secret().as_str());
    }

    #[test]
    fn identity_file_missing_sign_is_rejected() {
        let id = Identity::generate().unwrap();
        let contents = format!("{ENV_ENC}={}\n", id.enc_secret().as_str());
        assert!(parse_identity_file(&contents, "identity file").is_err());
    }

    /// A bad line names the file and the line. The parser's own error gives only the line,
    /// and the variable that named the file is not in the message. `import`'s advice to add a
    /// value with `bitfort set` is no fix for an identity file, so it is absent.
    #[test]
    fn a_bad_line_in_an_identity_file_names_the_file_and_the_line() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "BITFORT_IDENTITY=x\n[ci]\n").unwrap();
        let err = load_identity_file(file.path()).err().unwrap().to_string();
        assert!(err.contains(&file.path().display().to_string()), "{err}");
        assert!(err.contains("line 2"), "{err}");
        assert!(!err.contains("bitfort set"), "{err}");
    }

    /// The lookup the tests hand to [`identity_from_env`]: `vars` and nothing else.
    fn lookup<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |var| {
            vars.iter()
                .find(|(name, _)| *name == var)
                .map(|(_, value)| value.into())
        }
    }

    /// Half a pair is refused whichever half it is, and before the file is read: the file
    /// here does not exist, so a read would fail with another error. `Ok(None)` would send
    /// the caller to the keyring, which this test never reaches, as an e2e run would.
    #[test]
    fn half_a_pair_is_refused_before_the_file() {
        let id = Identity::generate().unwrap();
        let (enc, sign) = (id.enc_secret(), id.sign_secret());
        let file = (ENV_FILE, "/nonexistent/bitfort/id");
        for (vars, missing) in [
            (&[(ENV_ENC, enc.as_str())][..], ENV_SIGN),
            (&[(ENV_SIGN, sign.as_str())], ENV_ENC),
            (&[(ENV_ENC, enc.as_str()), file], ENV_SIGN),
            (&[(ENV_SIGN, sign.as_str()), file], ENV_ENC),
        ] {
            let err = identity_from_env(lookup(vars)).err().unwrap().to_string();
            assert!(err.contains(&format!("{missing} must be set")), "{err}");
        }
    }

    #[test]
    fn the_pair_resolves_and_no_source_is_none() {
        let id = Identity::generate().unwrap();
        let (enc, sign) = (id.enc_secret(), id.sign_secret());
        let vars = [(ENV_ENC, enc.as_str()), (ENV_SIGN, sign.as_str())];
        let found = identity_from_env(lookup(&vars)).unwrap().unwrap();
        assert_eq!(found.anchor(), id.anchor());
        assert!(identity_from_env(lookup(&[])).unwrap().is_none());
    }

    /// A malformed signing key reaches the user from each source with the variable's name
    /// and, for a file or the keyring entry, where it was read. Each message is compared in
    /// full, so a wrapper that adds the value or the decoder's own text fails here
    /// (invariant 6).
    #[test]
    fn a_malformed_signing_key_is_named_and_not_quoted_on_every_path() {
        let id = Identity::generate().unwrap();
        let (enc, sign) = (id.enc_secret(), id.sign_secret());
        // A wrong last symbol, the case the identity tests explain.
        let bad = format!("{}B{}", &sign[..42], &sign[43..]);
        let text = format!("{ENV_ENC}={}\n{ENV_SIGN}={bad}\n", enc.as_str());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        let vars = [(ENV_ENC, enc.as_str()), (ENV_SIGN, bad.as_str())];
        let why = format!("{ENV_SIGN} is not valid base64: a character is wrong");

        for (err, origin) in [
            (
                identity_from_env(lookup(&vars)).err().unwrap(),
                String::new(),
            ),
            (
                load_identity_file(file.path()).err().unwrap(),
                format!("identity file {}: ", file.path().display()),
            ),
            (
                build_identity(&text).err().unwrap(),
                "the keyring entry: ".into(),
            ),
        ] {
            assert_eq!(
                err.to_string(),
                format!("invalid key material: {origin}{why}")
            );
        }
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
