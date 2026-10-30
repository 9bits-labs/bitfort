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
/// Every variable the env sources read. `run` removes them from the child.
pub const IDENTITY_VARS: [&str; 3] = [ENV_ENC, ENV_SIGN, ENV_FILE];

/// Keyring service name. The local identity is stored as a single item under one
/// account (both secrets together), so loading it costs one keychain access - and, on
/// macOS, one authorization prompt - instead of one per secret.
pub const KEYRING_SERVICE: &str = "bitfort";
const IDENTITY_ACCOUNT: &str = "identity";

/// Load the local identity, trying each source in precedence order. `Ok(None)` means no
/// identity is configured anywhere, and every other failure is an `Err`, so a caller can tell
/// the case where generating an identity or advising `keygen` fits from a source that does not
/// load. A misconfigured env source (e.g. `BITFORT_IDENTITY` set but malformed, or one of the
/// pair set without the other) is a hard error, not "none" - otherwise a typo would silently
/// mint a second identity instead of surfacing the mistake.
pub fn find_identity() -> Result<Option<Identity>> {
    if let Some(identity) = identity_from_env(|var| std::env::var_os(var))? {
        return Ok(Some(identity));
    }
    match keyring_get(IDENTITY_ACCOUNT)? {
        None => Ok(None),
        // Wrap the returned blob so the plaintext secrets it holds are zeroized on drop.
        Some(blob) => build_identity(&Zeroizing::new(blob)).map(Some),
    }
}

/// The env sources, in precedence order: the variable pair, then the file named by
/// [`ENV_FILE`]. `None` means neither is configured and the caller goes on to the keyring.
///
/// Half a pair is an error, whichever half it is, and it is raised before the file is read, so
/// the stray half is never ignored in favor of another source.
///
/// An empty variable counts as unset. A CI platform gives a job that may not read its secrets
/// an empty string (on GitHub Actions, a pull request from a fork), and that job has no
/// identity, not a broken one: `verify --strict` fails on a broken one (docs/SPEC.md §3.1).
///
/// `var` reads one variable: `std::env::var_os` in use, a fixed list in the tests, so the
/// rules are tested without changing the process environment and without the keyring.
fn identity_from_env(var: impl Fn(&str) -> Option<OsString>) -> Result<Option<Identity>> {
    let var = |name: &str| var(name).filter(|value| !value.is_empty());
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

/// The variables of [`IDENTITY_VARS`] that are set to an empty string, which
/// [`identity_from_env`] counts as unset. The CLI names them in its advice to set the
/// variables, so that advice does not read as already followed.
pub fn empty_identity_vars() -> Vec<&'static str> {
    empty_vars(|var| std::env::var_os(var))
}

/// [`empty_identity_vars`] over `var`, the reader [`identity_from_env`] takes.
fn empty_vars(var: impl Fn(&str) -> Option<OsString>) -> Vec<&'static str> {
    IDENTITY_VARS
        .into_iter()
        .filter(|name| var(name).is_some_and(|value| value.is_empty()))
        .collect()
}

/// Load an identity from a `BITFORT_IDENTITY_FILE`-style file.
pub fn load_identity_file(path: &Path) -> Result<Identity> {
    // Quoted: the path comes from the environment, and the message goes to a terminal.
    let shown = dotenv::quoted_path(path);
    let origin = format!("identity file {shown}");
    let unreadable = |e| Error::file("read identity file", path, e);
    // Refuse group/world-accessible key files, ssh/gpg-style (security review #5).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(unreadable)?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::InvalidKey(format!(
                "{origin} is group/world accessible (mode {:o}); run: chmod 600 {shown}",
                mode & 0o777,
            )));
        }
    }
    let contents = Zeroizing::new(std::fs::read_to_string(path).map_err(unreadable)?);
    identity_from_text(&contents, &origin)
}

/// Build an identity from the text of an identity file or a keyring entry. Every key error
/// starts with `origin`: a parse error alone gives only a line number, and the variable a key
/// error names is not set in the environment, so the name alone would send the user to the
/// wrong place.
fn identity_from_text(contents: &str, origin: &str) -> Result<Identity> {
    parse_identity_file(contents)
        .and_then(|(enc, sign)| Identity::from_secret_strings(&enc, &sign))
        .map_err(|e| match e {
            Error::InvalidKey(m) => Error::InvalidKey(format!("{origin}: {m}")),
            e => e,
        })
}

/// Parse the two key variables out of a dotenv-style identity file, with the parser `import`
/// uses, so a file a shell can source (`export` prefixes, single quotes) reads the same here.
/// Unknown keys are skipped.
fn parse_identity_file(contents: &str) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let mut enc = None;
    let mut sign = None;
    let pairs = dotenv::parse(contents).map_err(|e| Error::InvalidKey(e.to_string()))?;
    for (key, value) in pairs {
        match key.as_str() {
            ENV_ENC => enc = Some(value),
            ENV_SIGN => sign = Some(value),
            _ => {}
        }
    }
    let enc = enc.ok_or_else(|| Error::InvalidKey(format!("{ENV_ENC} is missing")))?;
    let sign = sign.ok_or_else(|| Error::InvalidKey(format!("{ENV_SIGN} is missing")))?;
    Ok((enc, sign))
}

/// Persist an identity to the OS keyring as a single item under [`IDENTITY_ACCOUNT`].
/// Storing overwrites that one item, so a rotation replaces the previous secret in place
/// and never leaves stale private key material behind (security review #4).
pub fn store_identity(identity: &Identity) -> Result<()> {
    keyring_set(IDENTITY_ACCOUNT, serialize_identity(identity).as_str())
}

/// Rebuild an identity from a stored blob, reusing the identity-file parser so the
/// serialization format lives in exactly one place.
fn build_identity(blob: &str) -> Result<Identity> {
    identity_from_text(blob, &keyring_origin())
}

/// Where a key error from the keyring item was read. It names the item: no bitfort command
/// removes a damaged one (`keygen` fails on it too), so the user removes it with the OS
/// keyring tool and needs the service and the account to find it.
fn keyring_origin() -> String {
    format!("the keyring entry (service \"{KEYRING_SERVICE}\", account \"{IDENTITY_ACCOUNT}\")")
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

/// Fetch a keyring entry, mapping a genuinely-absent entry to `Ok(None)` while still
/// surfacing failures as errors (see [`keyring_read_error`]).
fn keyring_get(account: &str) -> Result<Option<String>> {
    match entry(account)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keyring_read_error(e)),
    }
}

/// The error for a failed keyring read. A backend failure (locked keyring, no Secret Service)
/// is [`Error::Keyring`], which callers read as "the keyring cannot be used". An entry that
/// exists but does not load is a configured source that is broken, like a malformed key, so it
/// names the entry instead: `keygen` cannot fix it, and `verify --strict` fails on it.
fn keyring_read_error(e: keyring::Error) -> Error {
    match e {
        keyring::Error::BadEncoding(_)
        | keyring::Error::BadDataFormat(..)
        | keyring::Error::Ambiguous(_) => Error::InvalidKey(format!("{}: {e}", keyring_origin())),
        e => Error::Keyring(e.to_string()),
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
        let (enc, sign) = parse_identity_file(&contents).unwrap();
        assert_eq!(enc.as_str(), id.enc_secret().as_str());
        assert_eq!(sign.as_str(), id.sign_secret().as_str());
    }

    /// A missing key starts with where the text was read, the same as a bad line and a
    /// malformed key do.
    #[test]
    fn a_missing_key_error_starts_with_its_origin() {
        let id = Identity::generate().unwrap();
        let (enc, sign) = (id.enc_secret(), id.sign_secret());
        for (contents, missing) in [
            (format!("{ENV_ENC}={}\n", enc.as_str()), ENV_SIGN),
            (format!("{ENV_SIGN}={}\n", sign.as_str()), ENV_ENC),
        ] {
            let err = build_identity(&contents).err().unwrap();
            assert_eq!(
                err.to_string(),
                format!(
                    "invalid key material: {}: {missing} is missing",
                    keyring_origin()
                )
            );
        }
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

    /// An empty variable counts as unset: a fork's pull request gets empty secrets, and that
    /// job has no identity, not a broken one. Half a pair is still refused when the other
    /// half is empty.
    #[test]
    fn an_empty_variable_counts_as_unset() {
        let id = Identity::generate().unwrap();
        let enc = id.enc_secret();
        let empty = [(ENV_ENC, ""), (ENV_SIGN, ""), (ENV_FILE, "")];
        assert!(identity_from_env(lookup(&empty)).unwrap().is_none());
        assert_eq!(empty_vars(lookup(&empty)), IDENTITY_VARS);

        let half = [(ENV_ENC, enc.as_str()), (ENV_SIGN, "")];
        let err = identity_from_env(lookup(&half)).err().unwrap().to_string();
        assert!(err.contains(&format!("{ENV_SIGN} must be set")), "{err}");
        assert_eq!(empty_vars(lookup(&half)), [ENV_SIGN]);
        assert!(empty_vars(lookup(&[])).is_empty());
    }

    /// An entry that exists but does not load is a broken source, not a keyring that cannot be
    /// used: the CLI treats [`Error::Keyring`] as the second, and passes `verify --strict` on it.
    /// The error names the service and the account, because the user removes the item by hand.
    #[test]
    fn an_unreadable_keyring_entry_is_not_a_keyring_failure() {
        let err = keyring_read_error(keyring::Error::BadEncoding(vec![0xff]));
        assert_eq!(
            err.to_string(),
            "invalid key material: the keyring entry (service \"bitfort\", account \"identity\"): \
             Password data is not valid UTF-8"
        );
        let err = keyring_read_error(keyring::Error::NoStorageAccess("locked".into()));
        assert!(matches!(err, Error::Keyring(_)), "{err:?}");
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
        let why = format!("{ENV_SIGN} is not valid base64: character 43 is wrong");

        for (err, origin) in [
            (
                identity_from_env(lookup(&vars)).err().unwrap(),
                String::new(),
            ),
            (
                load_identity_file(file.path()).err().unwrap(),
                format!("identity file \"{}\": ", file.path().display()),
            ),
            (
                build_identity(&text).err().unwrap(),
                format!("{}: ", keyring_origin()),
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

    /// A file that cannot be read names itself. The OS error says only "No such file or
    /// directory", and the variable that named the file is not in the message. The OS error
    /// itself is kept, not copied into a string.
    #[test]
    fn a_missing_identity_file_names_itself() {
        let err = load_identity_file(Path::new("/nonexistent/bitfort/id"))
            .err()
            .unwrap();
        assert!(
            matches!(&err, Error::File { error, .. } if error.kind() == std::io::ErrorKind::NotFound),
            "{err:?}"
        );
        let err = err.to_string();
        assert!(
            err.starts_with("cannot read identity file \"/nonexistent/bitfort/id\": "),
            "{err}"
        );
    }

    /// A control character in the path is escaped in the key errors too, not only in the read
    /// error [`Error::File`] prints, so a path from the environment cannot drive the terminal
    /// that prints the error.
    #[cfg(unix)]
    #[test]
    fn an_identity_file_path_is_escaped_in_its_key_errors() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x\x1b[31m.key");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_identity_file(&path).err().unwrap().to_string();
        assert!(!err.contains('\x1b'), "{err:?}");
        assert!(err.contains(r"x\x1b[31m.key"), "{err:?}");
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
        // The keyring alone: `find_identity` would take an identity from the environment.
        let stored = || build_identity(&keyring_get(IDENTITY_ACCOUNT).unwrap().unwrap());
        let id = Identity::generate().unwrap();
        store_identity(&id).unwrap();
        assert_eq!(stored().unwrap().anchor(), id.anchor());

        // Rotation overwrites the one item in place; no stale material to clean up.
        let rotated = Identity::generate().unwrap();
        store_identity(&rotated).unwrap();
        assert_eq!(stored().unwrap().enc_pubkey(), rotated.enc_pubkey());

        delete_identity().unwrap();
        assert!(keyring_get(IDENTITY_ACCOUNT).unwrap().is_none());
    }
}
