//! `config.toml`: project-level settings pinned once by `init` (docs/SPEC.md §4.2).
//! Holds the stable project id, the environment list, and - load-bearing for trust -
//! the `trust_anchor_fingerprint` that every roster's version-1 self-signature is
//! checked against (§5.1).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Current `config.toml` schema.
pub const SCHEMA_VERSION: u32 = 1;

/// The parsed `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub project_id: String,
    pub default_env: String,
    pub environments: Vec<String>,
    pub trust_anchor_fingerprint: String,
    /// Set by `rotate`; absent until the first rotation (docs/SPEC.md §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<String>,
}

impl Config {
    /// Build the initial config written by `init`, seeded with the default
    /// environment and the initializer's pinned trust anchor.
    pub fn new(
        project_id: impl Into<String>,
        default_env: impl Into<String>,
        trust_anchor_fingerprint: impl Into<String>,
    ) -> Self {
        let default_env = default_env.into();
        Self {
            schema_version: SCHEMA_VERSION,
            project_id: project_id.into(),
            environments: vec![default_env.clone()],
            default_env,
            trust_anchor_fingerprint: trust_anchor_fingerprint.into(),
            rotated_at: None,
        }
    }

    /// Parse a `config.toml` document.
    pub fn from_toml(s: &str) -> Result<Self> {
        let config: Config = toml::from_str(s).map_err(|e| Error::Config(e.to_string()))?;
        crate::error::check_schema("config", config.schema_version, SCHEMA_VERSION)?;
        config.check_env_names()?;
        Ok(config)
    }

    /// Refuse a config whose environment names are not safe path components.
    ///
    /// Every roster, chain and vault path is built by joining one of these names under
    /// `environments/`, and `config.toml` is an ordinary tracked file that a merge or a pull
    /// request can change. `environments = ["../../evil"]` therefore walks a vault write out
    /// of the project, and an absolute `default_env` walks it anywhere on the disk. The check
    /// lives in the parser, not in the one command that adds a name, so no caller can hold a
    /// `Config` whose names were never checked.
    fn check_env_names(&self) -> Result<()> {
        for name in self.environments.iter().chain([&self.default_env]) {
            check_env_name(name)?;
        }
        Ok(())
    }

    /// Serialize to `config.toml` text.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))
    }

    /// Whether `env` is a declared environment of this project.
    pub fn has_env(&self, env: &str) -> bool {
        self.environments.iter().any(|e| e == env)
    }

    /// Whether `name` can be added as a new environment: a filesystem-safe single path
    /// component and not already declared. This is the guard for the `environments/<name>`
    /// directory core builds from an env name (docs/SPEC.md §4.1), so it lives here rather
    /// than in one front end - a raw name with `..` or a separator must never reach the path.
    pub fn check_env_addable(&self, name: &str) -> Result<()> {
        if self.has_env(name) {
            return Err(Error::Config(format!(
                "environment '{name}' already exists"
            )));
        }
        check_env_name(name)
    }

    /// Register a new environment after validating it (see [`Config::check_env_addable`]).
    /// The single core-owned path for adding an environment to the list.
    pub fn add_env(&mut self, name: &str) -> Result<()> {
        self.check_env_addable(name)?;
        self.environments.push(name.to_string());
        Ok(())
    }
}

/// [`is_valid_env_name`] as a refusal, so every rejection carries the same message.
fn check_env_name(name: &str) -> Result<()> {
    if !is_valid_env_name(name) {
        return Err(Error::Config(format!(
            "`{name}` is not a valid environment name (use letters, digits, '-' or '_')"
        )));
    }
    Ok(())
}

/// A safe single path component for an environment directory: non-empty, and only ASCII
/// letters, digits, `-`, or `_` (rules out `.`, `..`, and any path separator, so an env name
/// cannot escape `environments/`). Mirrors [`crate::dotenv::is_valid_key`].
pub fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A fresh, stable, random project id (32 hex chars over 16 random bytes).
pub fn generate_project_id() -> Result<String> {
    // Zeroizing purely for tidiness; the id is public, but the buffer is transient.
    let mut bytes = Zeroizing::new([0u8; 16]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|e| Error::Random(e.to_string()))?;
    Ok(hex::encode(bytes.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_toml() {
        let c = Config::new("abc123", "development", "bf1:9c2a1f00");
        let text = c.to_toml().unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), c);
        assert!(!text.contains("rotated_at")); // omitted while None
    }

    #[test]
    fn a_future_schema_version_is_rejected() {
        let text = r#"
schema_version = 2
project_id = "x"
default_env = "development"
environments = ["development"]
trust_anchor_fingerprint = "bf1:0"
"#;
        assert!(matches!(
            Config::from_toml(text),
            Err(Error::UnsupportedSchema("config", 2, 1))
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = r#"
schema_version = 1
project_id = "x"
default_env = "development"
environments = ["development"]
trust_anchor_fingerprint = "bf1:0"
surprise = true
"#;
        assert!(Config::from_toml(text).is_err());
    }

    #[test]
    fn from_toml_rejects_an_environment_name_that_escapes_the_project() {
        // Regression: only `env add` validated a name, so a `config.toml` edited by hand or by
        // a merge could carry one. Every roster, chain and vault path is built by joining it
        // under `environments/`, so `bitfort set` wrote the vault outside the project.
        let escaping = r#"
schema_version = 1
project_id = "x"
default_env = "development"
environments = ["development", "../../evil"]
trust_anchor_fingerprint = "bf1:0"
"#;
        assert!(matches!(Config::from_toml(escaping), Err(Error::Config(_))));

        // The default is checked too: it is the name every command resolves without `--env`.
        let absolute_default = r#"
schema_version = 1
project_id = "x"
default_env = "/tmp/evil"
environments = ["development"]
trust_anchor_fingerprint = "bf1:0"
"#;
        assert!(matches!(
            Config::from_toml(absolute_default),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn project_ids_are_distinct_and_hex() {
        let a = generate_project_id().unwrap();
        let b = generate_project_id().unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn has_env_reflects_membership() {
        let c = Config::new("x", "development", "bf1:0");
        assert!(c.has_env("development"));
        assert!(!c.has_env("production"));
    }

    #[test]
    fn env_name_validation_rejects_path_tricks() {
        assert!(is_valid_env_name("production"));
        assert!(is_valid_env_name("staging-2"));
        assert!(is_valid_env_name("dev_env"));
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("..")); // traversal
        assert!(!is_valid_env_name("a/b")); // separator
        assert!(!is_valid_env_name("a.b")); // dot
    }

    #[test]
    fn add_env_validates_and_dedups() {
        let mut c = Config::new("x", "development", "bf1:0");
        c.add_env("production").unwrap();
        assert!(c.has_env("production"));
        assert!(c.add_env("development").is_err()); // duplicate
        assert!(c.add_env("../evil").is_err()); // invalid name, not registered
        assert_eq!(c.environments, vec!["development", "production"]);
    }
}
