//! `bitfort-core`: the crypto, roster, and vault engine shared by every BitFort
//! front end. This crate must stay free of any GUI/webview dependency so the CLI
//! that links it runs on bare Linux and CI runners (see docs/SPEC.md §9.1).
//!
//! The design this implements lives in docs/SPEC.md.

pub mod chain;
pub mod clock;
pub mod config;
pub mod dotenv;
pub mod error;
pub mod git;
pub mod identity;
pub mod invite;
pub mod keystore;
pub mod project;
pub mod resolve;
pub mod roster;
pub mod vault;
pub mod wordlist;

pub use chain::Chain;
pub use config::Config;
pub use error::{Error, Result};
pub use identity::{anchor_of, fingerprint_of, Identity};
pub use invite::Invite;
pub use project::Project;
pub use roster::{Member, Role, Roster, Signature};
pub use vault::Vault;

/// Crate version, surfaced by the CLI's `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_reported() {
        assert!(!VERSION.is_empty());
    }
}
