//! The copy/paste invite blob a new developer produces with `keygen` and hands to a
//! maintainer (docs/SPEC.md §5.2). It carries only public key material, so it is safe
//! to send over Slack/email. `member add` (M3) decodes it; M2 only produces it.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{Identity, B64};

/// Human-visible tag so a pasted blob is recognizable and versioned.
const INVITE_PREFIX: &str = "bfinvite1:";

/// The public halves of an identity, plus a self-suggested display name the maintainer
/// may override when adding the member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub name: String,
    pub enc_pubkey: String,
    pub sign_pubkey: String,
}

impl Invite {
    /// Build an invite from a local identity and a suggested name.
    pub fn from_identity(identity: &Identity, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enc_pubkey: identity.enc_pubkey(),
            sign_pubkey: identity.sign_pubkey(),
        }
    }

    /// Encode as `bfinvite1:<base64(json)>`.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(Error::serde)?;
        Ok(format!("{INVITE_PREFIX}{}", B64.encode(json)))
    }

    /// Decode a `bfinvite1:...` blob, rejecting a missing/incorrect prefix. The key material
    /// inside is still untrusted at this point; [`Invite::validate_keys`] checks it.
    pub fn decode(blob: &str) -> Result<Self> {
        let b64 = blob.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| {
            Error::InvalidKey(format!("invite must start with `{INVITE_PREFIX}`"))
        })?;
        let json = B64
            .decode(b64)
            .map_err(|e| Error::InvalidKey(format!("invite is not valid base64: {e}")))?;
        serde_json::from_slice(&json)
            .map_err(|e| Error::InvalidKey(format!("invite payload is malformed: {e}")))
    }

    /// Check that both public keys actually parse, before anything is written.
    ///
    /// An invite is untrusted input pasted from a chat message. Without this, a malformed
    /// `enc_pubkey` was only caught later, while encrypting the vault - which meant the
    /// roster could already be on disk one version ahead of the vault by the time it failed.
    pub fn validate_keys(&self) -> Result<()> {
        self.enc_pubkey
            .parse::<age::x25519::Recipient>()
            .map_err(|e: &str| Error::InvalidKey(format!("invite enc_pubkey: {e}")))?;
        crate::roster::verifying_key(&self.sign_pubkey)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_public_material() {
        let id = Identity::generate().unwrap();
        let invite = Invite::from_identity(&id, "alice");
        let blob = invite.encode().unwrap();
        assert!(blob.starts_with(INVITE_PREFIX));

        let back = Invite::decode(&blob).unwrap();
        assert_eq!(back, invite);
        assert_eq!(back.enc_pubkey, id.enc_pubkey());
        assert_eq!(back.sign_pubkey, id.sign_pubkey());
    }

    #[test]
    fn carries_no_secret_material() {
        let id = Identity::generate().unwrap();
        let blob = Invite::from_identity(&id, "alice").encode().unwrap();
        // The secret encryption key is `AGE-SECRET-KEY-...`; it must never appear.
        assert!(!blob.contains("SECRET"));
    }

    #[test]
    fn rejects_bad_prefix_and_payload() {
        assert!(Invite::decode("nope").is_err());
        assert!(Invite::decode("bfinvite1:!!!not-base64").is_err());
        assert!(Invite::decode("bfinvite1:aGVsbG8=").is_err()); // valid b64, not an Invite
    }
}
