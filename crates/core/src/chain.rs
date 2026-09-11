//! The roster chain (`chain.json`): every predecessor of the environment's current
//! `keys.json`, in order, so a version > 1 roster can be traced back to the pinned trust
//! anchor (docs/SPEC.md §4.3).
//!
//! The chain lives in the repository tree, not in Git history. History is a poor chain
//! store: `git log` applies history simplification (a merge can hide a committed version),
//! a shallow clone carries no predecessors at all (`actions/checkout` defaults to
//! `fetch-depth: 1`), and any git failure degrades into "no history" rather than an error.
//! Reading the chain from a file makes verification total: it works in a shallow clone, in
//! a tarball, and with no `git` binary on PATH.
//!
//! Git keeps exactly one job, in [`crate::git`]: the anti-rollback witness. That check
//! genuinely needs an append-only record an attacker cannot rewrite quietly, and nothing in
//! the working tree can provide one.
//!
//! Tamper evidence comes from `prev_digest`: each roster pins the SHA-256 of its
//! predecessor's signing bytes, so a link cannot be swapped, reordered, or dropped without
//! breaking its successor.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::roster::Roster;

/// Current `chain.json` schema.
pub const SCHEMA_VERSION: u32 = 1;

/// The predecessors of an environment's current roster: versions 1..N-1, ascending.
/// The current version N lives in `keys.json` and is never duplicated here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub schema_version: u32,
    pub rosters: Vec<Roster>,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    /// An empty chain, the correct state for an environment whose roster is still v1.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            rosters: Vec::new(),
        }
    }

    /// Parse a chain from its JSON bytes, rejecting a `schema_version` newer than this build
    /// understands. The single deserialization chokepoint for `chain.json`, mirroring
    /// [`Roster::from_json`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let chain: Chain = serde_json::from_slice(bytes).map_err(Error::serde)?;
        crate::error::check_schema("chain", chain.schema_version, SCHEMA_VERSION)?;
        Ok(chain)
    }

    /// The highest version the chain holds, or 0 when it is empty.
    pub fn highest(&self) -> u64 {
        self.rosters.last().map_or(0, |r| r.roster_version)
    }

    /// The predecessor at `version`, if this chain holds it. Versions are contiguous from 1,
    /// so the index is fixed, and the version is re-checked rather than assumed.
    ///
    /// This is what lets a reader authenticate a payload against the roster it was written
    /// for rather than against the current one: a vault written before a membership change
    /// was signed by a member of the roster of that moment, and looking its signer up in
    /// today's `keys.json` would call an authentic file a forgery (see [`Vault::decrypt`]).
    ///
    /// [`Vault::decrypt`]: crate::vault::Vault::decrypt
    pub fn roster_at(&self, version: u64) -> Option<&Roster> {
        let index = usize::try_from(version.checked_sub(1)?).ok()?;
        self.rosters
            .get(index)
            .filter(|r| r.roster_version == version)
    }

    /// Record `roster` as a predecessor. Callers pass the roster being superseded, so the
    /// appended version must be exactly one past the current tail.
    pub fn append(&mut self, roster: Roster) -> Result<()> {
        let expected = self.highest().checked_add(1).ok_or_else(|| {
            Error::Verification("chain version would overflow; cannot append".into())
        })?;
        if roster.roster_version != expected {
            return Err(Error::Verification(format!(
                "cannot append roster v{} to a chain ending at v{}; expected v{expected}",
                roster.roster_version,
                self.highest()
            )));
        }
        self.rosters.push(roster);
        Ok(())
    }

    /// Verify `current` against this chain, from the pinned anchor forward.
    ///
    /// Every link is checked: the chain is contiguous from v1, each link is signed by a
    /// maintainer of the link before it, each `prev_digest` matches, v1 is self-signed
    /// against `anchor_fingerprint`, and every link belongs to `expected_project` and
    /// `expected_env`. `highest_known_version` is the anti-rollback ceiling from Git and
    /// constrains only `current`; intermediate links are legitimately older.
    ///
    /// Needs no Git and no network. See the module docs for why that matters.
    pub fn verify(
        &self,
        current: &Roster,
        anchor_fingerprint: &str,
        highest_known_version: u64,
        expected_project: &str,
        expected_env: &str,
    ) -> Result<()> {
        // A crash between "append the superseded roster" and "write the new roster" leaves
        // the chain holding a copy of the roster still in `keys.json`. That tail signs the
        // same bytes as `current`, so ignoring it changes nothing we verify, and it saves the
        // environment from wedging on a half-finished amendment (see
        // [`crate::project::Project::commit_amendment`]). The next amendment rewrites both.
        let links: &[Roster] = match self.rosters.last() {
            Some(tail)
                if self.rosters.len() as u64 == current.roster_version
                    && tail.digest()? == current.digest()? =>
            {
                &self.rosters[..self.rosters.len() - 1]
            }
            _ => &self.rosters,
        };

        let expected_links = current.roster_version.saturating_sub(1);
        if links.len() as u64 != expected_links {
            return Err(Error::Verification(format!(
                "roster v{} needs {expected_links} predecessor(s) in chain.json for '{expected_env}', \
                 found {}. The chain file is truncated or out of date.",
                current.roster_version,
                links.len()
            )));
        }

        let mut previous: Option<&Roster> = None;
        for (index, link) in links.iter().enumerate() {
            let expected_version = index as u64 + 1;
            if link.roster_version != expected_version {
                return Err(Error::Verification(format!(
                    "chain.json for '{expected_env}' is out of order: entry {index} is v{}, \
                     expected v{expected_version}",
                    link.roster_version
                )));
            }
            if link.project_id != expected_project {
                return Err(Error::Verification(format!(
                    "chain.json entry v{expected_version} belongs to a different project"
                )));
            }
            // Intermediate links carry no rollback constraint of their own.
            link.verify(previous, anchor_fingerprint, 0, expected_env)?;
            previous = Some(link);
        }

        if current.project_id != expected_project {
            return Err(Error::Verification(
                "roster belongs to a different project than config.toml pins".into(),
            ));
        }
        current.verify(
            previous,
            anchor_fingerprint,
            highest_known_version,
            expected_env,
        )
    }

    /// Every signing key that holds, or has ever held, maintainer authority in this
    /// environment: the maintainers of each chain link plus those of `current`.
    ///
    /// This is the filter the anti-rollback ceiling uses. A committed roster only counts
    /// toward the ceiling if one of these keys signed it. Without the filter, anyone able to
    /// commit could push `{"roster_version": u64::MAX}` and wedge every write path forever,
    /// because the ceiling is read before any signature is checked.
    pub fn known_maintainer_keys(&self, current: &Roster) -> HashSet<String> {
        self.rosters
            .iter()
            .chain(std::iter::once(current))
            .flat_map(|r| r.maintainers())
            .map(|m| m.sign_pubkey.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::roster::{Member, Role};

    fn member(id: &Identity, name: &str, role: Role) -> Member {
        Member {
            name: name.to_string(),
            enc_pubkey: id.enc_pubkey(),
            sign_pubkey: id.sign_pubkey(),
            role,
            added_by: "test".to_string(),
            added_at: "2026-07-03T00:00:00Z".to_string(),
        }
    }

    /// A signed v1 roster plus the anchor it pins.
    fn v1(alice: &Identity) -> (Roster, String) {
        let mut r = Roster::new_v1(
            "proj-1",
            "development",
            vec![member(alice, "alice", Role::Maintainer)],
        );
        r.sign(alice, "alice").unwrap();
        (r, alice.anchor())
    }

    /// Supersede `current`: move it into `chain` and return the signed next version.
    fn advance(
        chain: &mut Chain,
        current: Roster,
        signer: &Identity,
        edit: impl FnOnce(&mut Vec<Member>),
    ) -> Roster {
        let mut next = current.amend().unwrap();
        edit(&mut next.members);
        next.sign(signer, "alice").unwrap();
        chain.append(current).unwrap();
        next
    }

    #[test]
    fn empty_chain_verifies_a_v1_roster() {
        let alice = Identity::generate().unwrap();
        let (r, anchor) = v1(&alice);
        Chain::new()
            .verify(&r, &anchor, 0, "proj-1", "development")
            .unwrap();
    }

    #[test]
    fn chain_verifies_across_three_versions_without_git() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (r1, anchor) = v1(&alice);
        let mut chain = Chain::new();

        let r2 = advance(&mut chain, r1, &alice, |m| {
            m.push(member(&bob, "bob", Role::Member))
        });
        let r3 = advance(&mut chain, r2, &alice, |m| m[1].role = Role::Maintainer);

        assert_eq!(chain.rosters.len(), 2);
        chain
            .verify(&r3, &anchor, 3, "proj-1", "development")
            .unwrap();
    }

    #[test]
    fn appending_past_the_last_version_is_refused_rather_than_overflowing() {
        let alice = Identity::generate().unwrap();
        let (mut last, _) = v1(&alice);
        last.roster_version = u64::MAX;
        let mut chain = Chain::new();
        chain.rosters.push(last.clone());

        assert!(chain.append(last).is_err());
    }

    #[test]
    fn a_truncated_chain_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (r1, anchor) = v1(&alice);
        let mut chain = Chain::new();
        let r2 = advance(&mut chain, r1, &alice, |_| {});
        let r3 = advance(&mut chain, r2, &alice, |_| {});

        chain.rosters.remove(0); // drop v1
        let err = chain
            .verify(&r3, &anchor, 0, "proj-1", "development")
            .unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("predecessor")),
            "expected a truncation rejection, got {err:?}"
        );
    }

    #[test]
    fn a_substituted_link_breaks_the_digest() {
        // An attacker swaps the committed v2 for a different, validly self-signed v2. The
        // version and signature both check out, so only `prev_digest` catches it.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let carol = Identity::generate().unwrap();
        let (r1, anchor) = v1(&alice);
        let mut chain = Chain::new();
        let r2 = advance(&mut chain, r1, &alice, |m| {
            m.push(member(&bob, "bob", Role::Member))
        });
        let r3 = advance(&mut chain, r2, &alice, |_| {});

        // Rebuild v2 with carol instead of bob, signed by the real maintainer.
        let mut forged = chain.rosters[1].clone();
        forged.members[1] = member(&carol, "carol", Role::Member);
        forged.signatures.clear();
        forged.sign(&alice, "alice").unwrap();
        chain.rosters[1] = forged;

        let err = chain
            .verify(&r3, &anchor, 0, "proj-1", "development")
            .unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("pins a different")),
            "expected a digest mismatch, got {err:?}"
        );
    }

    #[test]
    fn an_out_of_order_chain_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (r1, anchor) = v1(&alice);
        let mut chain = Chain::new();
        let r2 = advance(&mut chain, r1, &alice, |_| {});
        let r3 = advance(&mut chain, r2, &alice, |_| {});
        chain.rosters.swap(0, 1);

        let err = chain
            .verify(&r3, &anchor, 0, "proj-1", "development")
            .unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("out of order")),
            "expected an ordering rejection, got {err:?}"
        );
    }

    #[test]
    fn a_foreign_project_id_is_rejected() {
        let alice = Identity::generate().unwrap();
        let (r, anchor) = v1(&alice);
        let err = Chain::new()
            .verify(&r, &anchor, 0, "other-project", "development")
            .unwrap_err();
        assert!(
            matches!(&err, Error::Verification(m) if m.contains("different project")),
            "expected a project mismatch, got {err:?}"
        );
    }

    #[test]
    fn append_refuses_a_non_contiguous_version() {
        let alice = Identity::generate().unwrap();
        let (r1, _) = v1(&alice);
        let mut chain = Chain::new();
        chain.append(r1.clone()).unwrap();
        // v1 again: the chain already ends at v1, so the next append must be v2.
        assert!(chain.append(r1).is_err());
    }

    #[test]
    fn known_maintainer_keys_spans_the_whole_chain() {
        // A maintainer removed at v3 must still count, so a legitimate roster they signed
        // is not ignored by the anti-rollback ceiling filter.
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let (r1, _) = v1(&alice);
        let mut chain = Chain::new();
        let r2 = advance(&mut chain, r1, &alice, |m| {
            m.push(member(&bob, "bob", Role::Maintainer))
        });
        let r3 = advance(&mut chain, r2, &alice, |m| m.truncate(1)); // bob removed

        let keys = chain.known_maintainer_keys(&r3);
        assert!(keys.contains(&alice.sign_pubkey()));
        assert!(
            keys.contains(&bob.sign_pubkey()),
            "history must still count"
        );
    }

    #[test]
    fn from_json_rejects_a_future_schema() {
        let bytes = br#"{"schema_version": 2, "rosters": []}"#;
        assert!(matches!(
            Chain::from_json(bytes),
            Err(Error::UnsupportedSchema("chain", 2, 1))
        ));
    }

    #[test]
    fn json_roundtrips() {
        let alice = Identity::generate().unwrap();
        let (r1, _) = v1(&alice);
        let mut chain = Chain::new();
        chain.append(r1).unwrap();
        let bytes = serde_json::to_vec(&chain).unwrap();
        assert_eq!(Chain::from_json(&bytes).unwrap(), chain);
    }
}
