//! Vault conflict resolution after a git merge or rebase (docs/SPEC.md §4.5). The vault
//! is armored `age`, so a concurrent edit surfaces as an ordinary git text conflict.
//! Splitting the conflicted file back into its two sides and merging the two decrypted
//! `vars` maps are pure functions here; the CLI decrypts each side and re-encrypts the
//! merged result around them.

use std::collections::{BTreeMap, BTreeSet};

/// A key both branches changed, in different ways - a genuine conflict a human must
/// resolve. `None` on a side means that side deleted the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Conflict {
    pub key: String,
    pub ours: Option<String>,
    pub theirs: Option<String>,
}

/// Names and presence only. A derived `Debug` would put both sides' secret values into
/// whatever printed it - a panic message, a log line, a `--json` error path.
impl std::fmt::Debug for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shape = |side: &Option<String>| if side.is_some() { "set" } else { "deleted" };
        f.debug_struct("Conflict")
            .field("key", &self.key)
            .field("ours", &shape(&self.ours))
            .field("theirs", &shape(&self.theirs))
            .finish()
    }
}

/// The result of merging the `vars` maps: everything auto-resolvable in `merged` (holding
/// the `ours` value for any conflicting key), and the conflicting keys called out.
#[derive(Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    pub merged: BTreeMap<String, String>,
    pub conflicts: Vec<Conflict>,
}

/// Names only, for the reason given on [`Conflict`]'s impl: `merged` holds every secret
/// value the merge produced.
impl std::fmt::Debug for MergeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergeOutcome")
            .field("merged", &self.merged.keys().collect::<Vec<_>>())
            .field("conflicts", &self.conflicts)
            .finish()
    }
}

/// Whether `text` carries git conflict markers.
///
/// A detector, and deliberately nothing more. `resolve` once reconstructed both sides by
/// parsing these markers, and that made the merge's inputs ordinary file content: whoever can
/// write `vault.enc` chose what the merge saw, and the ancestor decides per key which side
/// wins. All three inputs now come from git's index, which git computed from the two commits
/// being merged (`Project::load_vault_conflict`).
///
/// What is left for this to do is tell one message from another. A file with markers that git
/// has no conflict for is a merge state that was dropped or was never real, and the user has
/// to restore it before anything can be merged.
///
/// Any leading `<` counts, rather than the seven of a default marker. The input is an armored
/// `age` document: `<` is outside base64 and outside the `-----BEGIN...` header, so it cannot
/// start a line of one. Matching the exact width would miss a repository that sets
/// `conflict-marker-size` below 7 through `.gitattributes`, and missing it turns a refusal
/// into "nothing to resolve".
pub fn has_conflict_markers(text: &str) -> bool {
    text.lines().any(|line| line.starts_with('<'))
}

/// Three-way merge of the decrypted `vars` maps against their common ancestor
/// (docs/SPEC.md §4.5). Per key: both sides agreeing is taken; one side matching `base` is
/// the side that did not change it, so the other side wins - deletion included; anything
/// else is reported as a [`Conflict`], with `merged` holding the `ours` value until the
/// caller chooses a side.
///
/// The base is what makes a deletion survive. A two-way union cannot tell "deleted on our
/// side" from "added on theirs", so `bitfort unset` on one branch was undone by the next
/// merge and the removed secret came back with no warning (finding 1.7).
///
/// **`base` is `None` when git held no ancestor, and that is a degraded merge, not a
/// variant of the same one.** It falls back to exactly the old two-way union - every key
/// differs from an absent base on whichever side has it, so that side wins - and the
/// resurrection above is live again. An `Option` rather than an empty map, because a caller
/// must not be able to reach that mode by accident: the one that passes `None` owes the user
/// a warning.
pub fn merge_vars(
    base: Option<&BTreeMap<String, String>>,
    ours: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
) -> MergeOutcome {
    let mut merged = BTreeMap::new();
    let mut conflicts = Vec::new();
    let keys: BTreeSet<&String> = base
        .into_iter()
        .flat_map(BTreeMap::keys)
        .chain(ours.keys())
        .chain(theirs.keys())
        .collect();

    for key in keys {
        let was = base.and_then(|b| b.get(key));
        let (ours, theirs) = (ours.get(key), theirs.get(key));
        let taken = if ours == theirs {
            ours
        } else if ours == was {
            theirs
        } else if theirs == was {
            ours
        } else {
            conflicts.push(Conflict {
                key: key.clone(),
                ours: ours.cloned(),
                theirs: theirs.cloned(),
            });
            ours
        };
        if let Some(value) = taken {
            merged.insert(key.clone(), value.clone());
        }
    }
    MergeOutcome { merged, conflicts }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_markers_in_both_conflict_styles() {
        let default = "head\n<<<<<<< HEAD\nA\n=======\nB\n>>>>>>> branch\ntail\n";
        let diff3 = "<<<<<<< ours\nA\n||||||| base\nBASE\n=======\nB\n>>>>>>> theirs\n";
        assert!(has_conflict_markers(default));
        assert!(has_conflict_markers(diff3));
    }

    #[test]
    fn a_clean_armored_vault_carries_no_markers() {
        // The `=` padding at the end of a base64 armor line is the near miss: it is why this
        // looks for the `<<<<<<<` opener and nothing else.
        let armored = "-----BEGIN AGE ENCRYPTED FILE-----\nYWJjZA==\n=======\n\
                       -----END AGE ENCRYPTED FILE-----\n";
        assert!(!has_conflict_markers(armored));
        assert!(!has_conflict_markers("just some text\nno markers\n"));
    }

    /// Build a map from `(key, value)` pairs.
    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn merges_disjoint_keys_without_conflict() {
        let base = map(&[]);
        let out = merge_vars(Some(&base), &map(&[("A", "1")]), &map(&[("B", "2")]));
        assert!(out.conflicts.is_empty());
        assert_eq!(out.merged, map(&[("A", "1"), ("B", "2")]));
    }

    #[test]
    fn identical_edits_are_not_a_conflict() {
        let ours = map(&[("A", "same")]);
        let out = merge_vars(Some(&map(&[("A", "old")])), &ours, &ours);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.merged, ours);
    }

    #[test]
    fn differing_values_are_reported_as_conflicts() {
        let out = merge_vars(
            Some(&map(&[("A", "old")])),
            &map(&[("A", "mine")]),
            &map(&[("A", "yours")]),
        );
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "A");
        assert_eq!(out.conflicts[0].ours.as_deref(), Some("mine"));
        assert_eq!(out.conflicts[0].theirs.as_deref(), Some("yours"));
        // Until the caller picks a side, `merged` holds ours.
        assert_eq!(out.merged.get("A").unwrap(), "mine");
    }

    #[test]
    fn a_deletion_on_one_side_survives_the_merge() {
        // Finding 1.7: the two-way union could not tell "deleted on our side" from "added on
        // theirs", so `bitfort unset` was undone by the next merge and a revoked secret came
        // back. The base is what separates the two.
        let base = map(&[("A", "1"), ("B", "2")]);
        let ours = map(&[("A", "1")]); // B unset here
        let theirs = map(&[("A", "1"), ("B", "2"), ("C", "3")]); // C added there

        let out = merge_vars(Some(&base), &ours, &theirs);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.merged, map(&[("A", "1"), ("C", "3")]));
    }

    #[test]
    fn a_deletion_against_an_edit_is_a_conflict() {
        let out = merge_vars(Some(&map(&[("A", "1")])), &map(&[]), &map(&[("A", "2")]));
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].ours, None);
        assert_eq!(out.conflicts[0].theirs.as_deref(), Some("2"));
        // `merged` holds our side, which deleted it, so the key is absent until a choice.
        assert!(!out.merged.contains_key("A"));
    }

    #[test]
    fn both_sides_deleting_is_not_a_conflict() {
        let out = merge_vars(Some(&map(&[("A", "1")])), &map(&[]), &map(&[]));
        assert!(out.conflicts.is_empty());
        assert!(out.merged.is_empty());
    }

    #[test]
    fn no_base_is_the_two_way_union() {
        // What the caller falls back to when git held no ancestor: nothing is deleted, and
        // only a key both sides carry with different values conflicts.
        let out = merge_vars(
            None,
            &map(&[("A", "1"), ("SHARED", "mine")]),
            &map(&[("B", "2"), ("SHARED", "yours")]),
        );
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "SHARED");
        assert_eq!(out.merged.get("A").unwrap(), "1");
        assert_eq!(out.merged.get("B").unwrap(), "2");
    }

    #[test]
    fn debug_prints_names_without_values() {
        let out = merge_vars(
            Some(&map(&[("A", "old")])),
            &map(&[("A", "mine"), ("KEPT", "plain")]),
            &map(&[("A", "yours")]),
        );
        let text = format!("{out:?}");
        for secret in ["old", "mine", "yours", "plain"] {
            assert!(!text.contains(secret), "a value leaked into Debug: {text}");
        }
        assert!(text.contains("KEPT"), "names are what Debug is for: {text}");
    }
}
