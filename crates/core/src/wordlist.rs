//! Human-comparable rendering of the trust anchor: the 8 fingerprint bytes re-encoded as
//! 6 BIP-39 English words (docs/SPEC.md §5.1). The hex fingerprint stays the source of
//! truth; the words are a written side-by-side comparison layer (README/Slack vs terminal)
//! that carries the *same* entropy in a form developers recognize and mistype less often.
//!
//! This is NOT a BIP-39 mnemonic: there is no checksum or seed derivation, just a
//! base-2048 encoding of the raw bytes. The mapping is injective over the 64-bit anchor
//! space, so two anchors share a word phrase only if their hex already collides - comparing
//! words is exactly as strong as comparing hex.

/// The canonical BIP-39 English wordlist (2048 words), vendored so the CLI needs no
/// wordlist dependency (invariant 5). Pinned by content:
/// SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
const WORDLIST: &str = include_str!("wordlist_en.txt");

/// The `bf1:` prefix every fingerprint/anchor string carries (see `identity::anchor_of`).
const ANCHOR_PREFIX: &str = "bf1:";

/// Render an anchor fingerprint (`bf1:<16 hex>`) as its 6-word BIP-39 phrase, or `None`
/// if it is not a well-formed anchor (wrong prefix or not 8 hex-encoded bytes) - callers
/// then show the hex alone.
pub fn anchor_words(anchor: &str) -> Option<String> {
    let bytes = anchor_bytes(anchor)?;
    let words: Vec<&str> = WORDLIST.lines().collect();
    // The 8 bytes are 64 bits; 6 words need 66, so shift left 2 to pad the low end. Each
    // word is an 11-bit group taken MSB-first, so the phrase covers all 64 bits in order.
    let padded = (u64::from_be_bytes(bytes) as u128) << 2;
    let phrase = (0..6)
        .map(|i| {
            let index = ((padded >> (55 - 11 * i)) & 0x7FF) as usize;
            words[index]
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(phrase)
}

/// Parse the 8 raw bytes out of a `bf1:<16 hex>` anchor string.
fn anchor_bytes(anchor: &str) -> Option<[u8; 8]> {
    let hex = anchor.strip_prefix(ANCHOR_PREFIX)?;
    hex::decode(hex).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_wordlist_matches_the_pinned_checksum() {
        // Vendoring (rather than a BIP-39 crate) rests on this file being the canonical,
        // unmodified English list. Pin it by content so any edit, truncation, or line-ending
        // reflow fails the build instead of silently shifting every phrase.
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(WORDLIST.as_bytes()));
        assert_eq!(
            digest,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn wordlist_is_the_full_2048() {
        // A truncated or reflowed vendored file would silently corrupt every phrase.
        assert_eq!(WORDLIST.lines().count(), 2048);
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words[0], "abandon");
        assert_eq!(words[2047], "zoo");
    }

    #[test]
    fn encodes_a_known_anchor_to_a_stable_phrase() {
        // Known vector: all-zero bytes -> the first word six times (index 0 each group).
        assert_eq!(
            anchor_words("bf1:0000000000000000").unwrap(),
            "abandon abandon abandon abandon abandon abandon"
        );
        // All-ones (0xFF..FF) -> top five groups are index 2047 ("zoo"); the last group is
        // the low 9 bits (0x1FF) shifted up by the 2-bit pad -> 0x7FC = 2044 ("zebra").
        assert_eq!(
            anchor_words("bf1:ffffffffffffffff").unwrap(),
            "zoo zoo zoo zoo zoo zebra"
        );
    }

    #[test]
    fn phrase_is_six_words() {
        let phrase = anchor_words("bf1:59ecb202647caeff").unwrap();
        assert_eq!(phrase.split(' ').count(), 6);
        assert!(phrase.split(' ').all(|w| !w.is_empty()));
    }

    #[test]
    fn distinct_anchors_give_distinct_phrases() {
        // The encoding is injective, so different hex -> different words (words compare as
        // strongly as hex).
        let a = anchor_words("bf1:59ecb202647caeff").unwrap();
        let b = anchor_words("bf1:59ecb202647caefe").unwrap(); // one bit different
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_anchors_return_none() {
        assert!(anchor_words("no-prefix").is_none());
        assert!(anchor_words("bf1:xyz").is_none()); // not hex
        assert!(anchor_words("bf1:00").is_none()); // too short (1 byte, not 8)
        assert!(anchor_words("bf1:000000000000000000").is_none()); // too long (9 bytes)
    }
}
