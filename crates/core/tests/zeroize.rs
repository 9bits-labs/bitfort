//! Zeroization shows only in the bytes a block holds when it is freed, so this test binary
//! installs an allocator that searches each freed block for a marker. A marker that reaches
//! `dealloc` is a plaintext copy that nobody wiped.
//!
//! Each test uses its own marker, so tests that run in parallel cannot report each other.
//! A reallocation goes to the system allocator unsearched. A block that moves leaves its old
//! copy behind, which `Zeroizing` does not cover and these tests do not measure; `age` does
//! this when it shrinks each decrypted chunk. The values here are built at their final size.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use bitfort_core::{dotenv, Chain, Identity, Member, Role, Roster, Vault};

const SELF_CHECK: &[u8] = b"zeroize-check-0b5e";
const PARSE: &[u8] = b"zeroize-parse-7f3a";
const SET: &[u8] = b"zeroize-set-91c2";
const VAULT: &[u8] = b"zeroize-vault-5d81";
const DECRYPT: &[u8] = b"zeroize-decrypt-e6a0";
const SIGN: &[u8] = b"zeroize-sign-3c4d";
const MARKERS: [&[u8]; 6] = [SELF_CHECK, PARSE, SET, VAULT, DECRYPT, SIGN];

static SEEN: [AtomicBool; MARKERS.len()] = [const { AtomicBool::new(false) }; MARKERS.len()];

struct Watch;

unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
        for (marker, seen) in MARKERS.iter().zip(&SEEN) {
            if block.windows(marker.len()).any(|w| w == *marker) {
                seen.store(true, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Watch = Watch;

/// Set once a block holding `marker` is freed, and cleared only by a test that resets it.
fn seen(marker: &[u8]) -> &'static AtomicBool {
    &SEEN[MARKERS.iter().position(|m| *m == marker).unwrap()]
}

/// The other tests pass when a marker is *not* seen, which an allocator that sees nothing
/// would also do. A plain `String` is freed unwiped, so this one must be seen.
#[test]
fn the_allocator_sees_a_string_freed_unwiped() {
    drop(String::from("zeroize-check-0b5e"));
    assert!(seen(SELF_CHECK).load(Ordering::SeqCst));
}

/// An identity file's keys go through `parse` as well as a `.env`. Each value is wiped when
/// it drops, and so are the values already read when a later line fails.
#[test]
fn parse_wipes_every_value_it_drops() {
    drop(dotenv::parse("A=zeroize-parse-7f3a\n").unwrap());
    assert!(dotenv::parse("A=zeroize-parse-7f3a\nno assignment\n").is_err());
    assert!(!seen(PARSE).load(Ordering::SeqCst));
}

/// `import` moves each value into `Vault::set`. A value that `set` refuses must be wiped
/// there, because the caller no longer holds it.
#[test]
fn set_wipes_a_value_it_refuses() {
    let mut vault = Vault::new("development");
    assert!(vault.set("K", String::from("zeroize-set-91c2\0")).is_err());
    assert!(vault.set("1K", String::from("zeroize-set-91c2")).is_err());
    assert!(!seen(SET).load(Ordering::SeqCst));
}

/// Every way a value leaves a vault wipes it: the vault or a clone of it drops, `set`
/// overwrites the value, `unset` removes it, or `with_vars` refuses the map it came in.
#[test]
fn a_vault_wipes_every_value_it_drops() {
    let mut vault = Vault::new("development");
    for key in ["A", "B", "C"] {
        vault.set(key, String::from("zeroize-vault-5d81")).unwrap();
    }
    drop(vault.clone());
    vault.set("A", String::from("other")).unwrap();
    vault.unset("B");
    drop(vault);

    let refused = BTreeMap::from([("1K".to_string(), String::from("zeroize-vault-5d81"))]);
    assert!(Vault::with_vars("development", refused).is_err());
    assert!(!seen(VAULT).load(Ordering::SeqCst));
}

/// A payload that `decrypt` refuses after it is parsed still holds real values, for example
/// an authentic vault copied into another environment's directory. They are wiped when the
/// refused payload drops.
#[test]
fn decrypt_wipes_a_payload_it_refuses() {
    let alice = Identity::generate().unwrap();
    let member = Member {
        name: "alice".to_string(),
        enc_pubkey: alice.enc_pubkey(),
        sign_pubkey: alice.sign_pubkey(),
        role: Role::Maintainer,
        added_by: "test".to_string(),
        added_at: "2026-10-29T00:00:00Z".to_string(),
    };
    let roster = Roster::new_v1("proj-1", "development", vec![member]);
    let mut vault = Vault::new("development");
    vault
        .set("A", String::from("zeroize-decrypt-e6a0"))
        .unwrap();
    let armored = vault.encrypt(&roster, &alice).unwrap();
    drop(vault);
    // Only the refusal is measured: `encrypt` makes copies of its own that it frees unwiped.
    seen(DECRYPT).store(false, Ordering::SeqCst);

    let refused = Vault::decrypt(&armored, &alice, &roster, &Chain::new(), "production");
    assert!(refused.is_err());
    assert!(!seen(DECRYPT).load(Ordering::SeqCst));
}

/// A signing key is decoded into a buffer that is wiped on every exit path. A key with a
/// wrong last symbol is refused after the decoder has written the first 30 bytes of the seed.
#[test]
fn a_signing_key_leaves_no_copy_of_its_seed() {
    let mut seed = [0u8; 32];
    seed[..SIGN.len()].copy_from_slice(SIGN);
    let sign = base64::engine::general_purpose::STANDARD.encode(seed);
    // The last data symbol is `A` (value 0); `B` sets one of its low bits.
    let bad = format!("{}B{}", &sign[..42], &sign[43..]);
    let enc = Identity::generate().unwrap().enc_secret();

    drop(Identity::from_secret_strings(&enc, &sign).unwrap());
    assert!(Identity::from_secret_strings(&enc, &bad).is_err());
    assert!(!seen(SIGN).load(Ordering::SeqCst));
}
