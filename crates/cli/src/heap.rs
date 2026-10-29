//! The global allocator: every heap block is wiped before it is freed (invariant 6).
//!
//! `Zeroizing` covers the buffers bitfort owns. It does not reach the copies that dependencies
//! make and free themselves - `serde_jcs` buffers every value while it sorts the keys it signs,
//! and `std::process::Command` keeps its own copy of the child's environment - nor the old
//! block a reallocation leaves behind when it moves. Wiping in the allocator covers all of
//! them, whoever allocated the block.

use std::alloc::{GlobalAlloc, Layout};
use std::mem::MaybeUninit;

use zeroize::Zeroize;

/// The allocator `A`, with each block wiped before `A` frees it.
pub struct WipeOnFree<A>(pub A);

// SAFETY: allocation is `A`'s, unchanged. `dealloc` writes only inside the block it is given,
// before it hands that block to `A`, and `realloc` is the trait's default, built on the two.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // `MaybeUninit`, because part of the block may never have been written. `zeroize`
        // writes volatile, so the compiler cannot drop the wipe as a dead store before a free.
        let block =
            unsafe { std::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), layout.size()) };
        block.zeroize();
        unsafe { self.0.dealloc(ptr, layout) }
    }

    // `realloc` is not overridden. The default allocates a new block, copies, and frees the
    // old one through `dealloc` above, which wipes it. `A::realloc` can move the block and
    // free the old copy unwiped.
}

#[cfg(test)]
mod tests {
    use std::alloc::System;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// `System`, plus a count of the blocks it was handed to free that held a nonzero byte.
    #[derive(Default)]
    struct Inspect {
        dirty: AtomicUsize,
    }

    unsafe impl GlobalAlloc for Inspect {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.iter().any(|&b| b != 0) {
                self.dirty.fetch_add(1, Ordering::SeqCst);
            }
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    /// A block filled with `0xAA` from `alloc`, the way a secret would sit in it.
    unsafe fn filled(alloc: &impl GlobalAlloc, layout: Layout) -> *mut u8 {
        let ptr = unsafe { alloc.alloc(layout) };
        assert!(!ptr.is_null());
        unsafe { ptr.write_bytes(0xAA, layout.size()) };
        ptr
    }

    #[test]
    fn a_freed_block_is_wiped() {
        let layout = Layout::from_size_align(64, 8).unwrap();

        // Without the wrapper the filled block reaches `free` as it is, so `Inspect` can see
        // a block that nobody wiped.
        let bare = Inspect::default();
        unsafe { bare.dealloc(filled(&bare, layout), layout) };
        assert_eq!(bare.dirty.load(Ordering::SeqCst), 1);

        let wiped = WipeOnFree(Inspect::default());
        unsafe { wiped.dealloc(filled(&wiped, layout), layout) };
        assert_eq!(wiped.0.dirty.load(Ordering::SeqCst), 0);
    }

    /// Growing and shrinking each leave an old block behind. Both are wiped, and the bytes
    /// the caller kept arrive in the new block.
    #[test]
    fn a_reallocation_wipes_the_block_it_leaves() {
        let alloc = WipeOnFree(Inspect::default());
        let small = Layout::from_size_align(16, 8).unwrap();

        let ptr = unsafe { filled(&alloc, small) };
        let grown = unsafe { alloc.realloc(ptr, small, 4096) };
        assert!(!grown.is_null());
        assert!(unsafe { std::slice::from_raw_parts(grown, 16) }
            .iter()
            .all(|&b| b == 0xAA));

        let large = Layout::from_size_align(4096, 8).unwrap();
        let shrunk = unsafe { alloc.realloc(grown, large, 8) };
        assert!(!shrunk.is_null());
        assert!(unsafe { std::slice::from_raw_parts(shrunk, 8) }
            .iter()
            .all(|&b| b == 0xAA));

        unsafe { alloc.dealloc(shrunk, Layout::from_size_align(8, 8).unwrap()) };
        assert_eq!(alloc.0.dirty.load(Ordering::SeqCst), 0);
    }
}
