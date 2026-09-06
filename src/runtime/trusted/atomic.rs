// SPDX-License-Identifier: GPL-2.0
//! An opaque atomic counter.
//!
//! A policy holds its mutable state in these: a `static` is the only
//! storage a BPF program has, and a `static` needs interior mutability. The
//! wrapper exists so that the policy never names an `Ordering` and Verus
//! never sees `core::sync::atomic`, which has no specification it could
//! use.
//!
//! Every access is `Relaxed`. BPF has no fence instruction, so a stronger
//! ordering is not expressible in the target; roadmap section 3.7 item 4
//! records the sequential-consistency assumption that proofs about these
//! will rest on, and the lint that will force it. The specs below are
//! empty -- a `load` says nothing about what was stored -- because a
//! useful one needs a ghost token per location, which arrives with the
//! phase 3 tokenized state machine.

use core::sync::atomic::{AtomicU64 as CoreAtomicU64, Ordering::Relaxed};

use crate::vprelude::*;

verus! {

#[verifier::external_body]
pub struct AtomicU64 {
    inner: CoreAtomicU64,
}

impl AtomicU64 {
    #[verifier::external_body]
    pub fn load(&self) -> (r: u64) {
        self.inner.load(Relaxed)
    }

    #[verifier::external_body]
    pub fn store(&self, v: u64) {
        self.inner.store(v, Relaxed)
    }

    #[verifier::external_body]
    pub fn fetch_add(&self, v: u64) {
        self.inner.fetch_add(v, Relaxed);
    }
}

} // verus!

// The constructor is plain Rust, outside `verus!`: it is `const` so that
// the `scheduler!` static can be initialized with it, and it is only ever
// called from that macro-generated initializer, which is external to Verus
// anyway.
impl AtomicU64 {
    pub const fn new(v: u64) -> Self {
        AtomicU64 { inner: CoreAtomicU64::new(v) }
    }
}
