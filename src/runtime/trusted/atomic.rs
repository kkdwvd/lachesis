// SPDX-License-Identifier: GPL-2.0
//! An opaque atomic counter.
//!
//! A policy holds its mutable state in these: a `static` is the only
//! storage a BPF program has, and a `static` needs interior mutability. The
//! wrapper exists so that the policy never names an `Ordering` and Verus
//! never sees `core::sync::atomic`, which has no specification it could
//! use.
//!
//! Every load and store is `Relaxed`: BPF has no fence instruction, so a
//! stronger ordering on those is not expressible in the target. Every
//! read-modify-write is `SeqCst`, and that is not a choice about
//! ordering: the BPF backend of the LLVM this pipeline uses lowers a
//! `Relaxed` `fetch_add` whose result is used to the non-fetching atomic
//! add and hands back the addend, silently, where any stronger ordering
//! gets the fetching form -- the instruction the kernel executes is the
//! same either way, a full barrier. Roadmap section 3.7 item 4 records
//! the sequential-consistency assumption that proofs about these rest on,
//! and the lint that will force it; this is one more reason for that
//! lint. The specs below are empty -- a `load` says nothing about what
//! was stored -- because a useful one needs a ghost token per location,
//! which arrives with the phase 3 tokenized state machine.

use core::sync::atomic::{AtomicU64 as CoreAtomicU64, Ordering::{Relaxed, SeqCst}};

use crate::log::{Log, Op};
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
        self.inner.fetch_add(v, SeqCst);
    }

    /// Wrapping decrement. A counter that is incremented on one path and
    /// decremented on another is exact only if the two are paired; the
    /// pairing is the caller's invariant, not this wrapper's.
    #[verifier::external_body]
    pub fn fetch_sub(&self, v: u64) {
        self.inner.fetch_sub(v, SeqCst);
    }
}

/// The published count: what a policy bumps before it does anything else
/// in `enqueue`, takes down in `dequeue`, and reads in `update_idle`. An
/// `AtomicU64` with a role, so that the receipt log can name it: the
/// refinement contracts look for `CountInc` before the idle search and for
/// `CountLoad` before a self-kick, and only this type produces them.
#[verifier::external_body]
pub struct Counter {
    inner: CoreAtomicU64,
}

impl Counter {
    #[verifier::external_body]
    pub fn inc(&self, log: &mut Log)
        ensures
            final(log).ops@ == old(log).ops@.push(Op::CountInc),
    {
        self.inner.fetch_add(1, Relaxed);
    }

    #[verifier::external_body]
    pub fn dec(&self, log: &mut Log)
        ensures
            final(log).ops@ == old(log).ops@.push(Op::CountDec),
    {
        self.inner.fetch_sub(1, Relaxed);
    }

    #[verifier::external_body]
    pub fn load(&self, log: &mut Log) -> (r: u64)
        ensures
            final(log).ops@ == old(log).ops@.push(Op::CountLoad { count: r }),
    {
        self.inner.load(Relaxed)
    }
}

} // verus!

// The constructors are plain Rust, outside `verus!`: they are `const` so
// that the `scheduler!` static can be initialized with them, and they are
// only ever called from that macro-generated initializer, which is
// external to Verus anyway.
impl AtomicU64 {
    pub const fn new(v: u64) -> Self {
        AtomicU64 { inner: CoreAtomicU64::new(v) }
    }
}

impl Counter {
    pub const fn new() -> Self {
        Counter { inner: CoreAtomicU64::new(0) }
    }
}
