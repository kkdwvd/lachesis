// SPDX-License-Identifier: GPL-2.0
//! Per-index flags in `.bss`.
//!
//! The per-CPU booleans a policy publishes for other CPUs to read without
//! a lock -- today, "CPU `i` is running a task", set by `running` and
//! cleared by `stopping`, which the steal scan consults so that it only
//! takes from a CPU that has something else to do, and "CPU `i` has been
//! claimed by an enqueue whose task it has not consumed yet", which keeps
//! two enqueues from claiming the same CPU while the first task is still
//! in flight. One atomic per slot,
//! like [`crate::stats::Stats`], so the slots do not share a word; every
//! access is `Relaxed` for the reason `atomic.rs` gives, and the
//! sequential-consistency assumption of roadmap section 3.7 covers the
//! reads a proof leans on.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::vprelude::*;

verus! {

#[verifier::external_body]
pub struct Flags<const N: usize> {
    bits: [AtomicU64; N],
}

impl<const N: usize> Flags<N> {
    /// Set slot `i`.
    #[verifier::external_body]
    pub fn set(&self, i: usize)
        requires
            i < N,
    {
        if let Some(b) = self.bits.get(i) {
            b.store(1, Relaxed);
        }
    }

    /// Set slot `i` and report whether it was already set: the claim
    /// primitive, exclusive between concurrent callers.
    #[verifier::external_body]
    pub fn test_and_set(&self, i: usize) -> (r: bool)
        requires
            i < N,
    {
        match self.bits.get(i) {
            Some(b) => b.fetch_or(1, Relaxed) != 0,
            None => true,
        }
    }

    /// Clear slot `i`.
    #[verifier::external_body]
    pub fn clear(&self, i: usize)
        requires
            i < N,
    {
        if let Some(b) = self.bits.get(i) {
            b.store(0, Relaxed);
        }
    }

    /// Read slot `i`. No contract: what the value means is the policy's
    /// invariant, and the value may be stale by the time it is used.
    #[verifier::external_body]
    pub fn get(&self, i: usize) -> (r: bool)
        requires
            i < N,
    {
        match self.bits.get(i) {
            Some(b) => b.load(Relaxed) != 0,
            None => false,
        }
    }
}

} // verus!

// `const` so the `scheduler!` static can be initialized with it; see
// `atomic.rs`.
impl<const N: usize> Flags<N> {
    pub const fn new() -> Self {
        Flags { bits: [const { AtomicU64::new(0) }; N] }
    }
}
