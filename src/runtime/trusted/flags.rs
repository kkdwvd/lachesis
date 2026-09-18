// SPDX-License-Identifier: GPL-2.0
//! Per-CPU flags in `.bss`, one type per role.
//!
//! [`Busy`] is "CPU `i` is running a task", set by `running`, cleared by
//! `stopping`, read by the steal scan so that it only takes from a CPU
//! that has something else to do. [`Claims`] is "an enqueue has claimed
//! CPU `i` and filed a task for its queue that nobody has consumed yet",
//! set with a test-and-set by the claimer, cleared by whoever consumes from
//! that queue. Two types rather than one so that the receipt log can tell
//! them apart: the refinement contracts look for a `BusyGet` before a steal
//! and a `Claim` before a placement. One atomic per slot, like
//! [`crate::stats::Stats`]; every access is `Relaxed` for the reason
//! `atomic.rs` gives, and the sequential-consistency assumption of roadmap
//! section 3.7 covers the reads a proof leans on.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::log::{Log, Op};
use crate::vprelude::*;

verus! {

#[verifier::external_body]
pub struct Busy<const N: usize> {
    bits: [AtomicU64; N],
}

impl<const N: usize> Busy<N> {
    /// Slot `i` is running a task.
    #[verifier::external_body]
    pub fn set(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::BusySet { slot: i, busy: true }),
    {
        if let Some(b) = self.bits.get(i) {
            b.store(1, Relaxed);
        }
    }

    /// Slot `i` no longer runs a task.
    #[verifier::external_body]
    pub fn clear(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::BusySet { slot: i, busy: false }),
    {
        if let Some(b) = self.bits.get(i) {
            b.store(0, Relaxed);
        }
    }

    /// Read slot `i`; the value may be stale by the time it is used.
    #[verifier::external_body]
    pub fn get(&self, i: usize, log: &mut Log) -> (r: bool)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::BusyGet { slot: i, busy: r }),
    {
        match self.bits.get(i) {
            Some(b) => b.load(Relaxed) != 0,
            None => false,
        }
    }
}

#[verifier::external_body]
pub struct Claims<const N: usize> {
    bits: [AtomicU64; N],
}

impl<const N: usize> Claims<N> {
    /// Mark slot `i` and report whether it already was: the claim
    /// primitive, exclusive between concurrent callers.
    #[verifier::external_body]
    pub fn test_and_set(&self, i: usize, log: &mut Log) -> (r: bool)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::Claim { slot: i, was: r }),
    {
        match self.bits.get(i) {
            Some(b) => b.fetch_or(1, Relaxed) != 0,
            None => true,
        }
    }

    /// Clear the mark of slot `i`.
    #[verifier::external_body]
    pub fn clear(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::Unclaim { slot: i }),
    {
        if let Some(b) = self.bits.get(i) {
            b.store(0, Relaxed);
        }
    }
}

} // verus!

// `const` so the `scheduler!` static can be initialized with them; see
// `atomic.rs`.
impl<const N: usize> Busy<N> {
    pub const fn new() -> Self {
        Busy { bits: [const { AtomicU64::new(0) }; N] }
    }
}

impl<const N: usize> Claims<N> {
    pub const fn new() -> Self {
        Claims { bits: [const { AtomicU64::new(0) }; N] }
    }
}
