// SPDX-License-Identifier: GPL-2.0
//! The policy's per-CPU word, in `.bss`.
//!
//! One of four values per CPU. [`FREE`]: the CPU is idle and nothing is
//! promised to it. [`PROMISED`]: an enqueue has claimed the CPU and filed a
//! task for its queue that has not run yet. [`BUSY`]: a task is running on
//! it. [`SCANNING`]: the CPU is looking for a task to steal. `running`
//! writes busy and `stopping` writes free; a placement is a
//! compare-and-swap from free to promised; a CPU about to steal
//! compare-and-swaps its own word from free to scanning first, and writes
//! it free again if it finds nothing; a thief that takes a task from a CPU
//! whose word says promised -- the task it took was the promised one --
//! compare-and-swaps that word back to free. Nothing else writes it, and
//! in particular the consumer of a promised task does not. The steal scan
//! reads it to take only from a CPU that is running another task, which
//! is Ipanema's `can_steal_core`; a placement reads it, through the
//! compare-and-swap, to learn that another task is on its way (promised),
//! that the CPU is about to fetch one itself (scanning), or that its claim
//! on the CPU's idle bit is stale, the CPU having run something since
//! (busy); and a CPU's own guard tells it, through its compare-and-swap,
//! that a task is on its way to it, in which case it does not steal and
//! waits for the kick that comes with the landing.
//!
//! The word replaces a busy flag and a claim mark that the consumer
//! cleared. A mark cleared on consumption let an enqueue that had claimed
//! a CPU's idle bit, then paused between reading its queue and marking it,
//! find the mark down after the CPU had picked up an older promise and
//! started running it, and file its task behind that one while a third
//! CPU idled; the finer-grained model found that trace. The guard came
//! from the same model: without it, a CPU could read a victim's word busy,
//! be promised a task itself, and steal, ending up with the stolen task
//! running and the promised one queued behind it. One atomic per slot,
//! like [`crate::stats::Stats`]; loads and stores are `Relaxed` and the
//! compare-and-swaps `SeqCst`, for the reasons `atomic.rs` gives, and the
//! sequential-consistency assumption of roadmap section 3.7 covers the
//! reads a proof leans on.

use core::sync::atomic::{AtomicU64, Ordering::{Relaxed, SeqCst}};

use crate::log::{Log, Op};
use crate::vprelude::*;

verus! {

pub const FREE: u64 = 0;
pub const PROMISED: u64 = 1;
pub const BUSY: u64 = 2;
pub const SCANNING: u64 = 3;

#[verifier::external_body]
pub struct Words<const N: usize> {
    words: [AtomicU64; N],
}

impl<const N: usize> Words<N> {
    /// Claim slot `i` for a placement: free becomes promised, and the
    /// result says whether it did. Exclusive between concurrent callers,
    /// and against a slot that is promised or busy.
    #[verifier::external_body]
    pub fn promise(&self, i: usize, log: &mut Log) -> (r: bool)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::Promise { slot: i, ok: r }),
    {
        let r = match self.words.get(i) {
            Some(w) => w.compare_exchange(FREE, PROMISED, SeqCst, SeqCst).is_ok(),
            None => false,
        };
        log.record(Op::Promise { slot: i, ok: r });
        r
    }

    /// A task is running on slot `i`.
    #[verifier::external_body]
    pub fn set_busy(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::SetBusy { slot: i }),
    {
        if let Some(w) = self.words.get(i) {
            w.store(BUSY, Relaxed);
        }
        log.record(Op::SetBusy { slot: i });
    }

    /// Guard slot `i` for a steal: free becomes scanning, and the result
    /// says whether it did. A slot that is promised stays so, and the
    /// caller does not steal.
    #[verifier::external_body]
    pub fn scan(&self, i: usize, log: &mut Log) -> (r: bool)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::Scan { slot: i, ok: r }),
    {
        let r = match self.words.get(i) {
            Some(w) => w.compare_exchange(FREE, SCANNING, SeqCst, SeqCst).is_ok(),
            None => false,
        };
        log.record(Op::Scan { slot: i, ok: r });
        r
    }

    /// The task promised to slot `i` was taken by the caller: promised
    /// becomes free, and anything else stays as it is.
    #[verifier::external_body]
    pub fn unpromise(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::Unpromise { slot: i }),
    {
        if let Some(w) = self.words.get(i) {
            let _ = w.compare_exchange(PROMISED, FREE, SeqCst, SeqCst);
        }
        log.record(Op::Unpromise { slot: i });
    }

    /// Slot `i` no longer runs a task, or its scan found nothing: free.
    #[verifier::external_body]
    pub fn set_free(&self, i: usize, log: &mut Log)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::SetFree { slot: i }),
    {
        if let Some(w) = self.words.get(i) {
            w.store(FREE, Relaxed);
        }
        log.record(Op::SetFree { slot: i });
    }

    /// Read whether slot `i` is busy; stale by the time it is used.
    #[verifier::external_body]
    pub fn is_busy(&self, i: usize, log: &mut Log) -> (r: bool)
        requires
            i < N,
        ensures
            final(log).ops@ == old(log).ops@.push(Op::IsBusy { slot: i, busy: r }),
    {
        let r = match self.words.get(i) {
            Some(w) => w.load(Relaxed) == BUSY,
            None => false,
        };
        log.record(Op::IsBusy { slot: i, busy: r });
        r
    }
}

} // verus!

// `const` so the `scheduler!` static can be initialized with it; see
// `atomic.rs`.
impl<const N: usize> Words<N> {
    pub const fn new() -> Self {
        Words { words: [const { AtomicU64::new(FREE) }; N] }
    }
}
