// SPDX-License-Identifier: GPL-2.0
//! The receipt log: the ghost record of what a callback did through the
//! trusted layer, and the currency of the refinement obligations.
//!
//! Every wrapper in this crate whose effect the model cares about takes a
//! `&mut Log` and appends one [`Op`] describing the call and its result. The trampolines hand each callback a fresh log, and the
//! `Policy` trait's contracts say which sequences of ops a callback may
//! leave behind, in the model's terms (`lachesis_model::refine`). The
//! policy proves it produces one; a policy that publishes after it
//! searches, kicks nothing, steals from an idle CPU, clears a CPU's word on
//! consuming from it or dispatches straight to a local DSQ leaves a
//! sequence the contract rejects, and Verus says so.
//!
//! The log's sequence is ghost; what the erased pass keeps is two bytes,
//! the callback's id and whether tracing is on, so that the same receipts
//! can go out through the trace recorder in [`crate::trace`] at runtime.
//! What is trusted is that each wrapper records the op that describes what
//! the kernel did, which is the same assumption as the wrapper's other
//! postconditions.

use crate::vprelude::*;

verus! {

/// One observable step through the trusted layer, with the values the
/// kernel returned. Payloads keep the exec types of the wrappers, and a
/// field name is used at one type only: a CPU number the kernel handed out
/// is `cpu: i32`, an index into one of the policy's per-CPU flag arrays is
/// `slot: usize`.
pub enum Op {
    /// The published count went up by one.
    CountInc,
    /// The published count went down by one.
    CountDec,
    /// The published count read `count`.
    CountLoad { count: u64 },
    /// `nr_cpu_ids` read `nr`.
    NrCpuIds { nr: u32 },
    /// The task's CPU read `cpu`.
    TaskCpu { cpu: i32 },
    /// The kernel's idle search: `idle` says it claimed `cpu`.
    SelectDfl { cpu: i32, idle: bool },
    /// A kick sent to `cpu`.
    Kick { cpu: i32 },
    /// `dsq_nr_queued(dsq)` read `n`.
    NrQueued { dsq: u64, n: i32 },
    /// The word of slot `slot` was compare-and-swapped from free to
    /// promised; `ok` says whether it went through.
    Promise { slot: usize, ok: bool },
    /// The word of slot `slot` was compare-and-swapped from free to
    /// scanning; `ok` says whether it went through.
    Scan { slot: usize, ok: bool },
    /// The word of slot `slot` was compare-and-swapped from promised to
    /// free.
    Unpromise { slot: usize },
    /// The word of slot `slot` was written busy.
    SetBusy { slot: usize },
    /// The word of slot `slot` was written free.
    SetFree { slot: usize },
    /// The word of slot `slot` was read; `busy` says whether it was busy.
    IsBusy { slot: usize, busy: bool },
    /// An insert into `dsq`.
    Insert { dsq: u64 },
    /// A move from `dsq` to the local DSQ; `moved` says whether one moved.
    MoveToLocal { dsq: u64, moved: bool },
    /// The idle bit of `cpu` test-and-cleared; `was` says whether it was up.
    TestAndClearIdle { cpu: i32, was: bool },
}

/// The callback a log belongs to, on the wire of the trace.
pub const CB_SELECT_CPU: u8 = 1;
pub const CB_ENQUEUE: u8 = 2;
pub const CB_DEQUEUE: u8 = 3;
pub const CB_DISPATCH: u8 = 4;
pub const CB_RUNNING: u8 = 5;
pub const CB_STOPPING: u8 = 6;
pub const CB_ENABLE: u8 = 7;
pub const CB_UPDATE_IDLE: u8 = 8;
pub const CB_INIT: u8 = 9;
pub const CB_EXIT: u8 = 10;

/// The receipts of one callback, in order. Exec-typed so that it can be
/// passed as `&mut` through code the erased pass compiles; `ops` is ghost,
/// and `cb` and `on` are the two bytes the trace recorder needs.
#[cfg(verus_keep_ghost)]
pub struct Log {
    pub cb: u8,
    pub on: bool,
    pub ops: Ghost<Seq<Op>>,
}

#[cfg(verus_keep_ghost)]
impl Log {
    /// A fresh log: what the trampoline hands a callback. Opens the
    /// callback on the trace when tracing is on.
    #[verifier::external_body]
    pub fn new(cb: u8, pid: i32) -> (l: Log)
        ensures
            l.ops@ == Seq::<Op>::empty(),
    {
        let on = crate::trace::enabled();
        if on {
            crate::trace::begin(cb, pid);
        }
        Log { cb, on, ops: Ghost(Seq::empty()) }
    }

    /// One receipt: what every wrapper appends, and the trace's event.
    #[verifier::external_body]
    pub fn record(&mut self, op: Op)
        ensures
            final(self).ops@ == old(self).ops@.push(op),
    {
        if self.on {
            crate::trace::record(self.cb, &op);
        }
        self.ops = Ghost(self.ops@.push(op));
    }

    /// The callback returned.
    #[verifier::external_body]
    pub fn end(&self) {
        if self.on {
            crate::trace::end(self.cb);
        }
    }
}

} // verus!

/// The erased pass sees the two exec bytes and no ghost field.
#[cfg(not(verus_keep_ghost))]
pub struct Log {
    pub cb: u8,
    pub on: bool,
}

#[cfg(not(verus_keep_ghost))]
impl Log {
    #[inline(always)]
    pub fn new(cb: u8, pid: i32) -> Log {
        let on = crate::trace::enabled();
        if on {
            crate::trace::begin(cb, pid);
        }
        Log { cb, on }
    }

    #[inline(always)]
    pub fn record(&mut self, op: Op) {
        if self.on {
            crate::trace::record(self.cb, &op);
        }
    }

    #[inline(always)]
    pub fn end(&self) {
        if self.on {
            crate::trace::end(self.cb);
        }
    }
}
