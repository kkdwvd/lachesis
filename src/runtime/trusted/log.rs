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
//! The log's only field is ghost: in the erased pass it is a zero-sized
//! struct, so nothing of it reaches the object but an argument the
//! optimizer removes. What is trusted is that each wrapper appends the op
//! that describes what the kernel did, which is the same assumption as the
//! wrapper's other postconditions.

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

/// The receipts of one callback, in order. Exec-typed so that it can be
/// passed as `&mut` through code the erased pass compiles; its one field
/// is ghost.
#[cfg(verus_keep_ghost)]
pub struct Log {
    pub ops: Ghost<Seq<Op>>,
}

#[cfg(verus_keep_ghost)]
impl Log {
    /// A fresh log: what the trampoline hands a callback.
    pub fn new() -> (l: Log)
        ensures
            l.ops@ == Seq::<Op>::empty(),
    {
        Log { ops: Ghost(Seq::empty()) }
    }
}

} // verus!

/// The erased pass sees a zero-sized log with no fields at all.
#[cfg(not(verus_keep_ghost))]
pub struct Log {}

#[cfg(not(verus_keep_ghost))]
impl Log {
    #[inline(always)]
    pub fn new() -> Log {
        Log {}
    }
}
