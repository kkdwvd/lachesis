// SPDX-License-Identifier: GPL-2.0
//! The `Policy` trait: the authoring interface, and where a callback's
//! contract is written down.
//!
//! One method per `struct sched_ext_ops` member a policy may implement,
//! declared inside `verus!` so that a policy's `impl` -- also inside
//! `verus!` -- is verified against these contracts without quoting them.
//! Verus rejects a `requires` on a trait method *implementation*, so there
//! is exactly one place each contract is stated. Every method has a default
//! body, so a policy implements only the callbacks it cares about and the
//! rest fall back to the kernel's do-nothing behaviour.
//!
//! Read a `requires` here as an assumption about what the kernel passes in.
//! The `scheduler!` trampolines that call these methods are C-ABI entry
//! points outside `verus!`, so Verus does not check a precondition at that
//! call; writing one down states, in the one place a reader will look, what
//! the callback is entitled to rely on. Phase 5's refinement layer is where
//! those assumptions get discharged against the kernel model. An `ensures`
//! runs the other way and is checked: the `impl` must prove it.

use crate::prelude::*;

verus! {

// The default bodies ignore their parameters by construction; the names
// are the interface's documentation, so they keep them.
#[allow(unused_variables)]
pub trait Policy {
    /// `ops.select_cpu`: pick a CPU for a waking task and return it. A
    /// policy may also dispatch `p` directly from here.
    ///
    /// `prev_cpu` is the CPU the task last ran on, so the kernel never
    /// passes a negative one.
    fn select_cpu(&self, p: Task, prev_cpu: i32, wake_flags: u64) -> (r: i32)
        requires
            prev_cpu >= 0,
    {
        prev_cpu
    }

    /// `ops.enqueue`: place a runnable task on a DSQ. A policy that
    /// enqueues nowhere leaves the task to the kernel's fallback.
    fn enqueue(&self, p: Task, enq_flags: u64) {
    }

    /// `ops.dispatch`: the local DSQ of `cpu` ran dry; move work onto it.
    /// `prev` is the task still running there, if any.
    fn dispatch(&self, cpu: i32, prev: Option<Task>)
        requires
            cpu >= 0,
    {
    }

    /// `ops.running`: `p` is about to start running.
    fn running(&self, p: Task) {
    }

    /// `ops.stopping`: `p` is coming off a CPU. `runnable` says whether it
    /// stays runnable or is going to sleep.
    fn stopping(&self, p: Task, runnable: bool) {
    }

    /// `ops.enable`: `p` is joining this scheduler.
    fn enable(&self, p: Task) {
    }

    /// `ops.init`: called once, in sleepable context, before any task is
    /// scheduled. Zero on success, a negative errno to refuse to attach --
    /// a positive return would be read as an errno by the kernel, so the
    /// postcondition is the struct_ops convention, and it is checked.
    fn init(&self) -> (r: i32)
        ensures
            r <= 0,
    {
        0
    }

    /// `ops.exit`: the scheduler is being unregistered.
    fn exit(&self, ei: &ExitInfo) {
    }
}

} // verus!
