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
//! Every callback also receives a receipt log, `&mut Log`, that the
//! trusted wrappers append to; it is ghost, and it is what the refinement
//! contracts are stated over. Six callbacks carry one -- `enqueue`,
//! `dequeue`, `dispatch`, `running`, `stopping`, `update_idle`, the six
//! the work-conservation model has an action for -- and each says which
//! receipts the callback may leave behind, in the model's terms
//! (`lachesis_model::refine`). Those six have no default body: a do-nothing
//! callback is exactly what the contracts forbid, so a policy writes all
//! six and proves each. `select_cpu` keeps its default and its contract
//! says the default is the only thing allowed: no receipts, which is to say
//! no dispatch from there.
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
    /// `ops.select_cpu`: pick a CPU for a waking task and return it.
    ///
    /// `prev_cpu` is the CPU the task last ran on, so the kernel never
    /// passes a negative one. The contract is that nothing else happens
    /// here: no insert, so no direct dispatch to a local DSQ, from which a
    /// task cannot be stolen. The placement is `enqueue`'s.
    fn select_cpu(&self, p: Task, prev_cpu: i32, wake_flags: u64, log: &mut Log) -> (r: i32)
        requires
            prev_cpu >= 0,
        ensures
            refine::select_cpu_ok(old(log).ops@, final(log).ops@),
    {
        prev_cpu
    }

    /// `ops.enqueue`: place a runnable task on a DSQ. The contract is the
    /// enqueue automaton: read the task's CPU and the CPU count; a CPU
    /// past the policy's queues goes to the global DSQ; otherwise publish
    /// first, then search, kicking every CPU the search claims, filing on
    /// the first claimed one whose queue read empty and whose word went
    /// from free to promised, or on the task's own CPU once the search
    /// returned nothing or ran its full length. One insert, and it is the
    /// last thing done.
    fn enqueue(&self, p: Task, enq_flags: u64, log: &mut Log)
        ensures
            refine::enqueue_ok(old(log).ops@, final(log).ops@);

    /// `ops.dequeue`: `p` is leaving the scheduler's custody, which it
    /// entered when `enqueue` put it on a user DSQ. Called exactly once per
    /// custody period, whatever ends it: a dispatch moving the task to a
    /// local DSQ, on this CPU or on the CPU that stole it, or the kernel
    /// removing a queued task because it exited or changed a scheduling
    /// property. Never called for a task `select_cpu` or `enqueue` sent
    /// straight to a terminal DSQ. That one-to-one pairing with the
    /// custody-taking insert is what lets a policy keep an exact count of
    /// its queued and in-flight work. The contract: the count comes down,
    /// once, and nothing else.
    fn dequeue(&self, p: Task, deq_flags: u64, log: &mut Log)
        ensures
            refine::dequeue_ok(old(log).ops@, final(log).ops@);

    /// `ops.dispatch`: the local DSQ of `cpu` ran dry; move work onto it.
    /// `prev` is the task still running there, if any. The contract is the
    /// dispatch automaton: try the own queue first; otherwise guard the own
    /// word from free to scanning, and stop if that does not take; then
    /// scan every other CPU in order, reading its word, then its queue
    /// count only if the word said busy, then moving only if the count was
    /// positive, and taking the victim's word from promised to free on a
    /// move. The scan ends only on a move or, after the last CPU, with the
    /// own word written free again. The promise a consumed task carried is
    /// fulfilled when it runs, so an own-queue hit writes nothing.
    fn dispatch(&self, cpu: i32, prev: Option<Task>, log: &mut Log)
        requires
            cpu >= 0,
        ensures
            refine::dispatch_ok(cpu as int, old(log).ops@, final(log).ops@);

    /// `ops.running`: `p` is about to start running. The contract: the
    /// word of its CPU is written busy, if the policy has one for it.
    fn running(&self, p: Task, log: &mut Log)
        ensures
            refine::busy_ok(true, old(log).ops@, final(log).ops@);

    /// `ops.stopping`: `p` is coming off a CPU. `runnable` says whether it
    /// stays runnable or is going to sleep. The contract: the word of its
    /// CPU is written free.
    fn stopping(&self, p: Task, runnable: bool, log: &mut Log)
        ensures
            refine::busy_ok(false, old(log).ops@, final(log).ops@);

    /// `ops.enable`: `p` is joining this scheduler.
    fn enable(&self, p: Task, log: &mut Log) {
    }

    /// `ops.update_idle`: `cpu` is entering idle (`idle` true) or leaving
    /// it. Called with the CPU's runqueue locked, after the kernel has
    /// updated the built-in idle mask -- that ordering is deliberate on the
    /// kernel's side, so that a policy can interlock this callback with
    /// `enqueue`: either the enqueue sees the idle bit, or this callback
    /// sees the task the enqueue queued. Implementing it disables the
    /// built-in idle tracking unless the ops table carries
    /// `SCX_OPS_KEEP_BUILTIN_IDLE`, which `scheduler!`'s `flags:` sets.
    /// The contract, on idle entry: read the published count; if it is
    /// non-zero, test-and-clear the own idle bit; if it was up, kick self.
    /// Nothing else, and nothing on idle exit.
    fn update_idle(&self, cpu: i32, idle: bool, log: &mut Log)
        requires
            cpu >= 0,
        ensures
            refine::update_idle_ok(cpu as int, idle, old(log).ops@, final(log).ops@);

    /// `ops.init`: called once, in sleepable context, before any task is
    /// scheduled. Zero on success, a negative errno to refuse to attach --
    /// a positive return would be read as an errno by the kernel, so the
    /// postcondition is the struct_ops convention, and it is checked.
    fn init(&self, log: &mut Log) -> (r: i32)
        ensures
            r <= 0,
    {
        0
    }

    /// `ops.exit`: the scheduler is being unregistered.
    fn exit(&self, ei: &ExitInfo, log: &mut Log) {
    }
}

} // verus!
