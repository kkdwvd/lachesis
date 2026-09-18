// SPDX-License-Identifier: GPL-2.0
//! Safe wrappers over the sched_ext kfuncs, and the kernel constants a
//! policy needs.
//!
//! The wrappers are safe because the BPF verifier proves the safety
//! conditions the C prototypes leave implicit: `p` is a valid task pointer
//! for the callback that received it, and a DSQ id either names a DSQ the
//! program created or is one of the builtin encodings below.
//!
//! They are `#[verifier::external_body]` because the body is an FFI call,
//! so every clause here is assumed rather than proved and belongs to the
//! trusted base. The contracts are deliberately small: value ranges the
//! kernel guarantees ([`create_dsq`], [`select_cpu_dfl`], [`task_cpu`],
//! [`nr_cpu_ids`]) and the preconditions that keep the scheduler from
//! being ejected ([`kick_cpu`], [`test_and_clear_cpu_idle`]). What a wrapper does to kernel state is
//! described in prose and in the `lachesis_model` actions, not here; phase
//! 5's refinement is where the two get tied together.

use crate::kfunc;
use crate::log::{Log, Op};
use crate::task::Task;
use crate::vprelude::*;

verus! {

// include/linux/sched/ext.h.
pub const SCX_DSQ_FLAG_BUILTIN: u64 = 0x8000_0000_0000_0000;
/// The global fallback DSQ, consumed by every CPU.
pub const SCX_DSQ_GLOBAL: u64 = 0x8000_0000_0000_0001;
/// The local DSQ of the CPU the callback is running on.
///
/// Upstream's `scx_simple.rs` uses `u64::MAX` here, which decodes as
/// `SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON | 0xffffffff`, i.e. "the
/// local DSQ of CPU -1"; the kernel then ejects the scheduler with
/// "invalid CPU -1 in SCX_DSQ_LOCAL_ON dispatch verdict".
pub const SCX_DSQ_LOCAL: u64 = 0x8000_0000_0000_0002;

/// The default time slice, 20ms in nanoseconds.
pub const SCX_SLICE_DFL: u64 = 20_000_000;

/// `SCX_KICK_IDLE`: make the target reschedule only if it is idle. A busy
/// CPU ignores it, so it is the flag for "come back into `dispatch`".
pub const SCX_KICK_IDLE: u64 = 1 << 0;

/// `SCX_OPS_KEEP_BUILTIN_IDLE`: keep the kernel's idle tracking, and with
/// it [`select_cpu_dfl`], alive although the policy implements
/// `ops.update_idle`. Without it, implementing that callback disables both.
/// `scheduler!` writes it into the ops table's `flags` member.
pub const SCX_OPS_KEEP_BUILTIN_IDLE: u64 = 1 << 0;

/// Pick a CPU for a waking task using the kernel's default idle-core
/// search. Returns the chosen CPU and whether it was found idle; a policy
/// that dispatches directly to `SCX_DSQ_LOCAL` on the idle path avoids the
/// enqueue entirely.
///
/// Callable from `ops.select_cpu` and from `ops.enqueue`, which is what
/// the enqueue side of the idle interlock uses: after the task is on a
/// queue, one more search, and a kick for whatever it claims. An idle
/// verdict comes with a valid CPU number: the search claims the CPU by
/// clearing its idle bit, so the number is one the kernel just handed out.
#[verifier::external_body]
pub fn select_cpu_dfl(
    p: &Task,
    prev_cpu: i32,
    wake_flags: u64,
    log: &mut Log,
) -> (r: (i32, bool))
    ensures
        r.1 ==> r.0 >= 0,
        final(log).ops@ == old(log).ops@.push(Op::SelectDfl { cpu: r.0, idle: r.1 }),
{
    let mut is_idle = false;
    let cpu = unsafe {
        kfunc::scx_bpf_select_cpu_dfl(p.as_ptr(), prev_cpu, wake_flags, &mut is_idle)
    };
    (cpu, is_idle)
}

/// Insert `p` at the tail of `dsq_id` with a time slice.
#[verifier::external_body]
pub fn dsq_insert(p: &Task, dsq_id: u64, slice: u64, enq_flags: u64, log: &mut Log)
    ensures
        final(log).ops@ == old(log).ops@.push(Op::Insert { dsq: dsq_id }),
{
    unsafe { kfunc::scx_bpf_dsq_insert(p.as_ptr(), dsq_id, slice, enq_flags) }
}

/// Insert `p` into `dsq_id` ordered by `vtime`.
#[verifier::external_body]
pub fn dsq_insert_vtime(
    p: &Task,
    dsq_id: u64,
    slice: u64,
    vtime: u64,
    enq_flags: u64,
    log: &mut Log,
)
    ensures
        final(log).ops@ == old(log).ops@.push(Op::Insert { dsq: dsq_id }),
{
    unsafe { kfunc::scx_bpf_dsq_insert_vtime(p.as_ptr(), dsq_id, slice, vtime, enq_flags) }
}

/// Move one task that may run on this CPU from `dsq_id` to the local DSQ
/// of the CPU being dispatched for. `true` if a task was moved, `false` if
/// the queue was empty or held only tasks that cannot run here. The
/// kernel walks the queue and skips the ineligible, so a policy's steal
/// needs no eligibility check of its own.
#[verifier::external_body]
pub fn dsq_move_to_local(dsq_id: u64, log: &mut Log) -> (r: bool)
    ensures
        final(log).ops@ == old(log).ops@.push(Op::MoveToLocal { dsq: dsq_id, moved: r }),
{
    unsafe { kfunc::scx_bpf_dsq_move_to_local(dsq_id) }
}

/// The number of tasks in `dsq_id` at some instant during the call, or a
/// negative errno if no such DSQ exists. Read without the DSQ lock
/// (`READ_ONCE(dsq->nr)`), so it is exact when read and stale by the time
/// it is acted on; that is the observation the work-conservation
/// argument turns on, and it is why every caller re-checks by attempting
/// the move. Ipanema had to prove its compiler-maintained `cload` never
/// underestimates; here the kernel maintains the count under its lock and
/// the property is assumed instead.
#[verifier::external_body]
pub fn dsq_nr_queued(dsq_id: u64, log: &mut Log) -> (r: i32)
    ensures
        final(log).ops@ == old(log).ops@.push(Op::NrQueued { dsq: dsq_id, n: r }),
{
    unsafe { kfunc::scx_bpf_dsq_nr_queued(dsq_id) }
}

/// Kick `cpu`. With [`SCX_KICK_IDLE`] it reschedules only if idle, which
/// makes it re-enter `dispatch`; the kick is delivered asynchronously
/// through an irq_work, so the caller returns before the target moves.
/// An invalid CPU number ejects the scheduler, hence the precondition; a
/// policy passes only numbers the kernel gave it.
#[verifier::external_body]
pub fn kick_cpu(cpu: i32, flags: u64, log: &mut Log)
    requires
        cpu >= 0,
    ensures
        final(log).ops@ == old(log).ops@.push(Op::Kick { cpu: cpu }),
{
    unsafe { kfunc::scx_bpf_kick_cpu(cpu, flags) }
}

/// The CPU `p` is assigned to, `task_cpu(p)`: after `ops.select_cpu` it
/// is the CPU that callback returned, and it is where a per-CPU queue
/// policy files the task. Always a valid CPU number, so never negative.
#[verifier::external_body]
pub fn task_cpu(p: &Task, log: &mut Log) -> (r: i32)
    ensures
        r >= 0,
        final(log).ops@ == old(log).ops@.push(Op::TaskCpu { cpu: r }),
{
    unsafe { kfunc::scx_bpf_task_cpu(p.as_ptr()) }
}

/// Atomically clear `cpu`'s bit in the kernel's idle mask and report
/// whether it was set. This is how the kernel's own idle search claims a
/// CPU; a policy that calls it on its own CPU from `update_idle` claims
/// itself before going to look for work, so that no concurrent placement
/// can pick it meanwhile, and learns in the same step whether one already
/// has. A full-barrier read-modify-write, which is what the
/// sequential-consistency assumption of roadmap section 3.7 asks of the
/// one read the interlock argument turns on. Ejects the scheduler on an
/// invalid CPU, hence the precondition.
#[verifier::external_body]
pub fn test_and_clear_cpu_idle(cpu: i32, log: &mut Log) -> (r: bool)
    requires
        cpu >= 0,
    ensures
        final(log).ops@ == old(log).ops@.push(Op::TestAndClearIdle { cpu: cpu, was: r }),
{
    unsafe { kfunc::scx_bpf_test_and_clear_cpu_idle(cpu) }
}

/// `nr_cpu_ids`, one more than the highest possible CPU number. At least
/// one, since the CPU asking exists.
#[verifier::external_body]
pub fn nr_cpu_ids(log: &mut Log) -> (r: u32)
    ensures
        r >= 1,
        final(log).ops@ == old(log).ops@.push(Op::NrCpuIds { nr: r }),
{
    unsafe { kfunc::scx_bpf_nr_cpu_ids() }
}

/// Create a user DSQ. `node` is a NUMA node or -1 for any.
///
/// Zero on success, a negative errno on failure -- which is also the
/// convention `ops.init` returns on, so a policy whose `init` is just this
/// call satisfies the `Policy::init` postcondition for free.
#[verifier::external_body]
pub fn create_dsq(dsq_id: u64, node: i32) -> (r: i32)
    ensures
        r <= 0,
{
    unsafe { kfunc::scx_bpf_create_dsq(dsq_id, node) }
}

} // verus!
