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
//! trusted base. The contracts start empty on purpose: [`create_dsq`] is
//! the only one that says anything today, and the rest stay silent until
//! the phase 3 kernel model gives a wrapper a ghost effect to describe and
//! phase 5 ties it to the model.

use crate::kfunc;
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

/// Pick a CPU for a waking task using the kernel's default idle-core
/// search. Returns the chosen CPU and whether it was found idle; a policy
/// that dispatches directly to `SCX_DSQ_LOCAL` on the idle path avoids the
/// enqueue entirely.
#[verifier::external_body]
pub fn select_cpu_dfl(p: &Task, prev_cpu: i32, wake_flags: u64) -> (r: (i32, bool)) {
    let mut is_idle = false;
    let cpu = unsafe {
        kfunc::scx_bpf_select_cpu_dfl(p.as_ptr(), prev_cpu, wake_flags, &mut is_idle)
    };
    (cpu, is_idle)
}

/// Insert `p` at the tail of `dsq_id` with a time slice.
#[verifier::external_body]
pub fn dsq_insert(p: &Task, dsq_id: u64, slice: u64, enq_flags: u64) {
    unsafe { kfunc::scx_bpf_dsq_insert(p.as_ptr(), dsq_id, slice, enq_flags) }
}

/// Insert `p` into `dsq_id` ordered by `vtime`.
#[verifier::external_body]
pub fn dsq_insert_vtime(p: &Task, dsq_id: u64, slice: u64, vtime: u64, enq_flags: u64) {
    unsafe { kfunc::scx_bpf_dsq_insert_vtime(p.as_ptr(), dsq_id, slice, vtime, enq_flags) }
}

/// Move one task from `dsq_id` to the local DSQ of the current CPU.
#[verifier::external_body]
pub fn dsq_move_to_local(dsq_id: u64) {
    unsafe { kfunc::scx_bpf_dsq_move_to_local(dsq_id) }
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
