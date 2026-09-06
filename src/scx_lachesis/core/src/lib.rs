// SPDX-License-Identifier: GPL-2.0
//! `scx_lachesis_core` -- the verified half of the userspace side.
//!
//! The loader in `../../src/main.rs` is ordinary `std` Rust over libbpf-rs
//! and is not verified; everything in it that is a *decision* rather than
//! plumbing lives here instead, in one crate, entirely inside `verus!`, and
//! is checked with `--no-cheating` by the same Verus driver that checks the
//! BPF crates.
//!
//! A crate rather than a module because Verus verifies crates: keeping the
//! core separate is what lets it be checked without the libbpf-rs
//! dependency graph, which Verus has no specifications for, being part of
//! the pass. It therefore depends on nothing but the `verus!` macro, is
//! `#![no_std]`, and calls no allocator.
//!
//! Adding a function here means: write it inside the `verus!` block with a
//! `requires`/`ensures` that says something a caller could get wrong, call
//! it from the loader, and re-run `make verify`. Nothing else is needed --
//! the crate is already wired into the pipeline through `USER_CORE_SRC` in
//! `../../Makefile`.

#![no_std]

// The same keep-vs-erase dance the BPF crates do, spelled out here because
// this crate does not depend on `lachesis_trusted`: the Verus driver sets
// `verus_keep_ghost` and supplies vstd, and the cargo build does neither, so
// the macro erases the ghost code and the exec bodies below are all that
// reaches the binary.
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;

verus! {

/// The most counter slots one sample can carry.
///
/// How many counters the policy actually has is a runtime fact, discovered
/// from the object's BTF, so the arrays here are one fixed size: the loader
/// refuses to start if the policy has more, and leaves the rest zero, which
/// makes their deltas zero too.
pub const MAX_COUNTERS: usize = 16;

/// What the loader prints for a counter: the difference between two
/// samples, wrapping, because a `.bss` counter is a `u64` the BPF side
/// increments without ever resetting and nothing stops it from wrapping.
pub open spec fn spec_delta(prev: u64, curr: u64) -> u64 {
    curr.wrapping_sub(prev)
}

/// The per-slot deltas between two samples of the counter array.
///
/// The postcondition is the whole point: it pins the arithmetic to
/// [`spec_delta`] slot by slot, so an off-by-one in the loop, a reversed
/// subtraction, or a saturating one, all fail here rather than printing a
/// plausible wrong number.
pub fn counter_deltas(
    prev: &[u64; MAX_COUNTERS],
    curr: &[u64; MAX_COUNTERS],
) -> (r: [u64; MAX_COUNTERS])
    ensures
        forall|i: int| #![trigger r[i]]
            0 <= i < MAX_COUNTERS ==> r[i] == spec_delta(prev[i], curr[i]),
{
    let mut out: [u64; MAX_COUNTERS] = [0; MAX_COUNTERS];
    let mut i: usize = 0;
    while i < MAX_COUNTERS
        invariant
            i <= MAX_COUNTERS,
            forall|j: int| #![trigger out[j]]
                0 <= j < i ==> out[j] == spec_delta(prev[j], curr[j]),
        decreases MAX_COUNTERS - i,
    {
        out[i] = curr[i].wrapping_sub(prev[i]);
        i = i + 1;
    }
    out
}

/// What a `struct scx_exit_info` kind means to the loader.
///
/// `enum scx_exit_kind` in `kernel/sched/ext/internal.h` is three bands of
/// values with gaps between them, and the loader only needs to know which
/// band it is in: whether the scheduler is still attached, whether it was
/// taken away on purpose, and whether it was ejected.
#[derive(Clone, Copy, Debug)]
pub enum ExitClass {
    /// `SCX_EXIT_NONE`: `ops.exit` has not run, so nothing was recorded.
    NotExited,
    /// `SCX_EXIT_DONE`.
    Done,
    /// `SCX_EXIT_UNREG*`, `SCX_EXIT_SYSRQ`, `SCX_EXIT_PARENT`: somebody
    /// asked for the scheduler to go away. Dropping the loader's link lands
    /// here, as `SCX_EXIT_UNREG`.
    Unregistered,
    /// `SCX_EXIT_ERROR`, `SCX_EXIT_ERROR_BPF`: the scheduler was ejected.
    Error,
    /// `SCX_EXIT_ERROR_STALL`: the watchdog ejected it.
    Stall,
    /// A kind this build does not know. The kernel is free to add one.
    Unknown,
}

/// Classify a raw `enum scx_exit_kind` value.
///
/// Every clause is an `<==>`, so the five bands together characterize the
/// function: widening a band, dropping a value from one, or letting an
/// unknown kind fall into `Error` all fail verification.
pub fn classify_exit(kind: u64) -> (r: ExitClass)
    ensures
        r == ExitClass::NotExited <==> kind == 0,
        r == ExitClass::Done <==> kind == 1,
        r == ExitClass::Unregistered <==> 64 <= kind <= 68,
        r == ExitClass::Error <==> 1024 <= kind <= 1025,
        r == ExitClass::Stall <==> kind == 1026,
{
    if kind == 0 {
        ExitClass::NotExited
    } else if kind == 1 {
        ExitClass::Done
    } else if 64 <= kind && kind <= 68 {
        ExitClass::Unregistered
    } else if 1024 <= kind && kind <= 1025 {
        ExitClass::Error
    } else if kind == 1026 {
        ExitClass::Stall
    } else {
        ExitClass::Unknown
    }
}

/// The kernel's own name for an exit kind.
///
/// The strings are `scx_exit_reason()` in `kernel/sched/ext/ext.c`, so the
/// loader's report reads like the kernel's own.
pub fn exit_kind_name(kind: u64) -> (r: &'static str) {
    if kind == 0 {
        "none"
    } else if kind == 1 {
        "done"
    } else if kind == 64 {
        "unregistered from user space"
    } else if kind == 65 {
        "unregistered from BPF"
    } else if kind == 66 {
        "unregistered from the main kernel"
    } else if kind == 67 {
        "disabled by sysrq-S"
    } else if kind == 68 {
        "parent exiting"
    } else if kind == 1024 {
        "runtime error"
    } else if kind == 1025 {
        "scx_bpf_error"
    } else if kind == 1026 {
        "runnable task stall"
    } else {
        "<UNKNOWN>"
    }
}

} // verus!
