// SPDX-License-Identifier: GPL-2.0
//! `lachesis_control` -- the control plane, verified with the policy.
//!
//! The loader in `../../../loader/main.rs` is ordinary `std` Rust over
//! libbpf-rs and is not verified. This crate is the part of the userspace
//! side that is not plumbing: the reading it takes of what the BPF side
//! wrote. It is checked with `--no-cheating` by the same Verus driver, in
//! the same `make verify` pass, as the policy it is paired with, which is
//! the point of it being a crate at all -- the two sides of a fact the
//! kernel reports are then proved to agree.
//!
//! A crate rather than a module because Verus verifies crates: keeping it
//! separate is what lets it be checked without the libbpf-rs dependency
//! graph, which Verus has no specifications for, being part of the pass. It
//! therefore depends on nothing but the `verus!` macro, is `#![no_std]`,
//! and calls no allocator.
//!
//! Only what is worth proving belongs here. A function whose `ensures` a
//! reader would accept at a glance -- formatting, name tables, arithmetic
//! with no invariant behind it -- belongs in the loader, where it costs
//! nothing to read. Adding one here means: write it inside the `verus!`
//! block with a contract that says something a caller could get wrong,
//! call it from the loader, and re-run `make verify`. Nothing else is
//! needed -- the crate is already wired into the pipeline through
//! `USER_CORE_SRC` in `../../Makefile`.

#![no_std]

// The same keep-vs-erase dance the BPF crates do, spelled out here because
// this crate does not depend on `lachesis_runtime_trusted`: the Verus
// driver sets `verus_keep_ghost` and supplies vstd, and the cargo build
// does neither, so the macro erases the ghost code and the exec bodies
// below are all that reaches the binary.
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;

verus! {

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

} // verus!
