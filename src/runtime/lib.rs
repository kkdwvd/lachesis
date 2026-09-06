// SPDX-License-Identifier: GPL-2.0
//! `lachesis_runtime` -- the verified substrate shared by every lachesis
//! scheduler.
//!
//! This crate is the checked layer between `lachesis_runtime_trusted` and
//! a policy. It contains no `unsafe`, no foreign declaration, no raw
//! pointer and no Verus cheat, and it is verified with `--no-cheating`.
//! What lives where:
//!
//! * [`policy`] -- the [`policy::Policy`] trait: one method per struct_ops
//!   callback, with the contracts a policy's `impl` inherits.
//! * [`vtime`] -- virtual-time arithmetic, verified.
//! * [`prelude`] -- everything a policy needs, in one glob.
//!
//! Anything that needs an assumption -- a kfunc, a CO-RE field read, an
//! atomic, the panic handler, the `scheduler!` trampolines -- lives in
//! `lachesis_runtime_trusted` and is re-exported through the prelude, so a
//! policy never names that crate.

#![no_std]

pub mod policy;
pub mod vtime;

/// Everything a policy needs, including the `verus!` macro.
pub mod prelude {
    // The `verus_keep_ghost` cfg dance, vstd, and the trusted surface:
    // `AtomicU64`, `ExitInfo`, `Stats`, `Task`, the `scx` wrappers and
    // their constants, and the `scheduler!` macro.
    pub use lachesis_runtime_trusted::prelude::*;

    pub use crate::policy::Policy;
    // Spec items are not re-exported: the `verus!` macro deletes them in the
    // erased pass, so naming one outside a `verus!` block breaks the BPF
    // build. A policy that needs `spec_vtime_before` imports it inside its
    // own `verus!` block.
    pub use crate::vtime::{charge_vtime, clamp_vtime, vtime_before};
}
