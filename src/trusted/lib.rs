// SPDX-License-Identifier: GPL-2.0
//! `lachesis_trusted` -- the trusted base, and the only place a proof may
//! be short-circuited.
//!
//! Everything that Verus cannot check, and everything `unsafe`, lives in
//! this crate: the raw kfunc declarations, the safe wrappers whose
//! contracts Verus takes on faith, the `#[btf]` kernel views and the
//! [`task::Task`] accessors, the atomics, the panic handler, and the
//! `scheduler!` trampolines the kernel calls. `make lint-trusted` fails if
//! `unsafe` or a Verus cheat appears anywhere under `src/` outside this
//! directory, and `make trusted-lines` prints how big it has grown; both
//! are roadmap section 3.7.
//!
//! It is also the one crate verified *without* `--no-cheating`, because
//! that flag rejects `#[verifier::external_body]` -- and an FFI call has no
//! body a verifier could look at, so an assumed contract is the only way to
//! give a kfunc a specification at all.
//!
//! One module per concern:
//!
//! * [`kfunc`] -- the only `extern "C"` block in the tree.
//! * [`scx`] -- safe wrappers over those kfuncs, and the kernel constants.
//! * [`task`] -- the `#[btf]` CO-RE views, [`task::Task`] and its specs.
//! * [`atomic`] -- an opaque [`atomic::AtomicU64`], no `Ordering` exposed.
//! * [`stats`] -- [`stats::Stats`], a `.bss` counter array.
//! * [`panic`] -- the `#[panic_handler]`, defined once for all policies.
//! * [`ops`] -- the `scheduler!` macro: struct_ops table and trampolines.
//!
//! Adding a kernel function means adding a declaration to [`kfunc`], a safe
//! wrapper to [`scx`] and a specification to that wrapper -- here, never in
//! `lachesis_rt` and never in a policy.

#![no_std]

pub mod atomic;
pub mod kfunc;
pub mod ops;
pub mod panic;
pub mod scx;
pub mod stats;
pub mod task;

/// vstd in the verification pass, the bare `verus!` macro in the erased
/// one.
///
/// The `verus!` macro decides keep-vs-erase by expanding
/// `cfg!(verus_keep_ghost)` in the crate being compiled, so one source
/// serves both passes: the verification pass runs under the Verus driver,
/// which sets that cfg and supplies vstd, and the compile pass is a plain
/// BPF rustc invocation, which does not and gets the ghost code erased by
/// the macro. This is the only place in the tree that names that cfg;
/// `lachesis_rt`'s prelude re-exports it.
#[doc(hidden)]
pub mod vprelude {
    #[cfg(verus_keep_ghost)]
    pub use vstd::prelude::*;
    #[cfg(not(verus_keep_ghost))]
    pub use verus_builtin_macros::verus;
}

/// The trusted half of a policy's prelude, re-exported by `lachesis_rt`.
pub mod prelude {
    pub use crate::vprelude::*;

    pub use crate::atomic::AtomicU64;
    pub use crate::scx::{
        self, SCX_DSQ_FLAG_BUILTIN, SCX_DSQ_GLOBAL, SCX_DSQ_LOCAL, SCX_SLICE_DFL,
    };
    pub use crate::scheduler;
    pub use crate::stats::Stats;
    pub use crate::task::{ExitInfo, Task};
}
