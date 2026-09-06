// SPDX-License-Identifier: GPL-2.0
//! Counters in `.bss`.
//!
//! There is no heap and no map API here yet, so a scheduler's statistics
//! are `N` atomics inside the policy's own `#[no_mangle]` static, which
//! libbpf turns into an internal `.bss` map. `bpftool map dump name <first
//! 8 chars of the object>.bss` prints the whole static while the scheduler
//! is attached, counters included.
//!
//! A policy names the slots with `const`s of its own, so the dump reads in
//! the order they are declared:
//!
//! ```ignore
//! const LOCAL: usize = 0;
//! ...
//! stats: Stats<3>,
//! ...
//! self.stats.inc(LOCAL);
//! ```

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::vprelude::*;

verus! {

#[verifier::external_body]
pub struct Stats<const N: usize> {
    counters: [AtomicU64; N],
}

impl<const N: usize> Stats<N> {
    /// Bump slot `i`.
    ///
    /// The precondition is real: a policy is inside `verus!`, so Verus
    /// checks it at the call. The body is bounds-checked anyway, because a
    /// panicking index would put the panic path -- and its two kfuncs --
    /// back into an object that currently has neither.
    #[verifier::external_body]
    pub fn inc(&self, i: usize)
        requires
            i < N,
    {
        if let Some(c) = self.counters.get(i) {
            c.fetch_add(1, Relaxed);
        }
    }
}

} // verus!

// `const` so the `scheduler!` static can be initialized with it; see
// `atomic.rs`.
impl<const N: usize> Stats<N> {
    pub const fn new() -> Self {
        Stats { counters: [const { AtomicU64::new(0) }; N] }
    }
}
