// SPDX-License-Identifier: GPL-2.0
//! The `scheduler!` macro: policy instance, struct_ops table, trampolines,
//! license.
//!
//! A policy implements `lachesis_runtime`'s `Policy` trait and then lists the
//! struct_ops members it wants exported. Everything
//! ABI-shaped -- the `extern "C"` trampolines, the context unpacking, the
//! `#[link_section]` names, the `#[repr(C)]` table, the
//! `.struct_ops.link` static and the license -- is generated here.
//!
//! The trampolines are the kernel-to-policy boundary and are trusted by
//! nature: they are `extern "C"` functions outside `verus!`, they cast the
//! kernel's `u64` slots to typed parameters, and Verus does not check the
//! calls they make. A `requires` on a `Policy` method is therefore an
//! assumption about what the kernel passes in, not something checked here.

use crate::task::{ExitInfo, Task, task_struct};

/// Every struct_ops program has this signature: the kernel passes its
/// arguments as an array of `u64` slots.
pub type OpFn = extern "C" fn(*const u64) -> i32;

/// Decode one context slot into a typed parameter.
///
/// Implemented for exactly the types a callback parameter may have, so the
/// macro needs no type matching of its own.
pub trait FromCtx {
    /// # Safety
    /// `raw` must be the slot the kernel filled in for this parameter.
    unsafe fn from_ctx(raw: u64) -> Self;
}

impl FromCtx for u64 {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { raw }
}

impl FromCtx for i32 {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { raw as i32 }
}

impl FromCtx for bool {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { raw != 0 }
}

impl FromCtx for Task {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { Task::from_raw(raw as *mut task_struct) }
}

impl FromCtx for Option<Task> {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { Task::from_raw_opt(raw as *mut task_struct) }
}

impl<'a> FromCtx for &'a ExitInfo {
    #[inline(always)]
    unsafe fn from_ctx(raw: u64) -> Self { unsafe { &*(raw as *const ExitInfo) } }
}

/// Turn a callback's return value into the `i32` the kernel expects, so a
/// policy method that returns nothing needs no `0` at the end.
pub trait IntoRet {
    fn into_ret(self) -> i32;
}

impl IntoRet for () {
    #[inline(always)]
    fn into_ret(self) -> i32 { 0 }
}

impl IntoRet for i32 {
    #[inline(always)]
    fn into_ret(self) -> i32 { self }
}

/// `struct sched_ext_ops`'s `name` field is a fixed 128-byte buffer.
pub const fn pad_name(s: &str) -> [u8; 128] {
    let b = s.as_bytes();
    let mut buf = [0u8; 128];
    let mut i = 0;
    while i < b.len() && i < 127 {
        buf[i] = b[i];
        i += 1;
    }
    buf
}

/// Generate a scheduler's policy instance, struct_ops table and BPF entry
/// points.
///
/// ```ignore
/// scheduler! {
///     map: lachesis_ops,
///     name: "lachesis",
///     policy: LACHESIS: Lachesis = Lachesis {
///         vtime_now: AtomicU64::new(0),
///         stats: Stats::new(),
///     },
///     ops {
///         enqueue as lachesis_enqueue,
///     }
///     sleepable {
///         init as lachesis_init,
///     }
/// }
/// ```
///
/// `policy:` names the `#[no_mangle]` static holding the one instance of
/// the policy, its type, and a `const` initializer -- `#[no_mangle]` so
/// that `bpftool map dump` finds the counters inside it. The static is
/// emitted outside `verus!` and passed to every callback as `&self`.
///
/// Each `ops` line reads "struct_ops member `as` exported program symbol".
/// The signature is not repeated: the `Policy` trait fixes it, and
/// [`__trampoline!`](crate::__trampoline) has one rule per member name that
/// knows how many context slots to unpack and how to type them. Two names
/// per line is the floor, because `macro_rules!` cannot mint an identifier.
/// Members listed under `sleepable` get a `struct_ops.s/` section, which is
/// what the kernel requires for callbacks it invokes in sleepable context
/// (`init`, `init_task`, `exit_task`, the cgroup ones).
///
/// Adding a member means adding it to the `Policy` trait and adding a rule
/// to `__trampoline!`; an unknown member is a `compile_error!`.
#[macro_export]
macro_rules! scheduler {
    (
        map: $map:ident,
        name: $name:literal,
        policy: $inst:ident : $ty:ty = $init:expr,
        ops { $($m:ident as $sym:ident),* $(,)? }
        $(sleepable { $($sm:ident as $ssym:ident),* $(,)? })?
    ) => {
        /// The one instance of the policy. Zero-initialized, so libbpf maps
        /// it into `.bss` and `bpftool map dump` can read it back.
        #[no_mangle]
        static $inst: $ty = $init;

        $($crate::__trampoline!("struct_ops", $inst, $m, $sym);)*
        $($($crate::__trampoline!("struct_ops.s", $inst, $sm, $ssym);)*)?

        #[repr(C)]
        #[allow(non_camel_case_types)]
        struct sched_ext_ops {
            $($m: $crate::ops::OpFn,)*
            $($($sm: $crate::ops::OpFn,)*)?
            name: [u8; 128],
        }

        // The struct_ops map is written once, by the kernel, at attach.
        unsafe impl ::core::marker::Sync for sched_ext_ops {}

        #[link_section = ".struct_ops.link"]
        #[no_mangle]
        static $map: sched_ext_ops = sched_ext_ops {
            $($m: $sym,)*
            $($($sm: $ssym,)*)?
            name: $crate::ops::pad_name($name),
        };

        #[link_section = "license"]
        #[no_mangle]
        static _LICENSE: [u8; 4] = *b"GPL\0";
    };
}

/// The signature of each struct_ops member the framework knows, one rule
/// per member name. This is the only place the kernel's context layout for
/// a callback is written down; it must agree with the `Policy` trait.
#[doc(hidden)]
#[macro_export]
macro_rules! __trampoline {
    ($sec:literal, $inst:ident, select_cpu, $sym:ident) => {
        $crate::__entry!($sec, $inst, select_cpu, $sym,
            (p: $crate::task::Task, prev_cpu: i32, wake_flags: u64));
    };
    ($sec:literal, $inst:ident, enqueue, $sym:ident) => {
        $crate::__entry!($sec, $inst, enqueue, $sym,
            (p: $crate::task::Task, enq_flags: u64));
    };
    ($sec:literal, $inst:ident, dispatch, $sym:ident) => {
        $crate::__entry!($sec, $inst, dispatch, $sym,
            (cpu: i32, prev: ::core::option::Option<$crate::task::Task>));
    };
    ($sec:literal, $inst:ident, running, $sym:ident) => {
        $crate::__entry!($sec, $inst, running, $sym, (p: $crate::task::Task));
    };
    ($sec:literal, $inst:ident, stopping, $sym:ident) => {
        $crate::__entry!($sec, $inst, stopping, $sym,
            (p: $crate::task::Task, runnable: bool));
    };
    ($sec:literal, $inst:ident, enable, $sym:ident) => {
        $crate::__entry!($sec, $inst, enable, $sym, (p: $crate::task::Task));
    };
    ($sec:literal, $inst:ident, exit, $sym:ident) => {
        $crate::__entry!($sec, $inst, exit, $sym, (ei: &$crate::task::ExitInfo));
    };
    ($sec:literal, $inst:ident, init, $sym:ident) => {
        $crate::__entry!($sec, $inst, init, $sym, ());
    };
    ($sec:literal, $inst:ident, $m:ident, $sym:ident) => {
        ::core::compile_error!(::core::concat!(
            "scheduler!: unknown struct_ops member `", ::core::stringify!($m),
            "`; add it to the Policy trait and to __trampoline! in trusted/ops.rs"));
    };
}

/// One `extern "C"` entry point: unpack the context, call the policy.
#[doc(hidden)]
#[macro_export]
macro_rules! __entry {
    ($sec:literal, $inst:ident, $m:ident, $sym:ident, ($($a:ident : $t:ty),*)) => {
        #[link_section = ::core::concat!($sec, "/", ::core::stringify!($sym))]
        #[no_mangle]
        #[allow(unused_variables, unused_mut, unused_assignments)]
        extern "C" fn $sym(ctx: *const u64) -> i32 {
            let mut slot = 0usize;
            $(
                let $a: $t = unsafe {
                    let raw = *ctx.add(slot);
                    slot += 1;
                    <$t as $crate::ops::FromCtx>::from_ctx(raw)
                };
            )*
            // Method-call syntax: the `Policy` trait comes in through the
            // policy crate's prelude, and this crate cannot name it -- it
            // is the dependency, not the dependent.
            $crate::ops::IntoRet::into_ret($inst.$m($($a),*))
        }
    };
}
