// SPDX-License-Identifier: GPL-2.0
//! Kernel type views and the [`Task`] handle.
//!
//! `#[btf]` declares the kernel fields a scheduler inspects. `bpf-postproc`
//! matches each declared path against the target kernel's BTF and emits
//! standard `.BTF.ext` CO-RE relocation records, so field offsets are
//! resolved when the object is loaded rather than when it is compiled.
//!
//! A field read is a raw pointer dereference through a relocated offset, so
//! every accessor is `#[verifier::external_body]` and its `ensures` is an
//! assumed fact about the kernel. [`Task::weight`] is the first one that
//! says anything, and it is the first kernel fact in the trusted base.

use btf_macros::btf;

use crate::vprelude::*;

#[btf]
pub struct sched_ext_entity {
    dsq_vtime: u64,
    slice: u64,
    weight: u32,
}

#[btf]
pub struct task_struct {
    scx: sched_ext_entity,
}

/// `enum scx_exit_kind`, mirrored from `kernel/sched/ext/internal.h`.
///
/// The values are never read as this type -- [`ExitInfo::kind`] reads the
/// field back as a `u32` -- but the *kind* of the local BTF type is what
/// makes the CO-RE relocation match. `bpf_core_fields_are_compat()` in
/// `tools/lib/bpf/relo_core.c` compares BTF kinds first, so a local `i32`
/// member never matches the kernel's `enum scx_exit_kind` member and the
/// object would be rejected at load time. Declaring a Rust enum of the same
/// name puts a BTF_KIND_ENUM in the object's local BTF instead, which does
/// match. `lachesis_control::classify_exit` is where these values are
/// interpreted.
#[repr(u32)]
#[allow(non_camel_case_types, dead_code)]
pub enum scx_exit_kind {
    SCX_EXIT_NONE = 0,
    SCX_EXIT_DONE = 1,
    SCX_EXIT_UNREG = 64,
    SCX_EXIT_UNREG_BPF = 65,
    SCX_EXIT_UNREG_KERN = 66,
    SCX_EXIT_SYSRQ = 67,
    SCX_EXIT_PARENT = 68,
    SCX_EXIT_ERROR = 1024,
    SCX_EXIT_ERROR_BPF = 1025,
    SCX_EXIT_ERROR_STALL = 1026,
}

// A leaf in a `#[btf]` field path has to name its own local BTF carrier.
// Every primitive gets this impl from the `btf` crate's own macro; an enum
// declared out here needs it written out.
impl ::btf::BtfType for scx_exit_kind {
    type Carrier = Self;

    type View<'a, Root, Path, Mode>
        = ::btf::Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: ::btf::BtfType + 'a;

    fn __btf_view<'a, Root, Path, Mode>(
        field: ::btf::Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: ::btf::BtfType + 'a,
    {
        field
    }
}

/// The two fields of `struct scx_exit_info` a scheduler reports on.
///
/// The rest of the struct is strings and a backtrace, which a BPF program
/// has no way to hand to userspace through `.bss`.
#[btf]
pub struct scx_exit_info {
    kind: scx_exit_kind,
    exit_code: i64,
}

verus! {

/// A borrowed kernel task.
///
/// Constructed only by the `scheduler!` trampolines out of a callback
/// context, so the pointer is whatever the kernel passed and is valid for
/// the duration of the callback. Opaque to Verus: the pointer has no Verus
/// specification and neither does the memory behind it.
#[verifier::external_body]
pub struct Task {
    p: *mut task_struct,
}

impl Task {
    /// `p->scx.dsq_vtime`
    ///
    /// No contract: the kernel model that says what a vtime *is* arrives in
    /// phase 3, and the refinement that ties this read to it in phase 5.
    #[verifier::external_body]
    pub fn vtime(&self) -> (r: u64) {
        *self.view().scx().dsq_vtime().get().unwrap()
    }

    /// `p->scx.slice`, the time budget left in the current run. No contract
    /// yet, for the same reason as [`Task::vtime`].
    #[verifier::external_body]
    pub fn slice(&self) -> (r: u64) {
        *self.view().scx().slice().get().unwrap()
    }

    /// `p->scx.weight`, 100 for a nice-0 task.
    ///
    /// The range is the kernel's, and assumed here: `scx_set_weight()` and
    /// `scx_reweight()` in `kernel/sched/ext/ext.c` both write
    /// `sched_weight_to_cgroup()`, which clamps to `CGROUP_WEIGHT_MIN ..=
    /// CGROUP_WEIGHT_MAX`, that is `1 ..= 10000`. This is what discharges
    /// `charge_vtime`'s precondition, so weakening it breaks the policy's
    /// proof rather than silently dividing by zero.
    #[verifier::external_body]
    pub fn weight(&self) -> (r: u32)
        ensures
            1 <= r <= 10000,
    {
        *self.view().scx().weight().get().unwrap()
    }

    /// Write `p->scx.dsq_vtime` through the CO-RE relocated offset. The
    /// kernel deprecates this in favour of `scx_bpf_task_set_vtime()`, but
    /// the direct write is what exercises CO-RE stores.
    #[verifier::external_body]
    pub fn set_vtime(&self, v: u64) {
        unsafe {
            *self.view().scx().dsq_vtime().as_mut_ptr() = v;
        }
    }
}

/// A borrowed `struct scx_exit_info`.
///
/// Opaque like [`Task`]: the trampoline hands the callback whatever pointer
/// the kernel passed, and the two accessors below read through CO-RE
/// relocated offsets.
#[verifier::external_body]
pub struct ExitInfo {
    _opaque: [u8; 0],
}

impl ExitInfo {
    /// `ei->kind`, a value of `enum scx_exit_kind`.
    ///
    /// Returned as the raw `u32` rather than as the enum, because the
    /// kernel is free to add a variant this build does not know and
    /// materializing an out-of-range discriminant would be undefined.
    /// `SCX_EXIT_NONE` is zero, which is what makes "kind is set" testable
    /// by a reader of the policy's `.bss`.
    #[verifier::external_body]
    pub fn kind(&self) -> (r: u32) {
        unsafe { *(self.view().kind().as_ptr() as *const u32) }
    }

    /// `ei->exit_code`, as raw bits.
    ///
    /// The kernel's field is an `s64`, but its meaning is the packed
    /// `enum scx_exit_code` layout (system action, system reason, user
    /// code), so the bits are what a reader wants.
    #[verifier::external_body]
    pub fn exit_code(&self) -> (r: u64) {
        unsafe { *(self.view().exit_code().as_ptr() as *const u64) }
    }
}

} // verus!

// Plain Rust, external to Verus: the trampolines' side of the handle.
impl Task {
    pub(crate) fn from_raw(p: *mut task_struct) -> Self {
        Task { p }
    }

    /// `NULL` becomes `None`; `ops.dispatch` is passed a null `prev`.
    pub(crate) fn from_raw_opt(p: *mut task_struct) -> Option<Self> {
        if p.is_null() { None } else { Some(Task { p }) }
    }

    pub(crate) fn as_ptr(&self) -> *mut task_struct {
        self.p
    }

    fn view(&self) -> &task_struct {
        unsafe { &*self.p }
    }
}

// Same shape on the exit-info side: `ExitInfo` is the handle the trampoline
// builds out of the kernel's pointer, `scx_exit_info` is the layout-free
// `#[btf]` view of the memory it points at. Both are zero-sized, so the
// cast only reinterprets the address.
impl ExitInfo {
    fn view(&self) -> &scx_exit_info {
        unsafe { &*(self as *const ExitInfo as *const scx_exit_info) }
    }
}
