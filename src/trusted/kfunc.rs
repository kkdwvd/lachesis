// SPDX-License-Identifier: GPL-2.0
//! Raw kfunc declarations.
//!
//! This is the only module in the tree with an `extern "C"` block. A new
//! kernel function is declared here and given a safe wrapper in
//! [`crate::scx`]; a policy never declares one.
//!
//! The names must match the kernel's exactly: `add_ksyms.py` tags each of
//! these declarations `.ksyms` and mirrors the prototype out of the target
//! kernel's BTF, and libbpf resolves them by name at load time.

use crate::task::task_struct;

// `task_struct` is deliberately an opaque `#[btf]` view with no layout of
// its own -- the kernel's layout is resolved by CO-RE -- so the FFI-safety
// lint has nothing useful to say about it.
#[allow(improper_ctypes)]
unsafe extern "C" {
    pub(crate) fn scx_bpf_select_cpu_dfl(
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        is_idle: *mut bool,
    ) -> i32;

    pub(crate) fn scx_bpf_dsq_insert(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    );

    pub(crate) fn scx_bpf_dsq_insert_vtime(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    );

    pub(crate) fn scx_bpf_dsq_move_to_local(dsq_id: u64);

    pub(crate) fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32;

    /// Abort the program with `cookie` as the exit code. The sanctioned way
    /// out of a Rust panic: the verifier rejects a reachable `__bpf_trap`.
    pub(crate) fn bpf_throw(cookie: u64) -> !;

    /// Append to a BPF stream. `fmt` must be a NUL-terminated string in
    /// read-only memory; `args` is `len` bytes of `u64` slots.
    pub(crate) fn bpf_stream_vprintk(
        stream_id: i32,
        fmt: *const u8,
        args: *const u64,
        len: u32,
    ) -> i32;
}
