// SPDX-License-Identifier: GPL-2.0
//! The panic handler.
//!
//! A `#[panic_handler]` may live in a dependency crate, so neither
//! `lachesis_runtime` nor a policy defines one; it is here once for every
//! scheduler. Nothing about it is checkable, which is why it is trusted.

use crate::kfunc;

/// Report a panic on BPF stream 0 and unwind out of the program.
///
/// Deliberately not `core::fmt`: `Formatter` and `&mut dyn Write` compile
/// to BPF `callx`, and `check_cfg()` rejects an indirect call anywhere in
/// the program -- reachable or not -- with "unknown opcode 8d". Formatting
/// the `PanicInfo` message would drag that machinery in through the panic
/// path that every `unwrap()` and every division already reaches, so only
/// the line number is reported, formatted by the kernel's own
/// `bstr_printf()`. `bpf_bprintf_prepare()` understands no precision
/// field, so upstream's `"%.*s"` is not an option either.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let line = match info.location() {
        Some(l) => l.line() as u64,
        None => 0,
    };
    let args: [u64; 1] = [line];
    unsafe {
        kfunc::bpf_stream_vprintk(
            0,
            b"lachesis: rust panic at line %u\n\0".as_ptr(),
            args.as_ptr(),
            8,
        );
        kfunc::bpf_throw(1)
    }
}
