// SPDX-License-Identifier: GPL-2.0
//! The trace recorder: the receipt log made concrete.
//!
//! The log a callback carries is ghost, and the object never sees it. This
//! module is the same record at runtime: when the loader has raised
//! [`lachesis_trace_on`], every op a wrapper appends to its log also goes
//! out through a BPF ring buffer, with the callback it belongs to, the CPU
//! it ran on, a timestamp, and, at the start of a callback, the task's
//! pid. The loader drains the buffer into a file, and the conformance
//! checker beside the policy replays those receipts against the same
//! automata the policy was verified against, and against the model's
//! ordering across CPUs. This is phase 5's trace recorder (roadmap section
//! 5.7): what the verified contracts say the callbacks do, checked against
//! what the kernel saw them do.
//!
//! Three things here are trusted and of a kind the rest of the crate does
//! not have. The map is a BTF-defined map: a static in the `.maps` section
//! whose type spells the map's parameters as pointers to arrays, the
//! convention libbpf reads back out of the object's BTF. The two clock and
//! output calls are BPF *helpers*, not kfuncs: fixed numbers the verifier
//! knows, called through a function pointer made from the number, which
//! the BPF backend lowers to a helper call. The emit is a global BPF
//! function, the object's only one, for the verifier's sake. And nothing
//! in the erased object depends on this module unless the flag is up: an
//! op is one test of a cached flag when tracing is off.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering::{Relaxed, SeqCst}};

use crate::log::Op;

/// `BPF_MAP_TYPE_RINGBUF`.
const RINGBUF: usize = 27;
/// The buffer, 16 MiB: about 400k events, at 40 bytes each; the VM load
/// produces half a million a second.
const TRACE_BYTES: usize = 1 << 24;
/// As many per-CPU sequence counters as the policy has queues.
const TRACE_CPUS: usize = 64;

/// A BTF-defined map. libbpf reads `type` and `max_entries` off the
/// pointed-to array lengths; the values are never dereferenced.
#[repr(C)]
pub struct RingBufDef {
    r#type: *const [i32; RINGBUF],
    max_entries: *const [i32; TRACE_BYTES],
}

// Written by nobody: the kernel replaces the static with the map's fd.
unsafe impl Sync for RingBufDef {}

/// The trace ring buffer.
#[link_section = ".maps"]
#[no_mangle]
pub static lachesis_trace: RingBufDef = RingBufDef {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
};

/// Non-zero while the loader wants events. In `.bss` like the counters,
/// and written from userspace through the same map.
#[no_mangle]
pub static lachesis_trace_on: AtomicU64 = AtomicU64::new(0);

/// Per CPU, the number of events emitted so far: each event carries its
/// own, so that the checker sees exactly where the ring buffer dropped.
#[no_mangle]
pub static lachesis_trace_seq: [AtomicU64; TRACE_CPUS] = [const { AtomicU64::new(0) }; TRACE_CPUS];

/// One event, 40 bytes. `op` is [`OP_BEGIN`], [`OP_END`] or an [`Op`]
/// kind as [`encode`] numbers them; `a` and `b` are its payload; `seq` is
/// the CPU's event count; `pid` is the task a callback was given, on its
/// begin event, and zero elsewhere.
#[repr(C)]
pub struct Event {
    pub ts: u64,
    pub a: u64,
    pub b: u64,
    pub seq: u32,
    pub pid: i32,
    pub cpu: u16,
    pub cb: u8,
    pub op: u8,
}

pub const OP_BEGIN: u8 = 0;
pub const OP_END: u8 = 1;

type RingbufOutput = unsafe extern "C" fn(*mut c_void, *const c_void, u64, u64) -> i64;
type KtimeGetNs = unsafe extern "C" fn() -> u64;
type SmpProcessorId = unsafe extern "C" fn() -> u32;

/// Helper numbers, from `include/uapi/linux/bpf.h`.
const BPF_FUNC_KTIME_GET_NS: usize = 5;
const BPF_FUNC_GET_SMP_PROCESSOR_ID: usize = 8;
const BPF_FUNC_RINGBUF_OUTPUT: usize = 130;

pub fn enabled() -> bool {
    lachesis_trace_on.load(Relaxed) != 0
}

#[inline(always)]
fn now() -> u64 {
    unsafe {
        let f: KtimeGetNs = core::mem::transmute(BPF_FUNC_KTIME_GET_NS);
        f()
    }
}

#[inline(always)]
fn this_cpu() -> u16 {
    unsafe {
        let f: SmpProcessorId = core::mem::transmute(BPF_FUNC_GET_SMP_PROCESSOR_ID);
        f() as u16
    }
}

/// Copy one event into the ring buffer. A full buffer drops the event; the
/// checker treats a gap in a callback's receipts as a recording gap, not
/// a violation.
///
/// A global BPF function -- exported, so `opt` leaves it a function of its
/// own and libbpf marks it global -- rather than inlined at each of its
/// forty-odd call sites: the verifier checks a global function once,
/// against its argument types, where an inlined body is walked again on
/// every path through the caller, and three helper calls per receipt
/// inside the steal loop put `dispatch` over the instruction budget.
/// Five scalar arguments, the most a BPF function takes; the clock and the
/// CPU are read in here.
#[no_mangle]
#[inline(never)]
pub extern "C" fn lachesis_trace_emit(a: u64, b: u64, pid: i32, cb: u8, op: u8) {
    let cpu = this_cpu();
    let seq = match lachesis_trace_seq.get(cpu as usize) {
        Some(c) => c.fetch_add(1, SeqCst) as u32,
        None => 0,
    };
    let ev = Event { ts: now(), a, b, seq, pid, cpu, cb, op };
    unsafe {
        let out: RingbufOutput = core::mem::transmute(BPF_FUNC_RINGBUF_OUTPUT);
        out(
            &lachesis_trace as *const RingBufDef as *mut c_void,
            &ev as *const Event as *const c_void,
            core::mem::size_of::<Event>() as u64,
            0,
        );
    }
}

pub fn begin(cb: u8, pid: i32) {
    lachesis_trace_emit(0, 0, pid, cb, OP_BEGIN);
}

pub fn end(cb: u8) {
    lachesis_trace_emit(0, 0, 0, cb, OP_END);
}

pub fn record(cb: u8, op: &Op) {
    let (k, a, b) = encode(op);
    lachesis_trace_emit(a, b, 0, cb, k);
}

/// The wire numbering of the ops, and their payloads. The checker's table
/// mirrors this.
fn encode(op: &Op) -> (u8, u64, u64) {
    match op {
        Op::CountInc => (2, 0, 0),
        Op::CountDec => (3, 0, 0),
        Op::CountLoad { count } => (4, *count, 0),
        Op::NrCpuIds { nr } => (5, *nr as u64, 0),
        Op::TaskCpu { cpu } => (6, *cpu as i64 as u64, 0),
        Op::SelectDfl { cpu, idle } => (7, *cpu as i64 as u64, *idle as u64),
        Op::Kick { cpu } => (8, *cpu as i64 as u64, 0),
        Op::NrQueued { dsq, n } => (9, *dsq, *n as i64 as u64),
        Op::Promise { slot, ok } => (10, *slot as u64, *ok as u64),
        Op::Scan { slot, ok } => (11, *slot as u64, *ok as u64),
        Op::Unpromise { slot } => (12, *slot as u64, 0),
        Op::SetBusy { slot } => (13, *slot as u64, 0),
        Op::SetFree { slot } => (14, *slot as u64, 0),
        Op::IsBusy { slot, busy } => (15, *slot as u64, *busy as u64),
        Op::Insert { dsq } => (16, *dsq, 0),
        Op::MoveToLocal { dsq, moved } => (17, *dsq, *moved as u64),
        Op::TestAndClearIdle { cpu, was } => (18, *cpu as i64 as u64, *was as u64),
    }
}
