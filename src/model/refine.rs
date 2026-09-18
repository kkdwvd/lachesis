// SPDX-License-Identifier: GPL-2.0
//! The refinement contracts: which sequences of receipts a callback may
//! leave in its log.
//!
//! Each callback of the `Policy` trait carries an `ensures` stated here,
//! over the ops the trusted wrappers appended to its receipt log. An
//! obligation is a small automaton over the ops -- the same phases the
//! model's actions step through -- and the callback must drive it to
//! `Done`. What the automata demand is exactly what the invariant in
//! `lib.rs` assumed of the policy when it was proved: publish before the
//! idle search; kick every CPU the search claims; file the task on the
//! first claimed CPU whose queue was empty and whose word went from free
//! to promised, and on the assigned CPU only after the kernel's search saw
//! nothing idle or the policy's own scan, which follows a claim that did
//! not take and tests every CPU's bit once, ran past the last CPU; guard
//! the own word from free to scanning before stealing, and do not steal
//! if that does not take; steal only from a CPU whose word says busy,
//! scanning every CPU in order until a move succeeds, take the victim's
//! word from promised to free on a move, and write the own word free
//! again when nothing was found; read the count and claim the own bit
//! before a self-kick; write the word busy in `running` and free in
//! `stopping`; never dispatch from `select_cpu`.
//! A policy that skips one of these -- CFS's domain-local placement, its
//! give-up-after-the-first-candidate balancing, a scheduler that steals
//! from an idle CPU's queue, clears a CPU's word when it consumes from it,
//! asks the kernel to search again instead of scanning, steals without
//! guarding its own word, leaves a victim's stolen promise standing, or
//! direct dispatches to a local DSQ -- cannot drive the automaton to
//! `Done`, and Verus rejects the callback. `src/sched/bpf/mutants/` holds
//! those variants and the build checks that each is rejected.
//!
//! The link between an automaton here and the actions in `lib.rs` is by
//! construction: the enqueue automaton's states are the model's `ev`
//! phases and the dispatch automaton's the `phase` values. Making that
//! link a theorem is phase 5's refinement proper.

use vstd::prelude::*;

use lachesis_runtime_trusted::log::Op;

verus! {

broadcast use vstd::seq_lib::group_seq_properties;

/// The policy's cap on CPUs it names; the policy's `MAX_CPUS`.
pub open spec fn max_cpus() -> int {
    64
}

pub open spec fn cap_of(n: u32) -> int {
    if n < 64 { n as int } else { 64 }
}

/// The kernel's global DSQ id, the fallback for a CPU without a queue.
pub open spec fn global_dsq() -> u64 {
    0x8000_0000_0000_0001
}

/// `after` is `before` with ops appended; `tail` is what was appended.
pub open spec fn extends(before: Seq<Op>, after: Seq<Op>) -> bool {
    before.len() <= after.len() && after.take(before.len() as int) == before
}

pub open spec fn tail_of(before: Seq<Op>, after: Seq<Op>) -> Seq<Op> {
    after.skip(before.len() as int)
}

/// Pushing one op onto a log commutes with taking the tail past a prefix.
pub broadcast proof fn lemma_skip_push(s: Seq<Op>, k: int, op: Op)
    requires
        0 <= k <= s.len(),
    ensures
        #[trigger] s.push(op).skip(k) == s.skip(k).push(op),
{
    assert(s.push(op).skip(k) =~= s.skip(k).push(op));
}

pub broadcast proof fn lemma_take_push(s: Seq<Op>, k: int, op: Op)
    requires
        0 <= k <= s.len(),
    ensures
        #[trigger] s.push(op).take(k) == s.take(k),
{
    assert(s.push(op).take(k) =~= s.take(k));
}

/// The base cases: a log extends itself, with nothing appended.
pub broadcast proof fn lemma_take_all(s: Seq<Op>)
    ensures
        #[trigger] s.take(s.len() as int) == s,
{
    assert(s.take(s.len() as int) =~= s);
}

pub broadcast proof fn lemma_skip_all(s: Seq<Op>)
    ensures
        #[trigger] s.skip(s.len() as int) == Seq::<Op>::empty(),
{
    assert(s.skip(s.len() as int) =~= Seq::<Op>::empty());
}

// ---------------------------------------------------------------------
// enqueue

pub struct EnqCtx {
    pub cpu: int,
    pub cap: int,
}

/// The enqueue automaton. After the publish, the kernel's pick: an idle
/// CPU it claimed, or none. A claim -- the kernel's, or the scan's at `j`
/// -- is kicked, then its queue is read, then its word is compare-and-
/// swapped; a claim that does not take sends the policy to its own scan,
/// which resumes at `next`: 0 after the kernel's pick, `j + 1` after a
/// scan claim at `j`. The scan tests and clears each CPU's bit once, in
/// order; past the last CPU the task goes to its own CPU. A second kernel
/// search in place of the scan is not allowed: it may return a CPU this
/// enqueue already claimed, if that CPU went idle again meanwhile, and no
/// bound on such retries guarantees that an idle CPU whose bit stays up is
/// ever probed.
pub enum EnqSt {
    Start,
    Cpu(int),
    Ready(EnqCtx),
    Published(EnqCtx),
    Claimed(EnqCtx, int, int),
    Kicked(EnqCtx, int, int),
    Empty(EnqCtx, int, int),
    Promised(EnqCtx, int),
    Fallback(EnqCtx),
    Scan(EnqCtx, int),
    Done,
}

/// One op moves the enqueue automaton, or breaks the protocol (`None`).
pub open spec fn enq_step(st: EnqSt, op: Op) -> Option<EnqSt> {
    match st {
        EnqSt::Start => match op {
            Op::TaskCpu { cpu } => Some(EnqSt::Cpu(cpu as int)),
            _ => None,
        },
        EnqSt::Cpu(c) => match op {
            Op::NrCpuIds { nr } => Some(EnqSt::Ready(EnqCtx { cpu: c, cap: cap_of(nr) })),
            _ => None,
        },
        EnqSt::Ready(x) => match op {
            // a CPU the policy has no queue for: the kernel's fallback, uncounted
            Op::Insert { dsq } => if x.cpu >= x.cap && dsq == global_dsq() { Some(EnqSt::Done) } else { None },
            // publish before anything else
            Op::CountInc => if x.cpu < x.cap { Some(EnqSt::Published(x)) } else { None },
            _ => None,
        },
        // the kernel's pick: a claim, or nothing idle
        EnqSt::Published(x) => match op {
            Op::SelectDfl { cpu, idle } => if idle { Some(EnqSt::Claimed(x, cpu as int, 0)) }
                                          else { Some(EnqSt::Fallback(x)) },
            _ => None,
        },
        // a claimed CPU is kicked, whatever else happens to it; one beyond
        // the policy's queues is only kicked, and the scan takes over
        EnqSt::Claimed(x, k, next) => match op {
            Op::Kick { cpu } => if cpu as int != k { None }
                                else if k >= x.cap { Some(EnqSt::Scan(x, next)) }
                                else { Some(EnqSt::Kicked(x, k, next)) },
            _ => None,
        },
        EnqSt::Kicked(x, k, next) => match op {
            Op::NrQueued { dsq, n } => if dsq as int == k {
                if n > 0 { Some(EnqSt::Scan(x, next)) } else { Some(EnqSt::Empty(x, k, next)) }
            } else { None },
            _ => None,
        },
        // the placement: the word goes from free to promised, or the scan
        // goes on
        EnqSt::Empty(x, k, next) => match op {
            Op::Promise { slot, ok } => if slot as int == k {
                if ok { Some(EnqSt::Promised(x, k)) } else { Some(EnqSt::Scan(x, next)) }
            } else { None },
            _ => None,
        },
        EnqSt::Promised(x, k) => match op {
            Op::Insert { dsq } => if dsq as int == k { Some(EnqSt::Done) } else { None },
            _ => None,
        },
        EnqSt::Fallback(x) => match op {
            Op::Insert { dsq } => if dsq as int == x.cpu { Some(EnqSt::Done) } else { None },
            _ => None,
        },
        // the policy's own scan: each CPU's bit once, in order; past the
        // last, the task's own CPU
        EnqSt::Scan(x, j) => if j >= x.cap {
            match op {
                Op::Insert { dsq } => if dsq as int == x.cpu { Some(EnqSt::Done) } else { None },
                _ => None,
            }
        } else {
            match op {
                Op::TestAndClearIdle { cpu, was } => if cpu as int == j {
                    if was { Some(EnqSt::Claimed(x, j, j + 1)) } else { Some(EnqSt::Scan(x, j + 1)) }
                } else { None },
                _ => None,
            }
        },
        EnqSt::Done => None,
    }
}

pub open spec fn enq_run(ops: Seq<Op>) -> Option<EnqSt>
    decreases ops.len(),
{
    if ops.len() == 0 {
        Some(EnqSt::Start)
    } else {
        match enq_run(ops.drop_last()) {
            Some(st) => enq_step(st, ops.last()),
            None => None,
        }
    }
}

pub broadcast proof fn lemma_enq_run_push(ops: Seq<Op>, op: Op)
    ensures
        #[trigger] enq_run(ops.push(op)) == match enq_run(ops) {
            Some(st) => enq_step(st, op),
            None => None,
        },
{
    assert(ops.push(op).drop_last() =~= ops);
}

/// The contract of `enqueue`: the ops it appended drive the automaton to
/// `Done`.
pub open spec fn enqueue_ok(before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && enq_run(tail_of(before, after)) == Some(EnqSt::Done)
}

/// The shape of `enqueue`'s loop invariant: the policy's own scan is at
/// `j`, no placement yet.
pub open spec fn searching(cpu: int, cap: int, j: int, st: Option<EnqSt>) -> bool {
    st == Some(EnqSt::Scan(EnqCtx { cpu, cap }, j))
}

/// What `enqueue`'s loop leaves behind on any exit: a state from which the
/// one insert, into `dsq`, is the last step.
pub open spec fn insert_finishes(st: Option<EnqSt>, dsq: u64) -> bool {
    match st {
        Some(s) => enq_step(s, Op::Insert { dsq }) == Some(EnqSt::Done),
        None => false,
    }
}

// ---------------------------------------------------------------------
// dispatch

pub struct StealCtx {
    pub cpu: int,
    pub cap: int,
    pub next: int,
}

/// The dispatch automaton. The own queue first; a move ends it. Then the
/// guard: the own word from free to scanning, and if that does not take,
/// a task is on its way and the dispatch ends without stealing. Then the
/// scan, every other CPU in order: its word, its queue count only if the
/// word said busy, a move only if the count was positive; a move takes
/// the victim's word from promised to free, in case the task taken was
/// its promise, and ends the dispatch. A scan past the last CPU writes
/// the own word free again and ends.
pub enum DspSt {
    Start,
    Own,
    Guarded,
    Scan(StealCtx),
    Busy(StealCtx),
    Loaded(StealCtx),
    Stole(StealCtx),
    Done,
}

pub open spec fn after(x: StealCtx, c: int) -> StealCtx {
    StealCtx { cpu: x.cpu, cap: x.cap, next: c + 1 }
}

/// The next CPU the scan must read, skipping its own; `cap` when done.
pub open spec fn skip_own(x: StealCtx) -> int {
    if x.next == x.cpu { x.next + 1 } else { x.next }
}

pub open spec fn dsp_step(cpu: int, st: DspSt, op: Op) -> Option<DspSt> {
    match st {
        // an own-queue hit ends the dispatch; the word is not touched, the
        // promise it may carry is fulfilled when the task runs
        DspSt::Start => match op {
            Op::MoveToLocal { dsq, moved } => if dsq as int == cpu {
                if moved { Some(DspSt::Done) } else { Some(DspSt::Own) }
            } else { None },
            _ => None,
        },
        // the guard; a CPU past the policy's cap has no word and stops here
        DspSt::Own => match op {
            Op::Scan { slot, ok } => if slot as int == cpu && cpu < max_cpus() {
                if ok { Some(DspSt::Guarded) } else { Some(DspSt::Done) }
            } else { None },
            _ => None,
        },
        DspSt::Guarded => match op {
            Op::NrCpuIds { nr } => Some(DspSt::Scan(StealCtx { cpu, cap: cap_of(nr), next: 0 })),
            _ => None,
        },
        DspSt::Scan(x) => {
            let c = skip_own(x);
            if c >= x.cap {
                // nothing found: the own word goes free again
                match op {
                    Op::SetFree { slot } => if slot as int == cpu { Some(DspSt::Done) } else { None },
                    _ => None,
                }
            } else {
                match op {
                    // the word first, of the next CPU in order
                    Op::IsBusy { slot, busy } => if slot as int == c {
                        if busy { Some(DspSt::Busy(StealCtx { cpu: x.cpu, cap: x.cap, next: c })) }
                        else { Some(DspSt::Scan(after(x, c))) }
                    } else { None },
                    _ => None,
                }
            }
        },
        DspSt::Busy(x) => match op {
            Op::NrQueued { dsq, n } => if dsq as int == x.next {
                if n > 0 { Some(DspSt::Loaded(x)) } else { Some(DspSt::Scan(after(x, x.next))) }
            } else { None },
            _ => None,
        },
        DspSt::Loaded(x) => match op {
            Op::MoveToLocal { dsq, moved } => if dsq as int == x.next {
                if moved { Some(DspSt::Stole(x)) } else { Some(DspSt::Scan(after(x, x.next))) }
            } else { None },
            _ => None,
        },
        // the task taken may have been the victim's promise
        DspSt::Stole(x) => match op {
            Op::Unpromise { slot } => if slot as int == x.next { Some(DspSt::Done) } else { None },
            _ => None,
        },
        DspSt::Done => None,
    }
}

pub open spec fn dsp_run(cpu: int, ops: Seq<Op>) -> Option<DspSt>
    decreases ops.len(),
{
    if ops.len() == 0 {
        Some(DspSt::Start)
    } else {
        match dsp_run(cpu, ops.drop_last()) {
            Some(st) => dsp_step(cpu, st, ops.last()),
            None => None,
        }
    }
}

pub broadcast proof fn lemma_dsp_run_push(cpu: int, ops: Seq<Op>, op: Op)
    ensures
        #[trigger] dsp_run(cpu, ops.push(op)) == match dsp_run(cpu, ops) {
            Some(st) => dsp_step(cpu, st, op),
            None => None,
        },
{
    assert(ops.push(op).drop_last() =~= ops);
}

/// Done, or stopped at the guard on a CPU past the policy's cap, which
/// has no word to guard with.
pub open spec fn dsp_accepts(cpu: int, st: DspSt) -> bool {
    match st {
        DspSt::Done => true,
        DspSt::Own => cpu >= max_cpus(),
        _ => false,
    }
}

pub open spec fn dispatch_ok(cpu: int, before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && match dsp_run(cpu, tail_of(before, after)) {
        Some(st) => dsp_accepts(cpu, st),
        None => false,
    }
}

/// The CPU a scan by `cpu` reads when its counter stands at `c`: `c`, or
/// `c + 1` when `c` is its own.
pub open spec fn want(cpu: int, c: int) -> int {
    if c == cpu { c + 1 } else { c }
}

/// The shape of `dispatch`'s loop invariant: mid-scan, every CPU below
/// `c` read, `want(cpu, c)` the next to read.
pub open spec fn scanning(cpu: int, cap: int, c: int, st: Option<DspSt>) -> bool {
    match st {
        Some(DspSt::Scan(x)) => x.cpu == cpu && x.cap == cap && skip_own(x) == want(cpu, c),
        _ => false,
    }
}

// ---------------------------------------------------------------------
// update_idle, dequeue, running, stopping, select_cpu

/// `update_idle` on idle entry: read the count; if there is work, claim
/// the own bit; if the claim succeeded, kick self. Nothing else, and
/// nothing at all on idle exit.
pub open spec fn update_idle_ok(cpu: int, idle: bool, before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && {
        let t = tail_of(before, after);
        if !idle {
            t.len() == 0
        } else {
            &&& t.len() >= 1
            &&& t[0] is CountLoad
            &&& (if t[0]->CountLoad_count == 0 {
                    t.len() == 1
                } else if t.len() >= 2 && t[1] == (Op::TestAndClearIdle { cpu: cpu as i32, was: false }) {
                    t.len() == 2
                } else {
                    t.len() == 3
                    && t[1] == (Op::TestAndClearIdle { cpu: cpu as i32, was: true })
                    && t[2] == (Op::Kick { cpu: cpu as i32 })
                })
        }
    }
}

/// `dequeue`: the count comes down, once.
pub open spec fn dequeue_ok(before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && tail_of(before, after) == seq![Op::CountDec]
}

/// `running` and `stopping`: the word of the task's CPU is written busy,
/// or free.
pub open spec fn busy_ok(busy: bool, before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && {
        let t = tail_of(before, after);
        &&& t.len() >= 1
        &&& t[0] is TaskCpu
        &&& (if (t[0]->TaskCpu_cpu as int) < max_cpus() {
                t.len() == 2
                && t[1] == (if busy { Op::SetBusy { slot: t[0]->TaskCpu_cpu as usize } }
                            else { Op::SetFree { slot: t[0]->TaskCpu_cpu as usize } })
            } else {
                t.len() == 1
            })
    }
}

/// `select_cpu`: no claim and no dispatch; the placement is `enqueue`'s.
pub open spec fn select_cpu_ok(before: Seq<Op>, after: Seq<Op>) -> bool {
    after == before
}

/// What a policy's proof needs: pushing an op commutes with the prefix
/// split, and one op steps each automaton.
pub broadcast group group_refine {
    lemma_skip_push,
    lemma_take_push,
    lemma_take_all,
    lemma_skip_all,
    lemma_enq_run_push,
    lemma_dsp_run_push,
}

} // verus!
