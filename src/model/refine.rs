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
//! first claimed CPU whose queue was empty and whose mark was down, and on
//! the assigned CPU only after the search ran out; steal only from a CPU
//! that is running a task, scanning every CPU in order until a move
//! succeeds; read the count and claim the own bit before a self-kick;
//! never dispatch from `select_cpu`. A policy that skips one of these --
//! CFS's domain-local placement, its give-up-after-the-first-candidate
//! balancing, a scheduler that steals from an idle CPU's queue or direct
//! dispatches to a local DSQ -- cannot drive the automaton to `Done`, and
//! Verus rejects the callback. `src/sched/bpf/mutants/` holds those
//! variants and the build checks that each is rejected.
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
    pub rounds: int,
}

pub enum EnqSt {
    Start,
    Cpu(int),
    Ready(EnqCtx),
    Published(EnqCtx),
    Claimed(EnqCtx, int),
    Kicked(EnqCtx, int),
    Empty(EnqCtx, int),
    Marked(EnqCtx, int),
    Fallback(EnqCtx),
    Done,
}

pub open spec fn bump(x: EnqCtx) -> EnqCtx {
    EnqCtx { cpu: x.cpu, cap: x.cap, rounds: x.rounds + 1 }
}

/// From a published state: the next round of the idle search, or the
/// insert on the assigned CPU once the search has run its full length.
pub open spec fn published_step(x: EnqCtx, op: Op) -> Option<EnqSt> {
    match op {
        Op::SelectDfl { cpu, idle } => if idle { Some(EnqSt::Claimed(x, cpu as int)) }
                                      else { Some(EnqSt::Fallback(x)) },
        Op::Insert { dsq } => if x.rounds >= x.cap && dsq as int == x.cpu { Some(EnqSt::Done) } else { None },
        _ => None,
    }
}

/// One op moves the enqueue automaton, or breaks the protocol (`None`).
pub open spec fn enq_step(st: EnqSt, op: Op) -> Option<EnqSt> {
    match st {
        EnqSt::Start => match op {
            Op::TaskCpu { cpu } => Some(EnqSt::Cpu(cpu as int)),
            _ => None,
        },
        EnqSt::Cpu(c) => match op {
            Op::NrCpuIds { nr } => Some(EnqSt::Ready(EnqCtx { cpu: c, cap: cap_of(nr), rounds: 0 })),
            _ => None,
        },
        EnqSt::Ready(x) => match op {
            // a CPU the policy has no queue for: the kernel's fallback, uncounted
            Op::Insert { dsq } => if x.cpu >= x.cap && dsq == global_dsq() { Some(EnqSt::Done) } else { None },
            // publish before anything else
            Op::CountInc => if x.cpu < x.cap { Some(EnqSt::Published(x)) } else { None },
            _ => None,
        },
        EnqSt::Published(x) => published_step(x, op),
        // a claimed CPU is kicked, whatever else happens to it; one beyond
        // the policy's queues is only kicked, and the search goes on
        EnqSt::Claimed(x, k) => match op {
            Op::Kick { cpu } => if cpu as int != k { None }
                                else if k >= x.cap { Some(EnqSt::Published(bump(x))) }
                                else { Some(EnqSt::Kicked(x, k)) },
            _ => None,
        },
        EnqSt::Kicked(x, k) => match op {
            Op::NrQueued { dsq, n } => if dsq as int == k {
                if n > 0 { Some(EnqSt::Published(bump(x))) } else { Some(EnqSt::Empty(x, k)) }
            } else { None },
            _ => None,
        },
        EnqSt::Empty(x, k) => match op {
            Op::Claim { slot, was } => if slot as int == k {
                if was { Some(EnqSt::Published(bump(x))) } else { Some(EnqSt::Marked(x, k)) }
            } else { None },
            _ => None,
        },
        EnqSt::Marked(x, k) => match op {
            Op::Insert { dsq } => if dsq as int == k { Some(EnqSt::Done) } else { None },
            _ => None,
        },
        EnqSt::Fallback(x) => match op {
            Op::Insert { dsq } => if dsq as int == x.cpu { Some(EnqSt::Done) } else { None },
            _ => None,
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

/// The shape of `enqueue`'s loop invariant: `rounds` rounds of the idle
/// search done, none of them a placement.
pub open spec fn searching(cpu: int, cap: int, rounds: int, st: Option<EnqSt>) -> bool {
    st == Some(EnqSt::Published(EnqCtx { cpu, cap, rounds }))
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

pub enum DspSt {
    Start,
    Own,
    Served,
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
        DspSt::Start => match op {
            Op::MoveToLocal { dsq, moved } => if dsq as int == cpu {
                if !moved { Some(DspSt::Own) }
                // a CPU past the policy's cap has no mark to clear
                else if cpu < max_cpus() { Some(DspSt::Served) }
                else { Some(DspSt::Done) }
            } else { None },
            _ => None,
        },
        // an own-queue hit clears the claim mark and ends the dispatch
        DspSt::Served => match op {
            Op::Unclaim { slot } => if slot as int == cpu { Some(DspSt::Done) } else { None },
            _ => None,
        },
        DspSt::Own => match op {
            Op::NrCpuIds { nr } => Some(DspSt::Scan(StealCtx { cpu, cap: cap_of(nr), next: 0 })),
            _ => None,
        },
        DspSt::Scan(x) => {
            let c = skip_own(x);
            if c >= x.cap {
                None
            } else {
                match op {
                    // the busy flag first, of the next CPU in order
                    Op::BusyGet { slot, busy } => if slot as int == c {
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
        DspSt::Stole(x) => match op {
            Op::Unclaim { slot } => if slot as int == x.next { Some(DspSt::Done) } else { None },
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

/// A scan that ran out of CPUs is done: the steal was exhaustive.
pub open spec fn dsp_accepts(st: DspSt) -> bool {
    match st {
        DspSt::Done => true,
        DspSt::Scan(x) => skip_own(x) >= x.cap,
        _ => false,
    }
}

pub open spec fn dispatch_ok(cpu: int, before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && match dsp_run(cpu, tail_of(before, after)) {
        Some(st) => dsp_accepts(st),
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

/// `running` and `stopping`: the busy flag of the task's CPU follows.
pub open spec fn busy_ok(busy: bool, before: Seq<Op>, after: Seq<Op>) -> bool {
    extends(before, after) && {
        let t = tail_of(before, after);
        &&& t.len() >= 1
        &&& t[0] is TaskCpu
        &&& (if (t[0]->TaskCpu_cpu as int) < max_cpus() {
                t.len() == 2
                && t[1] == (Op::BusySet { slot: t[0]->TaskCpu_cpu as usize, busy: busy })
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
