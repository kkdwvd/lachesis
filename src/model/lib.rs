// SPDX-License-Identifier: GPL-2.0
//! `lachesis_model` -- the concurrent work-conservation model, and its
//! proof.
//!
//! This crate is ghost only. It models the sched_ext event model at one
//! transition per shared-variable access, running the per-CPU-queue
//! policy in `src/sched/bpf/main.rs`, and proves that policy work
//! conserving in the sense of Lepers et al. (Ipanema, EuroSys 2020),
//! restated for sched_ext in roadmap section 5.4. `src/tla/Lachesis.tla`
//! is the same model in TLA+, under the same action names, and TLC checks
//! it and five weakened variants; the two are kept in step by hand.
//!
//! The shape of the model, and the kernel object behind each variable:
//!
//! * `loc[t]`: where task `t` is. `Blocked`; `Inflight(c)`, assigned to
//!   CPU `c` by `select_cpu` but on no queue yet; `Queued(c)`, on `c`'s
//!   user DSQ; `Running(c)`.
//! * `ev[t]`: the phase of `t`'s wake event. `Placing`, the target is
//!   chosen and `ops.enqueue` has not run; `Checking(i)`, the count is
//!   published and `enqueue`'s idle search is at bit `i`; `Landing(k, q)`,
//!   the callback is done, the insert into queue `q` has not landed, and a
//!   kick for CPU `k` (`n` for none) is delivered with the landing.
//! * `nr_queued`: the policy's published count of queued and in-flight
//!   work, bumped first thing in `enqueue`, taken down when a queued task
//!   is consumed (`ops.dequeue`).
//! * `phase[c]`: what CPU `c` is doing. `Running`; `Dispatch`, the
//!   own-queue move; `Steal(j)`, reading queue `j`'s count; `StealMove(j)`,
//!   moving from it with `c`'s own rq lock dropped; `IdleSet`, about to set
//!   the idle bit; `IdleCheck`, `update_idle` reading the count; `Halted`.
//! * `idle_bit[c]`, `kicked[c]`: the kernel's idle mask and a pending
//!   reschedule.
//! * `lk[c]`: `c`'s rq lock -- free, held by `c`'s own scheduling event
//!   from block or kick-wake through idle entry, or held by the enqueue
//!   path of a task assigned to `c`. Ipanema's per-core lock.
//!
//! What is proved. Ipanema's concurrent work conservation says: at the
//! end of an event, if some core is overloaded, then no core is idle,
//! with three relaxations -- U(c) excuses a core a concurrent placement is
//! filling, B(c) a core a concurrent block emptied, E(c) a core with an
//! event still in progress. For this design a stronger statement holds at
//! every state and needs only E: call a CPU *stuck* when it is halted with
//! its idle bit set and no kick pending, which is the one way a CPU can be
//! idle with nothing about to move it; then while any CPU is stuck, no CPU
//! is overloaded ([`cwc`]). The reason is the interlock: a CPU becomes
//! stuck only by reading a zero count after setting its bit, every later
//! placement publishes before it scans and so sees the bit, and a
//! placement that finds an idle CPU files the task on that CPU's queue
//! rather than leaving it on a busy one. B and U never come up, because
//! the placement is decided by an atomic claim at placement time, which is
//! what Ipanema's per-core lock bought the paper. The TLA+ mirror checks
//! both this statement and the paper's, with B and U.
//!
//! What is not modelled: time slices and ticks (a task runs until it
//! blocks), affinity (every task may run anywhere), the kernel's global
//! DSQ fallback, and more than one wakeup of the same task at once. The
//! correspondence between these actions and the callbacks is by
//! construction and by reading; phase 5's refinement is what will make it
//! checked.

#![no_std]
#![allow(unused_imports)]

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;

// Ghost only: the erased pass compiles an empty crate.
#[cfg(verus_keep_ghost)]
pub mod refine;

#[cfg(verus_keep_ghost)]
pub mod cwc {

use vstd::prelude::*;
use vstd::set_lib::{lemma_int_range, set_int_range};

verus! {

broadcast use vstd::set::group_set_lemmas;

pub enum Loc {
    Blocked,
    Inflight(int),
    Queued(int),
    Running(int),
}

/// `Checking(i, ks)`: the idle search is at bit `i` and has claimed the
/// CPUs in `ks`. `Landing(ks, q, hit)`: kicks for `ks` go out with the
/// landing, the task lands on queue `q`, and `hit` says a claim chose `q`.
pub enum Ev {
    Idle,
    Placing,
    Checking(int, Set<int>),
    Landing(Set<int>, int, bool),
}

pub enum Phase {
    Running,
    Dispatch,
    Steal(int),
    StealMove(int),
    IdleSet,
    IdleCheck,
    Halted,
}

pub enum Lk {
    Free,
    Sched,
    Enq(int),
}

pub struct State {
    pub n: int,
    pub tasks: Set<int>,
    pub loc: Map<int, Loc>,
    pub ev: Map<int, Ev>,
    pub nr_queued: int,
    pub phase: Map<int, Phase>,
    pub idle_bit: Map<int, bool>,
    pub kicked: Map<int, bool>,
    pub lk: Map<int, Lk>,
    pub claimed: Map<int, bool>,
}

// ---------------------------------------------------------------------
// Definitions

pub open spec fn is_cpu(s: State, c: int) -> bool {
    0 <= c < s.n
}

pub open spec fn is_task(s: State, t: int) -> bool {
    s.tasks.contains(t)
}

pub open spec fn cpus(s: State) -> Set<int> {
    set_int_range(0, s.n)
}

/// `t` is on `c`'s user DSQ or running on `c`: what Ipanema's runqueue
/// holds. An in-flight task is invisible, as an unblocking thread is
/// before `unblock_place` adds it.
pub open spec fn assigned(s: State, c: int, t: int) -> bool {
    is_task(s, t) && (s.loc[t] == Loc::Queued(c) || s.loc[t] == Loc::Running(c))
}

pub open spec fn queued_on(s: State, c: int, t: int) -> bool {
    is_task(s, t) && s.loc[t] == Loc::Queued(c)
}

pub open spec fn has_queued(s: State, c: int) -> bool {
    exists|t: int| queued_on(s, c, t)
}

pub open spec fn has_assigned(s: State, c: int) -> bool {
    exists|t: int| assigned(s, c, t)
}

pub open spec fn overloaded(s: State, c: int) -> bool {
    exists|t1: int, t2: int| t1 != t2 && assigned(s, c, t1) && assigned(s, c, t2)
}

pub open spec fn idle(s: State, c: int) -> bool {
    s.phase[c] == Phase::Halted && !has_assigned(s, c)
}

/// Ipanema's E, extended for sched_ext: an event in progress on `c`, a
/// kick pending for `c`, or `c` halted with its idle bit claimed by a
/// placement whose landing will kick it.
pub open spec fn in_event(s: State, c: int) -> bool {
    ||| !(s.phase[c] == Phase::Running || s.phase[c] == Phase::Halted)
    ||| s.kicked[c]
    ||| (s.phase[c] == Phase::Halted && !s.idle_bit[c])
}

/// Halted, advertised idle, nothing pending: the one way to be idle with
/// no event in progress.
pub open spec fn stuck(s: State, c: int) -> bool {
    s.phase[c] == Phase::Halted && s.idle_bit[c] && !s.kicked[c]
}

/// The theorem, in the paper's shape with only E: an idle CPU with no
/// event in progress means no CPU is overloaded. Stronger than the
/// paper's, which needs B and U as well and holds only at event ends.
pub open spec fn cwc(s: State) -> bool {
    forall|c2: int| #[trigger] is_cpu(s, c2) && idle(s, c2) && !in_event(s, c2)
        ==> forall|a: int| #[trigger] is_cpu(s, a) ==> !overloaded(s, a)
}

/// A task the published count stands for: queued, or past the bump of
/// its enqueue and not yet consumed.
pub open spec fn in_count(s: State, t: int) -> bool {
    is_task(s, t) && (s.loc[t] is Queued || s.ev[t] is Checking || s.ev[t] is Landing)
}

pub open spec fn counted(s: State) -> Set<int> {
    s.tasks.filter(|t: int| in_count(s, t))
}

/// The steal scan visits every CPU but `c` in index order.
pub open spec fn first_other(c: int) -> int {
    if c == 0 { 1 } else { 0 }
}

pub open spec fn next_other(c: int, j: int) -> int {
    if j + 1 == c { j + 2 } else { j + 1 }
}

pub open spec fn after_fail(s: State, c: int, j: int) -> Phase {
    if next_other(c, j) >= s.n { Phase::IdleSet } else { Phase::Steal(next_other(c, j)) }
}

// ---------------------------------------------------------------------
// Initial state and actions

pub open spec fn init(s: State) -> bool {
    &&& s.n >= 1
    &&& forall|t: int| #[trigger] is_task(s, t) ==> s.loc[t] == Loc::Blocked && s.ev[t] == Ev::Idle
    &&& s.nr_queued == 0
    &&& forall|c: int| #[trigger] is_cpu(s, c) ==> s.phase[c] == Phase::Halted && s.idle_bit[c]
        && !s.kicked[c] && s.lk[c] == Lk::Free && !s.claimed[c]
}

/// try_to_wake_up: `select_cpu` returns the previous CPU, so the kernel
/// assigns the task to a CPU of its choosing; it is not yet visible.
pub open spec fn wake_start(s: State, s2: State, t: int, c: int) -> bool {
    &&& is_task(s, t) && is_cpu(s, c)
    &&& s.loc[t] == Loc::Blocked
    &&& s2 == State {
        loc: s.loc.insert(t, Loc::Inflight(c)),
        ev: s.ev.insert(t, Ev::Placing),
        ..s
    }
}

/// activate on the assigned CPU: its rq lock is taken and `enqueue`'s
/// first act is to bump the count.
pub open spec fn publish(s: State, s2: State, t: int) -> bool {
    &&& is_task(s, t)
    &&& s.ev[t] == Ev::Placing
    &&& s.loc[t] matches Loc::Inflight(c) && s.lk[c] == Lk::Free
    &&& s2 == State {
        lk: s.lk.insert(s.loc[t]->Inflight_0, Lk::Enq(t)),
        nr_queued: s.nr_queued + 1,
        ev: s.ev.insert(t, Ev::Checking(0, Set::empty())),
        ..s
    }
}

/// `enqueue`'s idle search, one test-and-clear per step. A hit claims that
/// CPU: with an empty queue and no earlier claim outstanding it becomes
/// the destination, else it is kicked for what it has and the search goes
/// on; a scan that misses everywhere files the task on the CPU it was
/// assigned to.
pub open spec fn check_read(s: State, s2: State, t: int) -> bool {
    &&& is_task(s, t)
    &&& s.ev[t] matches Ev::Checking(i, ks)
    &&& s.loc[t] matches Loc::Inflight(c)
    &&& {
        let i = s.ev[t]->Checking_0;
        let ks = s.ev[t]->Checking_1;
        let c = s.loc[t]->Inflight_0;
        if i < s.n && s.idle_bit[i] && !has_queued(s, i) && !s.claimed[i] {
            s2 == State {
                idle_bit: s.idle_bit.insert(i, false),
                claimed: s.claimed.insert(i, true),
                ev: s.ev.insert(t, Ev::Landing(ks.insert(i), i, true)),
                ..s
            }
        } else if i < s.n && s.idle_bit[i] {
            s2 == State {
                idle_bit: s.idle_bit.insert(i, false),
                ev: s.ev.insert(t, Ev::Checking(i + 1, ks.insert(i))),
                ..s
            }
        } else if i < s.n {
            s2 == State { ev: s.ev.insert(t, Ev::Checking(i + 1, ks)), ..s }
        } else {
            s2 == State { ev: s.ev.insert(t, Ev::Landing(ks, c, false)), ..s }
        }
    }
}

/// the deferred insert lands after `enqueue` returned; the kernel
/// reschedules the assigned CPU if it is idle, the rq lock is dropped,
/// and the kicks the callback queued go out. An idle kick to a CPU that
/// is running by now is dropped.
pub open spec fn land(s: State, s2: State, t: int) -> bool {
    &&& is_task(s, t)
    &&& s.ev[t] matches Ev::Landing(ks, q, hit)
    &&& s.loc[t] matches Loc::Inflight(c)
    &&& {
        let ks = s.ev[t]->Landing_0;
        let q = s.ev[t]->Landing_1;
        let c = s.loc[t]->Inflight_0;
        s2 == State {
            loc: s.loc.insert(t, Loc::Queued(q)),
            lk: s.lk.insert(c, Lk::Free),
            kicked: Map::new(
                cpus(s),
                |d: int| if (ks.contains(d) && s.phase[d] != Phase::Running)
                            || (d == c && s.phase[c] == Phase::Halted) { true }
                         else { s.kicked[d] },
            ),
            ev: s.ev.insert(t, Ev::Idle),
            ..s
        }
    }
}

/// the running task blocks: schedule() takes `c`'s rq lock and `c` enters
/// the pick path.
pub open spec fn block(s: State, s2: State, t: int) -> bool {
    &&& is_task(s, t)
    &&& s.loc[t] matches Loc::Running(c) && s.lk[c] == Lk::Free
    &&& {
        let c = s.loc[t]->Running_0;
        s2 == State {
            lk: s.lk.insert(c, Lk::Sched),
            loc: s.loc.insert(t, Loc::Blocked),
            phase: s.phase.insert(c, Phase::Dispatch),
            ..s
        }
    }
}

/// a task starts running on `c` and the rq lock is dropped; `from` is the
/// queue it came off. Consuming from a queue is the dequeue that takes
/// the count back down, and it clears whatever claim was outstanding on
/// that queue.
pub open spec fn run(s: State, s2: State, c: int, t: int, from: int) -> bool {
    s2 == State {
        loc: s.loc.insert(t, Loc::Running(c)),
        nr_queued: s.nr_queued - 1,
        phase: s.phase.insert(c, Phase::Running),
        lk: s.lk.insert(c, Lk::Free),
        claimed: s.claimed.insert(from, false),
        ..s
    }
}

/// balance: `dispatch`'s own-queue move, or on to the steal scan.
pub open spec fn dispatch_own(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] == Phase::Dispatch
    &&& if has_queued(s, c) {
            exists|t: int| queued_on(s, c, t) && #[trigger] run(s, s2, c, t, c)
        } else {
            s2 == State {
                phase: s.phase.insert(c, if first_other(c) >= s.n { Phase::IdleSet }
                                         else { Phase::Steal(first_other(c)) }),
                ..s
            }
        }
}

/// the policy's busy flag for `j` and `scx_bpf_dsq_nr_queued` on queue
/// `j`, both lockless: a task is stolen only from a CPU that is running
/// another, Ipanema's `can_steal_core` taking only from an overloaded
/// core. A hit drops `c`'s own rq lock for the move that follows.
pub open spec fn steal_read(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] matches Phase::Steal(j)
    &&& {
        let j = s.phase[c]->Steal_0;
        if s.phase[j] == Phase::Running && has_queued(s, j) {
            s2 == State {
                phase: s.phase.insert(c, Phase::StealMove(j)),
                lk: s.lk.insert(c, Lk::Free),
                ..s
            }
        } else {
            s2 == State { phase: s.phase.insert(c, after_fail(s, c, j)), ..s }
        }
    }
}

/// `scx_bpf_dsq_move_to_local` from queue `j`: needs `j`'s rq lock and
/// `c`'s own back; the queue may have drained meanwhile.
pub open spec fn steal_move(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] matches Phase::StealMove(j)
    &&& {
        let j = s.phase[c]->StealMove_0;
        &&& s.lk[j] == Lk::Free && s.lk[c] == Lk::Free
        &&& if has_queued(s, j) {
                exists|t: int| queued_on(s, j, t) && #[trigger] run(s, s2, c, t, j)
            } else {
                s2 == State {
                    phase: s.phase.insert(c, after_fail(s, c, j)),
                    lk: s.lk.insert(c, Lk::Sched),
                    ..s
                }
            }
    }
}

/// the kernel sets the idle bit, then calls `update_idle`.
pub open spec fn idle_set(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] == Phase::IdleSet
    &&& s2 == State {
        idle_bit: s.idle_bit.insert(c, true),
        phase: s.phase.insert(c, Phase::IdleCheck),
        ..s
    }
}

/// `update_idle` reads the count and, if there is work, claims its own
/// idle bit and kicks itself; a CPU some enqueue already claimed finds its
/// bit clear and stays put. The CPU halts and its rq lock is dropped.
pub open spec fn idle_check(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] == Phase::IdleCheck
    &&& if s.nr_queued > 0 && s.idle_bit[c] {
            s2 == State {
                kicked: s.kicked.insert(c, true),
                idle_bit: s.idle_bit.insert(c, false),
                phase: s.phase.insert(c, Phase::Halted),
                lk: s.lk.insert(c, Lk::Free),
                ..s
            }
        } else {
            s2 == State {
                phase: s.phase.insert(c, Phase::Halted),
                lk: s.lk.insert(c, Lk::Free),
                ..s
            }
        }
}

/// a kicked idle CPU comes back through balance.
pub open spec fn kick_wake(s: State, s2: State, c: int) -> bool {
    &&& is_cpu(s, c)
    &&& s.phase[c] == Phase::Halted && s.kicked[c] && s.lk[c] == Lk::Free
    &&& s2 == State {
        lk: s.lk.insert(c, Lk::Sched),
        kicked: s.kicked.insert(c, false),
        idle_bit: s.idle_bit.insert(c, false),
        phase: s.phase.insert(c, Phase::Dispatch),
        ..s
    }
}

pub open spec fn next(s: State, s2: State) -> bool {
    ||| exists|t: int, c: int| wake_start(s, s2, t, c)
    ||| exists|t: int| publish(s, s2, t)
    ||| exists|t: int| check_read(s, s2, t)
    ||| exists|t: int| land(s, s2, t)
    ||| exists|t: int| block(s, s2, t)
    ||| exists|c: int| dispatch_own(s, s2, c)
    ||| exists|c: int| steal_read(s, s2, c)
    ||| exists|c: int| steal_move(s, s2, c)
    ||| exists|c: int| idle_set(s, s2, c)
    ||| exists|c: int| idle_check(s, s2, c)
    ||| exists|c: int| kick_wake(s, s2, c)
}

// ---------------------------------------------------------------------
// The inductive invariant

/// Every index a task or CPU names is in range.
pub open spec fn wf(s: State) -> bool {
    &&& s.n >= 1
    &&& forall|t: int| #[trigger] is_task(s, t) ==> match s.loc[t] {
            Loc::Blocked => true,
            Loc::Inflight(c) => is_cpu(s, c),
            Loc::Queued(c) => is_cpu(s, c),
            Loc::Running(c) => is_cpu(s, c),
        }
    &&& forall|t: int| #[trigger] is_task(s, t) ==> match s.ev[t] {
            Ev::Idle => true,
            Ev::Placing => true,
            Ev::Checking(i, ks) => 0 <= i <= s.n,
            Ev::Landing(ks, q, hit) => is_cpu(s, q),
        }
    &&& forall|c: int| #[trigger] is_cpu(s, c) ==> match s.phase[c] {
            Phase::Steal(j) => is_cpu(s, j) && j != c,
            Phase::StealMove(j) => is_cpu(s, j) && j != c,
            _ => true,
        }
}

pub open spec fn sched_locked(p: Phase) -> bool {
    p == Phase::Dispatch || p is Steal || p == Phase::IdleSet || p == Phase::IdleCheck
}

/// A task has a wake event in progress exactly while it is in flight; the
/// rq locks are held by whom the kernel says; a CPU is in phase Running
/// exactly when one task runs on it.
pub open spec fn structure(s: State) -> bool {
    &&& forall|t: int| #[trigger] is_task(s, t) ==> (s.ev[t] != Ev::Idle <==> s.loc[t] is Inflight)
    &&& forall|c: int| #[trigger] is_cpu(s, c) ==> (s.lk[c] == Lk::Sched <==> sched_locked(s.phase[c]))
    &&& forall|c: int| #[trigger] is_cpu(s, c) ==> match s.lk[c] {
            Lk::Enq(t) => is_task(s, t) && s.loc[t] == Loc::Inflight(c)
                && (s.ev[t] is Checking || s.ev[t] is Landing),
            _ => true,
        }
    &&& forall|t: int| #[trigger] is_task(s, t) && (s.ev[t] is Checking || s.ev[t] is Landing)
            ==> s.lk[s.loc[t]->Inflight_0] == Lk::Enq(t)
    &&& forall|c: int| #[trigger] is_cpu(s, c) ==>
            (s.phase[c] == Phase::Running <==>
                exists|t: int| #[trigger] is_task(s, t) && s.loc[t] == Loc::Running(c))
    &&& forall|t1: int, t2: int|
            #[trigger] is_task(s, t1) && #[trigger] is_task(s, t2) && t1 != t2
            && s.loc[t1] is Running && s.loc[t2] is Running
            ==> s.loc[t1]->Running_0 != s.loc[t2]->Running_0
    &&& forall|c: int| #[trigger] is_cpu(s, c) && s.idle_bit[c] ==>
            s.phase[c] == Phase::IdleCheck || s.phase[c] == Phase::Halted
}

/// What a stuck CPU tells about everyone else: nothing is overloaded;
/// every pending landing is a claim onto a CPU with nothing assigned, its
/// claim mark still up, and no other landing headed the same way; every
/// scan in progress has not passed the stuck CPU's bit; no queued task
/// sits on a CPU that is running; and a CPU mid-steal has nothing
/// assigned and nothing headed for it.
pub open spec fn stuck_impl(s: State, c: int) -> bool {
    &&& forall|a: int| #[trigger] is_cpu(s, a) ==> !overloaded(s, a)
    &&& forall|t: int| #[trigger] is_task(s, t) ==> match s.ev[t] {
            Ev::Landing(ks, q, hit) => hit && !has_assigned(s, q) && s.claimed[q],
            Ev::Checking(i, ks) => i <= c,
            _ => true,
        }
    &&& forall|t1: int, t2: int| #[trigger] is_task(s, t1) && #[trigger] is_task(s, t2)
            && t1 != t2 && s.ev[t1] is Landing && s.ev[t2] is Landing
            ==> s.ev[t1]->Landing_1 != s.ev[t2]->Landing_1
    &&& forall|t: int, q: int| #[trigger] queued_on(s, q, t) ==> s.phase[q] != Phase::Running
    &&& forall|d: int| #[trigger] is_cpu(s, d) && s.phase[d] is StealMove ==>
            !has_assigned(s, d)
            && forall|t: int| #[trigger] is_task(s, t) && s.ev[t] is Landing
                ==> s.ev[t]->Landing_1 != d
}

pub open spec fn inv(s: State) -> bool {
    &&& wf(s)
    &&& structure(s)
    &&& s.nr_queued == counted(s).len()
    &&& forall|c: int| #[trigger] is_cpu(s, c) && stuck(s, c) ==> stuck_impl(s, c)
}

// ---------------------------------------------------------------------
// Proofs

/// A counted task makes the count positive: the fact `idle_check` turns on.
proof fn lemma_count_pos(s: State, t: int)
    requires inv(s), in_count(s, t),
    ensures s.nr_queued >= 1,
{
    assert(counted(s).contains(t));
    assert(counted(s).remove(t).len() == counted(s).len() - 1);
}

/// A zero count means nothing is queued or in flight past the bump.
proof fn lemma_count_zero(s: State)
    requires inv(s), s.nr_queued == 0,
    ensures forall|t: int| !in_count(s, t),
{
    assert forall|t: int| !in_count(s, t) by {
        if in_count(s, t) {
            lemma_count_pos(s, t);
        }
    }
}

/// The count follows one task changing status, and nothing else.
proof fn lemma_count_same(s: State, s2: State)
    requires
        s2.tasks == s.tasks,
        forall|t: int| is_task(s, t) ==> (in_count(s2, t) <==> in_count(s, t)),
    ensures counted(s2) == counted(s),
{
    assert(counted(s2) =~= counted(s));
}

proof fn lemma_count_add(s: State, s2: State, t: int)
    requires
        s2.tasks == s.tasks, is_task(s, t), !in_count(s, t), in_count(s2, t),
        forall|u: int| is_task(s, u) && u != t ==> (in_count(s2, u) <==> in_count(s, u)),
    ensures counted(s2).len() == counted(s).len() + 1,
{
    assert(counted(s2) =~= counted(s).insert(t));
}

proof fn lemma_count_sub(s: State, s2: State, t: int)
    requires
        s2.tasks == s.tasks, is_task(s, t), in_count(s, t), !in_count(s2, t),
        forall|u: int| is_task(s, u) && u != t ==> (in_count(s2, u) <==> in_count(s, u)),
    ensures counted(s2).len() == counted(s).len() - 1,
{
    assert(counted(s2) =~= counted(s).remove(t));
}

proof fn lemma_init(s: State)
    requires init(s),
    ensures inv(s),
{
    assert(counted(s) =~= Set::<int>::empty());
    assert forall|c: int| #[trigger] is_cpu(s, c) && stuck(s, c) implies stuck_impl(s, c) by {
        assert forall|a: int| #[trigger] is_cpu(s, a) implies !overloaded(s, a) by {
            if overloaded(s, a) {
                let (t1, t2) = choose|t1: int, t2: int|
                    t1 != t2 && assigned(s, a, t1) && assigned(s, a, t2);
                assert(is_task(s, t1));
            }
        }
    }
}

proof fn lemma_inv_cwc(s: State)
    requires inv(s),
    ensures cwc(s),
{
    assert forall|c2: int| #[trigger] is_cpu(s, c2) && idle(s, c2) && !in_event(s, c2)
        implies forall|a: int| #[trigger] is_cpu(s, a) ==> !overloaded(s, a) by {
        assert(stuck(s, c2));
    }
}


// ---- small helpers -------------------------------------------------------

proof fn lemma_overload_same(s: State, s2: State, a: int)
    requires
        forall|u: int| #[trigger] assigned(s2, a, u) ==> assigned(s, a, u),
        !overloaded(s, a),
    ensures !overloaded(s2, a),
{
    if overloaded(s2, a) {
        let (t1, t2) = choose|t1: int, t2: int|
            t1 != t2 && assigned(s2, a, t1) && assigned(s2, a, t2);
        assert(overloaded(s, a));
    }
}

proof fn lemma_overload_single(s2: State, a: int, t: int)
    requires forall|u: int| #[trigger] assigned(s2, a, u) ==> u == t,
    ensures !overloaded(s2, a),
{
    if overloaded(s2, a) {
        let (t1, t2) = choose|t1: int, t2: int|
            t1 != t2 && assigned(s2, a, t1) && assigned(s2, a, t2);
    }
}

proof fn lemma_no_assigned_same(s: State, s2: State, q: int)
    requires
        forall|u: int| #[trigger] assigned(s2, q, u) ==> assigned(s, q, u),
        !has_assigned(s, q),
    ensures !has_assigned(s2, q),
{
    if has_assigned(s2, q) {
        let u = choose|u: int| assigned(s2, q, u);
        assert(assigned(s, q, u));
    }
}

/// Without a running task there is no task in `Running(c)`.
proof fn lemma_no_runner(s: State, c: int)
    requires inv(s), is_cpu(s, c), s.phase[c] != Phase::Running,
    ensures forall|u: int| is_task(s, u) ==> s.loc[u] != Loc::Running(c),
{
    assert forall|u: int| is_task(s, u) implies s.loc[u] != Loc::Running(c) by {
        if s.loc[u] == Loc::Running(c) {
            assert(exists|t: int| #[trigger] is_task(s, t) && s.loc[t] == Loc::Running(c));
        }
    }
}

/// A stuck CPU in the successor of a step that neither halts a CPU nor
/// sets a bit nor clears a kick was stuck before it too.
proof fn lemma_stuck_back(s: State, s2: State, c: int)
    requires
        is_cpu(s, c), stuck(s2, c),
        s2.phase[c] == s.phase[c], s2.idle_bit[c] ==> s.idle_bit[c], s.kicked[c] ==> s2.kicked[c],
    ensures stuck(s, c),
{
}

// ---- one lemma per action -------------------------------------------------

proof fn lemma_wake_start(s: State, s2: State, t: int, c: int)
    requires inv(s), wake_start(s, s2, t, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
    assert forall|a: int, u: int| #[trigger] assigned(s, a, u) implies assigned(s2, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

proof fn lemma_publish(s: State, s2: State, t: int)
    requires inv(s), publish(s, s2, t),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    let c = s.loc[t]->Inflight_0;
    assert forall|u: int| is_task(s, u) && u != t implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_add(s, s2, t);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
    assert forall|a: int, u: int| #[trigger] assigned(s, a, u) implies assigned(s2, a, u) by {}
    // nobody else held c's lock as an enqueue, so no other in-flight task
    // on c was checking or landing
    assert forall|u: int| #[trigger] is_task(s, u) && u != t
        && (s.ev[u] is Checking || s.ev[u] is Landing) implies s.loc[u]->Inflight_0 != c by {
        if s.loc[u]->Inflight_0 == c {
            assert(s.lk[c] == Lk::Enq(u));
        }
    }
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

proof fn lemma_check_read(s: State, s2: State, t: int)
    requires inv(s), check_read(s, s2, t),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    let i = s.ev[t]->Checking_0;
    let ks = s.ev[t]->Checking_1;
    let c = s.loc[t]->Inflight_0;
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
    assert forall|a: int, u: int| #[trigger] assigned(s, a, u) implies assigned(s2, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
        if i < s.n && s.idle_bit[i] {
            assert(is_cpu(s, i));
            // the bit at i went down, so the stuck CPU is not i
            assert(c2 != i);
            if !has_queued(s, i) && !s.claimed[i] {
                // the hit: i has nothing assigned, no queued by the branch and
                // no runner because its bit was up
                lemma_no_runner(s, i);
                assert(!has_assigned(s2, i)) by {
                    if has_assigned(s2, i) {
                        let u = choose|u: int| assigned(s2, i, u);
                        assert(queued_on(s, i, u));
                    }
                }
                // no other landing was headed for i: its mark was down
                assert forall|u: int| #[trigger] is_task(s, u) && u != t && s.ev[u] is Landing
                    implies s.ev[u]->Landing_1 != i by {
                    if s.ev[u]->Landing_1 == i {
                        assert(s.claimed[i]);
                    }
                }
            }
        }
    }
}

proof fn lemma_land(s: State, s2: State, t: int)
    requires inv(s), land(s, s2, t),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) && u != t implies queued_on(s, q, u) by {}
    let ks = s.ev[t]->Landing_0;
    let q = s.ev[t]->Landing_1;
    let hit = s.ev[t]->Landing_2;
    let c = s.loc[t]->Inflight_0;
    lemma_int_range(0, s.n);
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert(s.lk[c] == Lk::Enq(t));
    // no other in-flight task on c was checking or landing
    assert forall|u: int| #[trigger] is_task(s, u) && u != t
        && (s.ev[u] is Checking || s.ev[u] is Landing) implies s.loc[u]->Inflight_0 != c by {
        if s.loc[u]->Inflight_0 == c {
            assert(s.lk[c] == Lk::Enq(u));
        }
    }
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) && !(u == t && a == q)
        implies assigned(s, a, u) by {}
    assert forall|a: int, u: int| #[trigger] assigned(s, a, u) implies assigned(s2, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        assert(!s2.kicked[c2]);
        assert(s2.kicked[c2] == (if (ks.contains(c2) && s.phase[c2] != Phase::Running)
            || (c2 == c && s.phase[c] == Phase::Halted) { true } else { s.kicked[c2] }));
        lemma_stuck_back(s, s2, c2);
        // the landing was a claim onto an empty q with its mark up
        assert(hit && !has_assigned(s, q) && s.claimed[q]);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            if a == q {
                assert forall|u: int| #[trigger] assigned(s2, q, u) implies u == t by {
                    if u != t {
                        assert(assigned(s, q, u));
                    }
                }
                lemma_overload_single(s2, q, t);
            } else {
                assert forall|u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
                lemma_overload_same(s, s2, a);
            }
        }
        // no other pending landing is headed for q, so q is the only CPU
        // whose assigned set grew
        assert forall|u: int| #[trigger] is_task(s2, u) && u != t && s2.ev[u] is Landing
            implies s2.ev[u]->Landing_1 != q by {}
        assert forall|d: int| d != q && !has_assigned(s, d) implies !has_assigned(s2, d) by {
            if has_assigned(s2, d) {
                let u = choose|u: int| assigned(s2, d, u);
                assert(assigned(s, d, u));
            }
        }
        // q has no runner, so the queued t does not sit on a running CPU
        assert(is_cpu(s, q));
        assert(s.phase[q] != Phase::Running) by {
            if s.phase[q] == Phase::Running {
                let u = choose|u: int| #[trigger] is_task(s, u) && s.loc[u] == Loc::Running(q);
                assert(assigned(s, q, u));
            }
        }
        lemma_no_runner(s, q);
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            assert(d != q);
        }
    }
}

proof fn lemma_block(s: State, s2: State, t: int)
    requires inv(s), block(s, s2, t),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    let c = s.loc[t]->Running_0;
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    // t was the only runner on c
    assert forall|u: int| is_task(s2, u) implies s2.loc[u] != Loc::Running(c) by {
        if s2.loc[u] == Loc::Running(c) {
            assert(u != t);
            assert(s.loc[u] == Loc::Running(c));
        }
    }
    assert forall|u: int| #[trigger] is_task(s, u)
        && (s.ev[u] is Checking || s.ev[u] is Landing) implies s.loc[u]->Inflight_0 != c by {
        if s.loc[u]->Inflight_0 == c {
            assert(s.lk[c] == Lk::Enq(u));
        }
    }
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

/// The common part of the two consumes: `t`, queued on `from`, starts
/// running on `c`, which was in `Dispatch` (own queue) or `StealMove`.
proof fn lemma_run(s: State, s2: State, c: int, t: int, from: int)
    requires
        inv(s), run(s, s2, c, t, from), is_cpu(s, c), queued_on(s, from, t),
        s.phase[c] == Phase::Dispatch && from == c
            || s.phase[c] is StealMove && from == s.phase[c]->StealMove_0
                && s.lk[c] == Lk::Free && s.lk[from] == Lk::Free,
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    lemma_no_runner(s, c);
    assert(s.ev[t] == Ev::Idle);
    assert forall|u: int| is_task(s, u) && u != t implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_sub(s, s2, t);
    assert forall|u: int| #[trigger] is_task(s, u)
        && (s.ev[u] is Checking || s.ev[u] is Landing) implies s.loc[u]->Inflight_0 != c by {
        if s.loc[u]->Inflight_0 == c {
            assert(s.lk[c] == Lk::Enq(u));
        }
    }
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) && !(u == t && a == c)
        implies assigned(s, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        // before the move c had at most t assigned: nothing at all if it
        // was stealing, and only t if it was serving its own queue
        assert(is_cpu(s, from));
        assert(assigned(s, from, t));
        assert forall|u: int| #[trigger] assigned(s, c, u) implies u == t by {
            if u != t {
                if from == c {
                    assert(assigned(s, c, t));
                    assert(overloaded(s, c));
                } else {
                    assert(has_assigned(s, c));
                }
            }
        }
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            if a == c {
                assert forall|u: int| #[trigger] assigned(s2, c, u) implies u == t by {
                    if u != t {
                        assert(assigned(s, c, u));
                    }
                }
                lemma_overload_single(s2, c, t);
            } else {
                assert forall|u: int| #[trigger] assigned(s2, a, u) implies assigned(s, a, u) by {}
                lemma_overload_same(s, s2, a);
            }
        }
        // no pending landing was headed for c (its queue held t) nor for
        // from (its queue held t too)
        assert forall|u: int| #[trigger] is_task(s, u) && s.ev[u] is Landing
            implies s.ev[u]->Landing_1 != c && s.ev[u]->Landing_1 != from by {
            if s.ev[u]->Landing_1 == from {
                assert(assigned(s, from, t));
            }
        }
        assert forall|d: int| d != c && !has_assigned(s, d) implies !has_assigned(s2, d) by {
            if has_assigned(s2, d) {
                let u = choose|u: int| assigned(s2, d, u);
                assert(assigned(s, d, u));
            }
        }
        assert forall|u: int, q: int| #[trigger] queued_on(s2, q, u) implies s2.phase[q] != Phase::Running by {
            assert(queued_on(s, q, u));
            if q == c {
                assert(assigned(s, c, u));
            }
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            assert(d != c);
        }
    }
}

proof fn lemma_dispatch_own(s: State, s2: State, c: int)
    requires inv(s), dispatch_own(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    if has_queued(s, c) {
        let t = choose|t: int| queued_on(s, c, t) && #[trigger] run(s, s2, c, t, c);
        lemma_run(s, s2, c, t, c);
    } else {
        assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
        lemma_count_same(s, s2);
        assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
        assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
            lemma_stuck_back(s, s2, c2);
            assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
                lemma_overload_same(s, s2, a);
            }
            assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
                lemma_no_assigned_same(s, s2, q);
            }
            assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
                implies !has_assigned(s2, d) by {
                lemma_no_assigned_same(s, s2, d);
            }
        }
    }
}

proof fn lemma_steal_read(s: State, s2: State, c: int)
    requires inv(s), steal_read(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    let j = s.phase[c]->Steal_0;
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        if s.phase[j] == Phase::Running && has_queued(s, j) {
            // a running CPU with a queued task: impossible while stuck
            let u = choose|u: int| queued_on(s, j, u);
            assert(false);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

proof fn lemma_steal_move(s: State, s2: State, c: int)
    requires inv(s), steal_move(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    let j = s.phase[c]->StealMove_0;
    if has_queued(s, j) {
        let t = choose|t: int| queued_on(s, j, t) && #[trigger] run(s, s2, c, t, j);
        lemma_run(s, s2, c, t, j);
    } else {
        assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
        lemma_count_same(s, s2);
        assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
        assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
            lemma_stuck_back(s, s2, c2);
            assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
                lemma_overload_same(s, s2, a);
            }
            assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
                lemma_no_assigned_same(s, s2, q);
            }
            assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
                implies !has_assigned(s2, d) by {
                lemma_no_assigned_same(s, s2, d);
            }
        }
    }
}

proof fn lemma_idle_set(s: State, s2: State, c: int)
    requires inv(s), idle_set(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        assert(c2 != c);
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

proof fn lemma_idle_check(s: State, s2: State, c: int)
    requires inv(s), idle_check(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        if c2 == c {
            // c halts stuck only when it read a zero count with its bit up
            assert(!(s.nr_queued > 0 && s.idle_bit[c]));
            assert(s.idle_bit[c]);
            assert(s.nr_queued == 0);
            lemma_count_zero(s);
            assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
                if overloaded(s2, a) {
                    let (t1, t2) = choose|t1: int, t2: int|
                        t1 != t2 && assigned(s2, a, t1) && assigned(s2, a, t2);
                    assert(!in_count(s, t1) && !in_count(s, t2));
                    assert(s.loc[t1] == Loc::Running(a) && s.loc[t2] == Loc::Running(a));
                }
            }
            assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
                implies !has_assigned(s2, d) by {
                if has_assigned(s2, d) {
                    let u = choose|u: int| assigned(s2, d, u);
                    assert(!in_count(s, u));
                    assert(s.loc[u] == Loc::Running(d));
                    assert(exists|t: int| #[trigger] is_task(s, t) && s.loc[t] == Loc::Running(d));
                }
            }
        } else {
            lemma_stuck_back(s, s2, c2);
            assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
                lemma_overload_same(s, s2, a);
            }
            assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
                lemma_no_assigned_same(s, s2, q);
            }
            assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
                implies !has_assigned(s2, d) by {
                lemma_no_assigned_same(s, s2, d);
            }
        }
    }
}

proof fn lemma_kick_wake(s: State, s2: State, c: int)
    requires inv(s), kick_wake(s, s2, c),
    ensures inv(s2),
{
    // Bridge the two states for the quantifier triggers: every task and
    // CPU of the successor is one of the predecessor's.
    assert forall|u: int| #[trigger] is_task(s2, u) implies is_task(s, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s2, d) implies is_cpu(s, d) by {}
    assert forall|u: int| #[trigger] is_task(s, u) implies is_task(s2, u) by {}
    assert forall|d: int| #[trigger] is_cpu(s, d) implies is_cpu(s2, d) by {}
    assert forall|q: int, u: int| #[trigger] queued_on(s2, q, u) implies queued_on(s, q, u) by {}
    assert forall|u: int| is_task(s, u) implies (in_count(s2, u) <==> in_count(s, u)) by {}
    lemma_count_same(s, s2);
    assert forall|a: int, u: int| #[trigger] assigned(s2, a, u) <==> assigned(s, a, u) by {}
    assert forall|u: int| #[trigger] is_task(s, u)
        && (s.ev[u] is Checking || s.ev[u] is Landing) implies s.loc[u]->Inflight_0 != c by {
        if s.loc[u]->Inflight_0 == c {
            assert(s.lk[c] == Lk::Enq(u));
        }
    }
    assert forall|c2: int| #[trigger] is_cpu(s2, c2) && stuck(s2, c2) implies stuck_impl(s2, c2) by {
        assert(c2 != c);
        lemma_stuck_back(s, s2, c2);
        assert forall|a: int| #[trigger] is_cpu(s2, a) implies !overloaded(s2, a) by {
            lemma_overload_same(s, s2, a);
        }
        assert forall|q: int| !has_assigned(s, q) implies !has_assigned(s2, q) by {
            lemma_no_assigned_same(s, s2, q);
        }
        assert forall|d: int| #[trigger] is_cpu(s2, d) && s2.phase[d] is StealMove
            implies !has_assigned(s2, d) by {
            lemma_no_assigned_same(s, s2, d);
        }
    }
}

// ---- the theorem -----------------------------------------------------------

pub proof fn lemma_next_inv(s: State, s2: State)
    requires inv(s), next(s, s2),
    ensures inv(s2),
{
    if exists|t: int, c: int| wake_start(s, s2, t, c) {
        let (t, c) = choose|t: int, c: int| wake_start(s, s2, t, c);
        lemma_wake_start(s, s2, t, c);
    } else if exists|t: int| publish(s, s2, t) {
        lemma_publish(s, s2, choose|t: int| publish(s, s2, t));
    } else if exists|t: int| check_read(s, s2, t) {
        lemma_check_read(s, s2, choose|t: int| check_read(s, s2, t));
    } else if exists|t: int| land(s, s2, t) {
        lemma_land(s, s2, choose|t: int| land(s, s2, t));
    } else if exists|t: int| block(s, s2, t) {
        lemma_block(s, s2, choose|t: int| block(s, s2, t));
    } else if exists|c: int| dispatch_own(s, s2, c) {
        lemma_dispatch_own(s, s2, choose|c: int| dispatch_own(s, s2, c));
    } else if exists|c: int| steal_read(s, s2, c) {
        lemma_steal_read(s, s2, choose|c: int| steal_read(s, s2, c));
    } else if exists|c: int| steal_move(s, s2, c) {
        lemma_steal_move(s, s2, choose|c: int| steal_move(s, s2, c));
    } else if exists|c: int| idle_set(s, s2, c) {
        lemma_idle_set(s, s2, choose|c: int| idle_set(s, s2, c));
    } else if exists|c: int| idle_check(s, s2, c) {
        lemma_idle_check(s, s2, choose|c: int| idle_check(s, s2, c));
    } else {
        lemma_kick_wake(s, s2, choose|c: int| kick_wake(s, s2, c));
    }
}

/// An execution: a sequence of states that starts in `init` and steps by
/// `next`. Every state in it satisfies the invariant, and so the theorem.
pub open spec fn execution(ex: Seq<State>) -> bool {
    &&& ex.len() > 0
    &&& init(ex[0])
    &&& forall|i: int| 0 <= i && i + 1 < ex.len() ==> #[trigger] next(ex[i], ex[i + 1])
}

pub proof fn theorem_inv(ex: Seq<State>, i: int)
    requires execution(ex), 0 <= i < ex.len(),
    ensures inv(ex[i]),
    decreases i,
{
    if i == 0 {
        lemma_init(ex[0]);
    } else {
        theorem_inv(ex, i - 1);
        assert(next(ex[i - 1], ex[(i - 1) + 1]));
        lemma_next_inv(ex[i - 1], ex[i]);
    }
}

/// Concurrent work conservation: in every state of every execution, an
/// idle CPU with no event in progress means no CPU is overloaded.
pub proof fn theorem_cwc(ex: Seq<State>)
    requires execution(ex),
    ensures forall|i: int| 0 <= i < ex.len() ==> cwc(#[trigger] ex[i]),
{
    assert forall|i: int| 0 <= i < ex.len() implies cwc(#[trigger] ex[i]) by {
        theorem_inv(ex, i);
        lemma_inv_cwc(ex[i]);
    }
}
} // verus!

} // mod cwc
