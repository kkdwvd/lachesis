// SPDX-License-Identifier: GPL-2.0
//
// lachesis: per-CPU virtual-time queues, exhaustive idle stealing, and a
// two-sided idle interlock.
//
// This is the scheduler that phase 3a's concurrent work-conservation
// theorem is about (roadmap section 5.4), and its four mechanisms are the
// Ipanema handlers that theorem was first proved against:
//
//   * one user DSQ per CPU, ids `0 ..< nr_cpu_ids`: the per-core runqueue.
//     Every wakeup goes through one of them. `select_cpu` only returns the
//     previous CPU; the placement happens in `enqueue`, after the count
//     below is published, and a wakeup that finds an idle CPU is filed on
//     that CPU's queue -- Ipanema's `unblock_place`, choosing the core at
//     placement time. A task on a per-CPU user DSQ can be stolen, which
//     one on a local DSQ cannot: a direct dispatch that lands after its
//     CPU was kicked into stealing something else would be a bubble
//     nobody can fix, the model found that trace, and the fast path went;
//   * `dispatch` drains its own queue and otherwise scans every other CPU
//     and steals from the first that is running a task and has another
//     queued, going on to the next when the move fails because the queue
//     drained meanwhile -- Ipanema's `steal_for`, with the exhaustive loop
//     CFS lacks and with `can_steal_core` taking only from an overloaded
//     core: a task queued on an idle CPU is about to be run by that CPU,
//     which has been kicked for it, and stealing it away is what let a
//     concurrent placement land behind a stolen task in the model. The
//     "running a task" bit is the policy's own, set by `running` and
//     cleared by `stopping`;
//   * `enqueue` publishes the task first -- it bumps a count of queued
//     and in-flight work before it does anything else -- and only then runs
//     the kernel's idle search, filing the task on the CPU it claims and
//     kicking it, or on the task's own CPU if none is idle: the enqueue
//     side of the interlock. A claimed CPU whose queue is already
//     non-empty is kicked for that work and the search goes on: a task can
//     land on a CPU's queue between that CPU's failed dispatch and its
//     idle bit going up, because filing on another CPU's queue takes no
//     lock of that CPU, and a second task behind it would wait out a
//     slice while a third CPU idles. The count is what gets published rather than
//     the DSQ insert because an insert requested from `ops.enqueue` is only
//     marked there and lands after the callback returns, so the DSQ itself
//     is not visible in time; `dequeue`, which the kernel calls exactly
//     once when custody ends, takes the count back down. Ipanema's `cload`
//     has the same shape: bumped before the thread is added, exact once it
//     is;
//   * `update_idle` runs after the kernel has set this CPU's idle bit,
//     reads that count and, if it is non-zero, claims its own idle bit and
//     kicks itself: the idle side. Either the enqueue sees the bit or the
//     idle CPU sees the count; `__scx_update_idle()` in the kernel
//     documents that ordering, and `SCX_OPS_KEEP_BUILTIN_IDLE` is what
//     keeps the kernel's idle tracking alive while this callback exists.
//     The claim is what keeps a CPU that an enqueue has already picked
//     from going off to steal something else while that task is on its
//     way: it finds its bit clear and waits for the kick that comes with
//     the landing.
//
// Policy only. Every kfunc binding, kernel view, atomic, trampoline,
// section name and the panic handler live in lachesis_runtime_trusted; the
// contracts the callbacks below are checked against live in
// lachesis_runtime's Policy trait. The model the theorem is proved over is
// lachesis_model, verified in the same pass; each callback here is one of
// its actions, spelled out for the kernel, and phase 5's refinement is what
// will make that correspondence checked rather than read.

#![no_std]
#![no_main]

use lachesis_runtime::prelude::*;

verus! {

broadcast use refine::group_refine;

/// The most CPUs this policy attaches to. Per-CPU queue ids are the CPU
/// numbers, so they never collide with the kernel's builtin DSQs, whose
/// ids all have the top bit set; `init` refuses a larger machine rather
/// than queue for CPUs it cannot name.
const MAX_CPUS: u32 = 64;

/// `-E2BIG`, what `init` returns for a machine with more CPUs than that.
const E2BIG: i32 = 7;

/// Counter slots, in `bpftool map dump` order.
const PLACE_IDLE: usize = 0;
const PLACE_BUSY: usize = 1;
const OWN: usize = 2;
const STEAL: usize = 3;
const KICK_IDLE: usize = 4;
const IDLE: usize = 5;
const FALLBACK: usize = 6;

/// The global virtual clock -- the vtime of the most recent task to run --
/// the published count of queued and in-flight work, the counters, and
/// what the kernel last ejected the scheduler for.
///
/// The whole struct is the object's `.bss`, so the loader reads every field
/// of it back through the object's BTF. `nr_queued` is the number of tasks
/// `enqueue` has taken custody of and `dequeue` has not yet released: the
/// tasks on the per-CPU queues plus those whose insert has not landed yet,
/// so it never undercounts. The counters, in order: tasks `enqueue` filed
/// on an idle CPU's queue and kicked it for; tasks it filed on their own,
/// busy CPU's queue; dispatches served from the CPU's own queue;
/// dispatches served by stealing; kicks `update_idle` sent to itself;
/// dispatches that found nothing anywhere; tasks sent to the kernel's
/// global DSQ because their CPU has no queue.
pub struct Lachesis {
    vtime_now: AtomicU64,
    nr_queued: Counter,
    stats: Stats<7>,
    exit_kind: AtomicU64,
    exit_code: AtomicU64,
    /// Per CPU: a task is running there right now. Published for the
    /// steal scan; the loader does not print it.
    busy: Busy<64>,
    /// Per CPU: an enqueue has claimed it and filed a task for its queue
    /// that nobody has consumed yet. Set by the claimer, cleared by
    /// whoever consumes from that queue; a second claimer that finds it
    /// set kicks the CPU and looks on. Not printed either.
    claimed: Claims<64>,
}

/// The number of per-CPU queues, which is the number of possible CPUs
/// capped at the largest this policy attaches to. `init` refuses to attach
/// above the cap, so after a successful attach the cap never binds; it is
/// here so that every loop below has a bound Verus and the BPF verifier
/// can both see.
fn nr_cpus(log: &mut Log) -> (r: u32)
    ensures
        1 <= r <= MAX_CPUS,
        exists|m: u32| final(log).ops@ == old(log).ops@.push(Op::NrCpuIds { nr: m })
            && r as int == refine::cap_of(m),
{
    let n = scx::nr_cpu_ids(log);
    let r = if n < MAX_CPUS { n } else { MAX_CPUS };
    proof {
        // The witness for the postcondition's `exists`: what was read.
        assert(log.ops@ == old(log).ops@.push(Op::NrCpuIds { nr: n }) && r as int == refine::cap_of(n));
    }
    r
}

impl Policy for Lachesis {
    /// Stay on the previous CPU; the placement is `enqueue`'s. This
    /// callback exists only so that the kernel does not run its own
    /// default, which direct-dispatches to a local DSQ when it finds an
    /// idle CPU and skips `enqueue` altogether: see the header for the
    /// bubble that opens.
    fn select_cpu(&self, _p: Task, prev_cpu: i32, _wake_flags: u64, _log: &mut Log) -> i32 {
        prev_cpu
    }

    /// Publish, place, file, kick. The count goes up first, because the
    /// insert below is only marked here and lands after this callback
    /// returns; the count is the one thing an idle CPU can see in time.
    /// Then the kernel's idle search, repeated while it keeps finding idle
    /// CPUs: each hit claims that CPU and kicks it; the first whose queue
    /// is empty takes the task, one that already has work queued is left
    /// to run that, and a search that finds nothing files the task on the
    /// CPU it woke on. Either way by virtual time, clamped so an idling
    /// task cannot bank more than one slice of budget against the tasks
    /// that stayed runnable. This is the enqueue side of the interlock: a
    /// CPU that went idle while this ran has either not set its idle bit
    /// yet, in which case its `update_idle` will read the count after this
    /// bump, or has, in which case the search sees the bit.
    fn enqueue(&self, p: Task, enq_flags: u64, log: &mut Log) {
        let ghost pre = log.ops@;
        let vtime = clamp_vtime(p.vtime(), self.vtime_now.load(), SCX_SLICE_DFL);
        let cpu = scx::task_cpu(&p, log);
        let n = nr_cpus(log);
        if cpu as u32 >= n {
            // Unreachable after a successful `init`, which refuses a
            // machine this policy has no queue for; the global DSQ is the
            // kernel's own fallback, every CPU consumes it, and a task
            // sent there never enters custody, so it is not counted.
            self.stats.inc(FALLBACK);
            scx::dsq_insert_vtime(&p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, vtime, enq_flags, log);
            return;
        }
        self.nr_queued.inc(log);
        let mut q: u32 = cpu as u32;
        let mut placed_idle = false;
        let mut tries: u32 = 0;
        // Each pass claims one more idle CPU, so the search cannot see the
        // same one twice and ends within `n` passes.
        while tries < n
            invariant_except_break
                q == cpu as u32,
                refine::searching(cpu as int, n as int, tries as int,
                                  refine::enq_run(refine::tail_of(pre, log.ops@))),
            invariant
                tries <= n,
                n <= MAX_CPUS,
                q < n,
                cpu >= 0,
                refine::extends(pre, log.ops@),
            ensures
                refine::insert_finishes(refine::enq_run(refine::tail_of(pre, log.ops@)), q as u64),
            decreases n - tries,
        {
            let (target, is_idle) = scx::select_cpu_dfl(&p, cpu, 0, log);
            if !is_idle {
                break;
            }
            // Claimed, so kicked, before anything else is asked of it.
            scx::kick_cpu(target, SCX_KICK_IDLE, log);
            // Ours if it has a queue, its queue is empty and no earlier
            // claim is still waiting to land there; otherwise the kick
            // alone is what it needed, and the search goes on. A CPU
            // beyond the queues cannot come back from the search after a
            // successful `init`; it is kicked all the same.
            if (target as u32) < n
                && scx::dsq_nr_queued(target as u64, log) <= 0
                && !self.claimed.test_and_set(target as usize, log)
            {
                q = target as u32;
                placed_idle = true;
                break;
            }
            tries = tries + 1;
        }
        if placed_idle {
            self.stats.inc(PLACE_IDLE);
        } else {
            self.stats.inc(PLACE_BUSY);
        }
        scx::dsq_insert_vtime(&p, q as u64, SCX_SLICE_DFL, vtime, enq_flags, log);
    }

    /// The task is leaving custody: consumed by a dispatch here or on the
    /// CPU that stole it, or removed by the kernel. Either way it is no
    /// longer queued or in flight, and the count follows.
    fn dequeue(&self, _p: Task, _deq_flags: u64, log: &mut Log) {
        self.nr_queued.dec(log);
    }

    /// Serve this CPU from its own queue, and failing that steal: for
    /// every other CPU that is running a task, read its queue's count and
    /// move the head of the first non-empty one here. A count is stale by
    /// the time the move is attempted, so a failed move continues the scan
    /// instead of ending it; the scan ends idle only when every CPU it
    /// read was not overloaded when read. That is the exhaustiveness the
    /// work-conservation proof needs, and the thing CFS's balancer does
    /// not do; the busy test is Ipanema's `can_steal_core`.
    fn dispatch(&self, cpu: i32, _prev: Option<Task>, log: &mut Log) {
        let ghost pre = log.ops@;
        if scx::dsq_move_to_local(cpu as u64, log) {
            // Whatever an enqueue claimed this CPU for, it is being served.
            // The index is built from the 32-bit value the bound was
            // checked on: the BPF verifier does not carry a bound on a
            // sign-extended `i32` over to the 64-bit index.
            let me = cpu as u32;
            if me < MAX_CPUS {
                self.claimed.clear(me as usize, log);
            }
            self.stats.inc(OWN);
            return;
        }
        let n = nr_cpus(log);
        let mut c: u32 = 0;
        while c < n
            invariant
                c <= n,
                n <= MAX_CPUS,
                cpu >= 0,
                // A loop body is checked on its own, so the return inside
                // has to be told what `pre` is.
                pre == old(log).ops@,
                refine::extends(pre, log.ops@),
                refine::scanning(cpu as int, n as int, c as int,
                                 refine::dsp_run(cpu as int, refine::tail_of(pre, log.ops@))),
            decreases n - c,
        {
            if c != cpu as u32
                && self.busy.get(c as usize, log)
                && scx::dsq_nr_queued(c as u64, log) > 0
                && scx::dsq_move_to_local(c as u64, log)
            {
                // If that was a task an enqueue had filed there for a
                // claim, the claim is served; the mark must not outlive it.
                self.claimed.clear(c as usize, log);
                self.stats.inc(STEAL);
                return;
            }
            c = c + 1;
        }
        self.stats.inc(IDLE);
    }

    /// The global clock only moves forward, to the vtime of whatever runs;
    /// and this CPU is now busy, which is what makes its queue stealable.
    fn running(&self, p: Task, log: &mut Log) {
        let vtime = p.vtime();
        if vtime_before(self.vtime_now.load(), vtime) {
            self.vtime_now.store(vtime);
        }
        let cpu = scx::task_cpu(&p, log) as u32;
        if cpu < MAX_CPUS {
            self.busy.set(cpu as usize, log);
        }
    }

    /// Charge the time actually consumed, scaled by weight so a heavier
    /// task advances its vtime more slowly and is picked again sooner; and
    /// this CPU is no longer running a task, so its queue is its own to
    /// serve until `running` says otherwise.
    fn stopping(&self, p: Task, _runnable: bool, log: &mut Log) {
        p.set_vtime(charge_vtime(p.vtime(), p.slice(), SCX_SLICE_DFL, p.weight()));
        let cpu = scx::task_cpu(&p, log) as u32;
        if cpu < MAX_CPUS {
            self.busy.clear(cpu as usize, log);
        }
    }

    /// A task joining the scheduler starts at the current global vtime.
    fn enable(&self, p: Task, _log: &mut Log) {
        p.set_vtime(self.vtime_now.load());
    }

    /// The idle side of the interlock. The kernel has set this CPU's idle
    /// bit before calling; any enqueue that published before that and then
    /// searched for an idle CPU will find the bit, and any enqueue whose
    /// search missed it published after the bit was set, so the count
    /// read here includes its task. If there is work, claim this CPU's own
    /// bit -- a failed claim means an enqueue got there first, its task is
    /// headed for this queue and its kick comes with the landing, so stay
    /// put -- and kick self, which sends the CPU back through `dispatch`,
    /// where the steal happens. If the task has not landed yet by then,
    /// the CPU comes back here and kicks again, which is why the count and
    /// not the queues is what is read.
    fn update_idle(&self, cpu: i32, idle: bool, log: &mut Log) {
        if idle
            && self.nr_queued.load(log) > 0
            && scx::test_and_clear_cpu_idle(cpu, log)
        {
            self.stats.inc(KICK_IDLE);
            scx::kick_cpu(cpu, SCX_KICK_IDLE, log);
        }
    }

    /// One queue per possible CPU. A machine with more CPUs than this
    /// policy can name is refused, which is what makes the cap in
    /// `nr_cpus` never bind once attached.
    fn init(&self, log: &mut Log) -> i32 {
        let n = scx::nr_cpu_ids(log);
        if n > MAX_CPUS {
            return -E2BIG;
        }
        let mut c: u32 = 0;
        while c < n
            invariant
                c <= n,
                n <= MAX_CPUS,
            decreases n - c,
        {
            let rc = scx::create_dsq(c as u64, -1);
            if rc < 0 {
                return rc;
            }
            c = c + 1;
        }
        0
    }

    /// Record why the kernel is taking the scheduler away, so the loader can
    /// name it after the link is gone. `exit_code` is stored first: the
    /// loader treats a non-zero `exit_kind` as "both fields are set", and
    /// `SCX_EXIT_NONE` is zero.
    fn exit(&self, ei: &ExitInfo, _log: &mut Log) {
        self.exit_code.store(ei.exit_code());
        self.exit_kind.store(ei.kind() as u64);
    }
}

} // verus!

scheduler! {
    map: lachesis_ops,
    name: "lachesis",
    flags: SCX_OPS_KEEP_BUILTIN_IDLE,
    policy: LACHESIS: Lachesis = Lachesis {
        vtime_now: AtomicU64::new(0),
        nr_queued: Counter::new(),
        stats: Stats::new(),
        exit_kind: AtomicU64::new(0),
        exit_code: AtomicU64::new(0),
        busy: Busy::new(),
        claimed: Claims::new(),
    },
    ops {
        select_cpu as lachesis_select_cpu,
        enqueue as lachesis_enqueue,
        dequeue as lachesis_dequeue,
        dispatch as lachesis_dispatch,
        running as lachesis_running,
        stopping as lachesis_stopping,
        enable as lachesis_enable,
        update_idle as lachesis_update_idle,
        exit as lachesis_exit,
    }
    sleepable {
        init as lachesis_init,
    }
}
