// SPDX-License-Identifier: GPL-2.0
//
// lachesis: a virtual-time scheduler over one shared DSQ.
//
// Policy only. Every kfunc binding, kernel view, atomic, trampoline,
// section name and the panic handler live in lachesis_runtime_trusted; the
// contracts the callbacks below are checked against live in lachesis_runtime's
// Policy trait. What is left here is the scheduling decisions, and Verus
// checks them: the impl is inside verus! and inherits the trait's
// contracts, so calling charge_vtime with a weight that could be zero is a
// verification error rather than a division by zero in the kernel.
//
// Derived from 4ast/rust-bpf's scx_simple.rs, without its FIFO mode: this
// scheduler is vtime-only and will grow into the soft-partition policy.

#![no_std]
#![no_main]

use lachesis_runtime::prelude::*;

verus! {

/// The one user DSQ, ordered by virtual time; every CPU consumes from it.
const SHARED_DSQ: u64 = 0;

/// Counter slots, in `bpftool map dump` order.
const LOCAL: usize = 0;
const GLOBAL: usize = 1;
const DISPATCH: usize = 2;

/// The global virtual clock -- the vtime of the most recent task to run --
/// the counters, and what the kernel last ejected the scheduler for.
///
/// The whole struct is the object's `.bss`, so the loader reads every field
/// of it back through the object's BTF.
pub struct Lachesis {
    vtime_now: AtomicU64,
    stats: Stats<3>,
    exit_kind: AtomicU64,
    exit_code: AtomicU64,
}

impl Policy for Lachesis {
    /// Take the kernel's idle-core pick. If it found an idle CPU, put the
    /// task straight on that CPU's local DSQ and skip the shared queue.
    fn select_cpu(&self, p: Task, prev_cpu: i32, wake_flags: u64) -> i32 {
        let (cpu, is_idle) = scx::select_cpu_dfl(&p, prev_cpu, wake_flags);
        if is_idle {
            self.stats.inc(LOCAL);
            scx::dsq_insert(&p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        }
        cpu
    }

    /// Queue by virtual time, clamped so an idling task cannot bank more
    /// than one slice of budget against the tasks that stayed runnable.
    fn enqueue(&self, p: Task, enq_flags: u64) {
        self.stats.inc(GLOBAL);
        let vtime = clamp_vtime(p.vtime(), self.vtime_now.load(), SCX_SLICE_DFL);
        scx::dsq_insert_vtime(&p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
    }

    fn dispatch(&self, _cpu: i32, _prev: Option<Task>) {
        self.stats.inc(DISPATCH);
        scx::dsq_move_to_local(SHARED_DSQ);
    }

    /// The global clock only moves forward, to the vtime of whatever runs.
    fn running(&self, p: Task) {
        let vtime = p.vtime();
        if vtime_before(self.vtime_now.load(), vtime) {
            self.vtime_now.store(vtime);
        }
    }

    /// Charge the time actually consumed, scaled by weight so a heavier
    /// task advances its vtime more slowly and is picked again sooner.
    fn stopping(&self, p: Task, _runnable: bool) {
        p.set_vtime(charge_vtime(p.vtime(), p.slice(), SCX_SLICE_DFL, p.weight()));
    }

    /// A task joining the scheduler starts at the current global vtime.
    fn enable(&self, p: Task) {
        p.set_vtime(self.vtime_now.load());
    }

    fn init(&self) -> i32 {
        scx::create_dsq(SHARED_DSQ, -1)
    }

    /// Record why the kernel is taking the scheduler away, so the loader can
    /// name it after the link is gone. `exit_code` is stored first: the
    /// loader treats a non-zero `exit_kind` as "both fields are set", and
    /// `SCX_EXIT_NONE` is zero.
    fn exit(&self, ei: &ExitInfo) {
        self.exit_code.store(ei.exit_code());
        self.exit_kind.store(ei.kind() as u64);
    }
}

} // verus!

scheduler! {
    map: lachesis_ops,
    name: "lachesis",
    policy: LACHESIS: Lachesis = Lachesis {
        vtime_now: AtomicU64::new(0),
        stats: Stats::new(),
        exit_kind: AtomicU64::new(0),
        exit_code: AtomicU64::new(0),
    },
    ops {
        select_cpu as lachesis_select_cpu,
        enqueue as lachesis_enqueue,
        dispatch as lachesis_dispatch,
        running as lachesis_running,
        stopping as lachesis_stopping,
        enable as lachesis_enable,
        exit as lachesis_exit,
    }
    sleepable {
        init as lachesis_init,
    }
}
