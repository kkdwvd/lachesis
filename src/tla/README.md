# The TLA+ mirror of the work-conservation model

`Lachesis.tla` is the sched_ext event model of roadmap section 5.4,
running the per-CPU-queue policy in `src/sched/bpf/main.rs`, at one
transition per shared-variable access: every kfunc call and every access
to the policy's per-CPU word is its own step, which is the granularity of
the code and of the receipt log the policy is verified against. It
mirrors the Verus model in `src/model/lib.rs` under the same action
names; the two are kept in step by hand, and this one exists to find
counterexamples in seconds and to check the paper's own definition, with
its B and U relaxations, which the Verus proof does not need.

What is modelled: tasks that block, wake and, when `TICKS` is on, have
their slice expire; `select_cpu` returning the previous CPU; `enqueue`
publishing the count, the kernel's idle search probing CPUs in any order
and claiming the first bit it finds up, the claim's queue read and the
compare-and-swap of its word, the policy's own scan of every bit when the
claim did not take, the landing after the callback with its kicks; block,
balance, the guard of the own word, the busy-only steal with the mover's
own rq lock dropped and the victim's word reset, idle entry, `update_idle`
reading the count and claiming its own bit, and the kick-wake; the per-CPU
rq lock with the kernel's hold pattern; the word itself, free, promised,
busy or scanning. Not modelled: affinity, kernel dequeues that are not
consumptions, and the global DSQ fallback; roadmap section 7.4 lists every
gap between the models and the kernel.

Three properties are checked. `CWC` is Ipanema's concurrent work
conservation, evaluated at the end of every event through the ghost sets
`B` and `U` and the extended `E`. `WCStrong` is the stronger statement the
Verus proof establishes: while any CPU is stuck (halted, idle bit up, no
kick pending) no CPU is overloaded, at every state. `KickResolves`, under
fairness on everything but a task blocking, strong for the steps that
take an rq lock and weak for the rest, is the discharge of E: a pending
kick ends with the CPU running something or with nothing overloaded
anywhere.

Constants beyond the sizes: `NoTask` is a model value; `TICKS` enables
slice expiry; `FIXED_HOME` assigns every task to `Prev(t)`, which cuts the
state space for directed three-CPU checks; the five `NO_*`, `FIRST_ONLY`
and `LOCAL_SELECT` flags each weaken the policy in one way.

Configurations. `make` runs `all`: `pos_2x2`, `pos_2x3` and `pos_2x2_live`
must pass; `neg_no_enq_kick`, `neg_no_idle_kick` and `neg_local_select`
must violate `CWC`, and `neg_no_steal` must violate `KickResolves` -- it
runs without ticks, because with slices even a policy that never steals
is eventually work conserving, one slice at a time, as the expired task
goes back through `enqueue`. The negatives check `CWC` only, since the
stronger invariant can fail earlier and hide the paper's violation.
`neg_local_select` needs two tasks with the same home CPU, which `Prev`
derives from the task number, so its tasks are 1 and 3. `make long` runs
the three-CPU configurations. `pos_3x3h` and `pos_3x3b`, homes 0, 0, 2
and 0, 1, 2 with no ticks, are the checks that found two of the races
below and stay as regressions. `tol_first_only` is a steal that gives up
after its first candidate, Ipanema's CFS balancing bug, and it must pass:
the idle-side count check sends the CPU straight back into dispatch, so
in this design the exhaustive scan is a matter of liveness and
efficiency, not of safety. At two CPUs that variant is indistinguishable
from the policy, since the scan has only one other CPU to visit; an
earlier version of this suite ran it at two CPUs and concluded nothing.
`pos_3x2` is the unconstrained three-CPU run, hours on this host.

What this model found once it took one shared access per step, each
closed in the policy and each kept as a rejected variant in
`src/sched/bpf/mutants/`: a claim mark that the consumer cleared let an
enqueue holding a stale claim on a CPU's idle bit file behind the task
that CPU had just picked up (`pos_3x3h`, 30 steps); a second kernel
search after a failed claim can return a CPU the enqueue already claimed,
so no retry bound reaches an idle CPU whose bit stays up (by analysis,
`pos_3x3b` is the directed check); and a CPU that reads a victim busy and
its queue non-empty can be promised a task in between, and would run the
stolen one with the promised one queued behind it (by analysis; four
tasks are needed to reach it).

Run `make` here, or `make tlc` at the repository root. TLA+ tools 1.7.4
are fetched into `build/tla/` on first use, the last release that runs on
this host's Java 8; TLC's state files go there too.
