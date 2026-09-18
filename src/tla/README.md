# The TLA+ mirror of the work-conservation model

`Lachesis.tla` is the sched_ext event model of roadmap section 5.4, running
the per-CPU-queue policy in `src/sched/bpf/main.rs`, at one transition per
shared-variable access. It mirrors the Verus model in `src/model/lib.rs`
under the same action names; the two are kept in step by hand, and this
one exists to find counterexamples in seconds and to check the paper's own
definition, with its B and U relaxations, which the Verus proof does not
need.

What is modelled: tasks that block and wake; `select_cpu` returning the
previous CPU; `enqueue` publishing the count, running the idle search one
test-and-clear at a time, claiming, filing and kicking; the insert landing
after the callback; block, balance, the busy-only steal with the mover's
own rq lock dropped, idle entry, `update_idle` claiming its own bit, and
the kick-wake; the per-CPU rq lock with the kernel's hold pattern; the
policy's busy and claimed marks. Not modelled: slices and ticks, affinity,
the global DSQ fallback.

Three properties are checked. `CWC` is Ipanema's concurrent work
conservation, evaluated at the end of every event through the ghost sets
`B` and `U` and the extended `E`. `WCStrong` is the stronger statement the
Verus proof establishes: while any CPU is stuck (halted, idle bit up, no
kick pending) no CPU is overloaded, at every state. `KickResolves`, under
fairness on everything but a task blocking, strong for the three steps
that take an rq lock, since a lock holder's release enables them only
intermittently, and weak for the rest, is the discharge of E: a pending
kick ends with the CPU running something or with nothing overloaded
anywhere.

Configurations: `pos_*` must pass; each `neg_*` weakens the policy by one
constant and must report a violation. `neg_no_steal` violates
`KickResolves` rather than `CWC`, because a CPU that keeps kicking itself
is never idle in the definition's sense; that is why E needs the liveness
argument. `neg_local_select` needs two tasks with the same home CPU, which
`Prev` derives from the task number, so its tasks are 1 and 3.
`tol_first_only` is Ipanema's CFS balancing bug -- a steal that gives up
after its first candidate turns out empty -- and it must *pass*: the
idle-side count check sends the CPU straight back into dispatch, so in
this design the exhaustive scan is a matter of liveness and efficiency,
not of safety, which the paper's setting without an idle-side check could
not afford. `pos_3x2` is the long one, hours on this host, and is last.

Run `make` here, or `make tlc` at the repository root. TLA+ tools 1.7.4
are fetched into `build/tla/` on first use, the last release that runs on
this host's Java 8; TLC's state files go there too.
