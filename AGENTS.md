# AGENTS.md

Repo-wide guidance for agents working in this repository. `CLAUDE.md` is a
symlink to this file so Claude Code loads the same guidance.

## Repository layout

The superproject pins its submodules under `dep/` via gitlinks. In every
submodule, `origin` is the kkdwvd fork.

- `dep/kkd` — personal tooling monorepo (provides `kdev`); branch `main`
  tracks `origin/main`.
- `dep/verus-bpf` — the reusable Verus-to-BPF pipeline; branch `main`
  tracks `origin/main`. It owns the compiler configuration, Verus setup,
  CO-RE tools, verification/build rules, and editor-project generation.
- `dep/verus-bpf/dep/verus` — upstream Verus, pinned by verus-bpf. Its
  `rust-toolchain.toml` selects Rust. Treat this nested checkout as read-only;
  verifier build outputs are ignored upstream. Initialize submodules recursively.

`src/` is reserved for lachesis-native code and `build/` for generated
outputs; `build/` is ignored by git. `ROADMAP.md` is a symlink to the project
roadmap note in `dep/kkd`; read it before planning work and record decisions
in its decision log.

The pipeline is maintained in `dep/verus-bpf`, not under `src/`. Its
`TOOLCHAIN.md` records the rust-bpf import and consumer interface. Do not
add a README.md to verus-bpf. Lachesis owns its kernel selection, ordered
runtime crates, and explicit trust boundaries in `src/sched/Makefile`.

Five verified crates and one that is not. The BPF side is four of them
in dependency order -- `lachesis_runtime_trusted`, `lachesis_model`,
`lachesis_runtime`, then the policy -- each verified and compiled against
the ones before it; the model is ghost only and erases to an empty rlib,
and sits below the runtime because the runtime's `Policy` trait states
its contracts in the model's terms. `lachesis_control` is verified beside
them and imports none of them. The loader is verified by nothing.

- `src/runtime/trusted` — `lachesis_runtime_trusted`, the trusted base,
  and the only place in the tree where `unsafe` or a Verus cheat may
  appear. One module per concern: `kfunc.rs` (the only `extern "C"` block
  in the tree), `scx.rs` (safe wrappers over those kfuncs, their assumed
  contracts, and the kernel constants), `task.rs` (the `#[btf]` CO-RE
  views, the `Task` handle and its accessor specifications), `atomic.rs`
  (an opaque `AtomicU64` with no `Ordering` in its interface), `stats.rs`
  (`Stats<N>`, the `.bss` counters), `panic.rs` (the one
  `#[panic_handler]`), `flags.rs` (`Busy<N>` and `Claims<N>`, per-CPU
  booleans other CPUs read without a lock), `log.rs` (the receipt log:
  the ghost `Op` every wrapper appends, which the refinement contracts
  are stated over) and `ops.rs` (the `scheduler!` macro and its
  trampolines). `atomic.rs` also holds `Counter`, the published count,
  an `AtomicU64` with a role so that the log can name it.
- `src/runtime` — `lachesis_runtime`, the checked layer every scheduler
  links: `policy.rs` (the `Policy` trait, where a callback's contract is
  written down), `vtime.rs` (virtual-time arithmetic) and `lib.rs` with
  the `prelude`. No `unsafe`, no cheats, verified with `--no-cheating`.
  It sits beside `trusted/` and not above it because it is substrate: it
  belongs to no one scheduler.
- `src/model` — `lachesis_model`, the concurrent work-conservation model
  (roadmap section 5.4): the sched_ext event model at one transition per
  shared-variable access, the per-CPU-queue policy's actions under the
  same names, Ipanema's definitions restated for it, the inductive
  invariant and the theorem. `refine.rs` beside it is the refinement
  contracts: for each callback the model has an action for, an automaton
  over the receipts the callback may leave, which the `Policy` trait's
  `ensures` names and the policy proves it drives to the end. Ghost only,
  verified with `--no-cheating`, and a broken proof in it stops the
  object build like every library's does.
  `src/tla/` is its TLA+ mirror under the same action names; `make tlc`
  checks the theorem there, confirms that four weakened variants of the
  policy violate it, and that a fifth, the steal that gives up after its
  first candidate, is tolerated.
- `src/sched` — one scheduler, and everything about it that is verified:
  `bpf/main.rs` the policy, `bpf/mutants/` ten variants of it that the
  contracts must reject, `control/` the crate `lachesis_control`, the
  Makefile stub, and the `vm-run.sh`/`vm-guest.sh` pair that runs the
  whole thing in a VM.
- `src/loader` — `lachesis`, the userspace binary. Unverified by design,
  and its own directory so that the one thing nothing checks is one
  directory and not a file hidden inside a verified tree.

```text
src/
  runtime/         lachesis_runtime; substrate, verified
    trusted/       lachesis_runtime_trusted; assumed, `unsafe` lives here
  model/           lachesis_model; the model, its proof, the contracts
  tla/             the TLA+ mirror of that model; `make tlc`
  sched/           one scheduler
    Makefile       PROG, SRC, KEEP_SYMS, MUTANTS, USER_MANIFEST, USER_CORE_*
    bpf/main.rs    the BPF policy; verified, compiled by rules.mk
    bpf/mutants/   policies Verus must reject; `make verify` checks each
    control/       lachesis_control; verified, compiled by both
    vm-run.sh vm-guest.sh
  loader/          the `lachesis` binary; unverified, compiled by cargo
    Cargo.toml Cargo.lock main.rs
```

A build leaves one artefact at the repository root: `./lachesis`, a
symlink to `build/lachesis/lachesis`. The loader resolves its default
`--obj` through `/proc/self/exe`, which follows the link, so the object it
loads is still the one beside the real binary.

A program directory owns only its sources and a Makefile that sets `PROG`,
optionally `SRC`, `KEEP_SYMS` and the three userspace variables, and then
includes the pipeline:

```make
PROG := lachesis
SRC := bpf/main.rs
KEEP_SYMS := lachesis_ops lachesis_enqueue ... LACHESIS _LICENSE
USER_MANIFEST := ../loader/Cargo.toml
USER_CORE_SRC := control/src/lib.rs
USER_CORE_NAME := lachesis_control
ROOT_DIR := $(abspath ../..)
LLVM_PREFIX ?= $(if $(wildcard /usr/lib/llvm-22/bin/llc),/usr/lib/llvm-22,/usr)
MUTANTS := $(sort $(wildcard bpf/mutants/*.patch))
LIB_CRATES := lachesis_runtime_trusted lachesis_model lachesis_runtime
lachesis_runtime_trusted_DIR := $(ROOT_DIR)/src/runtime/trusted
lachesis_model_DIR := $(ROOT_DIR)/src/model
lachesis_runtime_DIR := $(ROOT_DIR)/src/runtime
NOCHEAT_CRATES := lachesis_model lachesis_runtime
TRUSTED_DIRS := $(lachesis_runtime_trusted_DIR)
include ../../dep/verus-bpf/rules.mk
```

`SRC`, `MUTANTS`, `USER_MANIFEST` and `USER_CORE_SRC` are relative to the
program directory. `KEEP_SYMS` is what `opt` may not internalize: the
struct_ops map, its entry points, the license, and anything userspace
reads back out of the maps, which today means the policy's own static.
`MUTANTS` lists unified diffs against `SRC`: `verify` applies each to a
copy of the policy, runs the policy's own pass on it, and fails unless
Verus rejects it with a verification error -- a mutant that does not
compile is a failure too, because it says nothing about the contracts.
Set `USER_MANIFEST` and the pipeline also builds a binary named `$(PROG)`
out of that cargo project; set `USER_CORE_SRC` and `USER_CORE_NAME` and it
also verifies that crate with `--no-cheating`. The consumer also declares
its crate order, trust boundaries, and target kernel; generic compilation
machinery belongs in verus-bpf.

## Writing a policy

A policy file is policy. It contains no `unsafe`, no `extern`, no
`#[link_section]`, no `#[no_mangle]`, no raw pointers, no `#[btf]` and no
`repr(C)`; `src/sched/bpf/main.rs` is the worked example, under four
hundred lines with its comments. `use lachesis_runtime::prelude::*;`
brings in everything, including the `verus!` macro.

What that policy does, in the mechanisms the work-conservation theorem
is about. One user DSQ per CPU, ids equal to the CPU numbers, created in
`init`, which refuses a machine with more than `MAX_CPUS`. `select_cpu`
returns the previous CPU and nothing else: the placement is `enqueue`'s,
and a task is never direct-dispatched to a local DSQ, because a task there
cannot be stolen. `enqueue` publishes first, bumping `nr_queued`, then
runs the kernel's idle search as often as it finds idle CPUs: each hit is
claimed and kicked; the first whose queue is empty and whose `claimed`
mark is down takes the task and gets the mark; one with work already
queued, or a mark up, is left to that; a search that finds nothing files
the task on the CPU it woke on. `dequeue`, which the kernel calls exactly
once when custody ends, takes the count back down. `dispatch` drains its
own queue and otherwise scans every other CPU, stealing from the first
that is running a task and has another queued, going on to the next when
the move fails; whoever consumes from a queue clears its claim mark.
`running` and `stopping` keep the per-CPU `busy` flag the steal consults.
`update_idle`, which the kernel calls after setting the CPU's idle bit,
reads the count and, if it is non-zero, claims its own bit with a
test-and-clear and kicks self. The publish and the self-claim are the two
sides of the idle interlock: either the enqueue sees the bit or the idle
CPU sees the count. Each of these rules closed a trace the model found,
and `src/model/lib.rs` says which.

The state is a struct and the callbacks are an `impl Policy`, both inside
`verus!`, so Verus checks them:

```rust
verus! {

broadcast use refine::group_refine;

const OWN: usize = 2;

pub struct Lachesis {
    vtime_now: AtomicU64,
    nr_queued: Counter,
    stats: Stats<7>,
    claimed: Claims<64>,
}

impl Policy for Lachesis {
    fn dequeue(&self, _p: Task, _deq_flags: u64, log: &mut Log) {
        self.nr_queued.dec(log);
    }
}

} // verus!
```

Every callback takes `log: &mut Log`, the receipt log. It is ghost: each
trusted wrapper whose effect the model cares about -- the count, the idle
search, a kick, a queue read, a claim, a busy flag, an insert, a move --
appends one `Op` naming the call and what the kernel returned, and in the
erased pass the log is a zero-sized struct. The `Policy` trait's
`ensures` for a callback is a predicate over the ops it appended, stated
in `src/model/refine.rs` as an automaton the ops must drive to its end:
`dequeue`'s says exactly one `CountDec` was appended, which
`Counter::dec` does; `enqueue`'s says the task's CPU and the CPU count
were read, the count published, the idle search run with every claimed
CPU kicked, and one insert made on the right queue; `dispatch`'s says the
own queue was tried first and the scan read every other CPU's busy flag
in order, its queue only when busy, and moved only from a queue that read
non-empty. A callback that does something the contract does not allow, in
an order it does not allow, or stops early, fails to verify. This is how
the policy is checked against the model without being written into it:
the model was proved over these action shapes, and the contracts are
those shapes.

The `Policy` trait in `src/runtime/policy.rs` declares every struct_ops
member a policy may implement, one method per callback. The six the model
has an action for -- `enqueue`, `dequeue`, `dispatch`, `running`,
`stopping`, `update_idle` -- carry a refinement contract and have no
default body, because a do-nothing callback is what the contracts forbid;
the rest have defaults, and `select_cpu`'s contract is that the default
is all it may do. Contracts are declared on the trait and inherited by
the `impl`: Verus rejects a `requires` on a trait method
*implementation*, so each contract is stated in exactly one place and a
policy never quotes one.

A `requires` on a trait method is an assumption about what the kernel
passes in. The `scheduler!` trampolines that call the impl are C-ABI entry
points outside `verus!` and do not check it; the clause states, where a
reader will look for it, what the callback is entitled to rely on, and
phase 5's refinement layer is where those assumptions get discharged
against the kernel model. An `ensures` runs the other way and is checked:
the `impl` must prove it. Preconditions on what a policy *calls* are now
enforced at the call site, which is the point of the impl being inside
`verus!` -- `charge_vtime`'s `1 <= weight` is discharged by `Task::weight()`
returning the kernel's `1 ..= 10000`.

Anything a policy names from inside `verus!` has to be declared inside
`verus!` too, `const`s included; an item outside the macro is external to
Verus and cannot be named from checked code.

A loop in a callback carries an `invariant` and a `decreases`, and Verus
verifies its body in isolation: a fact the body relies on -- the trait's
`cpu >= 0`, say, when the body kicks that CPU, or that the ghost `pre`
taken at the top of the callback is `old(log).ops@`, when the body
returns -- is restated in the invariant or it is not there. The
automaton's state at the loop head is an `invariant_except_break` (the
placement `break` leaves it elsewhere) and what every exit leaves behind
is the loop's `ensures`; `refine::searching` and `refine::scanning` are
those two invariant shapes, so the policy states them in one line each.
Every scan is bounded by the constant `MAX_CPUS`, which is a bound the
BPF verifier can see too; the 64-iteration steal in `dispatch` costs it
about eighty thousand instructions of the million it allows.

`scheduler!` wires the impl to the kernel:

```rust
scheduler! {
    map: lachesis_ops,
    name: "lachesis",
    flags: SCX_OPS_KEEP_BUILTIN_IDLE,
    policy: LACHESIS: Lachesis = Lachesis {
        vtime_now: AtomicU64::new(0),
        stats: Stats::new(),
    },
    ops {
        enqueue as lachesis_enqueue,
        update_idle as lachesis_update_idle,
    }
    sleepable {
        init as lachesis_init,
    }
}
```

`policy:` names the `#[no_mangle]` static holding the one instance of the
policy, its type, and a `const` initializer. The static is emitted outside
`verus!` and handed to every callback as `&self`; `bpftool map dump name
<first 8 chars of the object>.bss` prints the whole of it, counters
included. `flags:` is optional and lands in the ops table's `flags`
member; implementing `update_idle` turns the kernel's idle tracking off
unless `SCX_OPS_KEEP_BUILTIN_IDLE` is passed, and without that tracking
`select_cpu_dfl` stops working. Each `ops` line is "struct_ops member `as` exported program
symbol" and nothing more -- the trait fixes the signature, and
`__trampoline!` in `src/runtime/trusted/ops.rs` has one rule per member
name that knows the context layout. Two names per line is the floor, because
`macro_rules!` cannot mint an identifier. `sleepable` members get a
`struct_ops.s/` section, which the kernel requires for `init`, `init_task`,
`exit_task` and the cgroup callbacks. Counter slots are plain `usize`
consts and `self.stats.inc(GLOBAL)` bumps one; `Stats::inc` requires the
index to be in range and Verus checks it.

Adding a struct_ops member means adding a method to the `Policy` trait and
a rule to `__trampoline!`; an unknown member is a `compile_error!`. A
kernel function a policy needs is declared in
`src/runtime/trusted/kfunc.rs`, given a safe wrapper in
`src/runtime/trusted/scx.rs`, and given its specification on that
wrapper. Never in `lachesis_runtime`, never in a policy, and never a
second `extern` block anywhere.

## The userspace side

`lachesis` is a binary now, not a `bpftool struct_ops register`
invocation. It exists because the link has to be *held*: dropping it
unregisters the scheduler, which is how a dead loader stops being a wedged
machine, and it is the only way to read back the exit information the
kernel reports through `ops.exit`.

Three pieces, and the split between them is the point:

- `src/loader/main.rs`, the loader. Argument parsing, libbpf-rs, `.bss`
  decoding, signals, printing. **Not verified**, and not going to be: its
  dependency graph is libbpf-rs and libc, which Verus has no
  specifications for, and its job is I/O. `unsafe` is allowed here, and
  `lint-trusted` exempts this one directory from the `unsafe` half of the
  lint for exactly that reason (it still applies the cheat half). `make
  verify` prints its line count next to the BPF trusted base, so the size
  of what nothing checks stays visible.
- `src/sched/control/`, the crate `lachesis_control`. **Verified**,
  `#![no_std]`, everything inside `verus!`, checked with `--no-cheating`.
  It is a crate and not a module because Verus verifies crates: keeping it
  separate is what lets it be checked without libbpf-rs in the pass. It
  therefore depends on nothing but the `verus!` macro, taken as a path
  dependency on `dep/verus-bpf/dep/verus`. It lives with the policy, not with the
  loader, because what it is for is being checked in the same pass as the
  BPF side it reads.
- `src/sched/bpf/main.rs`, the policy, unchanged in kind: still the BPF
  side.

`lachesis_control` holds only what is worth proving. A function whose
contract a reader would accept at a glance -- a name table, a wrapping
subtraction, anything about formatting -- belongs in the loader, where the
cost of reading it is nothing and the proof would say nothing. Today the
crate is `classify_exit` and the `ExitClass` it returns, and that is the
whole of it. Adding to it: write the function inside the `verus!` block
with a `requires`/`ensures` that says something a caller could get wrong,
call it from `src/loader/main.rs`, and re-run `make verify`. There is no
wiring to do -- `USER_CORE_SRC` in the Makefile already points at the
crate, `verify` reports it on its own line, and the object build depends
on that pass like it does on the others.

### The binary

```
lachesis [--obj PATH] [--interval SECS] [--duration SECS] [--allow-host]
```

`--obj` defaults to `lachesis.o` beside the executable; the object is
loaded from a path rather than embedded, so the two builds stay
independent. `--interval` is the stats period, `--duration` (default 5
seconds) detaches and exits after that long; `--duration 0` runs until
SIGINT or SIGTERM instead.

**`--allow-host` is the guard.** Without it the binary refuses to attach
unless `/sys/class/dmi/id/sys_vendor` reads `QEMU`, mirroring
`vm-guest.sh`, because attaching displaces whatever sched_ext scheduler the
machine is already running and the development host runs one. It is the
escape hatch for the day this runs on a real host. Nothing in this
repository passes it, and nothing should on this machine.

Every interval the loader reads the `.bss` map -- the one whose name ends
in `.bss`; libbpf names it from the first eight characters of the object
name -- and decodes the policy's static through the object's BTF rather
than by hardcoded offsets: it walks the `.bss` datasec's variables down to
their leaf integers, keeping dotted names, with one simplification, that a
struct with a single member contributes no name of its own. Rust's atomics
are four nested single-field newtypes, so without that every counter would
print as `LACHESIS.stats.counters[0].v.value.__0`. Four leaf names are
special, matched on the last dotted component: `vtime_now` is printed as
the clock, `nr_queued` as a gauge, `exit_kind` and `exit_code` are the
exit report; and the per-CPU arrays `busy` and `claimed` are skipped. Everything else
is a counter and its per-interval delta is printed. Adding a counter to
the policy needs no change to the loader.

### How the exit info flows

`struct scx_exit_info` is a kernel pointer the `ops.exit` callback is
handed, and it is gone by the time anything in userspace could look at it.
So the BPF side copies the two fields that matter into its own static:

1. `src/runtime/trusted/task.rs` declares a `#[btf]` view of `struct
   scx_exit_info` with `kind` and `exit_code`, and two `external_body`
   accessors on
   `ExitInfo` that read them through CO-RE relocated offsets. `kind`'s
   local type is a Rust `enum scx_exit_kind` mirroring the kernel's, not an
   `i32`: libbpf's CO-RE matching compares BTF *kinds*, so an integer
   member would never match an enum member and the object would be
   rejected at load time.
2. `Lachesis::exit` in `bpf/main.rs` stores them into the policy's static,
   `exit_code` first, so that a non-zero `exit_kind` means both are set.
   `SCX_EXIT_NONE` is zero, which is what makes that testable.
3. The loader polls those two leaves every interval. If they become set
   while it still holds the link, the scheduler was ejected: it reports and
   exits non-zero. Otherwise, on SIGINT, SIGTERM or `--duration`, it drops
   the link, waits for the kernel to call `ops.exit` with `SCX_EXIT_UNREG`
   from its disable kthread, reports, and exits zero.
4. `lachesis_control::classify_exit` turns the raw kind into the band it
   belongs to, and that classification is what decides the process exit
   status. It is the one judgement on the userspace side, which is why it
   is the one thing over there that is verified; the loader's
   `exit_kind_name` beside it is only the kernel's own wording for the
   report.

## Submodules

- The gitlinks pin exact submodule commits. `git submodule update --init --recursive`
  restores those commits; do not add `--remote` unless intentionally updating
  the pinned versions.
- Always keep complete history: no `--depth`, `--shallow-submodules`, or
  `shallow = true` for any submodule.
- Fresh clones leave submodules on detached HEADs. Attach the working branches
  at the pinned commits before using the sync or rebase targets:

  ```sh
  git -C dep/kkd checkout -B main HEAD
  git -C dep/kkd branch --set-upstream-to=origin/main main
  git -C dep/verus-bpf checkout -B main HEAD
  git -C dep/verus-bpf branch --set-upstream-to=origin/main main
  git -C dep/verus-bpf/dep/verus checkout -B main HEAD
  git -C dep/verus-bpf/dep/verus branch --set-upstream-to=origin/main main
  ```

- These attachment commands are for fresh clones only. Do not rerun them over
  submodules that already contain local work.

## Builds

- Run `make help` for the target list and overridable variables instead of
  relying on this file to enumerate them; `make -C src/sched help` adds
  the per-program toolchain variables.
- `kdev` comes from the pinned `dep/kkd` submodule, not from a system install.
- `make verus` builds the verifier out of `dep/verus-bpf/dep/verus` with vstd in
  `no_std`/`no_alloc` mode; it is a no-op once current and is a prerequisite
  of `verify` and `lachesis`. `make verus-clean` drops its outputs.
- `make lachesis` verifies and then builds both
  `build/lachesis/lachesis.o` and the loader `build/lachesis/lachesis`,
  and links the latter to `./lachesis`; `make lachesis-run` boots a VM and
  runs the loader as that guest's sched_ext scheduler; `make
  lachesis-clean` removes `build/lachesis/` and the symlink. Nothing under
  `build/` is tracked; `build/rust-deps` caches the libcore build and
  `build/host` every cargo output (`CARGO_TARGET_DIR`, including the
  loader's), and both survive `lachesis-clean` — use
  `make -C src/sched distclean` to drop them.
- `make lachesis-run` streams the guest transcript as it happens and
  also writes it to `build/lachesis/run.log`. The guest runs one spinner
  fewer than it has CPUs plus twice as many bursty tasks, so that CPUs
  keep going idle while queued work exists: that is what makes the steal
  and kick counters move. `LACHESIS_SECS`
  (default 5) is how long the guest keeps the scheduler attached. Ctrl-C
  ends the run within about half a second and exits 130. `VM_TIMEOUT`
  (default 300) is the hard deadline for the whole run, enforced by a
  watchdog in `vm-run.sh`, and exits 124. Do not reintroduce a `timeout`
  around `vng`: the script's header explains why it cannot end a run and
  why it breaks the watchdog that can.
- `make tlc` runs TLC over `src/tla/`: the positive configurations must
  pass and every negative variant must report a violation. It fetches
  TLA+ tools 1.7.4 into `build/tla/` on first use, the last release that
  runs on this host's Java 8, and keeps TLC's state files there too.
- `src/sched/Makefile` picks `LLVM_PREFIX` itself: Ubuntu's
  `/usr/lib/llvm-22` when it exists, `/usr` otherwise, which is where the
  system LLVM 22 lives on the development host. Override it for anything
  else.
- Programs are heap-free: the pipeline builds `core`, `compiler_builtins`
  and `btf`, never `alloc`. The `bpf_alloc`/`bpf_free` kfuncs upstream's
  allocator bound exist in no kernel; if a policy ever needs dynamic
  allocation, back it with `bpf_arena` (see the roadmap), do not
  reintroduce a `#[global_allocator]` over out-of-tree kfuncs.
- The toolchain is pinned by variables, not by `PATH`, all `?=` and all
  listed by `make -C src/sched help`: `RUST_TOOLCHAIN`, `RUSTC`,
  `RUST_SRC`, `CARGO`, `LLVM_PREFIX`, `POSTPROC_FEATURES`, `PYTHON`,
  `BPFTOOL`, `BUILD_DIR`, `DEPDIR`, `HOSTDIR`, and `KERNEL_DIR` /
  `KERNEL_BUILD` / `VMLINUX`. rustc must not be newer than the LLVM tools:
  bitcode reads forward only. `bpf-postproc` needs `llvm-config` and
  llvm-devel matching its `llvm-sys` version.
- `make rust-project` regenerates `rust-project.json` at the repository
  root after a build; the BPF crates have no Cargo workspace, so that file
  is the only way rust-analyzer can see crates built by bare rustc and the
  Verus driver. The userspace side *is* a cargo project, and
  `rust-analyzer.toml` at the repository root names both through
  `linkedProjects`. That is what an editor's language server reads; the
  `rust-analyzer diagnostics` CLI ignores it and only ever loads
  `rust-project.json`. See `dep/verus-bpf/TOOLCHAIN.md`, "Editor support".

## Verification

- The same source is compiled twice: the Verus driver on the host target with
  ghost code kept, then plain rustc on the BPF target with ghost code erased
  by the `verus!` macro. `dep/verus-bpf/TOOLCHAIN.md` has the details and the
  toolchain matrix; the short version is that `rustc` is Verus's pin and its
  LLVM must not be newer than the LLVM tools.
- Four crates, in dependency order: `lachesis_runtime_trusted`,
  `lachesis_model`, `lachesis_runtime`, then the policy. `make verify`
  (or `make -C src/sched verify`) runs Verus over each in turn and fails
  unless each reports `0 errors`; each exports its proofs as a `.vir`
  that the next ones import. All four erased compiles depend on all four
  passes, so `make lachesis` verifies before it compiles, and prints the
  trusted line count when it is done. The model imports the trusted crate
  for the `Op` type its contracts range over, and the runtime imports the
  model for the contracts its `Policy` trait states; the `refine` module
  and the prelude's re-export of it exist only under `verus_keep_ghost`,
  and nothing outside a `verus!` block names them.
- `make verify` then applies every patch in `src/sched/bpf/mutants/` to a
  copy of the policy and runs the same pass on it, and fails unless Verus
  rejects each with a verification error, reported one per line as
  `mutant <name>`. The ten there reproduce known bugs -- the two the
  Ipanema paper found in CFS, the traces TLC found while this design was
  being built, an off-by-one -- and each patch's header says which step
  of which contract it breaks. `make -C src/sched verify-mutants` runs
  only those; a new mutant is a new patch, nothing else.
- A fifth pass, `lachesis_control`, runs beside them and is reported on
  its own line. It is a leaf: it imports none of the other crates, so it
  names no rlibs and no search paths, and it runs with `--no-cheating`
  unconditionally. The BPF object depends on it too, so a broken proof on
  the userspace side stops the object build.
- `--no-cheating` is not the per-crate flag it looks like. Verus runs the
  check over the merged crate graph, so a crate that *calls* an
  `external_body` function out of `lachesis_runtime_trusted` is rejected
  too, even though the cheat is not its own. The flag is therefore on for
  `lachesis_runtime` and `lachesis_model`, which call none, and off for
  `lachesis_runtime_trusted` and for the policy; `NOCHEAT_CRATES` in
  `rules.mk` is the list. `make
  lint-trusted` is what actually keeps cheats out of everything but
  `src/runtime/trusted`, and it is a `verify` prerequisite.
- `VERIFY=0` skips verification and prints a warning on every build. It is
  for debugging the compile pipeline. Never load an object built that way,
  and never leave it set in a script.
- No `assume(`, `admit(`, `external_body`, `assume_specification`,
  `external_fn_specification`, `#[verifier::external]` or `unsafe` may
  appear anywhere under `src/` outside `src/runtime/trusted/`. One
  exemption from the `unsafe` half only: `src/loader`, the directory holding
  the manifest `USER_MANIFEST`
  names, which is unverified by design and needs `unsafe` to install a
  signal handler. `lint-trusted` prints the exemption on every run. `make
  trusted-lines` prints `wc -l` over `src/runtime/trusted/*.rs` and over
  the loader, and `verify` prints both at the end, so the size of what
  nothing checks is visible on every run; adding to it needs human
  review.
- What is inside `verus!` and therefore checked: `src/runtime` entirely,
  `src/sched/control` entirely, and in a policy the state struct, the
  `impl Policy` and the `const`s. What is outside it and unchecked: the
  kfunc externs, the `#[btf]` views, the `Task` accessors, the atomics,
  the `scheduler!` trampolines, the struct_ops table and the panic handler
  -- all of them in `src/runtime/trusted`, and all of them with a
  specification that is assumed rather than proved.
  A `requires` is therefore enforced at a call from a policy, and not at a
  call from a trampoline.
- Raw `extern` and `unsafe` are expected in `src/runtime/trusted`; the
  lint is about where they live, not about whether they exist.

## sched_ext

- Never register, unregister or otherwise touch a sched_ext scheduler on
  the development host, and never write to `/sys/kernel/sched_ext` or
  `/sys/fs/bpf` there: the host runs its own scheduler and loading another
  displaces it. All loading happens inside the VM that
  `make lachesis-run` boots. Two guards, both on the DMI vendor:
  `vm-guest.sh` refuses to run anywhere that is not a QEMU guest, and the
  loader itself refuses to attach there unless given `--allow-host`. Never
  pass `--allow-host` on this machine.
- The target kernel's `vmlinux` is a build input, not just a run-time
  choice: `add_ksyms.py` mirrors kfunc prototypes out of its BTF. Rebuild
  the object after switching kernels.

## Sync and rebase

- `make sync` (or per-repo `kkd-sync`): pull and rebase each attached branch
  onto its fork tracking branch. Sync never pushes.
- `make rebase` (or per-repo `-rebase` variants): advance the patch stacks —
  fetch the true upstream base, rebase the attached branch onto it, then
  force-push (`--force-with-lease`) the branch back to the fork. Every step is
  a no-op when already current, so re-running is always safe. `dep/kkd` has no
  separate upstream, so its rebase base is `origin/main`, as are verus-bpf
  and the nested Verus checkout's configured bases.
- Both reject detached HEADs and tracked or staged changes; untracked files
  are left alone.
- If a rebase conflicts, `make rebase` continues with the remaining repos and
  lists the failures. Resolve the conflicts, `git rebase --continue`, then
  re-run `make rebase` to finish and push.
- Syncing and rebasing are explicit maintenance operations. Never make them
  prerequisites of `all` or any other build target.
- Afterwards, review the updated submodule commits and stage the resulting
  superproject gitlink bumps intentionally.

## Git conventions

- Use `--no-gpg-sign` when creating or amending commits to avoid GPG signing
  issues.
- Agent-authored commit messages start with the authoring agent in
  parentheses, then read like a short sentence fragment, for example:
  `(codex) Initialize the repository` or `(claude) Harden the sync guards`.
- Wrap every commit message line, subject and body alike, at 80 columns.
  Use real newlines; never emit literal `\n` escapes in commit messages.
