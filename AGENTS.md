# AGENTS.md

Repo-wide guidance for agents working in this repository. `CLAUDE.md` is a
symlink to this file so Claude Code loads the same guidance.

## Repository layout

The superproject pins its submodules under `dep/` via gitlinks. In every
submodule, `origin` is the kkdwvd fork.

- `dep/kkd` — personal tooling monorepo (provides `kdev`); branch `main`
  tracks `origin/main`.
- `dep/verus` — the Verus verifier, pinned; branch `main` tracks
  `origin/main`. There is no kkdwvd fork yet, so `origin` is upstream;
  `git submodule set-url` once one exists. Treat it as read-only — build
  artefacts (`source/target*`, `source/z3`, `tools/vargo/target`) are
  gitignored upstream, so `make verus` leaves the checkout clean.

`src/` is reserved for lachesis-native code and `build/` for generated
outputs; `build/` is ignored by git. `ROADMAP.md` is a symlink to the project
roadmap note in `dep/kkd`; read it before planning work and record decisions
in its decision log.

- `src/toolchain` — the Rust-to-BPF pipeline, lachesis-owned and free to
  modify. Most of it was imported verbatim from 4ast/rust-bpf `master` at
  `2570069dd7fa`; `src/toolchain/README.md` records what came from there,
  what is ours (`rules.mk`, `btf_fixup.py`) and why there are no local
  edits to the imported files. There is no submodule and no upstream to
  stay in sync with.

Three crates in dependency order, each one verified and compiled against
the ones before it:

- `src/trusted` — `lachesis_trusted`, the trusted base, and the only place
  in the tree where `unsafe` or a Verus cheat may appear. One module per
  concern: `kfunc.rs` (the only `extern "C"` block in the tree), `scx.rs`
  (safe wrappers over those kfuncs, their assumed contracts, and the kernel
  constants), `task.rs` (the `#[btf]` CO-RE views, the `Task` handle and
  its accessor specifications), `atomic.rs` (an opaque `AtomicU64` with no
  `Ordering` in its interface), `stats.rs` (`Stats<N>`, the `.bss`
  counters), `panic.rs` (the one `#[panic_handler]`) and `ops.rs` (the
  `scheduler!` macro and its trampolines).
- `src/rt` — `lachesis_rt`, the checked layer every scheduler links:
  `policy.rs` (the `Policy` trait, where a callback's contract is written
  down), `vtime.rs` (virtual-time arithmetic) and `lib.rs` with the
  `prelude`. No `unsafe`, no cheats, verified with `--no-cheating`.
- `src/scx_lachesis` — the scheduler as one cargo project: the BPF policy
  under `bpf/`, the loader binary under `src/`, its verified core under
  `core/`, the Makefile stub, and the `vm-run.sh`/`vm-guest.sh` pair that
  runs the whole thing in a VM.

```text
src/scx_lachesis/
  Cargo.toml       workspace root and the `scx_lachesis` binary package
  Cargo.lock       committed
  Makefile         PROG, SRC, KEEP_SYMS, USER_MANIFEST, USER_CORE_SRC
  bpf/main.rs      the BPF policy; verified, compiled by rules.mk
  src/main.rs      the loader; unverified, compiled by cargo
  core/            `scx_lachesis_core`, verified, compiled by both
  vm-run.sh vm-guest.sh
```

A program directory owns only its sources and a Makefile that sets `PROG`,
optionally `SRC`, `KEEP_SYMS`, `USER_MANIFEST` and `USER_CORE_SRC`, and then
includes the pipeline:

```make
PROG := scx_lachesis
SRC := bpf/main.rs
KEEP_SYMS := lachesis_ops lachesis_enqueue ... LACHESIS _LICENSE
USER_MANIFEST := Cargo.toml
USER_CORE_SRC := core/src/lib.rs
include ../toolchain/rules.mk
```

`SRC`, `USER_MANIFEST` and `USER_CORE_SRC` are relative to the program
directory. `KEEP_SYMS` is what `opt` may not internalize: the struct_ops
map, its entry points, the license, and anything userspace reads back out
of the maps, which today means the policy's own static. Set
`USER_MANIFEST` and the pipeline also builds a binary named `$(PROG)` out
of that cargo project; set `USER_CORE_SRC` and it also verifies that crate
with `--no-cheating`. Nothing else about the pipeline belongs in a
program's Makefile.

## Writing a policy

A policy file is policy. It contains no `unsafe`, no `extern`, no
`#[link_section]`, no `#[no_mangle]`, no raw pointers, no `#[btf]` and no
`repr(C)`; `src/scx_lachesis/bpf/main.rs` is the worked example and is just
over a hundred lines. `use lachesis_rt::prelude::*;` brings in
everything, including the `verus!` macro.

The state is a struct and the callbacks are an `impl Policy`, both inside
`verus!`, so Verus checks them:

```rust
verus! {

const GLOBAL: usize = 1;

pub struct Lachesis {
    vtime_now: AtomicU64,
    stats: Stats<3>,
}

impl Policy for Lachesis {
    fn enqueue(&self, p: Task, enq_flags: u64) {
        self.stats.inc(GLOBAL);
        let now = self.vtime_now.load();
        let vtime = clamp_vtime(p.vtime(), now, SCX_SLICE_DFL);
        scx::dsq_insert_vtime(&p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
    }
}

} // verus!
```

The `Policy` trait in `src/rt/policy.rs` declares every struct_ops member a
policy may implement, one method per callback, each with a default body, so
a policy writes only the callbacks it cares about. Contracts are declared
on the trait and inherited by the `impl`: Verus rejects a `requires` on a
trait method *implementation*, so each contract is stated in exactly one
place and a policy never quotes one.

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

`scheduler!` wires the impl to the kernel:

```rust
scheduler! {
    map: lachesis_ops,
    name: "lachesis",
    policy: LACHESIS: Lachesis = Lachesis {
        vtime_now: AtomicU64::new(0),
        stats: Stats::new(),
    },
    ops {
        enqueue as lachesis_enqueue,
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
included. Each `ops` line is "struct_ops member `as` exported program
symbol" and nothing more -- the trait fixes the signature, and
`__trampoline!` in `src/trusted/ops.rs` has one rule per member name that
knows the context layout. Two names per line is the floor, because
`macro_rules!` cannot mint an identifier. `sleepable` members get a
`struct_ops.s/` section, which the kernel requires for `init`, `init_task`,
`exit_task` and the cgroup callbacks. Counter slots are plain `usize`
consts and `self.stats.inc(GLOBAL)` bumps one; `Stats::inc` requires the
index to be in range and Verus checks it.

Adding a struct_ops member means adding a method to the `Policy` trait and
a rule to `__trampoline!`; an unknown member is a `compile_error!`. A
kernel function a policy needs is declared in `src/trusted/kfunc.rs`, given
a safe wrapper in `src/trusted/scx.rs`, and given its specification on that
wrapper. Never in `lachesis_rt`, never in a policy, and never a second
`extern` block anywhere.

## The userspace side

`scx_lachesis` is a binary now, not a `bpftool struct_ops register`
invocation. It exists because the link has to be *held*: dropping it
unregisters the scheduler, which is how a dead loader stops being a wedged
machine, and it is the only way to read back the exit information the
kernel reports through `ops.exit`.

Three pieces, and the split between them is the point:

- `src/main.rs`, the loader. Argument parsing, libbpf-rs, `.bss` decoding,
  signals, printing. **Not verified**, and not going to be: its dependency
  graph is libbpf-rs and libc, which Verus has no specifications for, and
  its job is I/O. `unsafe` is allowed here, and `lint-trusted` exempts this
  one directory from the `unsafe` half of the lint for exactly that reason
  (it still applies the cheat half). `make verify` prints its line count
  next to the BPF trusted base, so the size of what nothing checks stays
  visible.
- `core/`, the crate `scx_lachesis_core`. **Verified**, `#![no_std]`,
  everything inside `verus!`, checked with `--no-cheating`. It is a crate
  and not a module because Verus verifies crates: keeping it separate is
  what lets it be checked without libbpf-rs in the pass. It therefore
  depends on nothing but the `verus!` macro, taken as a path dependency on
  `dep/verus`.
- `bpf/main.rs`, the policy, unchanged in kind: still the BPF side.

Adding a function to the core: write it inside the `verus!` block with a
`requires`/`ensures` that says something a caller could get wrong, call it
from `src/main.rs`, and re-run `make verify`. There is no wiring to do --
`USER_CORE_SRC` in the Makefile already points at the crate, `verify`
reports it on its own line, and the object build depends on that pass like
it does on the others.

### The binary

```
scx_lachesis [--obj PATH] [--interval SECS] [--duration SECS] [--allow-host]
```

`--obj` defaults to `scx_lachesis.o` beside the executable; the object is
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
print as `LACHESIS.stats.counters[0].v.value.__0`. Three leaf names are
special, matched on the last dotted component: `vtime_now` is printed as
the clock, `exit_kind` and `exit_code` are the exit report. Everything else
is a counter and its per-interval delta is printed, computed by
`scx_lachesis_core::counter_deltas`. Adding a counter to the policy needs
no change to the loader.

### How the exit info flows

`struct scx_exit_info` is a kernel pointer the `ops.exit` callback is
handed, and it is gone by the time anything in userspace could look at it.
So the BPF side copies the two fields that matter into its own static:

1. `src/trusted/task.rs` declares a `#[btf]` view of `struct scx_exit_info`
   with `kind` and `exit_code`, and two `external_body` accessors on
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
4. `scx_lachesis_core::classify_exit` turns the raw kind into the band it
   belongs to and `exit_kind_name` gives it the kernel's own wording; the
   classification is what decides the process exit status.

## Submodules

- The gitlinks pin exact submodule commits. `git submodule update --init`
  restores those commits; do not add `--remote` unless intentionally updating
  the pinned versions.
- Always keep complete history: no `--depth`, `--shallow-submodules`, or
  `shallow = true` for any submodule.
- Fresh clones leave submodules on detached HEADs. Attach the working branches
  at the pinned commits before using the sync or rebase targets:

  ```sh
  git -C dep/kkd checkout -B main HEAD
  git -C dep/kkd branch --set-upstream-to=origin/main main
  git -C dep/verus checkout -B main HEAD
  git -C dep/verus branch --set-upstream-to=origin/main main
  ```

- These attachment commands are for fresh clones only. Do not rerun them over
  submodules that already contain local work.

## Builds

- Run `make help` for the target list and overridable variables instead of
  relying on this file to enumerate them; `make -C src/scx_lachesis help` adds
  the per-program toolchain variables.
- `kdev` comes from the pinned `dep/kkd` submodule, not from a system install.
- `make verus` builds the verifier out of `dep/verus` with vstd in
  `no_std`/`no_alloc` mode; it is a no-op once current and is a prerequisite
  of `verify` and `scx-lachesis`. `make verus-clean` drops its outputs.
- `make scx-lachesis` verifies and then builds both
  `build/scx_lachesis/scx_lachesis.o` and the loader
  `build/scx_lachesis/scx_lachesis`, `make scx-lachesis-run` boots a VM and
  runs the loader as that guest's sched_ext scheduler, and
  `make scx-lachesis-clean` removes `build/scx_lachesis/`. Nothing under
  `build/` is tracked; `build/rust-deps` caches the libcore build and
  `build/host` every cargo output (`CARGO_TARGET_DIR`, including the
  loader's), and both survive `scx-lachesis-clean` — use
  `make -C src/scx_lachesis distclean` to drop them.
- `make scx-lachesis-run` streams the guest transcript as it happens and
  also writes it to `build/scx_lachesis/run.log`. `SCX_LACHESIS_SECS`
  (default 5) is how long the guest keeps the scheduler attached. Ctrl-C
  ends the run within about half a second and exits 130. `VM_TIMEOUT`
  (default 300) is the hard deadline for the whole run, enforced by a
  watchdog in `vm-run.sh`, and exits 124. Do not reintroduce a `timeout`
  around `vng`: the script's header explains why it cannot end a run and
  why it breaks the watchdog that can.
- Programs are heap-free: the pipeline builds `core`, `compiler_builtins`
  and `btf`, never `alloc`. The `bpf_alloc`/`bpf_free` kfuncs upstream's
  allocator bound exist in no kernel; if a policy ever needs dynamic
  allocation, back it with `bpf_arena` (see the roadmap), do not
  reintroduce a `#[global_allocator]` over out-of-tree kfuncs.
- The toolchain is pinned by variables, not by `PATH`, all `?=` and all
  listed by `make -C src/scx_lachesis help`: `RUST_TOOLCHAIN`, `RUSTC`,
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
  `rust-project.json`. See `src/toolchain/README.md`, "Editor support".

## Verification

- The same source is compiled twice: the Verus driver on the host target with
  ghost code kept, then plain rustc on the BPF target with ghost code erased
  by the `verus!` macro. `src/toolchain/README.md` has the details and the
  toolchain matrix; the short version is that `rustc` is Verus's pin and its
  LLVM must not be newer than the LLVM tools.
- Three crates, in dependency order: `lachesis_trusted`, `lachesis_rt`,
  then the policy. `make verify` (or `make -C src/scx_lachesis verify`) runs
  Verus over each in turn and fails unless each reports `0 errors`; each
  exports its proofs as a `.vir` that the next ones import. All three erased
  compiles depend on all three passes, so `make scx-lachesis` verifies
  before it compiles, and prints the trusted line count when it is done.
- A fourth pass, `scx_lachesis_core`, runs beside them and is reported on
  its own line. It is a leaf: it imports none of the other crates, so it
  names no rlibs and no search paths, and it runs with `--no-cheating`
  unconditionally. The BPF object depends on it too, so a broken proof in
  the userspace core stops the object build.
- `--no-cheating` is not the per-crate flag it looks like. Verus runs the
  check over the merged crate graph, so a crate that *calls* an
  `external_body` function out of `lachesis_trusted` is rejected too, even
  though the cheat is not its own. The flag is therefore on for
  `lachesis_rt`, which calls none, and off for `lachesis_trusted` and for
  the policy; `NOCHEAT_CRATES` in `rules.mk` is the list. `make
  lint-trusted` is what actually keeps cheats out of everything but
  `src/trusted`, and it is a `verify` prerequisite.
- `VERIFY=0` skips verification and prints a warning on every build. It is
  for debugging the compile pipeline. Never load an object built that way,
  and never leave it set in a script.
- No `assume(`, `admit(`, `external_body`, `assume_specification`,
  `external_fn_specification`, `#[verifier::external]` or `unsafe` may
  appear anywhere under `src/` outside `src/trusted/`. Two exemptions, both
  from the `unsafe` half only: `src/toolchain`, the imported compile
  pipeline, trusted whole by roadmap section 3.7 item 5, and the loader's
  own directory (`$(USER_MANIFEST)`'s `src/`), which is unverified by
  design and needs `unsafe` to install a signal handler. `lint-trusted`
  prints the exemption on every run. `make trusted-lines` prints `wc -l`
  over `src/trusted/*.rs` and over the loader, and `verify` prints both at
  the end, so the size of what nothing checks is visible on every run;
  adding to it needs human review.
- What is inside `verus!` and therefore checked: `src/rt` entirely, and in a
  policy the state struct, the `impl Policy` and the `const`s. What is
  outside it and unchecked: the kfunc externs, the `#[btf]` views, the
  `Task` accessors, the atomics, the `scheduler!` trampolines, the
  struct_ops table and the panic handler -- all of them in `src/trusted`,
  and all of them with a specification that is assumed rather than proved.
  A `requires` is therefore enforced at a call from a policy, and not at a
  call from a trampoline.
- Raw `extern` and `unsafe` are expected in `src/trusted`; the lint is about
  where they live, not about whether they exist.

## sched_ext

- Never register, unregister or otherwise touch a sched_ext scheduler on
  the development host, and never write to `/sys/kernel/sched_ext` or
  `/sys/fs/bpf` there: the host runs its own scheduler and loading another
  displaces it. All loading happens inside the VM that
  `make scx-lachesis-run` boots. Two guards, both on the DMI vendor:
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
  separate upstream, so its rebase base is `origin/main`, and so is
  `dep/verus`'s.
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
