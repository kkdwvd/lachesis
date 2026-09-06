# src/toolchain

The Rust-to-BPF build pipeline: it compiles a `#![no_std]` Rust file into a
BPF object with no kernel crate and no `bpf-linker`. `rules.mk` is the entry
point; a program directory sets `PROG`, optionally `SRC` and `KEEP_SYMS`, and
includes it.

This tree is lachesis-owned. It started as an import, but there is no upstream
submodule any more and no obligation to stay in sync — change anything here
freely.

## Provenance

Imported from <https://github.com/4ast/rust-bpf>, branch `master`, commit
`2570069dd7fa` ("Merge pull request #1 from prozak/ksyms-robustness"), on
2026-09-06. Upstream is GPL-2.0 per the SPDX markers on the files that carry
one (`multi3.ll` and upstream's `Makefile`); the rest of upstream carries no
per-file header. Treat the whole import as GPL-2.0.

Imported unmodified (byte-for-byte from that commit):

| Path | What it does |
| --- | --- |
| `bpfel-unknown-none-v4.json` | rustc target: BPF little-endian, `obj-is-bitcode`, cpu v4 |
| `multi3.ll` | hand-written `__multi3` (128-bit multiply) that libcore needs |
| `add_ksyms.py` | tags extern declarations `.ksyms`, mirrors kfunc prototypes out of the target kernel's BTF, lowers `invoke`->`call` and `unreachable`->`ret`, renames mem libcalls to `bpf_arena_*` |
| `btf/` | `no_std` BPF-target crate backing the `#[btf]` field accessors |
| `btf-macros/` | host proc-macro crate providing `#[btf]` (with `Cargo.lock`) |
| `bpf-postproc/` | host tool that lowers the `#[btf]` polyfills into real CO-RE relocations, via `llvm-sys` (with `Cargo.lock`) |

Lachesis-authored:

| Path | What it does |
| --- | --- |
| `rules.mk` | the pipeline as a shared include, plus the Verus verification pass and the `lint-trusted` guardrail; upstream's `Makefile` was per-repo and hardcoded its own layout, so it was rewritten rather than imported |
| `btf_fixup.py` | rewrites rustc's DWARF so that the BTF `llc` derives from it passes the kernel's BTF verifier (illegal name characters, out-of-order struct members, `DW_ATE_UTF`, unnamed function parameters) |

## Local edits to imported files

None. Two upstream defaults are worked around from `rules.mk` instead of by
editing the import:

- `bpf-postproc` is built with `--features llvm-sys-22/prefer-dynamic`
  (`POSTPROC_FEATURES`), because static linking against `llvm-static` pulls
  `std::__glibcxx_assert_fail`, which RHEL 9's base libstdc++ lacks.
- `add_ksyms.py` execs `$BPFTOOL` directly, so `BPFTOOL` defaults to
  `/usr/sbin/bpftool` rather than a `/usr/local/bin` wrapper script. Without a
  working `bpftool` it silently skips kernel-BTF prototype mirroring and every
  kfunc gets an incompatible guessed prototype.

Upstream's `scx_simple.rs` and `scx_cosmos.rs` were not imported;
`src/sched/bpf/main.rs` derives from upstream's `scx_simple.rs`
and lives with the scheduler, not with the toolchain.

## Toolchain matrix

Everything in the same column has to agree; the constraint that binds them is
that **rustc's LLVM must not be newer than the LLVM tools**, because bitcode
reads forward only.

| Component | Version | Why this one |
| --- | --- | --- |
| rustc | 1.98.0 (LLVM 22.1.8) | Verus's pin, `dep/verus/rust-toolchain.toml`. One rustc serves the verification pass, the host proc macros, libcore and the BPF compile. |
| rustc components | rust-src, rustc-dev, llvm-tools, rustfmt, cargo | rust-src builds libcore for the BPF target; the rest are what vargo needs. |
| LLVM tools (`llc`, `opt`, `llvm-link`, `llvm-as`, `llvm-dis`, `llvm-objcopy`) | system 22.1.x in `/usr/bin` | Same major as rustc's LLVM, so it reads its bitcode. `LLVM_PREFIX` overrides. |
| `llvm-sys` (for `bpf-postproc`) | 221.0.1 against LLVM 22, `prefer-dynamic` | Pinned by the imported `Cargo.toml`; needs `llvm-config` from llvm-devel. |
| Verus | `dep/verus` @ `5f6eb59f7a55`, built `--vstd-no-std --vstd-no-alloc` | vstd must define no `std` lang items so it links against a `#![no_std]` crate with its own `#[panic_handler]`. |
| Z3 | 4.16.0 | Required by Verus. See the note below about which build. |
| bpftool | 7.8.0 (`/usr/sbin/bpftool`) | Reads the target kernel's BTF for `add_ksyms.py`. |
| libbpf-rs | 0.27, default features | The loader. Builds libbpf from libbpf-sys's bundled sources; needs the system libelf and zlib headers. Not pinned to the toolchain matrix -- it is host code and only has to build with `$(RUSTC)`. |
| Reference kernel | `/home/kkd/src/linux` bpf-next, `CONFIG_SCHED_CLASS_EXT=y`, BTF | `VMLINUX` is a build input, not just a run-time choice. |

Z3: upstream's `source/tools/get-z3.sh` fetches the release artifact built
against glibc 2.39, and RHEL 9 has 2.34, so that binary will not run here. The
root `Makefile`'s z3 rule runs upstream's script first and falls back to the
`z3_solver` wheel from the same release, a `manylinux_2_27` build of the same
4.16.0, when the downloaded binary fails `--version`.

## Two passes

The same source file is compiled twice, and the `verus!` macro behaves
differently in each because it decides keep-vs-erase by expanding
`cfg!(verus_keep_ghost)` in the crate being compiled.

1. **Verification**, `make verify`. The Verus driver compiles the crate for
   the *host* target with `--cfg verus_keep_ghost`, links its own host-target
   `vstd` and `verus_builtin`, and discharges the proof obligations through
   Z3. `--no-cheating` makes `assume`, `admit` and `external_body` errors.
   Items not written in Verus syntax -- the kfunc externs, the `#[btf]`
   views, the `scheduler!` trampolines, the struct_ops table, the panic
   handler -- are external to Verus and are not checked. All of them now
   live in `lachesis_runtime_trusted`.

2. **Erased compile**, the rest of `rules.mk`. Plain rustc for the BPF target,
   *without* `--cfg verus_keep_ghost`, so the macro drops the specs and proofs
   and emits the exec code alone. The only Verus input is
   `libverus_builtin_macros.so`; no `vstd` and no `verus_builtin` reach the
   BPF target. `register_tool(verus|verifier|verusfmt)` crate attributes are
   added so that any `#[verifier::...]` surviving erasure still parses.

Verification on the host target is a known phase 1 simplification: the proof
is about the source, and the object is produced by a separate pass over the
same file. Nothing checks that the two passes see the same code beyond the
macro's own erasure, and the compile pipeline is trusted (roadmap section
3.7, item 5).

### Three crates

There are three crates on each side of that split, and Verus checks them
separately, in dependency order: `lachesis_runtime_trusted`
(`src/runtime/trusted`), `lachesis_runtime` (`src/runtime`), then the policy
that links both. `rules.mk` drives them from `LIB_CRATES`, an ordered list,
so a fourth library crate is one line plus a `_DIR`.

Each library crate is verified with `--compile --export`:

```
verus --crate-type=lib --crate-name lachesis_runtime_trusted \
      --compile --export build/host/verus/lachesis_runtime_trusted.vir \
      --out-dir build/host/verus \
      --extern btf=... --extern btf_macros=... src/runtime/trusted/lib.rs

verus --no-cheating --crate-type=lib --crate-name lachesis_runtime \
      --compile --export build/host/verus/lachesis_runtime.vir \
      --out-dir build/host/verus \
      --extern lachesis_runtime_trusted=.../liblachesis_runtime_trusted.rlib \
      --import lachesis_runtime_trusted=.../lachesis_runtime_trusted.vir \
      --extern btf=... --extern btf_macros=... \
      -L dependency=build/host/verus \
      -L dependency=build/host/rust-deps \
      -L dependency=build/host/btf-macros/release/deps src/runtime/lib.rs
```

`--export` writes the proofs; `--compile` writes the host rlib next to
them, whose metadata still carries the ghost signatures because the driver
sets `verus_keep_ghost`. The policy's pass imports both crates the same way.

Every `-L dependency` path is load-bearing and was the whole difficulty.
`--extern` covers a crate's *direct* dependencies only; when rustc loads
`lachesis_runtime`'s metadata it must resolve `lachesis_runtime_trusted` by
searching, and when it loads *that* one it must resolve `btf` and the
`btf_macros` proc-macro dylib the same way -- the proc-macro under the hashed
filename cargo gave it (`libbtf_macros-<hash>.so` in cargo's `deps/`, not the
plain `libbtf_macros.so` beside it). Without them the failure is a bare
`error[E0463]: can't find crate for 'lachesis_runtime'` that says nothing
about the real cause. The erased BPF compiles need the same paths for the
same reason.

### Why three, and why `--no-cheating` is not per crate

`--no-cheating` rejects `assume`, `admit`, `#[verifier::external_body]` and
`assume_specification`. An FFI call has no body a verifier could look at, so
`external_body` with an assumed `ensures` is the only way to give a kfunc, a
CO-RE field read or an atomic a specification at all -- which is why those
live in their own crate, `lachesis_runtime_trusted`, verified without the flag.

The flag is not, however, a property of the crate it is passed to. Verus
runs the check over the merged crate graph after pruning, so a crate that
*calls* an `external_body` function out of `lachesis_runtime_trusted` is
rejected too, pointing at the callee's source in the other crate:

```
error: external_body/assume_specification not allowed with --no-cheating
  --> src/runtime/trusted/scx.rs:53:1
```

`lachesis_runtime` calls none of them -- pruning drops them and the flag
stays on -- but the policy calls several, so its pass runs without it.
`make lint-trusted` is what enforces the boundary in practice: no cheat and
no `unsafe` anywhere under `src/` outside `src/runtime/trusted/`, checked
before every verification pass, with `make trusted-lines` reporting the size
of what is left.

`make lachesis` runs pass 1 for all three crates and for the control crate,
then pass 2 for all three; the erased compiles depend on the verification
stamps, so a broken proof -- in any of the four -- stops the build before
anything is compiled. `VERIFY=0` skips verification and prints a warning on
every build -- for debugging the pipeline, never for anything you intend to
load.

## The userspace side

The pipeline can also build a userspace binary and verify a crate that
binary calls, and `lachesis` uses both. `rules.mk` drives them from three
variables the program's Makefile sets: `USER_MANIFEST`, a `Cargo.toml` whose
`[[bin]]` is named `$(PROG)`; `USER_CORE_SRC`, the `lib.rs` of the verified
crate; and `USER_CORE_NAME`, that crate's name. Set none and none of this
happens; the BPF object is the whole build.

The two live apart on purpose. `src/loader` is the loader binary, unverified
and named `lachesis` like the object; `src/sched/control` is
`lachesis_control`, verified in the same `make verify` as the policy it sits
beside, because what it decides -- how to read the scheduler's exit -- is
part of the scheduler and not part of the plumbing that loads it. So
`src/sched/Makefile` points `USER_MANIFEST` up at `../loader/Cargo.toml` and
`USER_CORE_SRC` down at `control/src/lib.rs`.

Four things about it are not obvious.

**The loader is a workspace of one.** Cargo requires every workspace member
to sit hierarchically below the workspace root, and `src/sched/control` is
not below `src/loader`, so it cannot be a member. `src/loader/Cargo.toml`
declares a bare `[workspace]` -- which stops cargo walking up to look for
one -- and takes `lachesis_control` as an ordinary path dependency. That
builds it exactly the same way and keeps one `Cargo.lock`, in `src/loader`.

**`CARGO_TARGET_DIR` is always set.** Every cargo invocation in the
pipeline -- `btf-macros`, `bpf-postproc`, the rust-analyzer erase-only
macro, and now the loader -- names its own directory under `$(HOSTDIR)`, so
nothing is written into the source tree and, for anything rooted in
`dep/verus`, nothing into the submodule. `USER_TARGET_DIR` is
`$(HOSTDIR)/$(PROG)-user`; the release binary is copied from there to
`$(OUT)/$(PROG)`, so `clean` drops the artefact and keeps the cache, like
`DEPDIR`.

**`RUSTC` is passed explicitly.** Cargo resolves `rustc` through `PATH`,
which on a rustup installation is the shim, and the shim picks a toolchain
from the *current* directory -- which cargo sets to each package's own
root. Without `RUSTC=$(RUSTC)` the registry crates get built by the default
toolchain and the path dependencies under `dep/verus` by Verus's pin, and
the two then refuse to link (`found crate ... compiled by an incompatible
version of rustc`).

**The `verus!` macro reaches cargo as a path dependency.** `lachesis_control`
depends on `verus_builtin_macros` at
`dep/verus/source/builtin_macros`. Cargo resolves that crate's workspace
inheritance against Verus's own workspace and builds it like any other
proc macro. It erases ghost code for the same reason the BPF compiles do:
the macro decides keep-vs-erase by expanding `cfg!(verus_keep_ghost)` in
the crate being compiled, this cargo run does not set that cfg, and
`dep/verus`'s `.cargo/config.toml` -- which would inject it -- is not read,
because cargo discovers configuration from the invocation's working
directory and not from a dependency's. `RUSTC_BOOTSTRAP` is not needed;
none of this is on a nightly path. `lachesis_control`'s `Cargo.toml`
declares `check-cfg = ['cfg(verus_keep_ghost)']` so the `#[cfg]` in its
prelude is not reported as unexpected.

libbpf-rs is taken with default features, which is
`libbpf-sys/vendored-libbpf`: libbpf itself is built from the bundled
sources and linked statically, against the system libelf and zlib. The
fuller `vendored` feature, which also builds elfutils and zlib, is not
needed here and would be a much longer build.

The loader is verified by nothing. `lachesis_control` is verified like a
library crate, with `--no-cheating`, by a pass that imports no other crate
-- which is the reason it is a crate and not a module of the loader, since
Verus verifies crates and libbpf-rs and libc have no specifications.

## No allocator

Nothing here builds `alloc`. Upstream's `scx_simple.rs` puts a
`#[global_allocator]` over `bpf_alloc`/`bpf_free`, which exist in no upstream
kernel; programs built here are heap-free and `core` is the whole runtime.
Only `core`, `compiler_builtins` and `btf` are compiled and linked.

## Editor support

The BPF crates have no Cargo workspace -- every one of them is built by
bare rustc and the Verus driver -- so `make rust-project` (`rules.mk`'s
`rust-project` target) writes a `rust-project.json` at the repository root
by hand, the format rust-analyzer reads in place of `Cargo.toml`. Two
things about the toolchain matrix make a naive project file (real paths,
real `VERUS_MACROS_SO`) fail:

- rust-analyzer on `PATH` is typically a stable build, but these crates are
  compiled by `$(RUST_TOOLCHAIN)`'s rustc, and a proc-macro dylib has to be
  expanded by a server built by the same compiler that built it. Naming
  that toolchain's sysroot (`RA_SYSROOT`) in `rust-project.json` is what
  makes rust-analyzer use `<sysroot>/libexec/rust-analyzer-proc-macro-srv`
  instead of its own bundled one.
- The `verus!` proc macro, built the normal way, panics under
  rust-analyzer's proc-macro server with "cfg_erase call failed": it calls
  the unstable `expand_expr` bridge, which that server does not implement.
  Verus's macro crate has an always-erase code path, the same one the BPF
  erased-compile passes above rely on, selected by building it *without*
  `--cfg verus_keep_ghost`. `dep/verus`'s own `.cargo/config.toml` injects
  that cfg into every `cargo build` via `rustflags`, so `rust-project`
  builds a second, erase-only `libverus_builtin_macros.so`
  (`RA_VERUS_MACROS_SO`, under `$(HOSTDIR)/verus-macros-erase`) with an
  explicit `RUSTFLAGS` that omits it -- cargo does not merge the two, the
  environment wins outright -- and with its own `CARGO_TARGET_DIR` so
  nothing lands in `dep/verus`. The real BPF compile keeps using
  `VERUS_MACROS_SO` from `make verus`; the erase-only dylib is for
  rust-analyzer only.

`rust-project.json` contains absolute host paths, so it is gitignored and
regenerated with `make rust-project` (or `make -C src/sched
rust-project`) after a build. The crate list is generated from
`LIB_CRATES`; `gen_rust_project.py` has the dependency edges.

The userspace side is a cargo project, so it is not in that file.
`rust-analyzer.toml` at the repository root lists both with
`linkedProjects`, which is the documented way to load two unrelated
projects in one workspace. That file is read by the language server an
editor starts. It is *not* read by the `rust-analyzer diagnostics` CLI:
that subcommand discovers a project itself and, with a `rust-project.json`
at the root, loads only the BPF crates -- verified by pointing
`linkedProjects` at the cargo project alone and getting the same sixteen
files. Checking the userspace crates from the command line means running
`cargo check` on them.
