# SPDX-License-Identifier: GPL-2.0
#
# Shared rules for building a #![no_std] Rust program into a BPF object.
#
# A scheduler directory's Makefile sets PROG (and optionally SRC, KEEP_SYMS
# and the two userspace variables) and includes this file:
#
#	PROG := scx_lachesis
#	SRC := bpf/main.rs
#	KEEP_SYMS := lachesis_ops lachesis_enqueue ... _LICENSE
#	USER_MANIFEST := Cargo.toml
#	USER_CORE_SRC := core/src/lib.rs
#	include ../toolchain/rules.mk
#
# The pipeline, imported from 4ast/rust-bpf (see README.md):
#
#   verus src/trusted, src/rt, the policy, the userspace core   (proofs)
#   rustc --target bpfel-unknown-none-v4.json --emit=llvm-bc  (LLVM bitcode)
#   llvm-link core + compiler_builtins + the lib crates + multi3
#   bpf-postproc                                               (CO-RE relocs)
#   opt -internalize -globaldce -O2                            (strip the rest)
#   add_ksyms.py                                               (.ksyms + BTF)
#   btf_fixup.py                              (BTF the kernel will accept)
#   llc -march=bpfel -mcpu=v4                                  (the .o)
#   cargo build --release                        (the userspace loader)
#
# There is no allocator and no liballoc: the only kfuncs a #[global_allocator]
# could call are out-of-tree, so BPF programs built here are heap-free and
# `core` is the whole runtime. Run `make help` for the variable list.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all

# This file, and the Makefile that included it.
TOOLCHAIN_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PROG_DIR := $(abspath $(dir $(firstword $(MAKEFILE_LIST))))
ROOT_DIR ?= $(abspath $(TOOLCHAIN_DIR)/../..)
BUILD_DIR ?= $(ROOT_DIR)/build

ifeq ($(strip $(PROG)),)
$(error include ../toolchain/rules.mk with PROG set to the program name)
endif
# Relative to the program directory unless it is already absolute, so a
# program Makefile writes `SRC := bpf/main.rs` and not a path expression.
SRC ?= $(PROG).rs
SRC := $(abspath $(if $(filter /%,$(SRC)),$(SRC),$(PROG_DIR)/$(SRC)))

OUT := $(BUILD_DIR)/$(PROG)
# Persistent across `clean` — the libcore build dominates a cold build and
# depends only on RUSTC/RUST_SRC, not on program source.
DEPDIR ?= $(BUILD_DIR)/rust-deps
HOSTDIR ?= $(BUILD_DIR)/host

# --- toolchain -------------------------------------------------------------
# The toolchain is Verus's pin (dep/verus/rust-toolchain.toml): one rustc
# serves the verification pass, the proc macros, libcore and the BPF compile.
# Its LLVM must not be newer than the LLVM tools below -- bitcode reads
# forward only. See README.md, "Toolchain matrix".
RUSTUP_HOME ?= $(HOME)/.rustup
RUST_TOOLCHAIN ?= 1.98.0-x86_64-unknown-linux-gnu
RUSTC ?= $(RUSTUP_HOME)/toolchains/$(RUST_TOOLCHAIN)/bin/rustc
RUST_SRC ?= $(RUSTUP_HOME)/toolchains/$(RUST_TOOLCHAIN)/lib/rustlib/src/rust/library
# Same toolchain's cargo, so the host proc-macro .so matches the rustc that
# will dlopen it.
CARGO ?= $(RUSTUP_HOME)/toolchains/$(RUST_TOOLCHAIN)/bin/cargo
# The toolchain root RUSTC/RUST_SRC/CARGO are rooted under. rust-project.json
# names it so that rust-analyzer, normally a stable build on PATH, expands
# proc macros with *this* toolchain's own
# <sysroot>/libexec/rust-analyzer-proc-macro-srv instead: a proc-macro
# dylib has to be loaded by a server built by the same compiler that built
# it. See the `rust-project` target below.
RA_SYSROOT ?= $(RUSTUP_HOME)/toolchains/$(RUST_TOOLCHAIN)

LLVM_PREFIX ?= /usr
LLC ?= $(LLVM_PREFIX)/bin/llc
OPT ?= $(LLVM_PREFIX)/bin/opt
LLVM_LINK ?= $(LLVM_PREFIX)/bin/llvm-link
LLVM_AS ?= $(LLVM_PREFIX)/bin/llvm-as
LLVM_DIS ?= $(LLVM_PREFIX)/bin/llvm-dis
LLVM_OBJCOPY ?= $(LLVM_PREFIX)/bin/llvm-objcopy
# llvm-sys finds LLVM through llvm-config on PATH.
LLVM_CONFIG_DIR ?= $(LLVM_PREFIX)/bin

# bpf-postproc links llvm-sys. Static linking against llvm-static pulls
# std::__glibcxx_assert_fail, which RHEL 9's base libstdc++ lacks; the shared
# libLLVM has it resolved internally, so link dynamically. Passed on the
# cargo command line so that the imported Cargo.toml stays untouched.
POSTPROC_FEATURES ?= llvm-sys-22/prefer-dynamic

PYTHON ?= python3
# /usr/local/bin/bpftool is a wrapper script on some hosts; add_ksyms.py
# execs the path directly, so default to the real binary.
BPFTOOL ?= /usr/sbin/bpftool

# --- Verus -----------------------------------------------------------------
# Built by `make verus` at the repository root. VERUS_DIR can point at an
# external checkout instead of the submodule.
VERUS_DIR ?= $(ROOT_DIR)/dep/verus
VERUS_TARGET ?= $(VERUS_DIR)/source/target-verus/release
VERUS ?= $(VERUS_TARGET)/verus
VERUS_MACROS_SO ?= $(VERUS_TARGET)/libverus_builtin_macros.so
# Set VERIFY=0 to skip verification when debugging the compile pipeline.
VERIFY ?= 1

# --- target kernel ---------------------------------------------------------
# add_ksyms.py mirrors kfunc prototypes out of this vmlinux's BTF, so it must
# be the kernel the object will be loaded into.
KERNEL_DIR ?= /home/kkd/src/linux
KERNEL_BUILD ?= $(KERNEL_DIR)/.kdev/build/kernel
VMLINUX ?= $(KERNEL_BUILD)/vmlinux

# ---------------------------------------------------------------------------

TARGET_JSON := $(TOOLCHAIN_DIR)/bpfel-unknown-none-v4.json
ADD_KSYMS := $(TOOLCHAIN_DIR)/add_ksyms.py
BTF_FIXUP := $(TOOLCHAIN_DIR)/btf_fixup.py
MULTI3_LL := $(TOOLCHAIN_DIR)/multi3.ll
BTF_CRATE := $(TOOLCHAIN_DIR)/btf/src/lib.rs
BTF_MACROS_DIR := $(TOOLCHAIN_DIR)/btf-macros
POSTPROC_DIR := $(TOOLCHAIN_DIR)/bpf-postproc

BTF_MACROS_SO := $(HOSTDIR)/btf-macros/release/libbtf_macros.so
# cargo writes the proc-macro dylib twice: once under a plain name and once
# under the hashed name that rustc's `-L dependency` search expects when
# resolving it as a *transitive* dependency of an already-built rlib.
# `--extern` only covers direct dependencies, so both are needed.
BTF_MACROS_DEPS := $(HOSTDIR)/btf-macros/release/deps
POSTPROC := $(HOSTDIR)/bpf-postproc/release/bpf-postproc
# Verification is a host-target compile of the crate, because Verus links
# its own host-target vstd and verus_builtin. Known simplification: the
# proof is about the source, and the BPF-target compile that follows is a
# separate, erased pass over the same file.
HOST_DEPS := $(HOSTDIR)/rust-deps
HOST_BTF_RLIB := $(HOST_DEPS)/libbtf.rlib

# --- the library crates ----------------------------------------------------
# An ordered list. Each crate is verified and compiled against the ones
# before it, and the policy against all of them. src/trusted holds every
# Verus cheat and every `unsafe` in the tree; src/rt is the checked layer
# on top of it. Each is compiled twice, like a policy: verified on the
# host, erased for BPF.
LIB_CRATES := lachesis_trusted lachesis_rt
lachesis_trusted_DIR ?= $(ROOT_DIR)/src/trusted
lachesis_rt_DIR ?= $(ROOT_DIR)/src/rt

# --no-cheating is not the per-crate property it looks like: Verus runs the
# check over the merged crate graph, so a crate that *calls* an
# external_body function out of lachesis_trusted is rejected too, even
# though the cheat is not its own. The flag is therefore set on every crate
# that does not, and `lint-trusted` is what keeps cheats out of the rest.
# See README.md, "Three crates". A policy joins the list under its PROG
# name once it stops calling anything trusted directly.
NOCHEAT_CRATES := lachesis_rt
nocheat = $(if $(filter $(1),$(NOCHEAT_CRATES)),--no-cheating)

HOST_VERUS_DIR := $(HOSTDIR)/verus
# `verus --compile` keeps the ghost signatures in the metadata, which is
# what a dependent crate's verification pass type-checks against; the .vir
# alongside it carries the proofs.
host_vir = $(HOST_VERUS_DIR)/$(1).vir
host_rlib = $(HOST_VERUS_DIR)/lib$(1).rlib
bpf_rlib = $(DEPDIR)/lib$(1).rlib
host_imports = $(foreach c,$(1),--extern $(c)=$(call host_rlib,$(c)) --import $(c)=$(call host_vir,$(c)))
bpf_externs = $(foreach c,$(1),--extern $(c)=$(call bpf_rlib,$(c)))

# Each crate's predecessors in LIB_CRATES, so a rule can name what it
# imports without repeating the list.
PREV_CRATES :=
$(foreach c,$(LIB_CRATES),$(eval $(c)_PREV := $(PREV_CRATES))$(eval PREV_CRATES := $(PREV_CRATES) $(c)))

LIB_VIRS := $(foreach c,$(LIB_CRATES),$(call host_vir,$(c)))
LIB_HOST_RLIBS := $(foreach c,$(LIB_CRATES),$(call host_rlib,$(c)))
LIB_BPF_RLIBS := $(foreach c,$(LIB_CRATES),$(call bpf_rlib,$(c)))

# Flags the compile pass needs so that the erased crate still parses: the
# `verus!` macro itself, and the register_tool attributes the Verus driver
# adds so that any `#[verifier::...]` left in erased code is accepted.
# Deliberately no `--cfg verus_keep_ghost`: its absence is what makes the
# macro erase ghost code.
VERUS_ERASE_FLAGS := --extern verus_builtin_macros=$(VERUS_MACROS_SO) \
	'-Zcrate-attr=feature(register_tool)' \
	'-Zcrate-attr=register_tool(verus)' \
	'-Zcrate-attr=register_tool(verifier)' \
	'-Zcrate-attr=register_tool(verusfmt)' \
	--check-cfg 'cfg(verus_keep_ghost)' \
	--check-cfg 'cfg(verus_keep_ghost_body)'

# Where rustc looks for a dependency's own dependencies. `--extern` covers
# a crate's *direct* dependencies only; loading lachesis_rt's metadata makes
# rustc resolve lachesis_trusted, and loading that one makes it resolve
# `btf`, `btf_macros` and `verus_builtin_macros`, all by search path. The
# proc-macro has to be found under the hashed filename cargo gave it, which
# is why BTF_MACROS_DEPS and not just BTF_MACROS_SO.
DEP_SEARCH := -L dependency=$(BTF_MACROS_DEPS) -L dependency=$(VERUS_TARGET)
HOST_DEP_SEARCH := -L dependency=$(HOST_VERUS_DIR) -L dependency=$(HOST_DEPS) \
	-L dependency=$(BTF_MACROS_DEPS)

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON := --target $(TARGET_JSON) -C opt-level=3 -C panic=unwind \
	-C debuginfo=2 -Z unstable-options -Z threads=64

# Symbols opt must not internalize: the struct_ops map, its entry points,
# the license, and anything userspace reads back out of the maps.
KEEP_SYMS ?=
INTERNALIZE := $(foreach s,$(KEEP_SYMS),--internalize-public-api-list=$(s))

# --- the userspace side ----------------------------------------------------
# Optional, and driven entirely by two paths a program directory sets, both
# relative to it: USER_MANIFEST, a Cargo.toml whose binary is named $(PROG),
# and USER_CORE_SRC, the lib.rs of that project's verified core crate. Set
# neither and nothing below happens; the BPF object is still the default
# goal either way.
#
# The split is the point: the binary is ordinary std Rust with a
# dependency graph Verus never sees, so it is not verified, while the core
# is pure logic in its own crate and is verified exactly like a library
# crate here -- with --no-cheating, since it calls nothing trusted.
USER_MANIFEST ?=
USER_CORE_SRC ?=
USER_CORE_NAME ?= $(PROG)_core
abs_prog_path = $(abspath $(if $(filter /%,$(1)),$(1),$(PROG_DIR)/$(1)))
ifneq ($(strip $(USER_MANIFEST)),)
USER_MANIFEST := $(call abs_prog_path,$(USER_MANIFEST))
USER_DIR := $(dir $(USER_MANIFEST))
USER_BIN := $(OUT)/$(PROG)
# cargo writes here and nowhere else, so nothing lands in the source tree
# and nothing in dep/. Like DEPDIR and the host tool builds it is a cache:
# `clean` keeps it, `distclean` drops it.
USER_TARGET_DIR ?= $(HOSTDIR)/$(PROG)-user
endif
ifneq ($(strip $(USER_CORE_SRC)),)
USER_CORE_SRC := $(call abs_prog_path,$(USER_CORE_SRC))
USER_CORE_SRCS := $(wildcard $(dir $(USER_CORE_SRC))*.rs)
USER_CORE_LOG := $(OUT)/$(USER_CORE_NAME).verify.log
USER_CORE_STAMP := $(OUT)/$(USER_CORE_NAME).verify.stamp
# VERIFY_ON is set further down, so this one has to stay recursive.
USER_CORE_DEP = $(if $(VERIFY_ON),$(USER_CORE_STAMP))
endif

RLIBS := $(DEPDIR)/libcore.rlib $(DEPDIR)/libcompiler_builtins.rlib

# Fail unless a Verus log reports a run with no errors. Verus exits 0 on a
# crate it declined to look at, so the results line is the real check.
define check_verified
	@grep -E '^verification results::' $(1) || { \
		echo "verify: no verification results in $(1)" >&2; \
		cat $(1) >&2; exit 1; }
	@grep -qE '^verification results:: [0-9]+ verified, 0 errors' $(1) || { \
		cat $(1) >&2; exit 1; }
endef

ifeq ($(VERIFY),0)
VERIFY_ON :=
VERIFY_DEP :=
else
VERIFY_ON := 1
VERIFY_DEP := $(OUT)/verify.stamp
endif

.PHONY: all clean distclean help verify lint-trusted trusted-lines rust-project
all: $(OUT)/$(PROG).o $(USER_BIN)

# --- core ---
$(DEPDIR)/libcore.rlib: $(RUST_SRC)/core/src/lib.rs
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null \
		--cfg 'no_fp_fmt_parse' \
		--crate-name core \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcore.rmeta \
		$<

# --- compiler_builtins (stub) ---
$(DEPDIR)/libcompiler_builtins.rlib: $(DEPDIR)/libcore.rlib
	@mkdir -p $(DEPDIR)
	echo '#![no_std]' '#![feature(compiler_builtins,rustc_attrs)]' '#![compiler_builtins]' '#![allow(internal_features)]' | \
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name compiler_builtins \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libcompiler_builtins.rmeta \
		-

# --- multi3 intrinsic ---
$(DEPDIR)/multi3.bc: $(MULTI3_LL)
	@mkdir -p $(DEPDIR)
	$(LLVM_AS) $< -o $@

# --- btf runtime crate (no_std, BPF target) ---
$(DEPDIR)/libbtf.rlib: $(BTF_CRATE) $(DEPDIR)/libcore.rlib
	@mkdir -p $(DEPDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name btf \
		--emit=link=$@ --emit=metadata=$(DEPDIR)/libbtf.rmeta \
		$<

# --- btf-macros proc-macro crate (host) ---
# Built with cargo because it depends on syn/quote/proc-macro2. Proc-macro
# crates are always host-targeted; rustc loads the .so when expanding #[btf]
# in a BPF-target build.
$(BTF_MACROS_SO): $(wildcard $(BTF_MACROS_DIR)/src/*.rs) $(BTF_MACROS_DIR)/Cargo.toml
	cd $(BTF_MACROS_DIR) && \
		CARGO_TARGET_DIR=$(HOSTDIR)/btf-macros RUSTC=$(RUSTC) $(CARGO) build --release

# --- bpf-postproc tool (host) ---
# Lowers the #[btf] __btf_field_byte_offset / __btf_field_exists polyfills
# into llvm.preserve.struct.access.index chains plus
# llvm.bpf.preserve.field.info calls, so the BPF backend emits CO-RE
# relocations.
$(POSTPROC): $(wildcard $(POSTPROC_DIR)/src/*.rs) $(POSTPROC_DIR)/Cargo.toml
	cd $(POSTPROC_DIR) && \
		CARGO_TARGET_DIR=$(HOSTDIR)/bpf-postproc \
		PATH="$(LLVM_CONFIG_DIR):$$PATH" \
		$(CARGO) build --release --features $(POSTPROC_FEATURES)

# --- btf runtime crate, host target (for the verification pass) ---
$(HOST_BTF_RLIB): $(BTF_CRATE)
	@mkdir -p $(dir $@)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib \
		--crate-name btf -C opt-level=0 -o $@ $<

# --- trusted-base lint ---
# The roadmap makes a trusted/ directory the only place a proof may be
# short-circuited, and src/trusted is the only one. Nothing else in src/ may
# assume, admit, hand Verus a body it does not check, or write `unsafe`.
# src/toolchain is excluded: it is the imported compile pipeline, already
# trusted as a whole by roadmap section 3.7 item 5.
LINT_SRC := $(ROOT_DIR)/src
CHEAT_RE := assume\(|admit\(|external_body|assume_specification|external_fn_specification|verifier::external\]
LINT_SKIP := /trusted/ /toolchain/

# The loader is not verified and is not going to be: it is argument
# parsing, libbpf-rs, signals and printing. `unsafe` there is expected --
# installing a signal handler needs it -- so the directory holding the
# binary's own sources is exempt from the unsafe half of the lint, the way
# src/trusted and src/toolchain are. Nothing else in the cargo project is:
# the verified core beside it is checked like any other crate, and the
# cheat half of the lint still covers the loader, where a Verus escape
# hatch would make no sense at all.
LINT_UNSAFE_SKIP = $(if $(USER_MANIFEST),$(USER_DIR)src/)

# $(call lint_forbid,<regex>,<what>[,<extra skip patterns>]). Skips
# LINT_SKIP, and skips whole-line comments so that prose about the rule
# does not trip it.
define lint_forbid
	@hits=$$(grep -RnE '$(1)' $(LINT_SRC) --include='*.rs' | \
		grep -v $(foreach p,$(LINT_SKIP) $(3),-e '$(p)') | \
		grep -vE ':[0-9]+:[[:space:]]*(//|\*)' || true); \
	if [[ -n "$$hits" ]]; then \
		echo "lint-trusted: $(2) outside src/trusted/:" >&2; \
		echo "$$hits" >&2; \
		exit 1; \
	fi
endef

lint-trusted:
	$(call lint_forbid,$(CHEAT_RE),proof escape hatches)
	$(call lint_forbid,\bunsafe\b,unsafe,$(LINT_UNSAFE_SKIP))
	@echo "lint-trusted: clean$(if $(LINT_UNSAFE_SKIP), (unsafe exempt: $(patsubst $(ROOT_DIR)/%,%,$(LINT_UNSAFE_SKIP))))"

# The size of what nothing checks, printed by `verify` so that growth is
# visible on every run (roadmap section 3.7): the BPF trusted base, and
# next to it the loader.
trusted-lines:
	@wc -l $(lachesis_trusted_DIR)/*.rs | sed 's|$(ROOT_DIR)/||'
	@$(if $(USER_MANIFEST),wc -l $(USER_DIR)src/*.rs | sed 's|$(ROOT_DIR)/||')

# --- verification and the erased compile, per library crate ---
# One template, applied to LIB_CRATES in order.
define lib_crate_rules
$(1)_SRCS := $$(wildcard $$($(1)_DIR)/*.rs)
$(1)_VIR := $$(call host_vir,$(1))
$(1)_HOST_RLIB := $$(call host_rlib,$(1))
$(1)_BPF_RLIB := $$(call bpf_rlib,$(1))
$(1)_LOG := $$(HOST_VERUS_DIR)/$(1).verify.log
$(1)_VERIFY_DEP := $$(if $$(VERIFY_ON),$$($(1)_VIR))

# Verification: a host-target compile of the crate under the Verus driver,
# which supplies vstd and sets verus_keep_ghost so the macro keeps the
# ghost code it then checks. --compile also emits the host rlib a dependent
# crate type-checks against; --export writes the proofs it imports. Known
# simplification: the proof is about the source, and the BPF-target compile
# that follows is a separate, erased pass over the same file.
$$($(1)_VIR): $$($(1)_SRCS) $$(HOST_BTF_RLIB) $$(BTF_MACROS_SO) $$(VERUS) \
		$$(foreach c,$$($(1)_PREV),$$(call host_vir,$$(c))) | lint-trusted
	@mkdir -p $$(HOST_VERUS_DIR)
	$$(VERUS) $$(call nocheat,$(1)) --crate-type=lib --crate-name $(1) \
		--compile --export $$@ --out-dir $$(HOST_VERUS_DIR) \
		--extern btf=$$(HOST_BTF_RLIB) \
		--extern btf_macros=$$(BTF_MACROS_SO) \
		$$(call host_imports,$$($(1)_PREV)) $$(HOST_DEP_SEARCH) \
		$$($(1)_DIR)/lib.rs > $$($(1)_LOG) 2>&1 || \
		{ cat $$($(1)_LOG) >&2; exit 1; }
	$$(call check_verified,$$($(1)_LOG))

# --compile writes both; this keeps make from running the rule twice.
$$($(1)_HOST_RLIB): $$($(1)_VIR)
	@:

# The erased pass. Emitted as an rlib whose members are bitcode (the target
# JSON sets obj-is-bitcode), so it links like libcore does.
$$($(1)_BPF_RLIB): $$($(1)_SRCS) $$(RLIBS) $$(DEPDIR)/libbtf.rlib $$(BTF_MACROS_SO) \
		$$(foreach c,$$($(1)_PREV),$$(call bpf_rlib,$$(c))) $$($(1)_VERIFY_DEP)
	@mkdir -p $$(DEPDIR)
	$$(RUSTFLAGS_ENV) $$(RUSTC) --edition 2021 --crate-type rlib $$(RUSTC_COMMON) \
		--sysroot=/dev/null -L$$(DEPDIR) $$(DEP_SEARCH) \
		--extern btf=$$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$$(BTF_MACROS_SO) \
		$$(call bpf_externs,$$($(1)_PREV)) \
		$$(VERUS_ERASE_FLAGS) \
		--crate-name $(1) \
		--emit=link=$$@ --emit=metadata=$$(DEPDIR)/lib$(1).rmeta \
		$$($(1)_DIR)/lib.rs
endef

$(foreach c,$(LIB_CRATES),$(eval $(call lib_crate_rules,$(c))))

# --- verification, the userspace core ---
# A crate of its own, and a leaf: it imports none of the BPF crates and
# depends on nothing but the `verus!` macro, so its pass names no rlibs and
# no search paths. --no-cheating is unconditional here; a core that needs a
# cheat is a core that has stopped being pure logic.
ifneq ($(strip $(USER_CORE_SRC)),)
$(USER_CORE_STAMP): $(USER_CORE_SRCS) $(VERUS) | lint-trusted
	@mkdir -p $(OUT)
	$(VERUS) --no-cheating --crate-type=lib --crate-name $(USER_CORE_NAME) \
		$(USER_CORE_SRC) > $(USER_CORE_LOG) 2>&1 || \
		{ cat $(USER_CORE_LOG) >&2; exit 1; }
	$(call check_verified,$(USER_CORE_LOG))
	@touch $@
endif

# --- verification, the policy ---
# It imports every library crate: the proofs from the .vir files, the ghost
# signatures from the host rlibs.
$(OUT)/verify.stamp: $(SRC) $(LIB_VIRS) $(LIB_HOST_RLIBS) $(HOST_BTF_RLIB) \
		$(BTF_MACROS_SO) $(VERUS) | lint-trusted
	@mkdir -p $(OUT)
	$(VERUS) $(call nocheat,$(PROG)) --crate-type=lib --crate-name $(PROG) \
		$(call host_imports,$(LIB_CRATES)) $(HOST_DEP_SEARCH) \
		$(SRC) > $(OUT)/verify.log 2>&1 || { cat $(OUT)/verify.log >&2; exit 1; }
	$(call check_verified,$(OUT)/verify.log)
	@touch $@

verify: $(OUT)/verify.stamp $(if $(USER_CORE_SRC),$(USER_CORE_STAMP))
	@$(foreach c,$(LIB_CRATES),printf '%-18s %s\n' '$(c)' \
		"$$(grep -E '^verification results::' $($(c)_LOG))";)
	@printf '%-18s %s\n' '$(PROG)' \
		"$$(grep -E '^verification results::' $(OUT)/verify.log)"
	@$(if $(USER_CORE_SRC),printf '%-18s %s\n' '$(USER_CORE_NAME)' \
		"$$(grep -E '^verification results::' $(USER_CORE_LOG))")
	@$(MAKE) --no-print-directory trusted-lines

# --- BPF program bitcode ---
# The erased pass. No --cfg verus_keep_ghost, so the verus! macro drops the
# specs and proofs and emits plain Rust.
$(OUT)/$(PROG).bc: $(SRC) $(RLIBS) $(DEPDIR)/libbtf.rlib $(LIB_BPF_RLIBS) $(BTF_MACROS_SO) \
		$(VERIFY_DEP) $(USER_CORE_DEP)
	@mkdir -p $(OUT)
ifeq ($(VERIFY),0)
	@echo '*** VERIFY=0: building UNVERIFIED; do not trust this object ***' >&2
endif
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) $(DEP_SEARCH) \
		--extern btf=$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$(BTF_MACROS_SO) \
		$(call bpf_externs,$(LIB_CRATES)) \
		$(VERUS_ERASE_FLAGS) \
		--crate-name $(PROG) \
		--emit=llvm-bc -o $@ $<

# --- extract .rlib contents for linking ---
$(DEPDIR)/extracted.stamp: $(RLIBS) $(LIB_BPF_RLIBS)
	@rm -rf $(DEPDIR)/extracted
	@for lib in $^; do \
		name=$$(basename $$lib .rlib | sed 's/^lib//'); \
		mkdir -p $(DEPDIR)/extracted/$$name; \
		cd $(DEPDIR)/extracted/$$name && ar x $$lib; \
	done
	@touch $@

# --- link all bitcode ---
$(OUT)/$(PROG)-linked.bc: $(OUT)/$(PROG).bc $(DEPDIR)/extracted.stamp $(DEPDIR)/multi3.bc
	@cp $< $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(DEPDIR)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(DEPDIR)/multi3.bc -o $@.tmp && mv $@.tmp $@

# --- lower btf polyfills to CO-RE relocations ---
$(OUT)/$(PROG)-reloc.bc: $(OUT)/$(PROG)-linked.bc $(POSTPROC)
	$(POSTPROC) $< $@

# --- internalize everything but the entry points, then optimize ---
$(OUT)/$(PROG)-opt.bc: $(OUT)/$(PROG)-reloc.bc
	$(OPT) $(INTERNALIZE) --force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $< -o $@

# --- add .ksyms, lower invoke->call and unreachable->ret, fix up BTF ---
# KSYM_BTF_FILES makes add_ksyms.py mirror the target kernel's kfunc
# prototypes; without it libbpf rejects the object because a guessed void*
# argument is not BTF-compatible with a struct pointer.
$(OUT)/$(PROG)-ksyms.bc: $(OUT)/$(PROG)-opt.bc $(ADD_KSYMS) $(BTF_FIXUP) $(VMLINUX)
	$(LLVM_DIS) $< -o $@.ll
	KSYM_BTF_FILES=$(VMLINUX) BPFTOOL=$(BPFTOOL) $(PYTHON) $(ADD_KSYMS) $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	KSYM_BTF_FILES=$(VMLINUX) BPFTOOL=$(BPFTOOL) $(PYTHON) $(ADD_KSYMS) $@.ll $@.ll
	$(PYTHON) $(BTF_FIXUP) $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# --- final BPF object ---
$(OUT)/$(PROG).o: $(OUT)/$(PROG)-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp
	@echo "built $@"

# --- the userspace binary --------------------------------------------------
# Plain cargo, with the same pinned rustc as everything else: cargo would
# otherwise resolve `rustc` through the rustup shim, which picks a toolchain
# from the *callee's* directory and would build the path dependencies on
# dep/verus with Verus's pin and the registry crates with the default
# toolchain, which then refuse to link. The verified core is a member of the
# same cargo workspace and is compiled here with ghost code erased, exactly
# like the BPF crates: this cargo run does not set `verus_keep_ghost`.
ifneq ($(strip $(USER_MANIFEST)),)
$(USER_BIN): $(wildcard $(USER_DIR)Cargo.toml $(USER_DIR)Cargo.lock \
		$(USER_DIR)src/*.rs) $(USER_CORE_SRCS) \
		$(wildcard $(dir $(USER_CORE_SRC))../Cargo.toml) $(USER_CORE_DEP)
	@mkdir -p $(OUT)
	CARGO_TARGET_DIR=$(USER_TARGET_DIR) RUSTC=$(RUSTC) \
		$(CARGO) build --release --manifest-path $(USER_MANIFEST) --bin $(PROG)
	@install -m 0755 $(USER_TARGET_DIR)/release/$(PROG) $@
	@echo "built $@"
endif

# --- rust-analyzer project file --------------------------------------------
# There is no Cargo workspace -- every crate above is built by bare rustc --
# so rust-project.json is the only way rust-analyzer can see them. Two
# problems block a hand-written one from just naming the real
# VERUS_MACROS_SO:
#
#  1. rust-analyzer on PATH is typically a stable build, but these crates
#     are compiled by $(RUST_TOOLCHAIN)'s rustc, and a proc-macro dylib has
#     to be expanded by a server built by the same compiler that built it.
#     Naming RA_SYSROOT in the project file is what makes rust-analyzer use
#     that toolchain's own proc-macro server instead of its own.
#  2. The `verus!` macro, built the normal way (VERUS_MACROS_SO), panics
#     under rust-analyzer's server with "cfg_erase call failed": it uses
#     the unstable `expand_expr` bridge call, which that server does not
#     implement. Verus's macro crate has an always-erase code path, taken
#     when the crate is built WITHOUT `--cfg verus_keep_ghost` -- exactly
#     like the BPF erased-compile rules above -- but dep/verus's own
#     .cargo/config.toml injects that cfg into every cargo build via
#     `rustflags`, so it has to be overridden with an explicit RUSTFLAGS
#     that omits it (cargo does not merge the two; the environment wins
#     outright). RA_VERUS_MACROS_SO is that erase-only dylib, built with its
#     own CARGO_TARGET_DIR so nothing lands in dep/verus. It is for
#     rust-analyzer only -- the real BPF compile keeps using
#     VERUS_MACROS_SO, built by `make verus`.
RA_DIR := $(HOSTDIR)/verus-macros-erase
RA_VERUS_MACROS_SO := $(RA_DIR)/release/libverus_builtin_macros.so
RA_VERUS_BUILTIN_MACROS_DIR := $(VERUS_DIR)/source/builtin_macros
GEN_RUST_PROJECT := $(TOOLCHAIN_DIR)/gen_rust_project.py
RUST_PROJECT_JSON ?= $(ROOT_DIR)/rust-project.json

$(RA_VERUS_MACROS_SO): $(wildcard $(RA_VERUS_BUILTIN_MACROS_DIR)/src/*.rs) \
		$(RA_VERUS_BUILTIN_MACROS_DIR)/Cargo.toml
	cd $(VERUS_DIR)/source && \
		CARGO_TARGET_DIR=$(RA_DIR) RUSTC_BOOTSTRAP=1 \
		RUSTFLAGS="--cfg proc_macro_span --cfg procmacro2_semver_exempt --cfg span_locations" \
		$(CARGO) build --release -p verus_builtin_macros

# Crate list generated from LIB_CRATES, so a fourth library crate needs no
# change here; see gen_rust_project.py for the dependency edges, which are
# not otherwise derivable from LIB_CRATES order alone.
.PHONY: rust-project
rust-project: $(BTF_MACROS_SO) $(RA_VERUS_MACROS_SO)
	$(PYTHON) $(GEN_RUST_PROJECT) \
		--sysroot $(RA_SYSROOT) \
		--sysroot-src $(RUST_SRC) \
		--btf btf:$(BTF_CRATE):2024 \
		--btf-macros btf_macros:$(BTF_MACROS_DIR)/src/lib.rs:2021:$(BTF_MACROS_SO) \
		--verus-macros verus_builtin_macros:$(RA_VERUS_BUILTIN_MACROS_DIR)/src/lib.rs:2018:$(RA_VERUS_MACROS_SO) \
		$(foreach c,$(LIB_CRATES),--lib-crate $(c):$($(c)_DIR)/lib.rs:2021) \
		--policy $(PROG):$(SRC):2021 \
		--out $(RUST_PROJECT_JSON)
	@echo "wrote $(RUST_PROJECT_JSON)"

clean:
	rm -rf $(OUT)

distclean: clean
	rm -rf $(DEPDIR) $(HOSTDIR)

help:
	@printf '%s\n' \
		'Targets:' \
		'  all           Verify, then build $$(OUT)/$$(PROG).o and the loader' \
		'  verify        Run Verus over $$(LIB_CRATES) and $$(SRC)' \
		'  lint-trusted  Forbid cheats and unsafe outside src/trusted/' \
		'  trusted-lines Print the size of the trusted base' \
		'  rust-project  Write $$(RUST_PROJECT_JSON) for rust-analyzer' \
		'  clean         Remove the per-program build directory' \
		'  distclean     Also remove the cached rustc/host-tool builds' \
		'' \
		'Set by the including Makefile:' \
		'  PROG=$(PROG)' \
		'  SRC=$(SRC)' \
		'  KEEP_SYMS=$(KEEP_SYMS)' \
		'  USER_MANIFEST=$(USER_MANIFEST)' \
		'  USER_CORE_SRC=$(USER_CORE_SRC)' \
		'' \
		'Variables (all ?= overridable):' \
		'  BUILD_DIR=$(BUILD_DIR)' \
		'  DEPDIR=$(DEPDIR)' \
		'  HOSTDIR=$(HOSTDIR)' \
		'  RUST_TOOLCHAIN=$(RUST_TOOLCHAIN)' \
		'  RUSTC=$(RUSTC)' \
		'  RUST_SRC=$(RUST_SRC)' \
		'  CARGO=$(CARGO)' \
		'  RA_SYSROOT=$(RA_SYSROOT)' \
		'  RUST_PROJECT_JSON=$(RUST_PROJECT_JSON)' \
		'  LLVM_PREFIX=$(LLVM_PREFIX)   (llc/opt/llvm-link/llvm-as/llvm-dis/llvm-objcopy)' \
		'  POSTPROC_FEATURES=$(POSTPROC_FEATURES)' \
		'  PYTHON=$(PYTHON)' \
		'  BPFTOOL=$(BPFTOOL)' \
		'  LIB_CRATES=$(LIB_CRATES)' \
		'  USER_CORE_NAME=$(USER_CORE_NAME)' \
		'  USER_TARGET_DIR=$(USER_TARGET_DIR)' \
		'  NOCHEAT_CRATES=$(NOCHEAT_CRATES)' \
		$(foreach c,$(LIB_CRATES),'  $(c)_DIR=$($(c)_DIR)') \
		'  VERUS_DIR=$(VERUS_DIR)' \
		'  VERUS=$(VERUS)' \
		'  VERIFY=$(VERIFY)   (0 skips verification, loudly)' \
		'  KERNEL_DIR=$(KERNEL_DIR)' \
		'  KERNEL_BUILD=$(KERNEL_BUILD)' \
		'  VMLINUX=$(VMLINUX)'
