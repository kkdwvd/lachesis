SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KKD_DIR ?= $(ROOT_DIR)/dep/kkd
VERUS_DIR ?= $(ROOT_DIR)/dep/verus

GIT ?= git
PYTHON ?= python3
KKD_REBASE_REMOTE ?= origin
KKD_REBASE_BRANCH ?= main
KKD_REBASE_URL ?=
VERUS_REBASE_REMOTE ?= origin
VERUS_REBASE_BRANCH ?= main
VERUS_REBASE_URL ?=

# --- scx_lachesis: the Rust sched_ext scheduler, built through src/toolchain ---
BUILD_DIR ?= $(ROOT_DIR)/build
SCX_LACHESIS_DIR ?= $(ROOT_DIR)/src/scx_lachesis
SCX_LACHESIS_OUT ?= $(BUILD_DIR)/scx_lachesis
SCX_LACHESIS_OBJ ?= $(SCX_LACHESIS_OUT)/scx_lachesis.o
SCX_LACHESIS_BIN ?= $(SCX_LACHESIS_OUT)/scx_lachesis
# Kernel the object is built against and run on. It must have
# CONFIG_SCHED_CLASS_EXT=y and BTF, and its vmlinux is what add_ksyms.py
# mirrors kfunc prototypes from.
KERNEL_DIR ?= /home/kkd/src/linux
KERNEL_BUILD ?= $(KERNEL_DIR)/.kdev/build/kernel
# Seconds of workload to run under the scheduler in the guest.
SCX_LACHESIS_SECS ?= 5

SCX_LACHESIS_MAKE = $(MAKE) -C $(SCX_LACHESIS_DIR) \
	BUILD_DIR=$(BUILD_DIR) KERNEL_DIR=$(KERNEL_DIR) \
	KERNEL_BUILD=$(KERNEL_BUILD) VERUS_DIR=$(VERUS_DIR)

# --- Verus ---
# Built out of the pinned submodule with vstd in no_std/no_alloc mode, so it
# can be linked against a #![no_std] crate that owns its own panic handler.
VERUS_SOURCE := $(VERUS_DIR)/source
VERUS_TARGET := $(VERUS_SOURCE)/target-verus/release
VERUS_BIN := $(VERUS_TARGET)/verus
VERUS_Z3 := $(VERUS_SOURCE)/z3
VERUS_Z3_VERSION ?= 4.16.0
# Upstream's get-z3.sh fetches a build linked against glibc 2.39; RHEL 9 has
# 2.34. The z3-solver wheel for the same release is a manylinux_2_27 build of
# the same version, so fall back to it when the release binary will not run.
VERUS_Z3_WHEEL ?= https://github.com/Z3Prover/z3/releases/download/z3-$(VERUS_Z3_VERSION)/z3_solver-$(VERUS_Z3_VERSION).0-py3-none-manylinux_2_27_x86_64.whl

.PHONY: help \
	kkd-sync verus-sync all-sync sync \
	kkd-rebase verus-rebase all-rebase rebase \
	verus verus-clean \
	verify scx-lachesis scx-lachesis-run scx-lachesis-clean rust-project

.NOTPARALLEL: all-sync

define sync_repo
	@if [[ ! -e "$(1)/.git" ]]; then \
		echo "$(2) checkout is missing at $(1); run 'git submodule update --init'" >&2; \
		exit 1; \
	fi; \
	branch="$$($(GIT) -C "$(1)" symbolic-ref --quiet --short HEAD)" || { \
		echo "$(2) is on a detached HEAD; attach its working branch first" >&2; \
		exit 1; \
	}; \
	upstream="$$($(GIT) -C "$(1)" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" || { \
		echo "$(2) branch '$$branch' has no tracking branch" >&2; \
		exit 1; \
	}; \
	if ! $(GIT) -C "$(1)" diff --quiet || \
	   ! $(GIT) -C "$(1)" diff --cached --quiet; then \
		echo "$(2) has tracked or staged changes; commit or stash them before syncing" >&2; \
		exit 1; \
	fi; \
	echo "Syncing $(2) $$branch onto $$upstream"; \
	$(GIT) -c commit.gpgsign=false -C "$(1)" pull --rebase --no-autostash
endef

# $(call rebase_repo,<dir>,<name>,<remote>,<branch>,<url-if-remote-missing>)
define rebase_repo
	@if [[ ! -e "$(1)/.git" ]]; then \
		echo "$(2) checkout is missing at $(1); run 'git submodule update --init'" >&2; \
		exit 1; \
	fi; \
	branch="$$($(GIT) -C "$(1)" symbolic-ref --quiet --short HEAD)" || { \
		echo "$(2) is on a detached HEAD; attach its working branch first" >&2; \
		exit 1; \
	}; \
	if ! $(GIT) -C "$(1)" diff --quiet || \
	   ! $(GIT) -C "$(1)" diff --cached --quiet; then \
		echo "$(2) has tracked or staged changes; commit or stash them before rebasing" >&2; \
		exit 1; \
	fi; \
	if ! $(GIT) -C "$(1)" remote get-url "$(3)" >/dev/null 2>&1; then \
		if [[ -n "$(5)" ]]; then \
			echo "Adding $(2) remote $(3) -> $(5)"; \
			$(GIT) -C "$(1)" remote add "$(3)" "$(5)"; \
		else \
			echo "$(2) has no remote named '$(3)'" >&2; \
			exit 1; \
		fi; \
	fi; \
	$(GIT) -C "$(1)" fetch "$(3)" "$(4)"; \
	echo "Rebasing $(2) $$branch onto $(3)/$(4)"; \
	$(GIT) -c commit.gpgsign=false -C "$(1)" rebase "$(3)/$(4)"; \
	push_remote="$$($(GIT) -C "$(1)" config --get "branch.$$branch.remote" || echo origin)"; \
	local_sha="$$($(GIT) -C "$(1)" rev-parse "refs/heads/$$branch")"; \
	remote_sha="$$($(GIT) -C "$(1)" rev-parse --quiet --verify "refs/remotes/$$push_remote/$$branch" || echo unpushed)"; \
	if [[ "$$local_sha" == "$$remote_sha" ]]; then \
		echo "$(2) $$branch already up to date on $$push_remote"; \
	else \
		echo "Force-pushing $(2) $$branch to $$push_remote"; \
		$(GIT) -C "$(1)" push --force-with-lease "$$push_remote" "$$branch"; \
	fi
endef

help:
	@printf '%s\n' \
		'Targets:' \
		'  kkd-sync           Pull and rebase kkd onto its tracking branch' \
		'  verus-sync         Pull and rebase verus onto its tracking branch' \
		'  all-sync           Sync every dep' \
		'  sync               Alias for all-sync' \
		'  kkd-rebase         Rebase kkd onto origin/main and push' \
		'  verus-rebase       Rebase verus onto origin/main and push' \
		'  all-rebase         Rebase+push every dep; keeps going past failures' \
		'  rebase             Alias for all-rebase' \
		'  verus              Build Verus from dep/verus (vstd no_std, no_alloc)' \
		'  verus-clean        Remove the Verus build outputs' \
		'  verify             Verus over src/trusted, src/rt, the policy and the core' \
		'  scx-lachesis       Verify, then build the BPF object and the loader' \
		'  scx-lachesis-run   Boot a VM, run the loader as its sched_ext scheduler' \
		'  scx-lachesis-clean Remove the scx_lachesis build outputs' \
		'  rust-project       Write rust-project.json for rust-analyzer' \
		'' \
		'Useful overrides:' \
		'  <DEP>_REBASE_REMOTE/_BRANCH/_URL with DEP=KKD or VERUS' \
		'  VERUS_DIR=$(VERUS_DIR)' \
		'  VERIFY=0 to build without verifying (loudly)' \
		'  BUILD_DIR=$(BUILD_DIR)' \
		'  KERNEL_DIR=$(KERNEL_DIR)' \
		'  KERNEL_BUILD=$(KERNEL_BUILD)' \
		'  SCX_LACHESIS_SECS=$(SCX_LACHESIS_SECS) (default: 5) seconds of guest workload' \
		'  VM_CPUS/VM_MEM/VM_TIMEOUT for scx-lachesis-run' \
		"  'make -C src/scx_lachesis help' for the toolchain variables"

kkd-sync:
	$(call sync_repo,$(KKD_DIR),kkd)

verus-sync:
	$(call sync_repo,$(VERUS_DIR),verus)

all-sync: kkd-sync verus-sync

sync: all-sync

kkd-rebase:
	$(call rebase_repo,$(KKD_DIR),kkd,$(KKD_REBASE_REMOTE),$(KKD_REBASE_BRANCH),$(KKD_REBASE_URL))

verus-rebase:
	$(call rebase_repo,$(VERUS_DIR),verus,$(VERUS_REBASE_REMOTE),$(VERUS_REBASE_BRANCH),$(VERUS_REBASE_URL))

all-rebase:
	@failed=""; \
	for target in kkd-rebase verus-rebase; do \
		$(MAKE) "$$target" || failed="$$failed $$target"; \
	done; \
	if [[ -n "$$failed" ]]; then \
		echo "rebase failed for:$$failed" >&2; \
		echo "conflicted repos are left mid-rebase; resolve and 'git rebase --continue'" >&2; \
		echo "(or 'git rebase --abort'), then re-run 'make rebase' to finish and push" >&2; \
		exit 1; \
	fi

rebase: all-rebase

# --- scx_lachesis -------------------------------------------------------
# Building runs entirely on the host; loading only ever happens inside the
# guest that scx-lachesis-run boots. Never register a sched_ext scheduler on
# the development host: it would displace the one the host is running. The
# loader refuses to attach outside a QEMU guest for the same reason, and
# `make` never passes it the --allow-host override.

verus: $(VERUS_BIN)

# vargo is incremental, so this is cheap when current; the binary is the
# stamp. Verifying vstd dominates a cold build.
$(VERUS_BIN): $(VERUS_Z3)
	@if [[ ! -e "$(VERUS_DIR)/.git" ]]; then \
		echo "verus checkout is missing at $(VERUS_DIR); run 'git submodule update --init'" >&2; \
		exit 1; \
	fi
	cd $(VERUS_SOURCE) && \
		source ../tools/activate && \
		RUSTC_BOOTSTRAP=1 vargo build --release --vstd-no-std --vstd-no-alloc

$(VERUS_Z3):
	cd $(VERUS_SOURCE) && ./tools/get-z3.sh
	@if ! $(VERUS_Z3) --version >/dev/null 2>&1; then \
		echo "z3 from upstream's release does not run here; using the manylinux wheel"; \
		tmp=$$(mktemp -d); \
		curl -sL -o "$$tmp/z3.whl" '$(VERUS_Z3_WHEEL)'; \
		$(PYTHON) -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extract(sys.argv[2], sys.argv[3])" \
			"$$tmp/z3.whl" 'z3_solver-$(VERUS_Z3_VERSION).0.data/data/bin/z3' "$$tmp"; \
		install -m 0755 "$$tmp/z3_solver-$(VERUS_Z3_VERSION).0.data/data/bin/z3" $(VERUS_Z3); \
		rm -rf "$$tmp"; \
	fi
	@rm -rf $(VERUS_SOURCE)/z3-$(VERUS_Z3_VERSION)-*
	$(VERUS_Z3) --version

verus-clean:
	rm -rf $(VERUS_SOURCE)/target $(VERUS_SOURCE)/target-verus \
		$(VERUS_DIR)/tools/vargo/target

verify: verus
	$(SCX_LACHESIS_MAKE) verify

scx-lachesis: verus
	$(SCX_LACHESIS_MAKE)

scx-lachesis-run: scx-lachesis
	$(SCX_LACHESIS_DIR)/vm-run.sh $(SCX_LACHESIS_BIN) $(SCX_LACHESIS_OBJ) \
		$(KERNEL_BUILD) $(SCX_LACHESIS_OUT) $(SCX_LACHESIS_SECS)

scx-lachesis-clean:
	$(SCX_LACHESIS_MAKE) clean

# rust-analyzer has no Cargo workspace to read; this writes the equivalent
# project file by hand. See src/toolchain/rules.mk and README.md, "Editor
# support".
rust-project:
	$(SCX_LACHESIS_MAKE) rust-project
