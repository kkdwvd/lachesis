# SPDX-License-Identifier: GPL-2.0
#
# lachesis: the BPF policy and the userspace side that runs it. The
# pipeline lives in ../../dep/verus-bpf/rules.mk; run `make help` for the
# variables it exposes.

PROG := lachesis
SRC := bpf/main.rs

# Symbols opt must not internalize: the struct_ops map, its entry points,
# the license, and the policy instance, whose counters and exit info the
# loader reads back out of `.bss`.
KEEP_SYMS := lachesis_ops \
             lachesis_select_cpu lachesis_enqueue lachesis_dequeue \
             lachesis_dispatch lachesis_running lachesis_stopping \
             lachesis_enable lachesis_update_idle lachesis_init \
             lachesis_exit \
             LACHESIS \
             _LICENSE

# Policies the contracts must reject, one patch against bpf/main.rs each;
# `make verify` fails if Verus accepts any of them.
MUTANTS := $(sort $(wildcard bpf/mutants/*.patch))

# The userspace side: the unverified loader in ../loader, and the verified
# control-plane crate beside this policy that it calls.
USER_MANIFEST := ../loader/Cargo.toml
USER_CORE_SRC := control/src/lib.rs
USER_CORE_NAME := lachesis_control

ROOT_DIR := $(abspath ../..)
KERNEL_DIR ?= $(HOME)/src/linux
# The pipeline defaults to Ubuntu's versioned prefix; a host whose LLVM 22
# is the system one (llc, opt, llvm-config under /usr/bin) is just /usr.
LLVM_PREFIX ?= $(if $(wildcard /usr/lib/llvm-22/bin/llc),/usr/lib/llvm-22,/usr)
KERNEL_BUILD ?= $(KERNEL_DIR)/.kdev/build/kernel
# The model sits between the trusted crate, whose receipt ops it names,
# and the runtime, whose Policy trait names its refinement contracts; it is
# ghost only, and its proof gates the object like the others.
LIB_CRATES := lachesis_runtime_trusted lachesis_model lachesis_runtime
lachesis_runtime_trusted_DIR := $(ROOT_DIR)/src/runtime/trusted
lachesis_model_DIR := $(ROOT_DIR)/src/model
lachesis_runtime_DIR := $(ROOT_DIR)/src/runtime
NOCHEAT_CRATES := lachesis_model lachesis_runtime
TRUSTED_DIRS := $(lachesis_runtime_trusted_DIR)

VERUS_BPF_DIR ?= $(ROOT_DIR)/dep/verus-bpf
include $(VERUS_BPF_DIR)/rules.mk
