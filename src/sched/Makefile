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
             lachesis_select_cpu lachesis_enqueue lachesis_dispatch \
             lachesis_running lachesis_stopping lachesis_enable \
             lachesis_init lachesis_exit \
             LACHESIS \
             _LICENSE

# The userspace side: the unverified loader in ../loader, and the verified
# control-plane crate beside this policy that it calls.
USER_MANIFEST := ../loader/Cargo.toml
USER_CORE_SRC := control/src/lib.rs
USER_CORE_NAME := lachesis_control

ROOT_DIR := $(abspath ../..)
KERNEL_DIR ?= $(HOME)/src/linux
KERNEL_BUILD ?= $(KERNEL_DIR)/.kdev/build/kernel
LIB_CRATES := lachesis_runtime_trusted lachesis_runtime
lachesis_runtime_trusted_DIR := $(ROOT_DIR)/src/runtime/trusted
lachesis_runtime_DIR := $(ROOT_DIR)/src/runtime
NOCHEAT_CRATES := lachesis_runtime
TRUSTED_DIRS := $(lachesis_runtime_trusted_DIR)

VERUS_BPF_DIR ?= $(ROOT_DIR)/dep/verus-bpf
include $(VERUS_BPF_DIR)/rules.mk
