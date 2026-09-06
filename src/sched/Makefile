# SPDX-License-Identifier: GPL-2.0
#
# lachesis: the BPF policy and the userspace side that runs it. The
# pipeline lives in ../toolchain/rules.mk; run `make help` for the
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

include ../toolchain/rules.mk
