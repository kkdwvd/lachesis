# SPDX-License-Identifier: GPL-2.0
#
# scx_lachesis: the BPF policy and the loader that runs it. The pipeline
# lives in ../toolchain/rules.mk; run `make help` for the variables it
# exposes.

PROG := scx_lachesis
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

# The userspace side: a cargo workspace whose binary is `scx_lachesis` and
# whose one verified crate is the core the binary calls.
USER_MANIFEST := Cargo.toml
USER_CORE_SRC := core/src/lib.rs

include ../toolchain/rules.mk
