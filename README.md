# Lachesis

<img align="left" src="docs/assets/lachesis.png" width="240" alt="Lachesis holding a spindle and a thread">

**Give every thread its due.**

In Greek mythology, Lachesis measures the thread of life and allots each
person their share. A CPU scheduler makes a kindred judgement: how to divide
finite CPU time among competing threads. Lachesis takes its name from that
responsibility, and its purpose from a simple ambition: to make fair
allocation a promise we can prove.

That promise reaches beyond any single scheduling decision. Runnable threads
must make progress, available CPUs must serve waiting work, and each workload
must receive its fair share. Lachesis aims to prove these properties across
concurrent callbacks and their interaction with the Linux kernel.

Written in Rust, checked with Verus, and compiled to eBPF for sched_ext,
Lachesis puts reusable contracts and proof machinery beneath readable
scheduling policies. An explicit trusted boundary makes the assumptions
visible. The goal is a scheduler whose guarantees stand up to both formal
reasoning and the demands of production: fairness with a proof, at the scale
and speed real workloads need.

## Summary

Lachesis is an early research prototype. The current scheduler uses a shared
queue ordered by virtual time, with a direct path to idle CPUs. The build
checks the policy, runtime, and userspace control crate with Verus before compiling
the BPF object and loader.

These checks establish the contracts written in the code. Whole-scheduler
proofs of starvation freedom, work conservation, and bounded fairness remain
goals. Kernel bindings and their assumed contracts live in an explicit trusted
base; the loader and compilation pipeline are also outside the proofs.

## Build and run

Initialize the pinned dependencies, then consult the build targets and
[toolchain requirements](src/toolchain/README.md#toolchain-matrix):

```sh
git submodule update --init
make help
make -C src/sched help
```

With the toolchain and a sched_ext-enabled kernel build available:

```sh
make verify         # Check the Verus contracts
make lachesis       # Verify and build the BPF object and loader
make lachesis-run   # Run the scheduler inside a QEMU VM
```

The kernel's BTF is a build input; use `KERNEL_DIR` and `KERNEL_BUILD` to
select the target kernel. Development runs belong in the VM: attaching a
scheduler on the host would displace its running sched_ext scheduler.
