# Lachesis

<img align="left" src="docs/assets/lachesis.png" width="200" alt="Lachesis holding a spindle and a thread">

**A measured share of time for every thread.**

In Greek mythology, Lachesis is the Fate who measures the thread of life and
allots each person their share. A CPU scheduler holds a similar responsibility:
it apportions a finite supply of time among competing threads, and its
choices determine which work can make progress. Lachesis takes its name from
that act of measurement and allocation, and reinforces it with a proof system
that guarantees correctness by construction.

Lachesis brings together Rust, Verus, and sched_ext to pursue that goal.
Policies compile to eBPF, with reusable contracts and proof machinery beneath
them and an explicit trusted boundary around their interaction with the
kernel. The ambition is to make rigorous guarantees part of writing a
scheduler, and to deliver them at the performance and scale production
workloads demand.

<br clear="all">

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
