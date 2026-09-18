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

Lachesis is an early research prototype. The current scheduler keeps one
virtual-time queue per CPU, places a waking task on an idle CPU's queue when
its enqueue finds one, steals from overloaded CPUs when a CPU runs dry, and
interlocks enqueue and idle entry through a published count. The build
checks the policy, the runtime, the userspace control crate and a model of
the scheduler under the kernel with Verus before compiling the BPF object
and loader.

The model carries the first whole-scheduler theorem: concurrent work
conservation in the sense of the Ipanema paper, restated for sched_ext and
proved as an inductive invariant. A TLA+ mirror of the same model checks it
with TLC and shows that four weakened variants of the policy violate it.
The compiled callbacks are checked against that model: every trusted
wrapper leaves a ghost receipt, the `Policy` trait's contracts say which
sequences of receipts the model's actions allow, and Verus proves the
policy produces one. The model takes one shared access per step, the
code's granularity; refining it to that found three races in the design,
each closed and each kept as a rejected variant. Thirteen variants of the
policy that reproduce known scheduler bugs, among them the two the
Ipanema paper found in CFS, are rejected by those contracts on every
build. Starvation freedom and bounded
fairness remain goals, and the link between the contracts and the model's
actions is by construction rather than a theorem. Kernel bindings and
their assumed contracts live in an explicit trusted base; the loader and
compilation pipeline are also outside the proofs.

## Build and run

Initialize the pinned dependencies, then consult the build targets and
[toolchain requirements](dep/verus-bpf/TOOLCHAIN.md#setup):

```sh
git submodule update --init --recursive
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
