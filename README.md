# Lachesis

<table>
  <tr>
    <td width="240" valign="top" align="left">
      <img src="docs/assets/lachesis.png" width="220" alt="Lachesis holding a spindle and a thread">
    </td>
    <td valign="top">
      <p><strong>Every thread deserves its time.</strong></p>
      <p>
        Named for the Fate who measures the thread of life, Lachesis explores
        how we give threads their share of a machine. It is a framework for
        building Linux CPU schedulers in Rust, checking their contracts with
        Verus, and compiling them to eBPF to run under sched_ext.
      </p>
      <p>
        A scheduler's promises unfold over time: runnable tasks make progress,
        available CPUs do useful work, and competing workloads receive their
        fair share. Lachesis aims to make those promises precise and prove
        that they survive the interaction of concurrent callbacks with the
        kernel.
      </p>
      <p>
        The design keeps scheduling decisions readable, puts reusable
        contracts beneath them, and makes the trusted boundary explicit.
        The ambition is practical: schedulers whose behavior we can explain,
        verify, and eventually trust in production.
      </p>
    </td>
  </tr>
</table>

## Where it stands

Lachesis is an early research prototype. The current scheduler uses a shared
queue ordered by virtual time, with a direct path to idle CPUs. The build
checks the policy, runtime, and userspace core with Verus before compiling
the BPF object and loader.

These checks establish the contracts written in the code. Whole-scheduler
proofs of starvation freedom, work conservation, and bounded fairness remain
goals. Kernel bindings and their assumed contracts live in an explicit trusted
base; the loader and compilation pipeline are also outside the proofs.

## Explore the code

- [Scheduling policy](src/scx_lachesis/bpf/main.rs): the scheduling decisions.
- [Checked runtime](src/rt): callback contracts and virtual-time arithmetic.
- [Trusted base](src/trusted): kernel bindings, task views, and trampolines.
- [Userspace core](src/scx_lachesis/core): verified helpers for the loader.
- [Toolchain](src/toolchain/README.md): build requirements, provenance, and
  verification boundaries.

## Build and run

Initialize the pinned dependencies, then consult the build targets and
[toolchain requirements](src/toolchain/README.md#toolchain-matrix):

```sh
git submodule update --init
make help
make -C src/scx_lachesis help
```

With the toolchain and a sched_ext-enabled kernel build available:

```sh
make verify             # Check the Verus contracts
make scx-lachesis       # Verify and build the BPF object and loader
make scx-lachesis-run   # Run the scheduler inside a QEMU VM
```

The kernel's BTF is a build input; use `KERNEL_DIR` and `KERNEL_BUILD` to
select the target kernel. Development runs belong in the VM: attaching a
scheduler on the host would displace its running sched_ext scheduler.
