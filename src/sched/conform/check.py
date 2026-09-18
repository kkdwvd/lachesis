#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Replay a lachesis trace against the receipt contracts and the model.

The loader's `--trace` writes the ring buffer of `src/runtime/trusted/trace.rs`
to a file: 40-byte events, native endian, `ts a b seq pid cpu cb op`. This
reads them back and checks two things.

Per callback: the receipts between a begin and an end event on one CPU are
run through the same automata the policy is verified against
(`src/model/refine.rs`), ported here by hand. Callbacks nest on a CPU --
`dequeue` runs inside the `dispatch` whose move ends a task's custody -- so
each CPU keeps a stack of open callbacks and an event goes to the innermost
open callback of its kind. Each event carries its CPU's sequence number,
so a drop by the ring buffer is seen exactly: the callbacks it cuts are
counted as gaps, not rejections, and the model's idle knowledge is reset. The policy cannot produce a
rejected sequence -- Verus proved that -- so a rejection here means the
trusted wrappers' receipts do not describe what ran, a recording gap, or a
port error; the count of accepted callbacks per kind is the useful number.

Across CPUs: the events are ordered by timestamp and the model's state is
rebuilt from them -- each CPU's word, whether it runs a task, how many
tasks its queue holds, and whether it is stuck, that is halted after an
`update_idle` that read the count zero and not since woken or claimed.
The strong property the Verus proof establishes, no CPU overloaded while
any CPU is stuck, is checked at every event. The rebuilt state is an
approximation: the ring buffer drops events when full, the clock is read
inside each callback rather than at the shared access, and a queue's
length is corrected whenever a callback reads it. Violations are reported
with their timestamps and the state around them, for a human to judge.

    check.py build/lachesis/trace.bin
"""
import struct
import sys
from collections import Counter, defaultdict

EVENT = struct.Struct("<QQQIihBBxxxx")  # 40 bytes: repr(C) pads the tail

CB = {1: "select_cpu", 2: "enqueue", 3: "dequeue", 4: "dispatch", 5: "running",
      6: "stopping", 7: "enable", 8: "update_idle", 9: "init", 10: "exit"}
OP = {0: "Begin", 1: "End", 2: "CountInc", 3: "CountDec", 4: "CountLoad",
      5: "NrCpuIds", 6: "TaskCpu", 7: "SelectDfl", 8: "Kick", 9: "NrQueued",
      10: "Promise", 11: "Scan", 12: "Unpromise", 13: "SetBusy", 14: "SetFree",
      15: "IsBusy", 16: "Insert", 17: "MoveToLocal", 18: "TestAndClearIdle"}

MAX_CPUS = 64
GLOBAL_DSQ = 0x8000_0000_0000_0001


def s64(v):
    return v - (1 << 64) if v >= (1 << 63) else v


def cap_of(n):
    return n if n < MAX_CPUS else MAX_CPUS


# --- the enqueue automaton, from refine.rs -----------------------------------

def enq_step(st, ev):
    kind, a, b = ev
    k = st[0]
    if k == "Start":
        return ("Cpu", s64(a)) if kind == "TaskCpu" else None
    if k == "Cpu":
        return ("Ready", st[1], cap_of(a)) if kind == "NrCpuIds" else None
    if k == "Ready":
        _, cpu, cap = st
        if kind == "Insert":
            return ("Done",) if cpu >= cap and a == GLOBAL_DSQ else None
        if kind == "CountInc":
            return ("Published", cpu, cap) if cpu < cap else None
        return None
    if k == "Published":
        _, cpu, cap = st
        if kind == "SelectDfl":
            return ("Claimed", cpu, cap, s64(a), 0) if b else ("Fallback", cpu, cap)
        return None
    if k == "Claimed":
        _, cpu, cap, c, nxt = st
        if kind == "Kick" and s64(a) == c:
            return ("Scan", cpu, cap, nxt) if c >= cap else ("Kicked", cpu, cap, c, nxt)
        return None
    if k == "Kicked":
        _, cpu, cap, c, nxt = st
        if kind == "NrQueued" and a == c:
            return ("Scan", cpu, cap, nxt) if s64(b) > 0 else ("Empty", cpu, cap, c, nxt)
        return None
    if k == "Empty":
        _, cpu, cap, c, nxt = st
        if kind == "Promise" and a == c:
            return ("Promised", cpu, cap, c) if b else ("Scan", cpu, cap, nxt)
        return None
    if k == "Promised":
        return ("Done",) if kind == "Insert" and a == st[3] else None
    if k == "Fallback":
        return ("Done",) if kind == "Insert" and a == st[1] else None
    if k == "Scan":
        _, cpu, cap, j = st
        if j >= cap:
            return ("Done",) if kind == "Insert" and a == cpu else None
        if kind == "TestAndClearIdle" and s64(a) == j:
            return ("Claimed", cpu, cap, j, j + 1) if b else ("Scan", cpu, cap, j + 1)
        return None
    return None


# --- the dispatch automaton --------------------------------------------------

def skip_own(cpu, nxt):
    return nxt + 1 if nxt == cpu else nxt


def dsp_step(cpu, st, ev):
    kind, a, b = ev
    k = st[0]
    if k == "Start":
        if kind == "MoveToLocal" and a == cpu:
            return ("Done",) if b else ("Own",)
        return None
    if k == "Own":
        if kind == "Scan" and a == cpu and cpu < MAX_CPUS:
            return ("Guarded",) if b else ("Done",)
        return None
    if k == "Guarded":
        return ("Scan", cap_of(a), 0) if kind == "NrCpuIds" else None
    if k == "Scan":
        _, cap, nxt = st
        c = skip_own(cpu, nxt)
        if c >= cap:
            return ("Done",) if kind == "SetFree" and a == cpu else None
        if kind == "IsBusy" and a == c:
            return ("Busy", cap, c) if b else ("Scan", cap, c + 1)
        return None
    if k == "Busy":
        _, cap, c = st
        if kind == "NrQueued" and a == c:
            return ("Loaded", cap, c) if s64(b) > 0 else ("Scan", cap, c + 1)
        return None
    if k == "Loaded":
        _, cap, c = st
        if kind == "MoveToLocal" and a == c:
            return ("Stole", cap, c) if b else ("Scan", cap, c + 1)
        return None
    if k == "Stole":
        return ("Done",) if kind == "Unpromise" and a == st[2] else None
    return None


def dsp_accepts(cpu, st):
    return st[0] == "Done" or (st[0] == "Own" and cpu >= MAX_CPUS)


# --- the short contracts -----------------------------------------------------

def update_idle_ok(cpu, ops):
    if not ops:
        return True  # idle exit: nothing
    if ops[0][0] != "CountLoad":
        return False
    if ops[0][1] == 0:
        return len(ops) == 1
    if len(ops) >= 2 and ops[1] == ("TestAndClearIdle", cpu, 0):
        return len(ops) == 2
    return len(ops) == 3 and ops[1] == ("TestAndClearIdle", cpu, 1) and ops[2] == ("Kick", cpu, 0)


def busy_ok(busy, ops):
    if not ops or ops[0][0] != "TaskCpu":
        return False
    c = s64(ops[0][1])
    if c < MAX_CPUS:
        return len(ops) == 2 and ops[1] == (("SetBusy" if busy else "SetFree"), c, 0)
    return len(ops) == 1


def callback_ok(cb, cpu, ops):
    if cb == "enqueue":
        st = ("Start",)
        for ev in ops:
            st = enq_step(st, ev)
            if st is None:
                return False
        return st == ("Done",)
    if cb == "dispatch":
        st = ("Start",)
        for ev in ops:
            st = dsp_step(cpu, st, ev)
            if st is None:
                return False
        return dsp_accepts(cpu, st)
    if cb == "dequeue":
        return ops == [("CountDec", 0, 0)]
    if cb == "running":
        return busy_ok(True, ops)
    if cb == "stopping":
        return busy_ok(False, ops)
    if cb == "update_idle":
        return update_idle_ok(cpu, ops)
    if cb == "select_cpu":
        return ops == []
    return True  # enable, init, exit: no contract


# --- the model across CPUs ---------------------------------------------------

class Model:
    """The model's state, rebuilt from the trace, checked for WCStrong.

    Each queued task is remembered with how it got there: `hit`, filed by
    a placement whose compare-and-swap took, or `fallback`, filed on the
    task's own CPU after the kernel's search saw nothing idle or the scan
    ran out. A fallback while another CPU's bit was up is what the model
    cannot produce and the kernel does for a task pinned to its CPU: the
    model has no affinity. Flagged states are classified by that.
    """

    def __init__(self):
        self.word = defaultdict(lambda: "free")
        self.running = defaultdict(lambda: False)
        self.queue = defaultdict(int)
        self.queued = defaultdict(list)   # cpu -> [(pid, how)]
        self.stuck = defaultdict(lambda: False)
        self.idle_bit = defaultdict(lambda: False)
        self.violations = []
        self.checked = 0
        self.fallback_with_idle = 0
        self.enq = {}                     # cpu -> (pid, how) of the open enqueue
        self.deq = {}                     # cpu -> pid of the open dequeue
        self.how_of = {}                  # pid -> how it was last filed

    def overloaded(self, c):
        return self.running[c] and self.queue[c] > 0

    def check(self, ts, why):
        self.checked += 1
        stuck = [c for c in list(self.stuck) if self.stuck[c]]
        if not stuck:
            return
        over = [c for c in set(list(self.running) + list(self.queue)) if self.overloaded(c)]
        if over:
            affine = any(how == "fallback" for c in over for _, how in self.queued[c]) \
                or any(self.running_how.get(c) == "fallback" for c in over)
            self.violations.append((ts, why, stuck, over, affine,
                                    {c: (self.word[c], self.running[c], self.queue[c],
                                         self.queued[c][-3:]) for c in over}))

    running_how = {}

    def apply(self, cpu, cb, kind, a, b, ts, pid):
        # any activity on a CPU wakes it in the model's sense
        if kind == "Begin":
            self.stuck[cpu] = False
            if cb == "running":
                self.running[cpu] = True
                # how the runner was last filed; its dequeue already took
                # it off the queue list
                self.running_how[cpu] = self.how_of.get(pid, "other")
            elif cb == "stopping":
                self.running[cpu] = False
            elif cb == "enqueue":
                self.enq[cpu] = [pid, "fallback"]
            elif cb == "dequeue":
                self.deq[cpu] = pid
            elif cb == "update_idle":
                self.idle_bit[cpu] = True
        elif kind == "Promise" and b and cb == "enqueue" and cpu in self.enq:
            self.enq[cpu][1] = "hit"
        if kind == "SelectDfl" and not b and cb == "enqueue":
            # the kernel saw nothing idle: was a bit up elsewhere?
            if any(self.idle_bit[c] for c in list(self.idle_bit) if c != cpu):
                self.fallback_with_idle += 1
        if kind in ("TestAndClearIdle", "SelectDfl") and b:
            self.idle_bit[s64(a)] = False
        if kind == "Begin" and cb != "update_idle":
            self.idle_bit[cpu] = False
        if kind == "SetBusy":
            self.word[a] = "busy"
        elif kind == "SetFree":
            self.word[a] = "free"
        elif kind == "Promise" and b:
            self.word[a] = "promised"
            self.stuck[a] = False
        elif kind == "Scan" and b:
            self.word[a] = "scanning"
        elif kind == "Unpromise":
            if self.word[a] == "promised":
                self.word[a] = "free"
        elif kind == "Insert":
            if a != GLOBAL_DSQ:
                self.queue[a] += 1
                pid_how = self.enq.get(cpu, [0, "fallback"])
                self.queued[a].append((pid_how[0], pid_how[1]))
                self.how_of[pid_how[0]] = pid_how[1]
        elif kind == "MoveToLocal" and b:
            self.queue[a] = max(0, self.queue[a] - 1)
        elif kind == "NrQueued":
            self.queue[a] = max(0, s64(b))  # a read corrects the drift
            del self.queued[a][:max(0, len(self.queued[a]) - self.queue[a])]
        elif kind == "CountDec" and cb == "dequeue":
            # the task leaving custody: drop it from whichever queue lists it
            dp = self.deq.get(cpu, 0)
            for c in list(self.queued):
                for i, (qp, how) in enumerate(self.queued[c]):
                    if qp == dp:
                        del self.queued[c][i]
                        break
        elif kind == "Kick":
            self.stuck[s64(a)] = False
        elif kind in ("TestAndClearIdle", "SelectDfl") and b:
            self.stuck[s64(a)] = False
        elif kind == "CountLoad" and cb == "update_idle" and a == 0:
            self.stuck[cpu] = True
        self.check(ts, f"{CB.get(cb, cb)}:{kind} on cpu {cpu}")


def main(path):
    raw = open(path, "rb").read()
    n = len(raw) // EVENT.size
    events = [EVENT.unpack_from(raw, i * EVENT.size) for i in range(n)]
    events.sort(key=lambda e: e[0])
    print(f"{n} events, {len(raw) - n * EVENT.size} trailing bytes")

    # per callback: a stack of open callbacks per CPU, gaps by sequence
    open_cb = defaultdict(list)
    accepted = Counter()
    rejected = Counter()
    gaps = 0
    cut = 0
    stray = 0
    examples = {}
    last_seq = {}
    gap_ts = []
    for ts, a, b, seq, pid, cpu, cb, op in events:
        cbn = CB.get(cb, str(cb))
        kind = OP.get(op, str(op))
        if cpu in last_seq and seq != (last_seq[cpu] + 1) & 0xffffffff:
            gaps += 1
            gap_ts.append(ts)
            cut += len(open_cb[cpu])
            open_cb[cpu].clear()
        last_seq[cpu] = seq
        stack = open_cb[cpu]
        if kind == "Begin":
            stack.append((cbn, []))
        elif kind == "End":
            for i in range(len(stack) - 1, -1, -1):
                if stack[i][0] == cbn:
                    name, ops = stack.pop(i)
                    cut += len(stack) - i  # anything opened inside and not ended
                    del stack[i:]
                    if callback_ok(name, cpu, ops):
                        accepted[name] += 1
                    else:
                        rejected[name] += 1
                        examples.setdefault(name, (ts, cpu, ops))
                    break
            else:
                stray += 1
        else:
            for i in range(len(stack) - 1, -1, -1):
                if stack[i][0] == cbn:
                    stack[i][1].append((kind, a, b))
                    break
            else:
                stray += 1
    cut += sum(len(v) for v in open_cb.values())
    print("per-callback receipts against the contracts:")
    for name in sorted(set(accepted) | set(rejected)):
        print(f"  {name:12s} accepted {accepted[name]:8d}  rejected {rejected[name]:6d}")
    print(f"  ring-buffer gaps: {gaps}; callbacks cut by a gap or the edges: {cut}; "
          f"stray events: {stray}")
    for name, (ts, cpu, ops) in examples.items():
        print(f"  first rejected {name} at {ts} on cpu {cpu}: {ops[:12]}{' ...' if len(ops) > 12 else ''}")

    # across CPUs; a gap anywhere resets what the model knows about idleness
    model = Model()
    gap_ts.sort()
    gi = 0
    for ts, a, b, seq, pid, cpu, cb, op in events:
        while gi < len(gap_ts) and gap_ts[gi] <= ts:
            model.stuck.clear()
            gi += 1
        model.apply(cpu, CB.get(cb, str(cb)), OP.get(op, str(op)), a, b, ts, pid)
    affine = sum(1 for v in model.violations if v[4])
    print(f"the model across CPUs: {model.checked} states checked, "
          f"{len(model.violations)} where a CPU was stuck beside an overloaded one, "
          f"{affine} of them with a task filed on its own CPU while another CPU's "
          f"bit was up -- a task the kernel would not place elsewhere, which the "
          f"model, having no affinity, cannot produce")
    print(f"  the kernel's search saw nothing idle while a bit was up elsewhere "
          f"{model.fallback_with_idle} times")
    unexplained = [v for v in model.violations if not v[4]]
    for ts, why, stuck, over, aff, detail in unexplained[:10]:
        print(f"  unexplained at {ts} after {why}: stuck {stuck}, overloaded {over} {detail}")
    return 1 if rejected or unexplained else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
