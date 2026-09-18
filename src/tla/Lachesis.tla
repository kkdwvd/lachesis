------------------------------ MODULE Lachesis ------------------------------
(***************************************************************************)
(* The concurrent work-conservation model of roadmap section 5.4: the      *)
(* sched_ext event model at one transition per shared-variable access,    *)
(* running the per-CPU-queue policy in src/sched/bpf/main.rs. This is the  *)
(* TLA+ mirror of the Verus model in src/model; action names agree.        *)
(*                                                                         *)
(* Shared variables, and the kernel object each stands for:               *)
(*   loc[t]      where task t is: blocked; waking (select_cpu running, no  *)
(*               target yet); inflight(c) (assigned to c but not on any    *)
(*               queue of c yet); queued(c) (on c's user DSQ); local(c)    *)
(*               (on c's local DSQ); running(c).                           *)
(*   ev[t]       the phase of t's wake event: placing, the task is        *)
(*               assigned to a CPU (ops.select_cpu returns prev_cpu, so   *)
(*               the kernel's choice, any CPU here) and ops.enqueue has   *)
(*               not started; checking(vis, ks), nr_queued is bumped and  *)
(*               the kernel's idle search (scx_bpf_select_cpu_dfl) is on: *)
(*               vis are the CPUs it has seen with their bit down, ks the *)
(*               CPUs the enqueue has claimed and will kick; each probe    *)
(*               may pick any CPU not yet seen, since the kernel's order   *)
(*               is not the policy's, and a search that has seen every    *)
(*               CPU down files the task on the CPU it was assigned to.   *)
(*               reading(i, ks, next), i's bit was claimed (test-and-      *)
(*               clear) and the policy is about to read i's queue count;  *)
(*               marking(i, ks, next), the count read empty and the        *)
(*               policy is about to compare-and-swap i's word; next is     *)
(*               where the policy's own scan resumes if the claim does     *)
(*               not take: 0 after the kernel's pick, j+1 after a scan     *)
(*               claim at j. scanning(j, ks), the kernel's pick did not    *)
(*               take and the policy is testing bits itself, j upward,    *)
(*               each CPU once; a scan past the last CPU files the task    *)
(*               on the CPU it was assigned to. A second kernel search     *)
(*               instead of the scan is not sound: it may return a CPU     *)
(*               the enqueue already claimed, if that CPU went idle again  *)
(*               meanwhile, so no bound on the retries guarantees that an  *)
(*               idle CPU whose bit stays up is ever probed. landing(ks,   *)
(*               q), the callback is done, the insert into queue q has     *)
(*               not landed, and kicks for the CPUs in ks go out with it,  *)
(*               because scx_bpf_kick_cpu is an irq_work that runs after   *)
(*               the rq lock is dropped. Every shared access is its own    *)
(*               step, the code's granularity. A claim whose queue read    *)
(*               empty and whose word went free to promised is the         *)
(*               destination (a task can land on a CPU's queue between its *)
(*               failed dispatch and its idle bit going up, since filing   *)
(*               on another CPU's queue takes no lock of that CPU). The    *)
(*               placement happens at placement time, as Ipanema's         *)
(*               unblock_place does, and a wakeup never lands on a busy    *)
(*               CPU while an idle one was observable. There is no direct  *)
(*               dispatch to a local DSQ: a task there cannot be stolen,   *)
(*               and one that lands after its CPU was kicked into stealing *)
(*               is a bubble nobody can fix.                               *)
(*   pub         the policy's nr_queued: bumped by ops.enqueue before      *)
(*               anything else, taken down when a queued task is consumed  *)
(*               (ops.dequeue).                                            *)
(*   phase[c]    what CPU c is doing: running; dispatch (local DSQ, then   *)
(*               ops.dispatch's own-queue move); guard (the compare-and-   *)
(*               swap of its own word from free to scanning); steal(j)     *)
(*               (reading j's word); stealcount(j) (reading queue j's      *)
(*               count); stealmove(j) (moving from it, own rq lock         *)
(*               dropped); unguard (writing its own word free again);      *)
(*               idleset (about to set the idle bit); idlecheck            *)
(*               (update_idle reading pub); idleclaim (test-and-clearing   *)
(*               its own bit); halted.                                     *)
(*   idle_bit[c] the kernel's idle mask bit.                               *)
(*   kicked[c]   a resched is pending for c.                               *)
(*   prevt[c]    the task whose slice expired on c and is still on the CPU  *)
(*               while c's balance runs: the kernel calls dispatch before   *)
(*               it re-enqueues prev, keeps prev if nothing else turns up,  *)
(*               and sends prev through enqueue only when something did.    *)
(*   st[c]       the policy's per-CPU word: free, c is idle and nothing is *)
(*               promised to it; promised, an enqueue has claimed c and   *)
(*               filed a task for its queue that has not run yet; busy, a *)
(*               task is running on c; scanning, c is looking for a task  *)
(*               to steal. A claim is a compare-and-swap from free;        *)
(*               ops.running writes busy and ops.stopping writes free; a  *)
(*               CPU about to steal compare-and-swaps its own word from    *)
(*               free to scanning and writes it free again if it finds     *)
(*               nothing; a thief takes the victim's word from promised    *)
(*               to free, in case the task it took was the promised one.  *)
(*               Nothing else touches it. A claimer that finds it not free *)
(*               kicks c and looks on. The consumer does not clear the     *)
(*               word: a mark cleared on consumption let a claimer holding *)
(*               a stale bit claim file behind the task just consumed. And *)
(*               a CPU whose guard fails does not steal: it is promised a  *)
(*               task, and stealing would run the stolen task with the     *)
(*               promised one queued behind it. This model found both.     *)
(*   lk[c]       c's rq lock: free, held by c's own scheduling event, or   *)
(*               held by the enqueue path of a task targeting c. The       *)
(*               kernel holds it across block, balance, idle entry and     *)
(*               update_idle, and across activate/ops.enqueue/landing;     *)
(*               a remote move drops the mover's own lock and takes the    *)
(*               victim's. This is Ipanema's per-core lock.                *)
(* Ghost: sb/su per CPU are B and U of c's in-progress Sched event; wb/wu  *)
(* per task the same for t's wake event; last is the (B, U) of the event   *)
(* that ended in the step just taken, NONE otherwise, so CWC is evaluated  *)
(* exactly at event ends.                                                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS N,            \* number of CPUs
          TASKS,        \* naturals for LOCAL_SELECT, else model values
          NoTask,       \* a model value: no expired task on a CPU
          TICKS,        \* slices expire: Tick is enabled
          NO_STEAL,     \* dispatch never steals (step 1 alone)
          FIRST_ONLY,   \* a failed steal move gives up (CFS balancing)
          NO_ENQ_KICK,  \* enqueue does not search for an idle CPU again
          NO_IDLE_KICK, \* update_idle does not read the count
          LOCAL_SELECT, \* the idle search looks only at prev(t) (CFS)
          FIXED_HOME    \* every task is assigned to prev(t): directed checks

ASSUME N \in Nat /\ N >= 1

CPUS == 0..N-1
Prev(t) == (t - 1) % N
NONE == [kind |-> "none"]
Perms == Permutations(TASKS)

VARIABLES loc, ev, pub, phase, idle_bit, kicked, lk, st, prevt,
          sb, su, wb, wu, last
vars == <<loc, ev, pub, phase, idle_bit, kicked, lk, st, prevt,
          sb, su, wb, wu, last>>
ghost == <<sb, su, wb, wu>>

(* task locations and wake-event phases *)
Blocked == [k |-> "blocked"]
Waking == [k |-> "waking"]
Inflight(c) == [k |-> "inflight", c |-> c]
Queued(c) == [k |-> "queued", c |-> c]
Local(c) == [k |-> "local", c |-> c]
Running(c) == [k |-> "running", c |-> c]
EvNone == [k |-> "none"]
EvPlacing == [k |-> "placing"]
EvChecking(vis, ks) == [k |-> "checking", vis |-> vis, ks |-> ks]
EvReading(i, ks, next) == [k |-> "reading", i |-> i, ks |-> ks, next |-> next]
EvMarking(i, ks, next) == [k |-> "marking", i |-> i, ks |-> ks, next |-> next]
EvScanning(j, ks) == [k |-> "scanning", j |-> j, ks |-> ks]
EvLanding(ks, q) == [k |-> "landing", ks |-> ks, q |-> q]

(* CPU phases and lock states *)
PhRunning == [k |-> "running"]
PhDispatch == [k |-> "dispatch"]
PhGuard == [k |-> "guard"]
PhUnguard == [k |-> "unguard"]
PhSteal(j) == [k |-> "steal", j |-> j]
PhStealCount(j) == [k |-> "stealcount", j |-> j]
PhStealMove(j) == [k |-> "stealmove", j |-> j]
PhIdleSet == [k |-> "idleset"]
PhIdleCheck == [k |-> "idlecheck"]
PhIdleClaim == [k |-> "idleclaim"]
PhHalted == [k |-> "halted"]
Free == [k |-> "free"]
LkSched == [k |-> "sched"]
LkEnq(t) == [k |-> "enq", t |-> t]

Dsq(c) == {t \in TASKS : loc[t].k = "queued" /\ loc[t].c = c}
LocalQ(c) == {t \in TASKS : loc[t].k = "local" /\ loc[t].c = c}
Assigned(c) == {t \in TASKS :
                  loc[t].k \in {"queued", "local", "running"} /\ loc[t].c = c}
Overloaded(c) == Cardinality(Assigned(c)) >= 2
Idle(c) == Assigned(c) = {} /\ phase[c].k = "halted"
InEvent(c) == phase[c].k \notin {"running", "halted"} \/ kicked[c]
              \/ (phase[c].k = "halted" /\ ~idle_bit[c])
SchedInProgress(c) == phase[c].k \notin {"running", "halted"}
WakeInProgress(t) == ev[t].k # "none"
Targets == {loc[t].c : t \in {u \in TASKS : loc[u].k = "inflight"}}
           \cup {ev[t].q : t \in {u \in TASKS : ev[u].k = "landing"}}

(* the policy's word says busy: written by ops.running, overwritten with
   free by ops.stopping, which for an expired task runs after balance --
   so a CPU whose balance still has prev on it is still busy *)
Busy(c) == st[c] = "busy"

(* the steal scan visits every CPU but c, in index order *)
FirstOther(c) == IF c = 0 THEN 1 ELSE 0
NextOther(c, j) == IF j + 1 = c THEN j + 2 ELSE j + 1

(* the CPUs the idle search may probe: all of them, or, for the CFS-like
   variant, only the task's previous CPU *)
Probe(t) == IF LOCAL_SELECT THEN {Prev(t)} ELSE CPUS

(* ghost bookkeeping *)
EndWake(t) == [kind |-> "wake", B |-> wb[t], U |-> wu[t]]
EndSched(c) == [kind |-> "sched", B |-> sb[c], U |-> su[c]]
(* a thread was placed on x during every other in-progress event *)
AddU(x, self) ==
  /\ su' = [d \in CPUS |-> IF SchedInProgress(d) THEN su[d] \cup {x}
                                                 ELSE su[d]]
  /\ wu' = [u \in TASKS |-> IF u # self /\ WakeInProgress(u)
                              THEN wu[u] \cup {x} ELSE wu[u]]
(* c's Sched event begins *)
StartSched(c) ==
  /\ sb' = [sb EXCEPT ![c] = {}]
  /\ su' = [su EXCEPT ![c] = Targets]

-----------------------------------------------------------------------------
Init ==
  /\ loc = [t \in TASKS |-> Blocked]
  /\ ev = [t \in TASKS |-> EvNone]
  /\ pub = 0
  /\ phase = [c \in CPUS |-> PhHalted]
  /\ idle_bit = [c \in CPUS |-> TRUE]
  /\ kicked = [c \in CPUS |-> FALSE]
  /\ lk = [c \in CPUS |-> Free]
  /\ st = [c \in CPUS |-> "free"]
  /\ prevt = [c \in CPUS |-> NoTask]
  /\ sb = [c \in CPUS |-> {}] /\ su = [c \in CPUS |-> {}]
  /\ wb = [t \in TASKS |-> {}] /\ wu = [t \in TASKS |-> {}]
  /\ last = NONE

(* try_to_wake_up: ops.select_cpu returns prev_cpu, so the kernel assigns
   the task to a CPU of its choosing; the task is not yet visible *)
WakeStart(t) ==
  /\ loc[t].k = "blocked"
  /\ \E c \in CPUS :
       /\ IF LOCAL_SELECT \/ FIXED_HOME THEN c = Prev(t) ELSE TRUE
       /\ loc' = [loc EXCEPT ![t] = Inflight(c)]
       /\ ev' = [ev EXCEPT ![t] = EvPlacing]
       /\ wb' = [wb EXCEPT ![t] = {}]
       /\ su' = [d \in CPUS |-> IF SchedInProgress(d) THEN su[d] \cup {c}
                                                     ELSE su[d]]
       /\ wu' = [u \in TASKS |-> IF u = t THEN Targets
                                 ELSE IF WakeInProgress(u) THEN wu[u] \cup {c}
                                 ELSE wu[u]]
  /\ last' = NONE
  /\ UNCHANGED <<pub, phase, idle_bit, kicked, lk, st, prevt, sb>>

(* activate on the assigned CPU: its rq lock is taken and ops.enqueue's
   first act is to bump nr_queued *)
Publish(t) ==
  /\ ev[t].k = "placing"
  /\ LET c == loc[t].c IN
     /\ lk[c].k = "free" \/ lk[c] = LkEnq(t)
     /\ lk' = [lk EXCEPT ![c] = LkEnq(t)]
  /\ pub' = pub + 1
  /\ ev' = [ev EXCEPT ![t] = IF NO_ENQ_KICK THEN EvLanding({}, loc[t].c)
                             ELSE EvChecking({}, {})]
  /\ last' = NONE
  /\ UNCHANGED <<loc, phase, idle_bit, kicked, st, prevt, ghost>>

(* one probe of the kernel's idle search inside ops.enqueue: any CPU it
   has not yet seen down. A bit found up is claimed, a test-and-clear, and
   the policy goes on to read that CPU's queue; a bit found down is
   remembered. A search that has seen every CPU down files the task on the
   CPU it was assigned to. *)
CheckBit(t) ==
  /\ ev[t].k = "checking"
  /\ LET vis == ev[t].vis
         ks == ev[t].ks
         c == loc[t].c IN
     IF vis = Probe(t)
       THEN /\ ev' = [ev EXCEPT ![t] = EvLanding(ks, c)]
            /\ UNCHANGED idle_bit
       ELSE \E i \in Probe(t) \ vis :
              IF idle_bit[i]
                THEN /\ idle_bit' = [idle_bit EXCEPT ![i] = FALSE]
                     /\ ev' = [ev EXCEPT ![t] = EvReading(i, ks \cup {i}, 0)]
                ELSE /\ ev' = [ev EXCEPT ![t] = EvChecking(vis \cup {i}, ks)]
                     /\ UNCHANGED idle_bit
  /\ last' = NONE
  /\ UNCHANGED <<loc, pub, phase, kicked, lk, st, prevt, ghost>>

(* the policy's own scan, after the kernel's pick did not take: the bits of
   the CPUs in index order, each tested and cleared once; a hit goes on to
   the queue read like the kernel's pick did, and a scan past the last CPU
   files the task on the CPU it was assigned to. The CFS-like variant does
   not scan. *)
ScanBit(t) ==
  /\ ev[t].k = "scanning"
  /\ LET j == ev[t].j
         ks == ev[t].ks
         c == loc[t].c IN
     IF j >= N \/ LOCAL_SELECT
       THEN /\ ev' = [ev EXCEPT ![t] = EvLanding(ks, c)]
            /\ UNCHANGED idle_bit
       ELSE IF idle_bit[j]
              THEN /\ idle_bit' = [idle_bit EXCEPT ![j] = FALSE]
                   /\ ev' = [ev EXCEPT ![t] = EvReading(j, ks \cup {j}, j + 1)]
              ELSE /\ ev' = [ev EXCEPT ![t] = EvScanning(j + 1, ks)]
                   /\ UNCHANGED idle_bit
  /\ last' = NONE
  /\ UNCHANGED <<loc, pub, phase, kicked, lk, st, prevt, ghost>>

(* scx_bpf_dsq_nr_queued on the claimed CPU's queue, lockless: empty, and
   the word is next; else the CPU is left to the work it has, kicked for it,
   and the scan goes on *)
CheckQueue(t) ==
  /\ ev[t].k = "reading"
  /\ LET i == ev[t].i IN
     ev' = [ev EXCEPT ![t] = IF Dsq(i) = {}
                               THEN EvMarking(i, ev[t].ks, ev[t].next)
                               ELSE EvScanning(ev[t].next, ev[t].ks)]
  /\ last' = NONE
  /\ UNCHANGED <<loc, pub, phase, idle_bit, kicked, lk, st, prevt, ghost>>

(* the claim, a compare-and-swap of i's word from free to promised: it
   went through, and i is the destination -- this is the placement; it did
   not, another task is on its way to i or i has run something since the
   bit was claimed, and the scan goes on *)
CheckMark(t) ==
  /\ ev[t].k = "marking"
  /\ LET i == ev[t].i IN
     IF st[i] # "free"
       THEN /\ ev' = [ev EXCEPT ![t] = EvScanning(ev[t].next, ev[t].ks)]
            /\ UNCHANGED <<st, su, wu>>
       ELSE /\ st' = [st EXCEPT ![i] = "promised"]
            /\ ev' = [ev EXCEPT ![t] = EvLanding(ev[t].ks, i)]
            /\ AddU(i, t)
  /\ last' = NONE
  /\ UNCHANGED <<loc, pub, phase, idle_bit, kicked, lk, prevt, sb, wb>>

(* the deferred insert lands after ops.enqueue returned; the kernel
   reschedules the assigned CPU if it is idle (wakeup_preempt against the
   idle class), the rq lock is dropped, and the kick the callback queued
   goes out: the wake ends *)
Land(t) ==
  /\ ev[t].k = "landing"
  /\ LET c == loc[t].c
         ks == ev[t].ks
         q == ev[t].q IN
     /\ loc' = [loc EXCEPT ![t] = Queued(q)]
     /\ lk' = [lk EXCEPT ![c] = Free]
     \* an idle kick to a CPU that is running by now is dropped
     /\ kicked' = [d \in CPUS |-> IF (d \in ks /\ ~Busy(d))
                                     \/ (d = c /\ phase[c].k = "halted")
                                  THEN TRUE ELSE kicked[d]]
  /\ ev' = [ev EXCEPT ![t] = EvNone]
  /\ last' = EndWake(t)
  /\ UNCHANGED <<pub, phase, idle_bit, st, prevt, ghost>>

(* the running task blocks: schedule() takes c's rq lock and c enters the
   pick path *)
Block(t) ==
  /\ loc[t].k = "running"
  /\ LET c == loc[t].c IN
     /\ lk[c].k = "free" /\ prevt[c] = NoTask
     /\ lk' = [lk EXCEPT ![c] = LkSched]
     /\ loc' = [loc EXCEPT ![t] = Blocked]
     /\ st' = [st EXCEPT ![c] = "free"]
     /\ phase' = [phase EXCEPT ![c] = PhDispatch]
     /\ sb' = [d \in CPUS |-> IF d = c THEN {}
                              ELSE IF SchedInProgress(d) THEN sb[d] \cup {c}
                              ELSE sb[d]]
     /\ su' = [su EXCEPT ![c] = Targets]
     /\ wb' = [u \in TASKS |-> IF WakeInProgress(u) THEN wb[u] \cup {c}
                               ELSE wb[u]]
  /\ last' = NONE
  /\ UNCHANGED <<ev, pub, idle_bit, kicked, prevt, wu>>

(* a task starts running on c and the rq lock is dropped. from is the
   user DSQ the task came off, or N for c's local DSQ; consuming from a
   user DSQ is the dequeue that takes nr_queued back down. Ipanema's rule
   for U: a thread stolen for c from a core j with U(j) may be the one
   placed concurrently, so every event with j in its U set gets c too. *)
Run(c, t, from) ==
  /\ loc' = IF prevt[c] = NoTask
              THEN [loc EXCEPT ![t] = Running(c)]
              ELSE [loc EXCEPT ![t] = Running(c), ![prevt[c]] = Inflight(c)]
  /\ pub' = IF from < N THEN pub - 1 ELSE pub
  \* a thief takes the victim's word from promised to free: the task it
  \* took was the one promised
  /\ st' = IF from < N /\ from # c /\ st[from] = "promised"
             THEN [st EXCEPT ![c] = "busy", ![from] = "free"]
             ELSE [st EXCEPT ![c] = "busy"]
  /\ phase' = [phase EXCEPT ![c] = PhRunning]
  \* an expired prev goes through enqueue under the rq lock this CPU
  \* already holds: put_prev_task_scx runs before the lock is dropped
  /\ lk' = [lk EXCEPT ![c] = IF prevt[c] = NoTask THEN Free ELSE LkEnq(prevt[c])]
  /\ ev' = IF prevt[c] = NoTask THEN ev ELSE [ev EXCEPT ![prevt[c]] = EvPlacing]
  /\ prevt' = [prevt EXCEPT ![c] = NoTask]
  /\ last' = EndSched(c)
  /\ su' = [d \in CPUS |-> IF (from < N /\ d # c /\ SchedInProgress(d)
                              /\ from \in su[d])
                              \/ (prevt[c] # NoTask /\ d # c /\ SchedInProgress(d))
                              THEN su[d] \cup {c} ELSE su[d]]
  /\ wu' = [u \in TASKS |-> IF prevt[c] # NoTask /\ u = prevt[c] THEN Targets
                             ELSE IF (from < N /\ WakeInProgress(u)
                                      /\ from \in wu[u])
                                     \/ (prevt[c] # NoTask /\ WakeInProgress(u))
                             THEN wu[u] \cup {c} ELSE wu[u]]
  /\ wb' = IF prevt[c] = NoTask THEN wb ELSE [wb EXCEPT ![prevt[c]] = {}]
  /\ UNCHANGED <<idle_bit, kicked, sb>>

(* the scan found nothing: the own word goes free again, then idle entry *)
GiveUp(c) ==
  /\ phase' = [phase EXCEPT ![c] = PhUnguard]
  /\ lk' = [lk EXCEPT ![c] = LkSched]
  /\ last' = NONE
  /\ UNCHANGED prevt

(* nothing to run and an expired task still on the CPU: keep running it --
   without SCX_OPS_ENQ_LAST the kernel keeps the expired task when there is
   nothing else; the word stays busy and there is no scan *)
KeepPrev(c) ==
  /\ phase' = [phase EXCEPT ![c] = PhRunning]
  /\ lk' = [lk EXCEPT ![c] = Free]
  /\ prevt' = [prevt EXCEPT ![c] = NoTask]
  /\ last' = EndSched(c)

(* the slice of the running task expires: schedule() takes c's rq lock and
   balance runs with prev still on the CPU. Off in the configurations that
   ask what a design does without the clock's help: with slices, even a
   policy that never steals is eventually work conserving, one slice at a
   time, because the expired task goes back through enqueue. *)
Tick(t) ==
  /\ TICKS
  /\ loc[t].k = "running"
  /\ LET c == loc[t].c IN
     /\ lk[c].k = "free" /\ prevt[c] = NoTask
     /\ lk' = [lk EXCEPT ![c] = LkSched]
     /\ prevt' = [prevt EXCEPT ![c] = t]
     /\ phase' = [phase EXCEPT ![c] = PhDispatch]
     /\ StartSched(c)
  /\ last' = NONE
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, wb, wu>>

(* balance: the local DSQ, then ops.dispatch's own-queue move *)
DispatchOwn(c) ==
  /\ phase[c].k = "dispatch"
  /\ \/ /\ LocalQ(c) # {}
        /\ \E t \in LocalQ(c) : Run(c, t, N)
     \/ /\ LocalQ(c) = {} /\ Dsq(c) # {}
        /\ \E t \in Dsq(c) : Run(c, t, c)
     \/ /\ LocalQ(c) = {} /\ Dsq(c) = {}
        /\ IF prevt[c] # NoTask
             THEN KeepPrev(c)
             ELSE IF NO_STEAL
                    THEN /\ phase' = [phase EXCEPT ![c] = PhIdleSet]
                         /\ last' = NONE
                         /\ UNCHANGED <<lk, prevt>>
                    ELSE /\ phase' = [phase EXCEPT ![c] = PhGuard]
                         /\ last' = NONE
                         /\ UNCHANGED <<lk, prevt>>
        /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, ghost>>

(* the guard: the own word from free to scanning, and the scan begins; or
   the word is promised, a task is on its way, and the CPU goes idle to
   wait for the kick that comes with the landing *)
DispatchGuard(c) ==
  /\ phase[c].k = "guard"
  /\ IF st[c] = "free"
       THEN /\ st' = [st EXCEPT ![c] = "scanning"]
            /\ phase' = [phase EXCEPT ![c] = IF FirstOther(c) >= N THEN PhUnguard
                                             ELSE PhSteal(FirstOther(c))]
       ELSE /\ phase' = [phase EXCEPT ![c] = PhIdleSet]
            /\ UNCHANGED st
  /\ last' = NONE
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, lk, prevt, ghost>>

(* the own word goes free again, then idle entry *)
DispatchUnguard(c) ==
  /\ phase[c].k = "unguard"
  /\ st' = [st EXCEPT ![c] = "free"]
  /\ phase' = [phase EXCEPT ![c] = PhIdleSet]
  /\ last' = NONE
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, lk, prevt, ghost>>

(* the policy's busy flag for j, set by ops.running and cleared by
   ops.stopping, read without a lock: a task is stolen only from a CPU that
   is running another one, which is Ipanema's can_steal_core taking only
   from an overloaded core *)
StealBusy(c) ==
  /\ phase[c].k = "steal"
  /\ LET j == phase[c].j
         nj == NextOther(c, j) IN
     IF Busy(j)
       THEN /\ phase' = [phase EXCEPT ![c] = PhStealCount(j)]
            /\ last' = NONE
            /\ UNCHANGED <<lk, prevt>>
       ELSE IF nj >= N
              THEN GiveUp(c)
              ELSE /\ phase' = [phase EXCEPT ![c] = PhSteal(nj)]
                   /\ last' = NONE
                   /\ UNCHANGED <<lk, prevt>>
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, ghost>>

(* scx_bpf_dsq_nr_queued on queue j, lockless. A hit drops c's own rq lock
   for the move that follows. *)
StealCount(c) ==
  /\ phase[c].k = "stealcount"
  /\ LET j == phase[c].j
         nj == NextOther(c, j) IN
     IF Dsq(j) # {}
       THEN /\ phase' = [phase EXCEPT ![c] = PhStealMove(j)]
            /\ lk' = [lk EXCEPT ![c] = Free]
            /\ last' = NONE
            /\ UNCHANGED prevt
       ELSE IF nj >= N
              THEN GiveUp(c)
              ELSE /\ phase' = [phase EXCEPT ![c] = PhSteal(nj)]
                   /\ last' = NONE
                   /\ UNCHANGED <<lk, prevt>>
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, ghost>>

(* scx_bpf_dsq_move_to_local from queue j: needs j's rq lock, then c's
   own back; the queue may have drained meanwhile *)
StealMove(c) ==
  /\ phase[c].k = "stealmove"
  /\ LET j == phase[c].j IN
     /\ lk[j].k = "free" /\ lk[c].k = "free"
     /\ \/ /\ Dsq(j) # {}
           /\ \E t \in Dsq(j) : Run(c, t, j)
        \/ /\ Dsq(j) = {}
           /\ IF FIRST_ONLY \/ NextOther(c, j) >= N
                THEN GiveUp(c)
                ELSE /\ phase' = [phase EXCEPT ![c] = PhSteal(NextOther(c, j))]
                     /\ lk' = [lk EXCEPT ![c] = LkSched]
                     /\ last' = NONE
                     /\ UNCHANGED prevt
           /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, ghost>>

(* the kernel sets the idle bit, then calls ops.update_idle *)
IdleSet(c) ==
  /\ phase[c].k = "idleset"
  /\ idle_bit' = [idle_bit EXCEPT ![c] = TRUE]
  /\ phase' = [phase EXCEPT ![c] = IF NO_IDLE_KICK THEN PhHalted
                                   ELSE PhIdleCheck]
  /\ lk' = IF NO_IDLE_KICK THEN [lk EXCEPT ![c] = Free] ELSE lk
  /\ last' = IF NO_IDLE_KICK THEN EndSched(c) ELSE NONE
  /\ UNCHANGED <<loc, ev, pub, kicked, st, prevt, ghost>>

(* update_idle reads nr_queued: nothing queued or in flight, and the CPU
   halts with its rq lock dropped; else it goes on to claim its own bit *)
IdleRead(c) ==
  /\ phase[c].k = "idlecheck"
  /\ IF pub > 0
       THEN /\ phase' = [phase EXCEPT ![c] = PhIdleClaim]
            /\ last' = NONE
            /\ UNCHANGED lk
       ELSE /\ phase' = [phase EXCEPT ![c] = PhHalted]
            /\ lk' = [lk EXCEPT ![c] = Free]
            /\ last' = EndSched(c)
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, st, prevt, ghost>>

(* the test-and-clear of the CPU's own idle bit, and the self-kick if it
   was up. A CPU some enqueue already claimed finds its bit clear and stays
   put: that enqueue's task is on its way to this CPU's queue and its kick
   comes with the landing, and a CPU that went stealing meanwhile would end
   up with both. The CPU halts and its rq lock is dropped. *)
IdleClaim(c) ==
  /\ phase[c].k = "idleclaim"
  /\ IF idle_bit[c]
       THEN /\ kicked' = [kicked EXCEPT ![c] = TRUE]
            /\ idle_bit' = [idle_bit EXCEPT ![c] = FALSE]
       ELSE UNCHANGED <<kicked, idle_bit>>
  /\ phase' = [phase EXCEPT ![c] = PhHalted]
  /\ lk' = [lk EXCEPT ![c] = Free]
  /\ last' = EndSched(c)
  /\ UNCHANGED <<loc, ev, pub, st, prevt, ghost>>

(* a kicked idle CPU comes back through balance *)
KickWake(c) ==
  /\ phase[c].k = "halted" /\ kicked[c]
  /\ lk[c].k = "free"
  /\ lk' = [lk EXCEPT ![c] = LkSched]
  /\ kicked' = [kicked EXCEPT ![c] = FALSE]
  /\ idle_bit' = [idle_bit EXCEPT ![c] = FALSE]
  /\ phase' = [phase EXCEPT ![c] = PhDispatch]
  /\ StartSched(c)
  /\ last' = NONE
  /\ UNCHANGED <<loc, ev, pub, st, prevt, wb, wu>>

Next ==
  \/ \E t \in TASKS : WakeStart(t) \/ Publish(t) \/ CheckBit(t)
                      \/ ScanBit(t) \/ CheckQueue(t) \/ CheckMark(t)
                      \/ Land(t) \/ Block(t) \/ Tick(t)
  \/ \E c \in CPUS : DispatchOwn(c) \/ DispatchGuard(c) \/ DispatchUnguard(c)
                     \/ StealBusy(c) \/ StealCount(c)
                     \/ StealMove(c) \/ IdleSet(c) \/ IdleRead(c)
                     \/ IdleClaim(c) \/ KickWake(c)

Spec == Init /\ [][Next]_vars

(* Fairness on everything but Block: a task may run forever, every other
   step eventually happens. The three steps that take an rq lock get strong
   fairness, because a lock holder's release enables them only
   intermittently and a raw spinlock does not starve its waiters; the rest
   get weak fairness. Under it, a pending kick is discharged: the kicked
   CPU ends up running something, or nothing is overloaded any more. This
   is the liveness obligation behind treating a pending kick as an event in
   progress in E, and it is what removing the steal breaks. *)
Fairness ==
  /\ \A t \in TASKS : WF_vars(WakeStart(t)) /\ SF_vars(Publish(t))
                      /\ WF_vars(CheckBit(t)) /\ WF_vars(ScanBit(t))
                      /\ WF_vars(CheckQueue(t)) /\ WF_vars(CheckMark(t))
                      /\ WF_vars(Land(t))
                      /\ SF_vars(Tick(t))
  /\ \A c \in CPUS : WF_vars(DispatchOwn(c)) /\ WF_vars(DispatchGuard(c))
                     /\ WF_vars(DispatchUnguard(c)) /\ WF_vars(StealBusy(c))
                     /\ WF_vars(StealCount(c)) /\ SF_vars(StealMove(c))
                     /\ WF_vars(IdleSet(c)) /\ WF_vars(IdleRead(c))
                     /\ WF_vars(IdleClaim(c)) /\ SF_vars(KickWake(c))
LiveSpec == Init /\ [][Next]_vars /\ Fairness
KickResolves ==
  \A c \in CPUS :
    [](kicked[c] => <>(phase[c].k = "running"
                       \/ \A a \in CPUS : ~Overloaded(a)))

-----------------------------------------------------------------------------
TypeOK ==
  /\ pub \in Nat
  /\ \A t \in TASKS : loc[t].k \in {"blocked", "waking", "inflight",
                                    "queued", "local", "running"}
  /\ \A t \in TASKS : ev[t].k \in {"none", "placing", "checking", "reading",
                                    "marking", "scanning", "landing"}
  /\ \A c \in CPUS : phase[c].k \in {"running", "dispatch", "guard", "steal",
                                     "stealcount", "stealmove", "unguard",
                                     "idleset", "idlecheck", "idleclaim",
                                     "halted"}
  /\ \A c \in CPUS : lk[c].k \in {"free", "sched", "enq"}
  /\ \A c \in CPUS : st[c] \in {"free", "promised", "busy", "scanning"}
  /\ \A c \in CPUS : prevt[c] \in TASKS \cup {NoTask}

(* the count is the queued tasks plus those in flight past the bump *)
PubExact ==
  pub = Cardinality({t \in TASKS : loc[t].k = "queued"})
      + Cardinality({t \in TASKS : ev[t].k \in {"checking", "reading",
                                                "marking", "scanning",
                                                "landing"}})

(* A CPU that is idle with its bit set and no kick pending: nothing will
   move it. It exists only when its last update_idle read a zero count. *)
Stuck(c) == phase[c].k = "halted" /\ idle_bit[c] /\ ~kicked[c]

(* The stronger fact this design satisfies at every state, and the one the
   Verus proof establishes: while any CPU is stuck, no CPU is overloaded.
   It implies CWC below for any B and U; only E is needed. *)
WCStrong == (\E c \in CPUS : Stuck(c)) => \A a \in CPUS : ~Overloaded(a)

(* Concurrent work conservation, at the end of every event *)
CWC ==
  last.kind = "none"
  \/ ((\E c \in CPUS : Overloaded(c) /\ c \notin last.U)
      => \A c2 \in CPUS : ~(Idle(c2) /\ c2 \notin last.B /\ ~InEvent(c2)))

=============================================================================
