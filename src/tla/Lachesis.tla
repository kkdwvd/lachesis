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
(*               not started; checking(i, ks), nr_queued is bumped, the   *)
(*               idle search is at bit i and ks are the CPUs it has       *)
(*               claimed so far; landing(ks, q), the callback is done,    *)
(*               the insert into queue q has not landed, and kicks for    *)
(*               the CPUs in ks go out with it, because scx_bpf_kick_cpu  *)
(*               is an irq_work that runs after the rq lock is dropped.   *)
(*               A hit in the search claims that CPU; if its queue is     *)
(*               empty it becomes the destination, else it is kicked for  *)
(*               the work it already has (a task can land on a CPU's      *)
(*               queue between its failed dispatch and its idle bit going *)
(*               up, since filing on another CPU's queue takes no lock of  *)
(*               that CPU) and the search goes on. The placement happens   *)
(*               at placement time, as Ipanema's unblock_place does, and   *)
(*               a wakeup never lands on a busy CPU while an idle one was  *)
(*               observable. There is no direct dispatch to a local DSQ:   *)
(*               a task there cannot be stolen, and one that lands after   *)
(*               its CPU was kicked into stealing is a bubble nobody can   *)
(*               fix.                                                      *)
(*   pub         the policy's nr_queued: bumped by ops.enqueue before      *)
(*               anything else, taken down when a queued task is consumed  *)
(*               (ops.dequeue).                                            *)
(*   phase[c]    what CPU c is doing: running; dispatch (local DSQ, then   *)
(*               ops.dispatch's own-queue move); steal(j) (reading queue   *)
(*               j's count); stealmove(j) (moving from it, own rq lock     *)
(*               dropped); idleset (about to set the idle bit); idlecheck  *)
(*               (update_idle reading pub); halted.                        *)
(*   idle_bit[c] the kernel's idle mask bit.                               *)
(*   kicked[c]   a resched is pending for c.                               *)
(*   claimed[c]  the policy's per-CPU mark: an enqueue has claimed c and   *)
(*               filed a task for its queue that nobody has consumed yet. *)
(*               Set by the claimer, cleared by whoever consumes from c's  *)
(*               queue; a second claimer finding it set kicks c and looks  *)
(*               on, since c will cycle through idle, and advertise its    *)
(*               bit again, if something else wakes it first.             *)
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
          NO_STEAL,     \* dispatch never steals (step 1 alone)
          FIRST_ONLY,   \* a failed steal move gives up (CFS balancing)
          NO_ENQ_KICK,  \* enqueue does not search for an idle CPU again
          NO_IDLE_KICK, \* update_idle does not read the count
          LOCAL_SELECT  \* the idle search looks only at prev(t) (CFS)

ASSUME N \in Nat /\ N >= 1

CPUS == 0..N-1
Prev(t) == (t - 1) % N
NONE == [kind |-> "none"]
Perms == Permutations(TASKS)

VARIABLES loc, ev, pub, phase, idle_bit, kicked, lk, claimed,
          sb, su, wb, wu, last
vars == <<loc, ev, pub, phase, idle_bit, kicked, lk, claimed,
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
EvChecking(i, ks) == [k |-> "checking", i |-> i, ks |-> ks]
EvLanding(ks, q) == [k |-> "landing", ks |-> ks, q |-> q]

(* CPU phases and lock states *)
PhRunning == [k |-> "running"]
PhDispatch == [k |-> "dispatch"]
PhSteal(j) == [k |-> "steal", j |-> j]
PhStealMove(j) == [k |-> "stealmove", j |-> j]
PhIdleSet == [k |-> "idleset"]
PhIdleCheck == [k |-> "idlecheck"]
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

(* the steal scan visits every CPU but c, in index order *)
FirstOther(c) == IF c = 0 THEN 1 ELSE 0
NextOther(c, j) == IF j + 1 = c THEN j + 2 ELSE j + 1
AfterFail(c, j) == LET nj == NextOther(c, j) IN
                     IF nj >= N THEN PhIdleSet ELSE PhSteal(nj)

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
  /\ claimed = [c \in CPUS |-> FALSE]
  /\ sb = [c \in CPUS |-> {}] /\ su = [c \in CPUS |-> {}]
  /\ wb = [t \in TASKS |-> {}] /\ wu = [t \in TASKS |-> {}]
  /\ last = NONE

(* try_to_wake_up: ops.select_cpu returns prev_cpu, so the kernel assigns
   the task to a CPU of its choosing; the task is not yet visible *)
WakeStart(t) ==
  /\ loc[t].k = "blocked"
  /\ \E c \in CPUS :
       /\ IF LOCAL_SELECT THEN c = Prev(t) ELSE TRUE
       /\ loc' = [loc EXCEPT ![t] = Inflight(c)]
       /\ ev' = [ev EXCEPT ![t] = EvPlacing]
       /\ wb' = [wb EXCEPT ![t] = {}]
       /\ su' = [d \in CPUS |-> IF SchedInProgress(d) THEN su[d] \cup {c}
                                                     ELSE su[d]]
       /\ wu' = [u \in TASKS |-> IF u = t THEN Targets
                                 ELSE IF WakeInProgress(u) THEN wu[u] \cup {c}
                                 ELSE wu[u]]
  /\ last' = NONE
  /\ UNCHANGED <<pub, phase, idle_bit, kicked, lk, claimed, sb>>

(* activate on the assigned CPU: its rq lock is taken and ops.enqueue's
   first act is to bump nr_queued *)
Publish(t) ==
  /\ ev[t].k = "placing"
  /\ LET c == loc[t].c IN
     /\ lk[c].k = "free"
     /\ lk' = [lk EXCEPT ![c] = LkEnq(t)]
  /\ pub' = pub + 1
  /\ ev' = [ev EXCEPT ![t] = IF NO_ENQ_KICK THEN EvLanding({}, loc[t].c)
                             ELSE EvChecking(IF LOCAL_SELECT THEN Prev(t)
                                             ELSE 0, {})]
  /\ last' = NONE
  /\ UNCHANGED <<loc, phase, idle_bit, kicked, claimed, ghost>>

(* the idle search inside ops.enqueue, one test-and-clear per step. A hit
   claims that CPU: with an empty queue it becomes the destination, else it
   is kicked for what it has and the search goes on; a scan that misses
   everywhere files the task on the CPU it was assigned to *)
CheckRead(t) ==
  /\ ev[t].k = "checking"
  /\ LET i == ev[t].i
         ks == ev[t].ks
         c == loc[t].c IN
     \/ /\ i < N /\ idle_bit[i] /\ Dsq(i) = {} /\ ~claimed[i]
        /\ idle_bit' = [idle_bit EXCEPT ![i] = FALSE]
        /\ claimed' = [claimed EXCEPT ![i] = TRUE]
        /\ ev' = [ev EXCEPT ![t] = EvLanding(ks \cup {i}, i)]
        /\ AddU(i, t)
     \/ /\ i < N /\ idle_bit[i] /\ (Dsq(i) # {} \/ claimed[i])
        /\ idle_bit' = [idle_bit EXCEPT ![i] = FALSE]
        /\ UNCHANGED claimed
        /\ ev' = [ev EXCEPT ![t] = IF LOCAL_SELECT THEN EvLanding(ks \cup {i}, c)
                                   ELSE EvChecking(i + 1, ks \cup {i})]
        /\ UNCHANGED <<su, wu>>
     \/ /\ i < N /\ ~idle_bit[i]
        /\ ev' = [ev EXCEPT ![t] = IF LOCAL_SELECT THEN EvLanding(ks, c)
                                   ELSE EvChecking(i + 1, ks)]
        /\ UNCHANGED <<idle_bit, claimed, su, wu>>
     \/ /\ i = N
        /\ ev' = [ev EXCEPT ![t] = EvLanding(ks, c)]
        /\ UNCHANGED <<idle_bit, claimed, su, wu>>
  /\ last' = NONE
  /\ UNCHANGED <<loc, pub, phase, kicked, lk, sb, wb>>

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
     /\ kicked' = [d \in CPUS |-> IF (d \in ks /\ phase[d].k # "running")
                                     \/ (d = c /\ phase[c].k = "halted")
                                  THEN TRUE ELSE kicked[d]]
  /\ ev' = [ev EXCEPT ![t] = EvNone]
  /\ last' = EndWake(t)
  /\ UNCHANGED <<pub, phase, idle_bit, claimed, ghost>>

(* the running task blocks: schedule() takes c's rq lock and c enters the
   pick path *)
Block(t) ==
  /\ loc[t].k = "running"
  /\ LET c == loc[t].c IN
     /\ lk[c].k = "free"
     /\ lk' = [lk EXCEPT ![c] = LkSched]
     /\ loc' = [loc EXCEPT ![t] = Blocked]
     /\ phase' = [phase EXCEPT ![c] = PhDispatch]
     /\ sb' = [d \in CPUS |-> IF d = c THEN {}
                              ELSE IF SchedInProgress(d) THEN sb[d] \cup {c}
                              ELSE sb[d]]
     /\ su' = [su EXCEPT ![c] = Targets]
     /\ wb' = [u \in TASKS |-> IF WakeInProgress(u) THEN wb[u] \cup {c}
                               ELSE wb[u]]
  /\ last' = NONE
  /\ UNCHANGED <<ev, pub, idle_bit, kicked, claimed, wu>>

(* a task starts running on c and the rq lock is dropped. from is the
   user DSQ the task came off, or N for c's local DSQ; consuming from a
   user DSQ is the dequeue that takes nr_queued back down. Ipanema's rule
   for U: a thread stolen for c from a core j with U(j) may be the one
   placed concurrently, so every event with j in its U set gets c too. *)
Run(c, t, from) ==
  /\ loc' = [loc EXCEPT ![t] = Running(c)]
  /\ pub' = IF from < N THEN pub - 1 ELSE pub
  /\ claimed' = IF from < N THEN [claimed EXCEPT ![from] = FALSE] ELSE claimed
  /\ phase' = [phase EXCEPT ![c] = PhRunning]
  /\ lk' = [lk EXCEPT ![c] = Free]
  /\ last' = EndSched(c)
  /\ su' = [d \in CPUS |-> IF from < N /\ d # c /\ SchedInProgress(d)
                              /\ from \in su[d]
                              THEN su[d] \cup {c} ELSE su[d]]
  /\ wu' = [u \in TASKS |-> IF from < N /\ WakeInProgress(u)
                               /\ from \in wu[u]
                               THEN wu[u] \cup {c} ELSE wu[u]]
  /\ UNCHANGED <<ev, idle_bit, kicked, sb, wb>>

(* balance: the local DSQ, then ops.dispatch's own-queue move *)
DispatchOwn(c) ==
  /\ phase[c].k = "dispatch"
  /\ \/ /\ LocalQ(c) # {}
        /\ \E t \in LocalQ(c) : Run(c, t, N)
     \/ /\ LocalQ(c) = {} /\ Dsq(c) # {}
        /\ \E t \in Dsq(c) : Run(c, t, c)
     \/ /\ LocalQ(c) = {} /\ Dsq(c) = {}
        /\ phase' = [phase EXCEPT ![c] =
                       IF NO_STEAL \/ FirstOther(c) >= N THEN PhIdleSet
                       ELSE PhSteal(FirstOther(c))]
        /\ last' = NONE
        /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, lk, claimed, ghost>>

(* the policy's busy flag for j (set by ops.running, cleared by
   ops.stopping) and scx_bpf_dsq_nr_queued on queue j, both lockless: a
   task is stolen only from a CPU that is running another one, which is
   Ipanema's can_steal_core taking only from an overloaded core. A hit
   drops c's own rq lock for the move that follows. *)
StealRead(c) ==
  /\ phase[c].k = "steal"
  /\ LET j == phase[c].j IN
     IF phase[j].k = "running" /\ Dsq(j) # {}
       THEN /\ phase' = [phase EXCEPT ![c] = PhStealMove(j)]
            /\ lk' = [lk EXCEPT ![c] = Free]
       ELSE /\ phase' = [phase EXCEPT ![c] = AfterFail(c, j)]
            /\ UNCHANGED lk
  /\ last' = NONE
  /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, claimed, ghost>>

(* scx_bpf_dsq_move_to_local from queue j: needs j's rq lock, then c's
   own back; the queue may have drained meanwhile *)
StealMove(c) ==
  /\ phase[c].k = "stealmove"
  /\ LET j == phase[c].j IN
     /\ lk[j].k = "free" /\ lk[c].k = "free"
     /\ \/ /\ Dsq(j) # {}
           /\ \E t \in Dsq(j) : Run(c, t, j)
        \/ /\ Dsq(j) = {}
           /\ phase' = [phase EXCEPT ![c] = IF FIRST_ONLY THEN PhIdleSet
                                            ELSE AfterFail(c, j)]
           /\ lk' = [lk EXCEPT ![c] = LkSched]
           /\ last' = NONE
           /\ UNCHANGED <<loc, ev, pub, idle_bit, kicked, claimed, ghost>>

(* the kernel sets the idle bit, then calls ops.update_idle *)
IdleSet(c) ==
  /\ phase[c].k = "idleset"
  /\ idle_bit' = [idle_bit EXCEPT ![c] = TRUE]
  /\ phase' = [phase EXCEPT ![c] = IF NO_IDLE_KICK THEN PhHalted
                                   ELSE PhIdleCheck]
  /\ lk' = IF NO_IDLE_KICK THEN [lk EXCEPT ![c] = Free] ELSE lk
  /\ last' = IF NO_IDLE_KICK THEN EndSched(c) ELSE NONE
  /\ UNCHANGED <<loc, ev, pub, kicked, claimed, ghost>>

(* update_idle reads nr_queued and, if work exists, claims its own idle
   bit with a test-and-clear and kicks self. A CPU some enqueue already
   claimed finds its bit clear and stays put: that enqueue's task is on its
   way to this CPU's queue and its kick comes with the landing, and a CPU
   that went stealing meanwhile would end up with both. The CPU halts and
   its rq lock is dropped. *)
IdleCheck(c) ==
  /\ phase[c].k = "idlecheck"
  /\ IF pub > 0 /\ idle_bit[c]
       THEN /\ kicked' = [kicked EXCEPT ![c] = TRUE]
            /\ idle_bit' = [idle_bit EXCEPT ![c] = FALSE]
       ELSE UNCHANGED <<kicked, idle_bit>>
  /\ phase' = [phase EXCEPT ![c] = PhHalted]
  /\ lk' = [lk EXCEPT ![c] = Free]
  /\ last' = EndSched(c)
  /\ UNCHANGED <<loc, ev, pub, claimed, ghost>>

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
  /\ UNCHANGED <<loc, ev, pub, claimed, wb, wu>>

Next ==
  \/ \E t \in TASKS : WakeStart(t) \/ Publish(t) \/ CheckRead(t)
                      \/ Land(t) \/ Block(t)
  \/ \E c \in CPUS : DispatchOwn(c) \/ StealRead(c) \/ StealMove(c)
                     \/ IdleSet(c) \/ IdleCheck(c) \/ KickWake(c)

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
                      /\ WF_vars(CheckRead(t)) /\ WF_vars(Land(t))
  /\ \A c \in CPUS : WF_vars(DispatchOwn(c)) /\ WF_vars(StealRead(c))
                     /\ SF_vars(StealMove(c)) /\ WF_vars(IdleSet(c))
                     /\ WF_vars(IdleCheck(c)) /\ SF_vars(KickWake(c))
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
  /\ \A t \in TASKS : ev[t].k \in {"none", "placing", "checking", "landing"}
  /\ \A c \in CPUS : phase[c].k \in {"running", "dispatch", "steal",
                                     "stealmove", "idleset", "idlecheck",
                                     "halted"}
  /\ \A c \in CPUS : lk[c].k \in {"free", "sched", "enq"}
  /\ \A c \in CPUS : claimed[c] \in BOOLEAN

(* the count is the queued tasks plus those in flight past the bump *)
PubExact ==
  pub = Cardinality({t \in TASKS : loc[t].k = "queued"})
      + Cardinality({t \in TASKS : ev[t].k \in {"checking", "landing"}})

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
