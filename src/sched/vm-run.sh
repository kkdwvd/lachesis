#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Host side of `make lachesis-run`: boot the target kernel under
# virtme-ng and hand vm-guest.sh the loader and the object it loads.
#
# The scheduler is only ever loaded inside the guest; nothing here touches
# the host's /sys/kernel/sched_ext or /sys/fs/bpf.
#
# Usage: vm-run.sh <binary> <object> <kernel-build-dir> <output-dir> [seconds]

set -euo pipefail

USAGE='usage: vm-run.sh <binary> <object> <kernel-build-dir> <output-dir> [seconds]'
BIN=${1:?$USAGE}
OBJ=${2:?$USAGE}
KERNEL=${3:?$USAGE}
OUTDIR=${4:?$USAGE}
SECS=${5:-5}

SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUEST=$SRC_DIR/vm-guest.sh
LOG=$OUTDIR/run.log

VNG=${VNG:-vng}
VM_CPUS=${VM_CPUS:-4}
VM_MEM=${VM_MEM:-2G}
# A wedged scheduler must never hang the caller. sched_ext's own watchdog
# ejects a stalled scheduler long before this fires.
VM_TIMEOUT=${VM_TIMEOUT:-300}

[[ -x "$BIN" ]] || { echo "no loader at $BIN; run 'make lachesis' first" >&2; exit 1; }
[[ -f "$OBJ" ]] || { echo "no object at $OBJ; run 'make lachesis' first" >&2; exit 1; }
[[ -d "$KERNEL" || -f "$KERNEL" ]] || { echo "no kernel at $KERNEL" >&2; exit 1; }
command -v "$VNG" >/dev/null || { echo "virtme-ng ($VNG) not found" >&2; exit 1; }

mkdir -p "$OUTDIR"

# --- ending the run --------------------------------------------------------
#
# vng execs virtme-run with a plain fork+exec, and virtme-run execs qemu the
# same way; nothing in that chain calls setsid or setpgid, and this script
# never backgrounds the pipeline below or turns on job control. So the whole
# tree -- this script, vng, tee, virtme-run and qemu -- shares one process
# group: whatever the terminal's foreground group was when
# `make lachesis-run` started. A Ctrl-C is delivered by the tty driver to
# that group, so it reaches every one of them at once, and that is most of
# what makes a run interruptible.
#
# There is deliberately no `timeout` wrapped around vng. It cannot end a run
# either way it is used: plain, it calls setpgid() on itself and its child,
# moving the tree out of the terminal's foreground group where a Ctrl-C can
# never reach it; with --foreground, its expiry signal goes only to its
# immediate child, by its own man page's wording ("children of COMMAND will
# not be timed out"), so vng dies while qemu runs the guest to completion.
# That second case is worse than useless here: killing vng reparents
# virtme-run to init, which takes the VM out of this script's process tree
# and hides it from the walk below. The watchdog is the deadline instead,
# and it signals qemu directly.
#
# `reap` is the backstop for everything a terminal signal does not finish:
# it finds what is still ours and still alive and signals it, escalating to
# SIGKILL if a few seconds of SIGTERM did not do it. It runs from the
# INT/TERM trap, from the watchdog when VM_TIMEOUT expires, and once more
# after the pipeline exits.

interrupted=0

# A snapshot of the process table, taken with exactly one fork. Enumerating
# descendants by calling `pgrep -P` once per node instead makes each of those
# calls itself a transient child of $$ for the instant it runs, so a loop
# that reruns the same query to ask "is anything left" always sees at least
# its own scanning machinery and never converges. `ps` itself is no exception
# -- it lists itself while it is still alive and gathering the table -- so
# its own row (named "ps", the one thing this snapshot forks) is dropped.
declare -A CHILDREN
declare -A COMM
snapshot() {
	CHILDREN=()
	COMM=()
	local tmp pid ppid comm
	tmp=$(mktemp)
	ps -eo pid,ppid,comm --no-headers >"$tmp"
	while read -r pid ppid comm; do
		[[ "$comm" == ps ]] && continue
		CHILDREN[$ppid]+=" $pid"
		COMM[$pid]=$comm
	done <"$tmp"
	rm -f "$tmp"
}

# Every live descendant of $1 in the last snapshot, breadth-first.
descendants_of() {
	local -a queue=("$1") out=()
	local p kid
	while ((${#queue[@]})); do
		p=${queue[0]}
		queue=("${queue[@]:1}")
		for kid in ${CHILDREN[$p]-}; do
			out+=("$kid")
			queue+=("$kid")
		done
	done
	((${#out[@]})) || return 0
	printf '%s\n' "${out[@]}"
}

# Everything this run has ever owned, pid -> the name it had when first seen.
# Membership has to be remembered rather than recomputed: killing a process
# in the middle of the chain reparents what is below it to init, and an
# orphaned qemu is no longer reachable by walking down from $$. Remembering
# the name as well is what makes that safe -- a pid recycled onto an
# unrelated process between two rounds no longer matches and is not signalled.
declare -A TRACKED
GUEST_MARK="--script-sh bash $GUEST"

# Fold the current snapshot into TRACKED: this script's descendants, plus any
# already-orphaned virtme-run still carrying this run's guest command line,
# plus everything under it.
track() {
	local root kid
	snapshot
	for kid in $(descendants_of $$); do
		TRACKED[$kid]=${COMM[$kid]-}
	done
	for root in $(pgrep -f -- "$GUEST_MARK" 2>/dev/null || true); do
		[[ -n "${COMM[$root]-}" ]] || continue
		TRACKED[$root]=${COMM[$root]}
		for kid in $(descendants_of "$root"); do
			TRACKED[$kid]=${COMM[$kid]-}
		done
	done
}

# The tracked processes still present in the last snapshot under the name
# they were tracked with. Fails when there are none, which is what ends the
# reap loop. Never reports the caller itself: the watchdog subshell is a
# descendant of $$ like everything else.
survivors() {
	local p out=()
	for p in "${!TRACKED[@]}"; do
		[[ "$p" == "$BASHPID" || "$p" == "$$" ]] && continue
		[[ "${COMM[$p]-}" == "${TRACKED[$p]}" ]] || continue
		out+=("$p")
	done
	((${#out[@]})) || return 1
	printf '%s\n' "${out[@]}"
}

reap() {
	local pids i
	for i in $(seq 1 15); do
		track
		pids=$(survivors) || return 0
		kill -TERM $pids 2>/dev/null || true
		sleep 0.2
	done
	track
	pids=$(survivors) || return 0
	kill -KILL $pids 2>/dev/null || true
}

# The watchdog: the deadline for the whole run, and the only thing that can
# end one the pipeline itself will not end. A marker file tells the main
# script afterwards that this is what happened.
#
# It must not inherit the pipeline's stdout. A background process holding the
# write end keeps the reader waiting for EOF, so a normal run would not
# finish until the watchdog's sleep ran out -- five minutes for a
# twelve-second run. Its output goes to the log instead.
WATCHDOG_MARK=$OUTDIR/.watchdog-fired
rm -f "$WATCHDOG_MARK"
watchdog() {
	sleep "$VM_TIMEOUT"
	touch "$WATCHDOG_MARK"
	echo "watchdog: VM_TIMEOUT=${VM_TIMEOUT}s expired; terminating the VM"
	reap
}

# Stop the watchdog and the `sleep` it is blocked in. Killing the subshell
# alone would reparent the sleep to init, where it keeps running -- harmless
# in itself, but it holds the log open and, before the redirection above, it
# held the caller's pipe open too.
stop_watchdog() {
	[[ -n "${WATCHDOG_PID:-}" ]] || return 0
	pkill -P "$WATCHDOG_PID" 2>/dev/null || true
	kill "$WATCHDOG_PID" 2>/dev/null || true
	wait "$WATCHDOG_PID" 2>/dev/null || true
	WATCHDOG_PID=
}

on_signal() {
	interrupted=1
	echo "interrupted; transcript in $LOG"
	stop_watchdog
	reap
}
trap on_signal INT TERM

echo "$(date '+%H:%M:%S') booting $KERNEL under $VNG (${VM_CPUS} cpus, ${VM_MEM}); transcript -> $LOG"
watchdog >>"$LOG" 2>&1 &
WATCHDOG_PID=$!
set +e
"$VNG" --run "$KERNEL" \
	--user root --cpus "$VM_CPUS" --memory "$VM_MEM" \
	--disable-microvm --rw \
	-- "bash $(printf '%q' "$GUEST") $(printf '%q' "$BIN") $(printf '%q' "$OBJ") $(printf '%q' "$OUTDIR") $SECS" \
	2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
set -e

trap - INT TERM
stop_watchdog
reap

if ((interrupted)); then
	exit 130
fi

if [[ -e "$WATCHDOG_MARK" ]]; then
	rm -f "$WATCHDOG_MARK"
	echo "VM run exceeded VM_TIMEOUT=${VM_TIMEOUT}s and was terminated; see $LOG" >&2
	exit 124
fi

if ((rc != 0)); then
	echo "vng exited with $rc; see $LOG" >&2
	exit "$rc"
fi
# vng always exits 0; the guest script's verdict is the real result.
if ! grep -q '^OK: scheduler attached' "$LOG"; then
	echo "guest run did not report success; see $LOG" >&2
	exit 1
fi
echo "lachesis ran as the guest's sched_ext scheduler; transcript in $LOG"
