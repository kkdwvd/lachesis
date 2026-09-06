#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Guest side of `make lachesis-run`: run the lachesis loader as the
# machine's sched_ext scheduler, put a workload under it, print the evidence
# and let it detach again.
#
# Runs as root inside the virtme-ng guest, which shares the host filesystem,
# so it reads the binary and the object straight out of build/ and writes its
# logs back there. It refuses to run anywhere that does not look like a QEMU
# guest: loading a scheduler on the development host would displace whatever
# sched_ext scheduler that host is running. The loader applies the same guard
# itself -- this one is here so the script stops before it has done anything
# at all.
#
# Usage: vm-guest.sh <binary> <object> <output-dir> [workload-seconds]

set -u

BIN=${1:?usage: vm-guest.sh <binary> <object> <output-dir> [seconds]}
OBJ=${2:?usage: vm-guest.sh <binary> <object> <output-dir> [seconds]}
OUTDIR=${3:?usage: vm-guest.sh <binary> <object> <output-dir> [seconds]}
SECS=${4:-5}
BPFTOOL=${BPFTOOL:-/usr/sbin/bpftool}
VERIFY_PIN=/sys/fs/bpf/lachesis_verify
SCX=/sys/kernel/sched_ext

hdr() { printf '\n===== %s =====\n' "$*"; }

# Host-visible marker: the guest transcript starts here, with its own
# wall-clock timestamp, so the host side can tell how long boot took versus
# how long the guest script itself ran.
echo "$(date '+%H:%M:%S') guest transcript starting"

vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo unknown)
if [[ "$vendor" != QEMU ]]; then
	echo "refusing to load a sched_ext scheduler outside a VM" >&2
	echo "(/sys/class/dmi/id/sys_vendor is '$vendor', expected 'QEMU')" >&2
	exit 1
fi

hdr "guest"
uname -a
echo "nr_cpus=$(nproc)"
echo "bpftool=$($BPFTOOL version | head -1)"
echo "loader=$BIN"
echo "object=$OBJ"

mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir -p "$OUTDIR"

hdr "initial sched_ext state"
cat "$SCX/state"
echo "enable_seq=$(cat "$SCX/enable_seq")"
echo "nr_rejected=$(cat "$SCX/nr_rejected")"

# Verifier-only pass: prog loadall creates the maps and runs every program
# through the verifier without attaching the scheduler. The loader would
# report a load failure too, but this separates "the verifier rejected the
# program" from "attaching failed".
hdr "verifier pass (log in $OUTDIR/verifier.log)"
rm -rf "$VERIFY_PIN"
$BPFTOOL -d prog loadall "$OBJ" "$VERIFY_PIN" > "$OUTDIR/verifier.log" 2>&1
vrc=$?
echo "bpftool prog loadall rc=$vrc, $(wc -l < "$OUTDIR/verifier.log") log lines"
grep -E "^(processed|libbpf: prog .*: -- BEGIN|.*BPF program load failed)" \
	"$OUTDIR/verifier.log" | head -20
rm -rf "$VERIFY_PIN"

# What sched_ext itself thinks, sampled once a second for as long as the
# loader holds the link. Recorded to a file rather than to stdout so the two
# streams do not interleave in the transcript.
( start=$SECONDS
  while ((SECONDS - start <= SECS + 3)); do
	printf '%2ds state=%-9s root/ops=%s\n' "$((SECONDS - start))" \
		"$(cat "$SCX/state" 2>/dev/null || echo -)" \
		"$(cat "$SCX/root/ops" 2>/dev/null || echo -)"
	sleep 1
  done ) > "$OUTDIR/sched_ext.log" 2>&1 &

# Something to schedule: busy loops on every CPU, plus a few sleepers to
# exercise enqueue and dispatch rather than just the running path.
for _ in $(seq "$(nproc)"); do
	timeout "$SECS" sh -c 'while :; do :; done' &
done
for _ in 1 2 3 4; do
	timeout "$SECS" sh -c 'while :; do sleep 0.01; done' &
done

hdr "run: lachesis --duration $SECS --interval 1"
"$BIN" --obj "$OBJ" --duration "$SECS" --interval 1
rc=$?
echo "lachesis rc=$rc"
wait

hdr "sched_ext while it ran"
cat "$OUTDIR/sched_ext.log"

hdr "sched_ext state after detach"
echo "state=$(cat "$SCX/state")"
echo "enable_seq=$(cat "$SCX/enable_seq")"
echo "nr_rejected=$(cat "$SCX/nr_rejected")"
test -e "$SCX/root/ops" && echo "root/ops=$(cat "$SCX/root/ops")" || echo "root/ops gone"

hdr "dmesg (sched_ext)"
dmesg | grep -iE 'sched_ext|scx' | tail -30

hdr "result"
state=$(cat "$SCX/state")
if ((rc == 0)) && [[ "$state" == disabled ]]; then
	echo "OK: scheduler attached, ran the workload and detached cleanly"
else
	echo "FAIL: lachesis rc=$rc, sched_ext state is $state after detach"
	exit 1
fi
