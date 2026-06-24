#!/usr/bin/env bash
# Wait until the target block device(s) report zero in-flight I/O before a
# capture window opens, so a short job is not polluted by the *previous* job's
# still-draining commands. The access-pattern / counter checks read the start of
# the window; leftover commands there scramble seq/rnd classification and inflate
# counts (see container-mode val_seqread failures).
#
# Best-effort and bounded: unresolvable targets and a missing helper just return
# immediately (never block the suite), and the poll gives up after <timeout_s>.
#
# Usage: wait_device_idle.sh <dev-or-path-csv> [timeout_s]
#   dev-or-path-csv : comma-separated device names (nvme1n1), device nodes
#                     (/dev/nvme1n1, /dev/ng1n1 generic char dev), or a
#                     filesystem path (resolved to its backing disk via findmnt).
#   timeout_s       : max seconds to wait for quiescence (default 10).
set -u

spec="${1:-}"
timeout_s="${2:-10}"

# Resolve one spec item to a whole-disk name under /sys/block, or nothing.
to_block() {
  local x="$1"
  # A filesystem path -> its backing source device.
  if [ -e "$x" ] && [ "${x#/dev/}" = "$x" ]; then
    local src
    src=$(findmnt -no SOURCE --target "$x" 2>/dev/null) || return 0
    [ -n "$src" ] && x="$src"
  fi
  x="${x#/dev/}"
  # nvme generic char device ngXnY -> block namespace nvmeXnY.
  if [[ "$x" =~ ^ng([0-9]+)n([0-9]+)$ ]]; then
    x="nvme${BASH_REMATCH[1]}n${BASH_REMATCH[2]}"
  fi
  if [ -e "/sys/block/$x/inflight" ]; then
    printf '%s\n' "$x"
    return 0
  fi
  # Reduce a partition to its whole disk (nvme/mmc use ...pN, sd*/vd* trailing N).
  local parent="$x"
  if [[ "$x" =~ ^(nvme[0-9]+n[0-9]+|mmcblk[0-9]+)p[0-9]+$ ]]; then
    parent="${BASH_REMATCH[1]}"
  elif [[ "$x" =~ ^([a-z]+)[0-9]+$ ]]; then
    parent="${BASH_REMATCH[1]}"
  fi
  [ -e "/sys/block/$parent/inflight" ] && printf '%s\n' "$parent"
}

declare -A seen=()
declare -a devs=()
IFS=',' read -ra items <<< "$spec"
for it in "${items[@]}"; do
  [ -z "$it" ] && continue
  d=$(to_block "$it") || continue
  [ -z "$d" ] && continue
  [ -n "${seen[$d]:-}" ] && continue
  seen[$d]=1
  devs+=("$d")
done

# Nothing resolvable -> do not block.
[ ${#devs[@]} -eq 0 ] && exit 0

inflight_total() {
  local sum=0 r w d
  for d in "${devs[@]}"; do
    read -r r w < "/sys/block/$d/inflight" 2>/dev/null || continue
    sum=$(( sum + r + w ))
  done
  printf '%s' "$sum"
}

deadline=$(( $(date +%s) + timeout_s ))
while [ "$(inflight_total)" -ne 0 ]; do
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 0.2
done
exit 0
