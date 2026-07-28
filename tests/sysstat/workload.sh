#!/bin/sh
# Deterministic memory workload for the sysstat cgroup-memory tests.
#
# Unlike the fio-driven suites there is no external tool to compare against, so
# this script *is* the ground truth: it allocates exactly the amounts the test
# Makefile asks for, and check_test.py asserts the collector saw them.
#
#   ANON_BYTES   anonymous memory to hold resident (0 = none)
#   FILE_BYTES   file to create and keep read into page cache (0 = none)
#   DURATION     seconds to hold the allocation before exiting (0 = forever)
#
# POSIX sh only — this runs under busybox in the alpine test image.

set -u

ANON_BYTES="${ANON_BYTES:-0}"
FILE_BYTES="${FILE_BYTES:-0}"
DURATION="${DURATION:-0}"
WORK_FILE="${WORK_FILE:-/tmp/sysstat-memtest.dat}"

if [ "$FILE_BYTES" -gt 0 ]; then
    # Write the file, then drop it from *this* process's address space and read
    # it back — the pages stay in page cache, charged to the cgroup as `file`,
    # which is precisely the memory that process-resident RSS cannot see.
    dd if=/dev/zero of="$WORK_FILE" bs=1048576 count=$((FILE_BYTES / 1048576)) 2>/dev/null
    cat "$WORK_FILE" > /dev/null
fi

if [ "$ANON_BYTES" -gt 0 ]; then
    # A shell variable holding N bytes is N bytes of heap, i.e. anonymous memory.
    # `tr` is needed because command substitution strips NUL bytes.
    #
    # Deliberately NOT exported: an exported variable goes into the environment,
    # which is copied into every subsequent exec's argv/env block, and N MB there
    # makes exec fail with E2BIG. That stays invisible under busybox (where
    # `sleep` is a shell builtin, so nothing execs) and breaks immediately on a
    # host shell with a real /bin/sleep.
    ANON_HOLD=$(head -c "$ANON_BYTES" /dev/zero | tr '\0' 'x')
fi

echo "workload ready: anon=${ANON_BYTES}B file=${FILE_BYTES}B"
# Referenced once so no shell can decide the variable is dead and free it.
[ "$ANON_BYTES" -gt 0 ] && [ -z "${ANON_HOLD:-}" ] && echo "warning: anon allocation lost" >&2

# Keep re-reading the file so its pages stay hot (and stay accounted) for the
# whole collection window rather than ageing out of the active list.
elapsed=0
while [ "$DURATION" -eq 0 ] || [ "$elapsed" -lt "$DURATION" ]; do
    if [ "$FILE_BYTES" -gt 0 ]; then
        cat "$WORK_FILE" > /dev/null
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done
