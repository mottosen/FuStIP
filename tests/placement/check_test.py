#!/usr/bin/env python3
"""Correctness suite for PROFILER_CPUSET — the collector-placement contract.

WHY THIS SUITE EXISTS AND WHY IT NEEDS NO HARDWARE. Every other suite here compares
the profiler's accounting against FIO's, so it needs root, a device and minutes of
I/O. What PROFILER_CPUSET changes is not accounting but the *command line* each
layer launches, and that is fully determined before anything runs. So this suite
asserts on `make -n` output: it needs no root, no NVMe device, no fio, and runs in
about a second, which means it can be part of every change rather than a thing
someone remembers to do occasionally.

WHAT IT PROTECTS. Two properties, in order of importance:

  1. BACKWARDS COMPATIBILITY. With PROFILER_CPUSET unset the emitted command must
     be exactly what it was before the option existed. This is asserted
     structurally rather than against a recorded snapshot: the pinned command must
     equal the unpinned one with a `taskset -c <set> ` prefix and NOTHING else
     changed. A snapshot would drift; this cannot.

  2. NO SILENT NO-OP. A launch site that lost its $(TASKSET) prefix would leave the
     collector unpinned while everything still appeared to work — the profiler
     would quietly lose events again under load. Every launch site in every layer
     is enumerated here so adding one without pinning it fails the suite.

It also checks that an impossible cpuset is refused at parse time, because the
alternative is the failure this whole option exists to remove: taskset exits
"Invalid argument", the backgrounded collector never starts, start-collection
still returns 0, and the run produces an empty capture that looks normal.

    python3 tests/placement/check_test.py          # or: make -C tests/placement validate
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

LAYERS = Path(__file__).resolve().parent.parent.parent / "layers"

# One entry per process a layer launches and must pin. `args` is what the layer
# needs to reach that branch; `match` identifies the launch line in the dry run.
#
# Both modes of the three eBPF layers are covered: `detailed` runs the standalone
# loader, `summary` runs bpftrace. Both consume events in userspace, so both can
# lose them, so both are pinned and both are checked.
SITES = [
    ("nvme    detailed", "nvme", ["MODE=detailed", "CONTAINER_FILTER=x"], "sudo ./bpf/c/standalone"),
    ("nvme    summary", "nvme", ["MODE=summary", "DEV_FILTER=nvme0n1"], "./bt/trace.bt"),
    ("block   detailed", "block", ["MODE=detailed", "CONTAINER_FILTER=x"], "sudo ./bpf/c/standalone"),
    ("block   summary", "block", ["MODE=summary", "DEV_FILTER=nvme0n1"], "./bt/trace.bt"),
    ("fs      detailed", "fs", ["MODE=detailed", "CONTAINER_FILTER=x"], "sudo ./bpf/c/standalone"),
    ("fs      summary", "fs", ["MODE=summary", "COMM_FILTER=fio"], "./bt/trace.bt"),
    ("sysstat pidstat", "sysstat", [], "pidstat -turd"),
    # Anchored on the pidfile, not the script name: the layer also runs
    # collect_cgroup_mem.py synchronously as a --check preflight, and that one is
    # not a long-lived sampler and is not pinned. Only the backgrounded launch
    # writes cgroup_mem.pid.
    ("sysstat cgroup", "sysstat", [], "cgroup_mem.pid"),
]

CPUSET = "0"          # CPU 0 exists on every machine, so the suite is portable
BAD_CPUSET = "999999"  # and no machine has this one

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'✓' if ok else '✗'} {name}")
    if not ok:
        if detail:
            print("\n".join(f"      {line}" for line in detail.splitlines()))
        failures.append(name)


def dry_run(layer: str, args: list[str], cpuset: str | None) -> tuple[int, str]:
    """`make -n start-collection` for one layer. Returns (rc, combined output).

    -n prints recipes without running them, so nothing is launched, no privileges
    are needed and no results directory is written. RESULTS_DIR still has to exist
    as a string for the recipe to expand.
    """
    cmd = ["make", "-n", "-C", str(LAYERS / layer), "start-collection", "RESULTS_DIR=/tmp", *args]
    if cpuset is not None:
        cmd.append(f"PROFILER_CPUSET={cpuset}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def launch_line(out: str, match: str) -> str | None:
    """The recipe line that starts the collector, normalised to one line.

    Recipes are continued with trailing backslashes, so the launch spans several
    output lines; they are joined and whitespace-collapsed because only the
    command's *shape* is under test, not how the Makefile happens to wrap it.
    """
    joined, buf = [], ""
    for line in out.splitlines():
        buf = f"{buf} {line.strip()}" if buf else line.strip()
        if line.rstrip().endswith("\\"):
            continue
        joined.append(re.sub(r"\s*\\\s*", " ", buf))
        buf = ""
    if buf:
        joined.append(buf)
    return next((re.sub(r"\s+", " ", l).strip() for l in joined if match in l), None)


def main() -> int:
    print("every launch site is unpinned by default (backwards compatibility)")
    baselines: dict[str, str] = {}
    for name, layer, args, match in SITES:
        rc, out = dry_run(layer, args, None)
        line = launch_line(out, match)
        if rc != 0 or line is None:
            check(f"  {name}", False, f"rc={rc}, no line matching {match!r}\n{out[-400:]}")
            continue
        baselines[name] = line
        check(f"  {name}", "taskset" not in line, f"got: {line}")

    print("\nsetting PROFILER_CPUSET prefixes taskset and changes NOTHING else")
    for name, layer, args, match in SITES:
        if name not in baselines:
            continue
        rc, out = dry_run(layer, args, CPUSET)
        line = launch_line(out, match)
        if rc != 0 or line is None:
            check(f"  {name}", False, f"rc={rc}, no line matching {match!r}")
            continue
        want = f"taskset -c {CPUSET} {baselines[name]}"
        check(f"  {name}", line == want, f"want: {want}\ngot:  {line}")

    print("\nan impossible cpuset is refused before anything is launched")
    for layer in ("nvme", "block", "fs", "sysstat"):
        rc, out = dry_run(layer, ["MODE=detailed", "CONTAINER_FILTER=x"], BAD_CPUSET)
        check(f"  {layer} rejects PROFILER_CPUSET={BAD_CPUSET}",
              rc != 0 and "PROFILER_CPUSET" in out,
              f"rc={rc} (expected non-zero, naming PROFILER_CPUSET)\n{out[-300:]}")

    print("\nan empty PROFILER_CPUSET means unpinned, not invalid")
    # The experiments repo emits PROFILER_CPUSET="" for a machine with no
    # reservation, so empty has to be a legitimate value rather than a typo.
    for layer in ("nvme", "sysstat"):
        args = ["MODE=detailed", "CONTAINER_FILTER=x"] if layer == "nvme" else []
        rc, out = dry_run(layer, args, "")
        check(f"  {layer} accepts an empty cpuset", rc == 0 and "taskset" not in out,
              f"rc={rc}")

    print()
    if failures:
        print(f"✗ {len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print(f"✓ all checks passed ({len(SITES)} launch sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
