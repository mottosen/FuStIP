#!/usr/bin/env python3
"""Poll Docker container process names and write container_map.json on exit.

Started alongside pidstat in start-collection. Killed by the existing
stop-profiling loop (iterates all *.pid files). On SIGTERM writes
container_map.json atomically via temp-file rename, then exits.

Usage:
    python poll_container_comms.py <sysstat_dir> <container_filter_csv>
"""

import json
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path


def _pids_from_cgroup(pid: str) -> set[str]:
    """Return all process TGIDs in the container's cgroup (host-side, no shell needed).

    Supports both cgroup v2 (unified hierarchy, hierarchy_id "0") and cgroup v1
    (uses the memory subsystem as the canonical controller).
    """
    pids: set[str] = set()
    try:
        cgroup_lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except OSError:
        return pids
    for line in cgroup_lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        hierarchy_id, controllers, cgroup_path = parts
        if hierarchy_id == "0":                          # cgroup v2 unified
            procs = Path("/sys/fs/cgroup") / cgroup_path.lstrip("/") / "cgroup.procs"
        elif "memory" in controllers.split(","):         # cgroup v1 memory subsystem
            procs = Path("/sys/fs/cgroup/memory") / cgroup_path.lstrip("/") / "cgroup.procs"
        else:
            continue
        try:
            for p in procs.read_text().splitlines():
                if p.strip().isdigit():
                    pids.add(p.strip())
        except OSError:
            continue
        if hierarchy_id == "0":
            break  # cgroup v2: only one unified entry
    return pids


def _write(comms_per, tgids_per, containers, out_path):
    data = {
        "version": 2,
        "containers": {
            c: {
                "comms": sorted(comms_per.get(c, set())),
                "tgids": sorted(tgids_per.get(c, set()), key=int),
            }
            for c in containers
        },
    }
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.rename(out_path)
    print(f"Container map written: {out_path}", flush=True)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <sysstat_dir> <container_filter_csv>", file=sys.stderr)
        sys.exit(1)

    sysstat_dir = Path(sys.argv[1])
    containers = [c.strip() for c in sys.argv[2].split(",") if c.strip()]
    out_path = sysstat_dir / "container_map.json"
    comms_per = defaultdict(set)
    tgids_per = defaultdict(set)

    def _exit(sig, frame):
        _write(comms_per, tgids_per, containers, out_path)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _exit)
    signal.signal(signal.SIGINT, _exit)

    while True:
        for cname in containers:
            pid_result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Pid}}", cname],
                capture_output=True, text=True,
            )
            if pid_result.returncode != 0:
                continue
            pid_str = pid_result.stdout.strip()
            if not pid_str.isdigit():
                continue

            tgids_per[cname].add(pid_str)

            # Primary: enumerate all container processes via cgroupfs
            # (no container shell required, works for distroless images).
            container_pids = _pids_from_cgroup(pid_str)
            tgids_per[cname].update(container_pids)
            for p in container_pids:
                try:
                    comm = Path(f"/proc/{p}/comm").read_text().strip()
                    if comm:
                        comms_per[cname].add(comm)
                except OSError:
                    pass
            if container_pids:
                continue

            # Fallback 1: docker top (may fail on some Docker/ps configurations).
            result = subprocess.run(
                ["docker", "top", cname, "-eo", "comm"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[1:]:
                    comm = line.strip()
                    if comm:
                        comms_per[cname].add(comm)
                continue

            # Fallback 2: single init process comm.
            try:
                comm = Path(f"/proc/{pid_str}/comm").read_text().strip()
                if comm:
                    comms_per[cname].add(comm)
            except OSError:
                pass
        time.sleep(2)



if __name__ == "__main__":
    main()
