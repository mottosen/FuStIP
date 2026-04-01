#!/usr/bin/env python3
"""Poll container identity mapping and write results/container_map.json on exit."""

import json
import signal
import subprocess
import sys
import time
from pathlib import Path


def _run(args):
    return subprocess.run(args, capture_output=True, text=True)


def _inspect_pid(container: str) -> str | None:
    res = _run(["docker", "inspect", "-f", "{{.State.Pid}}", container])
    if res.returncode != 0:
        return None
    pid = res.stdout.strip()
    return pid if pid.isdigit() else None


def _mntns_from_pid(pid: str) -> int | None:
    ns_link = Path(f"/proc/{pid}/ns/mnt")
    # Use is_symlink() rather than exists(): exists() follows the magic namespace
    # symlink whose target ("mnt:[inode]") is not a real path, so it returns False
    # even for running containers.  is_symlink() uses lstat and does not follow.
    if not ns_link.is_symlink():
        return None
    try:
        raw = ns_link.readlink().as_posix()  # e.g. mnt:[4026531840]
    except PermissionError:
        # Container processes are owned by root; fall back to sudo readlink.
        # run.sh keeps sudo credentials alive for the duration of profiling.
        res = subprocess.run(
            ["sudo", "readlink", str(ns_link)],
            capture_output=True, text=True,
        )
        if res.returncode != 0:
            return None
        raw = res.stdout.strip()
    except OSError:
        return None
    if "[" not in raw or "]" not in raw:
        return None
    try:
        return int(raw.split("[", 1)[1].split("]", 1)[0])
    except ValueError:
        return None


def _mntns_from_container(container: str) -> int | None:
    """Fallback: read mount namespace from inside container PID 1."""
    res = _run(["docker", "exec", container, "sh", "-lc", "readlink /proc/1/ns/mnt"])
    if res.returncode != 0:
        return None
    raw = res.stdout.strip()  # e.g. mnt:[4026531840]
    if "[" not in raw or "]" not in raw:
        return None
    try:
        return int(raw.split("[", 1)[1].split("]", 1)[0])
    except ValueError:
        return None


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


def _collect_comms(container: str, pid: str) -> set[str]:
    """Return all process comm names visible in the container.

    Primary: read /proc/{p}/comm for every PID in the container's cgroup
    (no container shell required, works for distroless images).
    Fallback 1: docker top -eo comm (may fail on some Docker/ps configurations).
    Fallback 2: /proc/{pid}/comm of the container init process only.
    """
    comms: set[str] = set()
    # Primary: enumerate all container processes via cgroupfs
    for p in _pids_from_cgroup(pid):
        try:
            comm = Path(f"/proc/{p}/comm").read_text().strip()
            if comm:
                comms.add(comm)
        except OSError:
            pass
    if comms:
        return comms
    # Fallback 1: docker top
    top_res = _run(["docker", "top", container, "-eo", "comm"])
    if top_res.returncode == 0:
        for line in top_res.stdout.splitlines()[1:]:
            comm = line.strip()
            if comm:
                comms.add(comm)
        if comms:
            return comms
    # Fallback 2: single init process comm
    try:
        comm = Path(f"/proc/{pid}/comm").read_text().strip()
        if comm:
            comms.add(comm)
    except OSError:
        pass
    return comms


def _write(out_path: Path, state: dict):
    data = {"version": 1, "containers": {}}
    for cname, payload in state.items():
        data["containers"][cname] = {
            "tgids": sorted(payload["tgids"], key=int),
            "mntns_ids": sorted(payload["mntns_ids"]),
            "comms": sorted(payload["comms"]),
        }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.rename(out_path)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <results_dir> <container_csv>", file=sys.stderr)
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    containers = [c.strip() for c in sys.argv[2].split(",") if c.strip()]
    out_path = results_dir / "container_map.json"

    state = {
        cname: {"tgids": set(), "mntns_ids": set(), "comms": set()}
        for cname in containers
    }

    def _exit(sig, frame):
        _write(out_path, state)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _exit)
    signal.signal(signal.SIGINT, _exit)

    while True:
        for cname in containers:
            pid = _inspect_pid(cname)
            if not pid:
                continue
            state[cname]["tgids"].add(pid)
            # Enumerate all container PIDs from cgroup for comprehensive tgid/comm coverage
            container_pids = _pids_from_cgroup(pid)
            state[cname]["tgids"].update(container_pids)
            # Try mntns from init pid, then all cgroup pids, then docker exec fallback
            if not state[cname]["mntns_ids"]:
                mntns_id = _mntns_from_pid(pid)
                if not mntns_id:
                    for p in container_pids:
                        mntns_id = _mntns_from_pid(p)
                        if mntns_id:
                            break
                if not mntns_id:
                    mntns_id = _mntns_from_container(cname)
                if mntns_id:
                    state[cname]["mntns_ids"].add(mntns_id)
            state[cname]["comms"].update(_collect_comms(cname, pid))
        time.sleep(2)


if __name__ == "__main__":
    main()
