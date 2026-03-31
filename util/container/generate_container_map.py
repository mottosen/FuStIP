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
    if not ns_link.exists():
        return None
    raw = ns_link.readlink().as_posix()  # e.g. mnt:[4026531840]
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


def _collect_comms(container: str, pid: str) -> set[str]:
    comms: set[str] = set()
    top_res = _run(["docker", "top", container, "-eo", "comm"])
    if top_res.returncode == 0:
        for line in top_res.stdout.splitlines()[1:]:
            comm = line.strip()
            if comm:
                comms.add(comm)
        if comms:
            return comms

    proc_comm = Path(f"/proc/{pid}/comm")
    if proc_comm.exists():
        comm = proc_comm.read_text().strip()
        if comm:
            comms.add(comm)
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
            mntns_id = _mntns_from_pid(pid) or _mntns_from_container(cname)
            if mntns_id:
                state[cname]["mntns_ids"].add(mntns_id)
            state[cname]["comms"].update(_collect_comms(cname, pid))
        time.sleep(2)


if __name__ == "__main__":
    main()
