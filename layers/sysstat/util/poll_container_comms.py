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


def _write(comms_per, out_path):
    data = {"version": 1, "containers": {c: sorted(s) for c, s in comms_per.items()}}
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

    def _exit(sig, frame):
        _write(comms_per, out_path)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _exit)
    signal.signal(signal.SIGINT, _exit)

    while True:
        for cname in containers:
            result = subprocess.run(
                ["docker", "top", cname, "-eo", "comm"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[1:]:
                    comm = line.strip()
                    if comm:
                        comms_per[cname].add(comm)
        time.sleep(2)


if __name__ == "__main__":
    main()
