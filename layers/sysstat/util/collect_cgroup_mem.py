#!/usr/bin/env python3
"""Sample cgroup v2 memory accounting at a fixed interval, alongside pidstat.

pidstat reports *process-resident* memory (RSS/VSZ), which omits the page cache
holding a workload's file-backed data.  For anything that serves data from disk
(a mmap'd or disk-resident index, say) a large part of the real memory footprint
lives in page cache and appears in nobody's RSS.  cgroup v2 accounts for it.

The unit here is a **cgroup**, not a process and not a container, because that is
the granularity the kernel actually charges memory at.  Which cgroups get sampled
follows whichever filter tier is set:

    --container      one cgroup per container (docker inspect -> /proc/PID/cgroup)
    --comm/--pid     the cgroup of each matching process, deduped by path
    (neither)        the root cgroup, labelled "system"

Container wins when set: comm/pid can narrow *within* a cgroup, but memory.current
cannot express one process's share of it, so the accounting stays cgroup-granular.
Every row carries the resolved cgroup path so the attribution stays auditable —
in comm/pid mode a cgroup may hold processes that don't match the filter, and
several labels may resolve to the *same* cgroup (dockerd/containerd/containerd-shim
all live in system.slice/docker.service), in which case they report identical
numbers and must not be summed.

Output is <sysstat_dir>/cgroup_mem.csv, one row per (time, label, cgroup_path),
appended and flushed every tick so an abrupt kill loses at most the current sample.

Usage:
    python collect_cgroup_mem.py <sysstat_dir> [--container CSV] [--comm CSV]
                                 [--pid CSV] [--interval SECONDS]
    python collect_cgroup_mem.py --check          # verify cgroup v2, exit 1 on v1
    python collect_cgroup_mem.py --benchmark      # measure the collector's own cost
"""

import argparse
import ctypes
import ctypes.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP2_SUPER_MAGIC = 0x63677270

# Gauges read straight from single-value files.  Missing file -> ABSENT.
FILE_GAUGES = [
    ("memory_current", "memory.current"),
    ("memory_peak", "memory.peak"),
]
# Limit files, where the literal "max" means unlimited.
FILE_LIMITS = [
    ("memory_max", "memory.max"),
    ("memory_high", "memory.high"),
]
# Fields lifted out of memory.stat.  Grouped only for documentation; they all
# come from the one read.
STAT_GAUGES = [
    "anon", "file", "active_file", "inactive_file", "file_mapped",
    "shmem", "slab", "kernel", "pagetables", "percpu", "sock",
]
STAT_COUNTERS = [
    "pgmajfault", "pgscan", "pgsteal",
    "workingset_refault_file", "workingset_refault_anon",
]
# memory.events keys, emitted with an "ev_" prefix to keep them visibly separate
# from the gauges (they are cumulative, not sampled levels).
EVENT_KEYS = ["low", "high", "max", "oom", "oom_kill"]

# Sentinel for "the kernel does not expose this here".  Distinguishable from a
# real 0 -- the root cgroup, for instance, has memory.stat but none of the rest.
ABSENT = -1

CSV_COLUMNS = (
    ["time", "label", "cgroup_path"]
    + [name for name, _ in FILE_GAUGES]
    + STAT_GAUGES
    + [name for name, _ in FILE_LIMITS]
    + [f"ev_{k}" for k in EVENT_KEYS]
    + STAT_COUNTERS
)

SYSTEM_LABEL = "system"


# ── cgroup v2 detection ──


def _fs_magic(path: Path) -> int | None:
    """Return the filesystem magic of `path` via statfs, or None if unavailable."""
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return None

    class Statfs(ctypes.Structure):
        _fields_ = [
            ("f_type", ctypes.c_long),
            ("f_bsize", ctypes.c_long),
            ("f_blocks", ctypes.c_ulong),
            ("f_bfree", ctypes.c_ulong),
            ("f_bavail", ctypes.c_ulong),
            ("f_files", ctypes.c_ulong),
            ("f_ffree", ctypes.c_ulong),
            ("f_fsid", ctypes.c_long * 2),
            ("f_namelen", ctypes.c_long),
            ("f_frsize", ctypes.c_long),
            ("f_flags", ctypes.c_long),
            ("f_spare", ctypes.c_long * 4),
        ]

    buf = Statfs()
    libc = ctypes.CDLL(libc_name, use_errno=True)
    if libc.statfs(str(path).encode(), ctypes.byref(buf)) != 0:
        return None
    return buf.f_type & 0xFFFFFFFF


def check_cgroup_v2() -> tuple[bool, str]:
    """Return (ok, message). cgroup v1 is a hard failure, not an empty CSV."""
    if not CGROUP_ROOT.is_dir():
        return False, f"{CGROUP_ROOT} does not exist — no cgroup filesystem mounted"

    magic = _fs_magic(CGROUP_ROOT)
    if magic == CGROUP2_SUPER_MAGIC:
        return True, "cgroup v2 (unified hierarchy) detected"

    # statfs failed or reported something else; fall back to the structural test.
    # A v2 root always has cgroup.controllers; a v1 root has per-controller dirs.
    if magic is None and (CGROUP_ROOT / "cgroup.controllers").exists():
        return True, "cgroup v2 detected (statfs unavailable, used cgroup.controllers)"

    return False, (
        f"{CGROUP_ROOT} is not a cgroup v2 unified hierarchy "
        f"(statfs magic {magic!r}, expected {CGROUP2_SUPER_MAGIC:#x}). "
        "cgroup memory accounting requires cgroup v2. Boot with "
        "systemd.unified_cgroup_hierarchy=1 (or cgroup_no_v1=all), or drop the "
        "sysstat layer's cgroup collection."
    )


# ── cgroup path resolution ──


def cgroup_dir_for_pid(pid: str) -> Path | None:
    """Return the cgroup v2 directory a PID belongs to, host-side.

    /proc/PID/cgroup renders the path relative to the *reader's* cgroup namespace.
    This collector runs on the host, so it gets the full host path — which is what
    makes docker's systemd driver (system.slice/docker-<id>.scope) and its cgroupfs
    driver (docker/<id>) both resolve without either being hardcoded.
    """
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":  # unified hierarchy
            return CGROUP_ROOT / parts[2].lstrip("/")
    return None


def container_pid(name: str) -> str | None:
    """Return a container's host init PID, or None if it is not running."""
    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Pid}}", name],
            capture_output=True, text=True,
        )
    except (OSError, ValueError):
        return None
    if res.returncode != 0:
        return None
    pid = res.stdout.strip()
    # A stopped container inspects as PID 0.
    return pid if pid.isdigit() and pid != "0" else None


class Resolver:
    """Resolves the cgroups to sample each tick, caching across ticks.

    Caching is not an optimisation detail — it is what keeps the collector from
    perturbing the very measurement it runs beside. `docker inspect` forks the
    docker CLI and round-trips the daemon, ~12 ms per container per call; at 1 Hz
    across a compose stack that is several percent of a core plus a handful of
    process spawns every second, all of it landing in pidstat's own numbers.

    A resolved cgroup directory is therefore reused until it disappears, which is
    a ~microsecond existence check and an exact invalidation signal: a container's
    cgroup dir is removed when the container is, and a recreated container gets a
    new ID and hence a new path. Re-resolution cost is paid on transitions only.

    Same idea for the comm/pid tier, where reading /proc/<pid>/comm across every
    process is the dominant cost (~5 ms for ~400 processes). comm is cached per
    PID and read only for PIDs not seen before, so a newly spawned process is
    still picked up within one tick; the whole cache is refreshed every
    COMM_REFRESH_TICKS so a process that execs into a matching name is picked up
    within that bound rather than never. Cgroups are resolved only for PIDs that
    actually match the filter, not for all of /proc.
    """

    # Full comm re-read cadence, in ticks. Bounds how long an exec'd process can
    # go unnoticed; costs one full scan per period.
    COMM_REFRESH_TICKS = 30

    def __init__(self, containers, comms, pids):
        self.containers = containers
        self.comms = comms
        self.pids = pids
        self._container_cgroup: dict[str, Path] = {}
        self._comm: dict[str, str] = {}           # pid -> comm
        self._cgroup: dict[str, Path] = {}        # pid -> cgroup dir (matches only)
        self._tick = 0

    @staticmethod
    def _alive(cgroup_dir: Path) -> bool:
        return (cgroup_dir / "memory.stat").exists()

    def _resolve_container(self, name: str) -> Path | None:
        cached = self._container_cgroup.get(name)
        if cached is not None and self._alive(cached):
            return cached
        self._container_cgroup.pop(name, None)

        pid = container_pid(name)
        if pid is None:
            return None
        cgroup_dir = cgroup_dir_for_pid(pid)
        if cgroup_dir is None or not self._alive(cgroup_dir):
            return None
        self._container_cgroup[name] = cgroup_dir
        return cgroup_dir

    def _comm_for(self, pid: str, refresh: bool) -> str | None:
        if not refresh:
            cached = self._comm.get(pid)
            if cached is not None:
                return cached
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            return None
        if comm:
            self._comm[pid] = comm
        return comm or None

    def _cgroup_for_matching_pid(self, pid: str) -> Path | None:
        cached = self._cgroup.get(pid)
        if cached is not None and self._alive(cached):
            return cached
        self._cgroup.pop(pid, None)

        cgroup_dir = cgroup_dir_for_pid(pid)
        if cgroup_dir is None or not self._alive(cgroup_dir):
            return None
        self._cgroup[pid] = cgroup_dir
        return cgroup_dir

    def targets(self) -> list[tuple[str, Path]]:
        """Return the (label, cgroup_dir) pairs to sample this tick.

        Discovery follows the filter tier that is set; see the module docstring.
        Deduped on (label, path), so a label spanning several cgroups keeps them
        all while several processes sharing one cgroup are counted once.
        """
        seen: set[tuple[str, str]] = set()
        out: list[tuple[str, Path]] = []

        def add(label: str, path: Path | None):
            if path is None:
                return
            key = (label, str(path))
            if key not in seen:
                seen.add(key)
                out.append((label, path))

        if self.containers:
            for name in self.containers:
                add(name, self._resolve_container(name))
            return out

        if self.comms or self.pids:
            self._tick += 1
            refresh = self._tick % self.COMM_REFRESH_TICKS == 1
            live = set()
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                live.add(entry)
                comm = self._comm_for(entry, refresh)
                if comm is None:
                    continue
                # comm is a substring match, pid is exact — the same semantics
                # generate_stats.py applies when bucketing pidstat rows.
                if any(c in comm for c in self.comms) or entry in self.pids:
                    add(comm, self._cgroup_for_matching_pid(entry))
            # Drop exited PIDs so the caches track /proc rather than growing.
            for gone in self._comm.keys() - live:
                del self._comm[gone]
            for gone in self._cgroup.keys() - live:
                del self._cgroup[gone]
            return out

        # No filters: the root cgroup is the system-wide view. It has memory.stat
        # but none of the per-cgroup files, which the ABSENT sentinel handles.
        add(SYSTEM_LABEL, CGROUP_ROOT)
        return out


# ── sampling ──


def _read_int(path: Path) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return ABSENT


def _read_limit(path: Path) -> int:
    """Read a limit file; the literal "max" (unlimited) maps to ABSENT."""
    try:
        raw = path.read_text().strip()
    except OSError:
        return ABSENT
    if raw == "max":
        return ABSENT
    try:
        return int(raw)
    except ValueError:
        return ABSENT


def _read_keyed(path: Path) -> dict[str, int]:
    """Parse a "key value" file (memory.stat, memory.events)."""
    out: dict[str, int] = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return out


def sample(cgroup_dir: Path) -> dict[str, int]:
    """Read one full sample from a cgroup directory.

    Four file reads regardless of how many fields are extracted: memory.stat
    carries all of STAT_GAUGES and STAT_COUNTERS in a single pass.
    """
    row: dict[str, int] = {}
    for name, fname in FILE_GAUGES:
        row[name] = _read_int(cgroup_dir / fname)
    for name, fname in FILE_LIMITS:
        row[name] = _read_limit(cgroup_dir / fname)

    stat = _read_keyed(cgroup_dir / "memory.stat")
    for key in STAT_GAUGES + STAT_COUNTERS:
        row[key] = stat.get(key, ABSENT)

    events = _read_keyed(cgroup_dir / "memory.events")
    for key in EVENT_KEYS:
        row[f"ev_{key}"] = events.get(key, ABSENT)

    return row


# ── collection loop ──


def collect(sysstat_dir: Path, containers, comms, pids, interval: float):
    sysstat_dir.mkdir(parents=True, exist_ok=True)
    out_path = sysstat_dir / "cgroup_mem.csv"

    # Timestamps use localtime so they share pidstat's clock; the sysstat
    # Makefile exports TZ=UTC to both, which is what lets a consumer line the
    # two CSVs up sample-for-sample.
    f = out_path.open("w", buffering=1)
    f.write(",".join(CSV_COLUMNS) + "\n")

    running = True

    def _stop(_sig, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(f"cgroup memory collection -> {out_path}", flush=True)

    resolver = Resolver(containers, comms, pids)
    deadline = time.monotonic()
    while running:
        stamp = time.strftime("%H:%M:%S", time.localtime())
        for label, cgroup_dir in resolver.targets():
            row = sample(cgroup_dir)
            row["time"] = stamp
            row["label"] = label
            row["cgroup_path"] = str(cgroup_dir)
            f.write(",".join(str(row[c]) for c in CSV_COLUMNS) + "\n")

        # Absolute deadlines rather than sleep(interval), so a slow tick does not
        # push every later sample later — the 1 Hz cadence has to stay comparable
        # to pidstat's over a long run.
        deadline += interval
        remaining = deadline - time.monotonic()
        if remaining < 0:
            deadline = time.monotonic()  # fell behind; resync rather than burn CPU
            remaining = 0
        # Sleep in slices so a SIGTERM is honoured promptly instead of after a
        # whole interval.
        while remaining > 0 and running:
            time.sleep(min(0.1, remaining))
            remaining = deadline - time.monotonic()

    f.close()
    print("cgroup memory collection stopped", flush=True)


def benchmark(containers, comms, pids, iterations: int = 200):
    """Measure the collector's own cost per tick, cold and in steady state.

    Both numbers matter: the cold figure is what a transition costs (a container
    coming up), the steady-state one is what the collector actually charges the
    machine for the rest of the run.
    """
    cold_resolver = Resolver(containers, comms, pids)
    t0 = time.perf_counter()
    targets = cold_resolver.targets()
    cold_us = (time.perf_counter() - t0) * 1e6

    if not targets:
        print("benchmark: no cgroups resolved — nothing to measure", file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    for _ in range(iterations):
        cold_resolver.targets()
    resolve_us = (time.perf_counter() - t0) / iterations * 1e6

    t0 = time.perf_counter()
    for _ in range(iterations):
        for _label, cgroup_dir in targets:
            sample(cgroup_dir)
    sample_us = (time.perf_counter() - t0) / iterations * 1e6

    total_us = resolve_us + sample_us
    print(f"cgroups resolved : {len(targets)}")
    for label, path in targets:
        print(f"  {label:<24} {path}")
    print(f"resolution, cold : {cold_us:9.1f} us   (once per cgroup transition)")
    print(f"resolution, warm : {resolve_us:9.1f} us/tick")
    print(f"sampling         : {sample_us:9.1f} us/tick "
          f"({sample_us / len(targets):.1f} us/cgroup)")
    print(f"steady-state     : {total_us:9.1f} us/tick")
    print(f"at 1 Hz          : {total_us / 1e6 * 100:.4f}% of one core")
    return 0


def _csv_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="Sample cgroup v2 memory accounting alongside pidstat"
    )
    parser.add_argument("sysstat_dir", type=Path, nargs="?",
                        help="Output directory (cgroup_mem.csv is written here)")
    parser.add_argument("--container", "-c", type=_csv_list, default=[],
                        help="Comma-separated container names (top filter tier)")
    parser.add_argument("--comm", "-p", type=_csv_list, default=[],
                        help="Comma-separated process names, substring match")
    parser.add_argument("--pid", "-P", type=_csv_list, default=[],
                        help="Comma-separated process IDs (tgid), exact match")
    parser.add_argument("--interval", "-i", type=float, default=1.0,
                        help="Sampling interval in seconds (default: 1)")
    parser.add_argument("--check", action="store_true",
                        help="Verify cgroup v2 is available and exit")
    parser.add_argument("--benchmark", action="store_true",
                        help="Measure the collector's own CPU cost and exit")
    args = parser.parse_args()

    ok, message = check_cgroup_v2()
    if not ok:
        print(f"Error: {message}", file=sys.stderr)
        sys.exit(1)

    if args.check:
        print(message)
        return

    if args.benchmark:
        sys.exit(benchmark(args.container, args.comm, set(args.pid)))

    if args.sysstat_dir is None:
        parser.error("sysstat_dir is required unless --check/--benchmark is given")

    collect(args.sysstat_dir, args.container, args.comm, set(args.pid),
            args.interval)


if __name__ == "__main__":
    main()
