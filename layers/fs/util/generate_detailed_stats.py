#!/usr/bin/env python3
"""Generate stats JSON from filesystem layer detailed CSV output.

Reads detailed.csv from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses two CSV passes to limit peak memory on large files:
  Pass 1: counters, distributions, tseries (no tid/fd/offset columns)
  Pass 2: access pattern (no latency_ns/inflight columns)

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_fs_access_pattern,
                                     derive_throughput,
                                     series_stats,
                                     tseries_stats)

LAYER_PREFIX = "fs"

# IO syscalls that have meaningful bytes/latency for histograms
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}


def _cat_code(cat_accessor, name):
    """Return the integer category code for *name*, or -1 if absent."""
    cats = cat_accessor.categories
    return int(cats.get_loc(name)) if name in cats else -1


def compute_rw_access_pattern(df):
    """Compute access pattern for read/write using position reconstruction.

    Expects a pre-filtered DataFrame with only relevant syscalls
    (read, write, openat, lseek, close) and columns:
    event, syscall, timestamp_ns, tid, fd, bytes.

    Uses numpy arrays with category codes for fast scalar access,
    avoiding iterrows() overhead on large DataFrames.
    """
    df.sort_values("timestamp_ns", inplace=True)

    # Category codes → int8 arrays for fast integer comparison
    ev_cat = df["event"].cat
    ev_codes = ev_cat.codes.to_numpy(dtype="int8")
    ENTER = _cat_code(ev_cat, "enter")
    EXIT = _cat_code(ev_cat, "exit")

    sc_cat = df["syscall"].cat
    sc_codes = sc_cat.codes.to_numpy(dtype="int8")
    READ = _cat_code(sc_cat, "read")
    WRITE = _cat_code(sc_cat, "write")
    OPENAT = _cat_code(sc_cat, "openat")
    LSEEK = _cat_code(sc_cat, "lseek")
    CLOSE = _cat_code(sc_cat, "close")

    tids = df["tid"].to_numpy(dtype="float64")
    fds = df["fd"].to_numpy(dtype="float64")
    bytes_arr = df["bytes"].to_numpy(dtype="float64")

    n = len(ev_codes)
    pos = {}  # (tid, fd) -> file position
    rw_positions = {}  # "read"/"write" -> [(offset, bytes), ...]

    for i in range(n):
        ev = ev_codes[i]
        sc = sc_codes[i]
        tid_v = tids[i]
        fd_v = fds[i]
        bv = bytes_arr[i]

        # NaN check: NaN != NaN
        tid_ok = tid_v == tid_v
        fd_ok = fd_v == fd_v and fd_v >= 0

        # Record position for read/write enter events (before state update)
        if ev == ENTER and (sc == READ or sc == WRITE) and tid_ok and fd_ok:
            key = (int(tid_v), int(fd_v))
            if key in pos:
                bv_int = int(bv) if bv == bv and bv > 0 else 0
                sc_name = "read" if sc == READ else "write"
                rw_positions.setdefault(sc_name, []).append((pos[key], bv_int))

        # Update position state
        if ev == EXIT:
            if sc == OPENAT:
                ret = int(bv) if bv == bv else -1
                if ret >= 0 and tid_ok:
                    pos[(int(tid_v), ret)] = 0
            elif sc == LSEEK:
                ret = int(bv) if bv == bv else -1
                if ret >= 0 and fd_ok and tid_ok:
                    pos[(int(tid_v), int(fd_v))] = ret
            elif sc == READ or sc == WRITE:
                ret = int(bv) if bv == bv else 0
                if ret > 0 and fd_ok and tid_ok:
                    key = (int(tid_v), int(fd_v))
                    if key in pos:
                        pos[key] += ret
        elif ev == ENTER and sc == CLOSE:
            if fd_ok and tid_ok:
                pos.pop((int(tid_v), int(fd_v)), None)

    result = {}
    for sc in ("read", "write"):
        positions = rw_positions.get(sc, [])
        if len(positions) < 2:
            continue
        offsets = [p[0] for p in positions]
        bytes_list = [p[1] for p in positions]
        result[sc] = compute_fs_access_pattern(offsets, bytes_list)

    return result


def generate_stats(csv_path):
    """Parse an FS layer detailed CSV and compute stats."""

    # Check header for optional columns
    with open(csv_path) as f:
        header = f.readline().strip().split(",")
    has_inflight = "inflight" in header
    has_offset = "offset" in header

    # --- Pass 1: Counters, distributions, derived, tseries ---
    main_cols = ["event", "syscall", "timestamp_ns", "bytes", "latency_ns"]
    if has_inflight:
        main_cols.append("inflight")

    df = pd.read_csv(csv_path, usecols=main_cols,
                     dtype={"event": "category", "syscall": "category"})

    exits = df[df["event"] == "exit"]
    enters = df[df["event"] == "enter"]

    # Duration
    if len(df) > 1:
        duration_ns = int(df["timestamp_ns"].max() - df["timestamp_ns"].min())
        duration_s = duration_ns / 1e9
    else:
        duration_s = 0

    # IO exits (read/write/pread64/pwrite64)
    io_exits = exits[exits["syscall"].isin(IO_SYSCALLS)]

    # Build counters
    counters = {}

    # sc_completed: count of exit events per IO syscall
    if len(io_exits) > 0:
        counters["sc_completed"] = io_exits.groupby("syscall").size().to_dict()

    # sc_entered: count of enter events per IO syscall
    io_enters = enters[enters["syscall"].isin(IO_SYSCALLS)]
    if len(io_enters) > 0:
        counters["sc_entered"] = io_enters.groupby("syscall").size().to_dict()

    # sc_total_bytes: sum of bytes (from exit events, positive returns only)
    positive_exits = io_exits[io_exits["bytes"] > 0]
    if len(positive_exits) > 0:
        byte_sums = positive_exits.groupby("syscall")["bytes"].sum().to_dict()
        counters["sc_total_bytes"] = {k: int(v) for k, v in byte_sums.items()}

    # sc_count: count of non-IO syscalls (enter events)
    non_io_enters = enters[~enters["syscall"].isin(IO_SYSCALLS)]
    if len(non_io_enters) > 0:
        counters["sc_count"] = non_io_enters.groupby("syscall").size().to_dict()

    result = {
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "distributions": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "sc_completed", "sc_total_bytes")
    result["derived"].update(throughput)

    # Distributions (stats only, no histogram bucket data)
    lat_exits = io_exits[io_exits["latency_ns"].notna() & (io_exits["latency_ns"] > 0)]
    if len(lat_exits) > 0:
        result["distributions"]["sc_latencies"] = {}
        for sc, group in lat_exits.groupby("syscall"):
            result["distributions"]["sc_latencies"][sc] = series_stats(
                group["latency_ns"].tolist()
            )

    if len(positive_exits) > 0:
        result["distributions"]["sc_sizes"] = {}
        for sc, group in positive_exits.groupby("syscall"):
            result["distributions"]["sc_sizes"][sc] = series_stats(
                group["bytes"].tolist()
            )

    # Inflight time-series (IO syscalls only)
    if len(io_enters) > 0 and len(io_exits) > 0:
        t_min = df["timestamp_ns"].min()
        window_ns = 1_000_000_000

        result["tseries"]["sc_inflight"] = {}
        io_events = df[df["syscall"].isin(IO_SYSCALLS)]

        if has_inflight and "inflight" in df.columns:
            # Use pre-computed in-kernel inflight column
            for sc in io_events["syscall"].unique():
                sc_df = io_events[io_events["syscall"] == sc].sort_values("timestamp_ns")
                secs = ((sc_df["timestamp_ns"].values - t_min) / window_ns).astype(int)
                sc_df = sc_df.assign(sec=secs)
                sampled = sc_df.groupby("sec")["inflight"].last()
                points = []
                for s, v in sampled.items():
                    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
                    points.append({"time": f"{h:02d}:{m:02d}:{ss:02d}",
                                   "value": max(0, int(v))})
                if points:
                    result["tseries"]["sc_inflight"][sc] = tseries_stats(points)
        else:
            # Fallback: compute from enter/exit event counts
            t_max = df["timestamp_ns"].max()
            for sc in io_enters["syscall"].unique():
                enter_ts = io_enters[io_enters["syscall"] == sc]["timestamp_ns"].values
                exit_ts = io_exits[io_exits["syscall"] == sc]["timestamp_ns"].values
                points = []
                t = t_min
                sec = 0
                while t <= t_max:
                    inflight = int((enter_ts <= t).sum() - (exit_ts <= t).sum())
                    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
                    points.append({"time": f"{h:02d}:{m:02d}:{s:02d}",
                                   "value": max(0, inflight)})
                    t += window_ns
                    sec += 1
                if points:
                    result["tseries"]["sc_inflight"][sc] = tseries_stats(points)

    del df  # Free pass 1 DataFrame

    # --- Pass 2: Access pattern ---
    ap_cols = ["event", "syscall", "timestamp_ns", "tid", "fd", "bytes"]
    if has_offset:
        ap_cols.append("offset")

    df = pd.read_csv(csv_path, usecols=ap_cols,
                     dtype={"event": "category", "syscall": "category"})

    io_enters = df[(df["event"] == "enter") & df["syscall"].isin(IO_SYSCALLS)]

    # pread64/pwrite64: use explicit offsets from enter events
    offset_syscalls = {"pread64", "pwrite64"}
    result["access_pattern"] = {"sc_offsets": {}}
    if has_offset:
        offset_enters = io_enters[
            io_enters["syscall"].isin(offset_syscalls) & io_enters["offset"].notna()
        ]
        if len(offset_enters) >= 2:
            for sc, group in offset_enters.sort_values("timestamp_ns").groupby("syscall"):
                offsets = group["offset"].astype(int).tolist()
                bytes_list = group["bytes"].astype(int).tolist()
                if len(offsets) >= 2:
                    result["access_pattern"]["sc_offsets"][sc] = compute_fs_access_pattern(
                        offsets, bytes_list
                    )

    # read/write: pre-filter to relevant syscalls, reconstruct positions
    rw_relevant = {"read", "write", "openat", "lseek", "close"}
    rw_cols = ["event", "syscall", "timestamp_ns", "tid", "fd", "bytes"]
    rw_df = df.loc[df["syscall"].isin(rw_relevant), rw_cols].copy()
    del df  # Free pass 2 full DataFrame

    rw_pattern = compute_rw_access_pattern(rw_df)
    del rw_df

    for sc, pat in rw_pattern.items():
        result["access_pattern"]["sc_offsets"][sc] = pat

    return result


def load_data_quality(layer_dir, csv_file):
    """Load per-type counters.json and compute data quality metrics."""
    counters_file = layer_dir / "counters.json"
    if not counters_file.exists():
        return None
    try:
        with open(counters_file) as f:
            counters = json.load(f)

        # Read only the event column for per-type received counts
        events = pd.read_csv(csv_file, usecols=["event"], dtype={"event": "category"})["event"]

        per_event_type = {}
        total_generated = 0
        total_dropped = 0

        for event_type in ("enter", "exit"):
            entry = counters.get(event_type, {})
            gen = entry.get("generated", 0)
            drop = entry.get("dropped", 0)
            received = int((events == event_type).sum())
            total_generated += gen
            total_dropped += drop
            per_event_type[event_type] = {
                "generated": gen,
                "dropped": drop,
                "received": received,
                "drop_pct": round(100 * drop / gen, 4) if gen > 0 else 0.0,
            }

        total_received = total_generated - total_dropped
        return {
            "total_generated": total_generated,
            "total_dropped": total_dropped,
            "total_received": total_received,
            "drop_pct": round(100 * total_dropped / total_generated, 4) if total_generated > 0 else 0.0,
            "per_event_type": per_event_type,
        }
    except (json.JSONDecodeError, OSError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from fs layer detailed CSV output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    args = parser.parse_args()

    layer_dir = args.results_dir / LAYER_PREFIX
    if not layer_dir.is_dir():
        print(f"Error: {layer_dir} not found", file=sys.stderr)
        sys.exit(1)

    csv_file = layer_dir / "detailed.csv"
    if not csv_file.exists():
        print(f"No detailed output found: {csv_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {csv_file.name}...")
    stats = generate_stats(csv_file)

    dq = load_data_quality(layer_dir, csv_file)
    if dq:
        stats["data_quality"] = dq
    # Always remove counters.json — transient file consumed by stats generation
    counters_file = layer_dir / "counters.json"
    counters_file.unlink(missing_ok=True)

    output_file = layer_dir / "detailed-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
