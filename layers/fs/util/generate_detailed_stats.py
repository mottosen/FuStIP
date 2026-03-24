#!/usr/bin/env python3
"""Generate stats JSON from filesystem layer detailed CSV output.

Reads detailed.csv from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (latency/size stats per syscall)
  Scan 3: inflight time-series
  Scan 4: access pattern (pread64/pwrite64 offsets + read/write position tracking)

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_fs_access_pattern,
                                     derive_throughput,
                                     series_stats,
                                     tseries_stats)

LAYER_PREFIX = "fs"

# IO syscalls that have meaningful bytes/latency for histograms
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}


def _sec_to_time(s):
    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
    return f"{h:02d}:{m:02d}:{ss:02d}"


def compute_rw_access_pattern(df):
    """Compute access pattern for read/write using position reconstruction.

    Expects a pre-filtered Polars DataFrame with only relevant syscalls
    (read, write, openat, lseek, close) and columns:
    event, syscall, timestamp_ns, tid, fd, bytes.

    Uses numpy arrays for fast scalar access in the state machine loop.
    """
    df = df.sort("timestamp_ns")

    # Extract numpy arrays for fast access
    events = df["event"].to_numpy(allow_copy=True).astype(str)
    syscalls = df["syscall"].to_numpy(allow_copy=True).astype(str)
    tids = df["tid"].to_numpy(allow_copy=True).astype("float64")
    fds = df["fd"].to_numpy(allow_copy=True).astype("float64")
    bytes_arr = df["bytes"].to_numpy(allow_copy=True).astype("float64")

    n = len(events)
    pos = {}  # (tid, fd) -> file position
    rw_positions = {}  # "read"/"write" -> [(offset, bytes), ...]

    for i in range(n):
        ev = events[i]
        sc = syscalls[i]
        tid_v = tids[i]
        fd_v = fds[i]
        bv = bytes_arr[i]

        # NaN check: NaN != NaN
        tid_ok = tid_v == tid_v
        fd_ok = fd_v == fd_v and fd_v >= 0

        # Record position for read/write enter events (before state update)
        if ev == "enter" and (sc == "read" or sc == "write") and tid_ok and fd_ok:
            key = (int(tid_v), int(fd_v))
            if key in pos:
                bv_int = int(bv) if bv == bv and bv > 0 else 0
                rw_positions.setdefault(sc, []).append((pos[key], bv_int))

        # Update position state
        if ev == "exit":
            if sc == "openat":
                ret = int(bv) if bv == bv else -1
                if ret >= 0 and tid_ok:
                    pos[(int(tid_v), ret)] = 0
            elif sc == "lseek":
                ret = int(bv) if bv == bv else -1
                if ret >= 0 and fd_ok and tid_ok:
                    pos[(int(tid_v), int(fd_v))] = ret
            elif sc == "read" or sc == "write":
                ret = int(bv) if bv == bv else 0
                if ret > 0 and fd_ok and tid_ok:
                    key = (int(tid_v), int(fd_v))
                    if key in pos:
                        pos[key] += ret
        elif ev == "enter" and sc == "close":
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

    io_syscalls_list = list(IO_SYSCALLS)

    # --- Scan 1: Counters, duration, event counts ---
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})

    # Get per-(event, syscall) aggregates
    agg = (lf.group_by("event", "syscall")
             .agg(
                 pl.len().alias("count"),
                 pl.col("bytes").sum().alias("total_bytes"),
                 pl.col("timestamp_ns").min().alias("ts_min"),
                 pl.col("timestamp_ns").max().alias("ts_max"),
                 # Sum of positive bytes for sc_total_bytes
                 pl.col("bytes").filter(pl.col("bytes") > 0).sum().alias("pos_bytes"),
             )
             .collect())

    # Duration from all events
    ts_min = agg["ts_min"].min()
    ts_max = agg["ts_max"].max()
    if ts_min is not None and ts_max is not None and ts_max > ts_min:
        duration_ns = int(ts_max - ts_min)
        duration_s = duration_ns / 1e9
    else:
        duration_s = 0

    # Build counters
    counters = {}

    # sc_completed: count of exit events per IO syscall
    exit_io = agg.filter((pl.col("event") == "exit") & pl.col("syscall").is_in(io_syscalls_list))
    if len(exit_io) > 0:
        counters["sc_completed"] = dict(zip(
            exit_io["syscall"].to_list(),
            [int(v) for v in exit_io["count"].to_list()]
        ))

    # sc_entered: count of enter events per IO syscall
    enter_io = agg.filter((pl.col("event") == "enter") & pl.col("syscall").is_in(io_syscalls_list))
    if len(enter_io) > 0:
        counters["sc_entered"] = dict(zip(
            enter_io["syscall"].to_list(),
            [int(v) for v in enter_io["count"].to_list()]
        ))

    # sc_total_bytes: sum of positive bytes from exit IO events
    if len(exit_io) > 0:
        pos_bytes_rows = exit_io.filter(pl.col("pos_bytes") > 0)
        if len(pos_bytes_rows) > 0:
            counters["sc_total_bytes"] = dict(zip(
                pos_bytes_rows["syscall"].to_list(),
                [int(v) for v in pos_bytes_rows["pos_bytes"].to_list()]
            ))

    # sc_count: count of non-IO syscalls (enter events)
    non_io_enters = agg.filter((pl.col("event") == "enter") & ~pl.col("syscall").is_in(io_syscalls_list))
    if len(non_io_enters) > 0:
        counters["sc_count"] = dict(zip(
            non_io_enters["syscall"].to_list(),
            [int(v) for v in non_io_enters["count"].to_list()]
        ))

    # Event counts for data quality (avoids separate CSV pass)
    event_counts = dict(zip(
        agg.group_by("event").agg(pl.col("count").sum())["event"].to_list(),
        agg.group_by("event").agg(pl.col("count").sum())["count"].to_list(),
    ))

    result = {
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "distributions": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "sc_completed", "sc_total_bytes")
    result["derived"].update(throughput)

    del agg

    # --- Scan 2: Distributions ---
    # Latencies (from exit IO events with valid latency)
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
    lat_df = (lf.filter(pl.col("event") == "exit")
                .filter(pl.col("syscall").is_in(io_syscalls_list))
                .filter(pl.col("latency_ns").is_not_null() & (pl.col("latency_ns") > 0))
                .select("syscall", "latency_ns")
                .collect())
    if len(lat_df) > 0:
        result["distributions"]["sc_latencies"] = {}
        for sc in lat_df["syscall"].unique().sort().to_list():
            vals = lat_df.filter(pl.col("syscall") == sc)["latency_ns"].to_numpy()
            result["distributions"]["sc_latencies"][sc] = series_stats(vals)
    del lat_df

    # Sizes (from exit IO events with positive bytes)
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
    size_df = (lf.filter(pl.col("event") == "exit")
                 .filter(pl.col("syscall").is_in(io_syscalls_list))
                 .filter(pl.col("bytes") > 0)
                 .select("syscall", "bytes")
                 .collect())
    if len(size_df) > 0:
        result["distributions"]["sc_sizes"] = {}
        for sc in size_df["syscall"].unique().sort().to_list():
            vals = size_df.filter(pl.col("syscall") == sc)["bytes"].to_numpy()
            result["distributions"]["sc_sizes"][sc] = series_stats(vals)
    del size_df

    # --- Scan 3: Inflight time-series (IO syscalls only) ---
    if duration_s > 0:
        window_ns = 1_000_000_000
        result["tseries"]["sc_inflight"] = {}

        if has_inflight:
            lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
            inf_df = (lf.filter(pl.col("syscall").is_in(io_syscalls_list))
                        .select("syscall", "timestamp_ns", "inflight")
                        .sort("timestamp_ns")
                        .with_columns(
                            ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                        )
                        .group_by("syscall", "sec")
                        .agg(pl.col("inflight").last())
                        .sort("syscall", "sec")
                        .collect())

            for sc in inf_df["syscall"].unique().sort().to_list():
                sc_df = inf_df.filter(pl.col("syscall") == sc)
                points = [
                    {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                    for s, v in zip(sc_df["sec"].to_list(), sc_df["inflight"].to_list())
                ]
                if points:
                    result["tseries"]["sc_inflight"][sc] = tseries_stats(points)
            del inf_df
        else:
            # Fallback: compute from enter/exit event counts
            lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
            ev_df = (lf.filter(pl.col("syscall").is_in(io_syscalls_list))
                       .select("event", "syscall", "timestamp_ns")
                       .collect())

            io_enters = ev_df.filter(pl.col("event") == "enter")
            io_exits = ev_df.filter(pl.col("event") == "exit")

            for sc in io_enters["syscall"].unique().sort().to_list():
                enter_ts = io_enters.filter(pl.col("syscall") == sc)["timestamp_ns"].to_numpy()
                exit_ts = io_exits.filter(pl.col("syscall") == sc)["timestamp_ns"].to_numpy()
                points = []
                t = ts_min
                sec = 0
                while t <= ts_max:
                    inflight = int((enter_ts <= t).sum() - (exit_ts <= t).sum())
                    points.append({"time": _sec_to_time(sec), "value": max(0, inflight)})
                    t += window_ns
                    sec += 1
                if points:
                    result["tseries"]["sc_inflight"][sc] = tseries_stats(points)
            del ev_df

    # --- Scan 4: Access pattern ---
    result["access_pattern"] = {"sc_offsets": {}}

    # pread64/pwrite64: use explicit offsets from enter events
    if has_offset:
        lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
        offset_df = (lf.filter(pl.col("event") == "enter")
                       .filter(pl.col("syscall").is_in(["pread64", "pwrite64"]))
                       .filter(pl.col("offset").is_not_null())
                       .select("syscall", "timestamp_ns", "offset", "bytes")
                       .sort("timestamp_ns")
                       .collect())

        if len(offset_df) >= 2:
            for sc in offset_df["syscall"].unique().sort().to_list():
                sc_df = offset_df.filter(pl.col("syscall") == sc)
                offsets = sc_df["offset"].cast(pl.Int64).to_numpy()
                bytes_list = sc_df["bytes"].cast(pl.Int64).to_numpy()
                if len(offsets) >= 2:
                    result["access_pattern"]["sc_offsets"][sc] = compute_fs_access_pattern(
                        offsets, bytes_list
                    )
        del offset_df

    # read/write: pre-filter to relevant syscalls, reconstruct positions
    rw_relevant = ["read", "write", "openat", "lseek", "close"]
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "syscall": pl.Utf8})
    rw_df = (lf.filter(pl.col("syscall").is_in(rw_relevant))
               .select("event", "syscall", "timestamp_ns", "tid", "fd", "bytes")
               .collect())

    rw_pattern = compute_rw_access_pattern(rw_df)
    del rw_df

    for sc, pat in rw_pattern.items():
        result["access_pattern"]["sc_offsets"][sc] = pat

    return result, event_counts


def load_data_quality(layer_dir, event_counts):
    """Load per-type counters.json and compute data quality metrics."""
    counters_file = layer_dir / "counters.json"
    if not counters_file.exists():
        return None
    try:
        with open(counters_file) as f:
            counters = json.load(f)

        per_event_type = {}
        total_generated = 0
        total_dropped = 0

        for event_type in ("enter", "exit"):
            entry = counters.get(event_type, {})
            gen = entry.get("generated", 0)
            drop = entry.get("dropped", 0)
            received = int(event_counts.get(event_type, 0))
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
    stats, event_counts = generate_stats(csv_file)

    dq = load_data_quality(layer_dir, event_counts)
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
