#!/usr/bin/env python3
"""Generate stats JSON from filesystem layer detailed Parquet output.

Reads detailed.parquet from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (Polars-native quantiles, ~4-row result)
  Scan 3: inflight time-series (aggregated per-second counts)
  Scan 4: access pattern (per-syscall scans + read/write position tracking)

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
                                     tseries_stats)
from container.labeling import add_label_column, load_mntns_label_map

LAYER_PREFIX = "fs"

# IO syscalls that have meaningful bytes/latency for histograms
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}


def _sec_to_time(s):
    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
    return f"{h:02d}:{m:02d}:{ss:02d}"


def _series_stats_exprs(col):
    """Polars aggregation expressions for distribution stats."""
    c = pl.col(col)
    return [
        c.count().alias("count"),
        c.min().alias("min"),
        c.max().alias("max"),
        c.mean().alias("mean"),
        c.quantile(0.01, interpolation="linear").alias("p1"),
        c.quantile(0.05, interpolation="linear").alias("p5"),
        c.quantile(0.50, interpolation="linear").alias("p50"),
        c.quantile(0.95, interpolation="linear").alias("p95"),
        c.quantile(0.99, interpolation="linear").alias("p99"),
    ]


def _row_to_stats(row):
    """Convert a Polars agg row dict to series_stats-compatible dict."""
    def _val(v):
        return round(float(v), 2) if v is not None else 0.0
    return {
        "count": int(row["count"]) if row["count"] is not None else 0,
        "min": _val(row["min"]),
        "max": _val(row["max"]),
        "mean": _val(row["mean"]),
        "p1": _val(row["p1"]),
        "p5": _val(row["p5"]),
        "p50": _val(row["p50"]),
        "p95": _val(row["p95"]),
        "p99": _val(row["p99"]),
    }


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
    rw_positions = {}  # "read"/"write" -> {fd: [(offset, bytes), ...]}

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
                rw_positions.setdefault(sc, {}).setdefault(int(fd_v), []).append((pos[key], bv_int))

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
        fd_groups = rw_positions.get(sc, {})
        total_ios = 0
        seq_count = 0
        rnd_count = 0
        for fd_positions in fd_groups.values():
            total_ios += len(fd_positions)
            if len(fd_positions) < 2:
                continue
            offsets = [p[0] for p in fd_positions]
            bytes_list = [p[1] for p in fd_positions]
            pat = compute_fs_access_pattern(offsets, bytes_list)
            seq_count += pat["sequential_count"]
            rnd_count += pat["random_count"]

        total_gaps = seq_count + rnd_count
        if total_gaps > 0:
            result[sc] = {
                "total_ios": total_ios,
                "sequential_count": seq_count,
                "random_count": rnd_count,
                "sequential_pct": round(100 * seq_count / total_gaps, 2),
                "random_pct": round(100 * rnd_count / total_gaps, 2),
            }

    return result


def generate_stats(parquet_path):
    """Parse an FS layer detailed Parquet and compute stats."""

    # Check schema for optional columns
    results_dir = parquet_path.parent.parent
    mntns_map = load_mntns_label_map(results_dir)
    schema = add_label_column(pl.scan_parquet(parquet_path), mntns_map).collect_schema()
    has_offset = "offset" in schema

    io_syscalls_list = list(IO_SYSCALLS)

    # --- Scan 1: Counters, duration, event counts ---
    print("  Scan 1: counters...", flush=True)
    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)

    # Get per-(event, syscall) aggregates — streaming to avoid 15GB+ materialization
    agg = (lf.group_by("event", "syscall")
             .agg(
                 pl.len().alias("count"),
                 pl.col("bytes").sum().alias("total_bytes"),
                 pl.col("timestamp_ns").min().alias("ts_min"),
                 pl.col("timestamp_ns").max().alias("ts_max"),
                 pl.when(pl.col("bytes") > 0).then(pl.col("bytes")).otherwise(0).sum().alias("pos_bytes"),
             )
             .collect(engine="streaming"))

    # Duration from all events
    ts_min = agg["ts_min"].min()
    ts_max = agg["ts_max"].max()
    if ts_min is not None and ts_max is not None and ts_max > ts_min:
        duration_s = (ts_max - ts_min) / 1e9
    else:
        duration_s = 0

    # Build counters
    counters = {}

    exit_io = agg.filter((pl.col("event") == "exit") & pl.col("syscall").is_in(io_syscalls_list))
    if len(exit_io) > 0:
        counters["sc_completed"] = dict(zip(
            exit_io["syscall"].to_list(),
            [int(v) for v in exit_io["count"].to_list()]
        ))

    enter_io = agg.filter((pl.col("event") == "enter") & pl.col("syscall").is_in(io_syscalls_list))
    if len(enter_io) > 0:
        counters["sc_entered"] = dict(zip(
            enter_io["syscall"].to_list(),
            [int(v) for v in enter_io["count"].to_list()]
        ))

    if len(exit_io) > 0:
        pos_bytes_rows = exit_io.filter(pl.col("pos_bytes") > 0)
        if len(pos_bytes_rows) > 0:
            counters["sc_total_bytes"] = dict(zip(
                pos_bytes_rows["syscall"].to_list(),
                [int(v) for v in pos_bytes_rows["pos_bytes"].to_list()]
            ))

    non_io_enters = agg.filter((pl.col("event") == "enter") & ~pl.col("syscall").is_in(io_syscalls_list))
    if len(non_io_enters) > 0:
        counters["sc_count"] = dict(zip(
            non_io_enters["syscall"].to_list(),
            [int(v) for v in non_io_enters["count"].to_list()]
        ))

    # Event counts for data quality (avoids separate scan)
    event_agg = agg.group_by("event").agg(pl.col("count").sum())
    event_counts = dict(zip(event_agg["event"].to_list(), event_agg["count"].to_list()))

    result = {
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "distributions": {},
        "tseries": {},
    }

    throughput = derive_throughput(counters, duration_s, "sc_completed", "sc_total_bytes")
    result["derived"].update(throughput)

    del agg

    if "label" in schema:
        per_comm = {}
        comm_agg = (add_label_column(pl.scan_parquet(parquet_path), mntns_map)
                      .filter(pl.col("label").is_not_null())
                      .group_by("label", "event", "syscall")
                      .agg(
                          pl.len().alias("count"),
                          pl.col("bytes").sum().alias("total_bytes"),
                          pl.col("timestamp_ns").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max"),
                          pl.when(pl.col("bytes") > 0).then(pl.col("bytes")).otherwise(0).sum().alias("pos_bytes"),
                      )
                      .collect(engine="streaming"))
        for comm in comm_agg["label"].unique().sort().to_list():
            comm_rows = comm_agg.filter(pl.col("label") == comm)
            comm_counters = {}

            comm_exit_io = comm_rows.filter((pl.col("event") == "exit") & pl.col("syscall").is_in(io_syscalls_list))
            if len(comm_exit_io) > 0:
                comm_counters["sc_completed"] = dict(zip(
                    comm_exit_io["syscall"].to_list(),
                    [int(v) for v in comm_exit_io["count"].to_list()]
                ))

            comm_enter_io = comm_rows.filter((pl.col("event") == "enter") & pl.col("syscall").is_in(io_syscalls_list))
            if len(comm_enter_io) > 0:
                comm_counters["sc_entered"] = dict(zip(
                    comm_enter_io["syscall"].to_list(),
                    [int(v) for v in comm_enter_io["count"].to_list()]
                ))

            if len(comm_exit_io) > 0:
                comm_pos_bytes = comm_exit_io.filter(pl.col("pos_bytes") > 0)
                if len(comm_pos_bytes) > 0:
                    comm_counters["sc_total_bytes"] = dict(zip(
                        comm_pos_bytes["syscall"].to_list(),
                        [int(v) for v in comm_pos_bytes["pos_bytes"].to_list()]
                    ))

            comm_non_io_enters = comm_rows.filter((pl.col("event") == "enter") & ~pl.col("syscall").is_in(io_syscalls_list))
            if len(comm_non_io_enters) > 0:
                comm_counters["sc_count"] = dict(zip(
                    comm_non_io_enters["syscall"].to_list(),
                    [int(v) for v in comm_non_io_enters["count"].to_list()]
                ))

            comm_ts_min = comm_rows["ts_min"].min()
            comm_ts_max = comm_rows["ts_max"].max()
            if comm_ts_min is not None and comm_ts_max is not None and comm_ts_max > comm_ts_min:
                comm_duration_s = (comm_ts_max - comm_ts_min) / 1e9
            else:
                comm_duration_s = 0

            comm_derived = {"duration_s": round(comm_duration_s, 2)}
            comm_derived.update(derive_throughput(
                comm_counters, comm_duration_s, "sc_completed", "sc_total_bytes"
            ))
            per_comm[comm] = {"counters": comm_counters, "derived": comm_derived}
        result["per_comm"] = per_comm

    # --- Scan 2: Distributions (Polars-native quantiles, no data in Python) ---
    print("  Scan 2: distributions...", flush=True)
    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    lat_stats = (lf.filter(pl.col("event") == "exit")
                   .filter(pl.col("syscall").is_in(io_syscalls_list))
                   .filter(pl.col("latency_ns").is_not_null() & (pl.col("latency_ns") > 0))
                   .group_by("syscall")
                   .agg(_series_stats_exprs("latency_ns"))
                   .sort("syscall")
                   .collect(engine="streaming"))
    if len(lat_stats) > 0:
        result["distributions"]["sc_latencies"] = {
            row["syscall"]: _row_to_stats(row)
            for row in lat_stats.iter_rows(named=True)
        }
    del lat_stats

    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    size_stats = (lf.filter(pl.col("event") == "exit")
                    .filter(pl.col("syscall").is_in(io_syscalls_list))
                    .filter(pl.col("bytes") > 0)
                    .group_by("syscall")
                    .agg(_series_stats_exprs("bytes"))
                    .sort("syscall")
                    .collect(engine="streaming"))
    if len(size_stats) > 0:
        result["distributions"]["sc_sizes"] = {
            row["syscall"]: _row_to_stats(row)
            for row in size_stats.iter_rows(named=True)
        }
    del size_stats

    # --- Scan 3: Inflight time-series (aggregated, no full-data collect) ---
    print("  Scan 3: tseries...", flush=True)
    if duration_s > 0:
        window_ns = 1_000_000_000
        result["tseries"]["sc_inflight"] = {}

        lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
        inf_df = (lf.filter(pl.col("syscall").is_in(io_syscalls_list))
                    .with_columns(
                        ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                    )
                    .group_by("syscall", "sec")
                    .agg(pl.col("inflight").last())
                    .sort("syscall", "sec")
                    .collect(engine="streaming"))

        for sc in inf_df["syscall"].unique().sort().to_list():
            sc_df = inf_df.filter(pl.col("syscall") == sc)
            points = [
                {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                for s, v in zip(sc_df["sec"].to_list(), sc_df["inflight"].to_list())
                if v is not None
            ]
            if points:
                result["tseries"]["sc_inflight"][sc] = tseries_stats(points)
        del inf_df

    # --- Scan 4: Access pattern ---
    print("  Scan 4: access pattern...", flush=True)
    result["access_pattern"] = {"sc_offsets": {}}

    # pread64/pwrite64: per-syscall scan with explicit offsets, per-fd analysis
    if has_offset:
        for sc in ["pread64", "pwrite64"]:
            lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
            sc_df = (lf.filter((pl.col("event") == "enter") & (pl.col("syscall") == sc)
                               & pl.col("offset").is_not_null())
                       .select("timestamp_ns", "offset", "bytes", "fd")
                       .sort("timestamp_ns")
                       .collect(engine="streaming"))
            if len(sc_df) < 2:
                del sc_df
                continue

            total_ios = 0
            seq_count = 0
            rnd_count = 0
            for fd_val in sc_df.drop_nulls("fd")["fd"].unique().to_list():
                fd_group = sc_df.filter(pl.col("fd") == fd_val)
                total_ios += len(fd_group)
                if len(fd_group) < 2:
                    continue
                offsets = fd_group["offset"].cast(pl.Int64).to_numpy()
                bytes_list = fd_group["bytes"].cast(pl.Int64).to_numpy()
                pat = compute_fs_access_pattern(offsets, bytes_list)
                seq_count += pat["sequential_count"]
                rnd_count += pat["random_count"]

            total_gaps = seq_count + rnd_count
            if total_gaps > 0:
                result["access_pattern"]["sc_offsets"][sc] = {
                    "total_ios": total_ios,
                    "sequential_count": seq_count,
                    "random_count": rnd_count,
                    "sequential_pct": round(100 * seq_count / total_gaps, 2),
                    "random_pct": round(100 * rnd_count / total_gaps, 2),
                }
            del sc_df

    # read/write: pre-filter to relevant syscalls, reconstruct positions
    rw_relevant = ["read", "write", "openat", "lseek", "close"]
    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    rw_df = (lf.filter(pl.col("syscall").is_in(rw_relevant))
               .select("event", "syscall", "timestamp_ns", "tid", "fd", "bytes")
               .collect(engine="streaming"))

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
        description="Generate stats from fs layer detailed Parquet output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    args = parser.parse_args()

    layer_dir = args.results_dir / LAYER_PREFIX
    if not layer_dir.is_dir():
        print(f"Error: {layer_dir} not found", file=sys.stderr)
        sys.exit(1)

    parquet_file = layer_dir / "detailed.parquet"
    if not parquet_file.exists():
        print(f"No detailed output found: {parquet_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {parquet_file.name}...")
    stats, event_counts = generate_stats(parquet_file)

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
