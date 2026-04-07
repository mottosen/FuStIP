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

Container/comm binding is deferred to a final bind_containers() pass over
the small in-memory result — no add_label_column() in any Polars scan.

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_fs_access_pattern,
                                     tseries_stats)
from container.labeling import bind_containers, load_comm_label_map, load_mntns_label_map

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


def _comm_key(row, has_mntns):
    """Extract (comm, mntns_id_str) key from a row dict."""
    mntns_id = row.get("mntns_id") if has_mntns else None
    return row["comm"], (str(mntns_id) if mntns_id is not None else "")


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

    results_dir = parquet_path.parent.parent
    mntns_map = load_mntns_label_map(results_dir)
    comm_map = load_comm_label_map(results_dir)
    schema = pl.scan_parquet(parquet_path).collect_schema()
    has_offset = "offset" in schema
    has_mntns = "mntns_id" in schema
    id_keys = ["comm", "mntns_id"] if has_mntns else ["comm"]

    io_syscalls_list = list(IO_SYSCALLS)

    # Entries keyed by (comm, mntns_id_str) — bind_containers maps to labels at the end.
    _entries: dict = {}

    def ensure_comm_entry(comm, mntns_id_str):
        key = (comm, mntns_id_str)
        if key not in _entries:
            _entries[key] = {
                "counters": {},
                "distributions": {},
                "tseries": {},
                "access_pattern": {},
            }
        return _entries[key]

    # --- Scan 1: Counters, duration, event counts ---
    print("  Scan 1: counters...", flush=True)
    # Group by raw (comm, mntns_id) — streaming engine stays effective.
    # ts_min/ts_max and event_counts derived from this result (no separate scan).
    # Explicit select avoids loading unreferenced columns (fd, offset, tid, etc.).
    comm_agg_raw = (pl.scan_parquet(parquet_path)
                      .select([*id_keys, "event", "syscall", "bytes", "timestamp_ns"])
                      .group_by(*id_keys, "event", "syscall")
                      .agg(
                          pl.len().alias("count"),
                          pl.col("bytes").sum().alias("total_bytes"),
                          pl.col("timestamp_ns").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max"),
                          pl.when(pl.col("bytes") > 0).then(pl.col("bytes")).otherwise(0).sum().alias("pos_bytes"),
                      )
                      .collect(engine="streaming"))

    ts_min = comm_agg_raw["ts_min"].min()
    ts_max = comm_agg_raw["ts_max"].max()
    duration_s = (ts_max - ts_min) / 1e9 if ts_min and ts_max and ts_max > ts_min else 0
    event_agg = comm_agg_raw.group_by("event").agg(pl.col("count").sum())
    event_counts = dict(zip(event_agg["event"].to_list(), event_agg["count"].to_list()))

    for part in comm_agg_raw.partition_by(id_keys, maintain_order=False):
        row0 = part.row(0, named=True)
        comm, mntns_id_str = _comm_key(row0, has_mntns)
        entry = ensure_comm_entry(comm, mntns_id_str)
        comm_counters = {}

        comm_exit_io = part.filter((pl.col("event") == "exit") & pl.col("syscall").is_in(io_syscalls_list))
        if len(comm_exit_io) > 0:
            comm_counters["sc_completed"] = dict(zip(
                comm_exit_io["syscall"].to_list(),
                [int(v) for v in comm_exit_io["count"].to_list()]
            ))

        comm_enter_io = part.filter((pl.col("event") == "enter") & pl.col("syscall").is_in(io_syscalls_list))
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

        comm_non_io_enters = part.filter((pl.col("event") == "enter") & ~pl.col("syscall").is_in(io_syscalls_list))
        if len(comm_non_io_enters) > 0:
            comm_counters["sc_count"] = dict(zip(
                comm_non_io_enters["syscall"].to_list(),
                [int(v) for v in comm_non_io_enters["count"].to_list()]
            ))

        entry["counters"] = comm_counters

    del comm_agg_raw

    # --- Scan 2: Distributions (per comm, per syscall) ---
    # Process one IO syscall at a time: each scan buffers ~93M latency values
    # for exact quantile computation (~11 GB RSS per scan). Per-syscall scans
    # reuse allocator memory, staying under 13 GB total.
    print("  Scan 2: distributions...", flush=True)
    for sc in io_syscalls_list:
        raw_lat_sc = (pl.scan_parquet(parquet_path)
                        .select([*id_keys, "event", "syscall", "latency_ns"])
                        .filter(pl.col("event") == "exit")
                        .filter(pl.col("syscall") == sc)
                        .filter(pl.col("latency_ns").is_not_null() & (pl.col("latency_ns") > 0))
                        .group_by(*id_keys)
                        .agg(_series_stats_exprs("latency_ns"))
                        .collect(engine="streaming"))
        for row in raw_lat_sc.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("sc_latencies", {})[sc] = _row_to_stats(row)
        del raw_lat_sc

    for sc in io_syscalls_list:
        raw_size_sc = (pl.scan_parquet(parquet_path)
                         .select([*id_keys, "event", "syscall", "bytes"])
                         .filter(pl.col("event") == "exit")
                         .filter(pl.col("syscall") == sc)
                         .filter(pl.col("bytes") > 0)
                         .group_by(*id_keys)
                         .agg(_series_stats_exprs("bytes"))
                         .collect(engine="streaming"))
        for row in raw_size_sc.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("sc_sizes", {})[sc] = _row_to_stats(row)
        del raw_size_sc

    # --- Scan 3: Inflight time-series (per comm) ---
    # Explicit select for projection pushdown.
    # tseries computed per comm; bind_containers keeps dominant comm's for container labels.
    print("  Scan 3: tseries...", flush=True)
    if duration_s > 0:
        window_ns = 1_000_000_000
        total_secs = math.ceil(duration_s)
        per_comm_snap = (pl.scan_parquet(parquet_path)
                           .select([*id_keys, "event", "syscall", "timestamp_ns", "inflight"])
                           .filter(pl.col("syscall").is_in(io_syscalls_list))
                           .with_columns(
                               ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                           )
                           .group_by(*id_keys, "syscall", "sec")
                           .agg(
                               pl.col("inflight").last(),
                               pl.when(pl.col("event") == "exit")
                                 .then(pl.lit(1)).otherwise(pl.lit(0)).sum().alias("io_count"),
                           )
                           .collect(engine="streaming"))

        for part in per_comm_snap.partition_by(id_keys, maintain_order=False):
            row0 = part.row(0, named=True)
            comm, mntns_id_str = _comm_key(row0, has_mntns)
            entry = ensure_comm_entry(comm, mntns_id_str)
            for sc_part in part.partition_by("syscall", maintain_order=False):
                sc = sc_part["syscall"][0]
                points = [
                    {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                    for s, v in zip(sc_part["sec"].to_list(), sc_part["inflight"].to_list())
                    if v is not None
                ]
                if points:
                    entry["tseries"].setdefault("sc_inflight", {})[sc] = tseries_stats(points)
                # IOPS time series: zero-filled over the global profiling window
                sec_to_iops = {
                    int(s): int(v)
                    for s, v in zip(sc_part["sec"].to_list(), sc_part["io_count"].to_list())
                    if v is not None
                }
                iops_points = [
                    {"time": _sec_to_time(s), "value": sec_to_iops.get(s, 0)}
                    for s in range(total_secs)
                ]
                if iops_points:
                    entry["tseries"].setdefault("iops", {})[sc] = tseries_stats(iops_points)
        del per_comm_snap

    # --- Scan 4: Access pattern (per comm) ---
    print("  Scan 4: access pattern...", flush=True)
    if has_offset:
        # Scan per-comm to avoid partition_by on 80M-row DataFrames (partition_by
        # creates full copies — 80M rows × 2 copies = OOM on tight memory budget).
        # Filter at scan time, keep only the 3 columns needed for gap analysis.
        comm_keys = list(_entries.keys())
        for sc in ["pread64", "pwrite64"]:
            for (comm, mntns_id_str) in comm_keys:
                if has_mntns and mntns_id_str:
                    comm_filter = (pl.col("comm") == comm) & (pl.col("mntns_id") == int(mntns_id_str))
                else:
                    comm_filter = (pl.col("comm") == comm)

                sc_df = (pl.scan_parquet(parquet_path)
                           .filter((pl.col("event") == "enter") & (pl.col("syscall") == sc)
                                   & pl.col("offset").is_not_null() & comm_filter)
                           .select(["offset", "bytes", "fd"])
                           .collect(engine="streaming"))
                if len(sc_df) < 2:
                    del sc_df
                    continue

                entry = ensure_comm_entry(comm, mntns_id_str)
                entry["access_pattern"].setdefault("sc_offsets", {})
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
                    entry["access_pattern"]["sc_offsets"][sc] = {
                        "total_ios": total_ios,
                        "sequential_count": seq_count,
                        "random_count": rnd_count,
                        "sequential_pct": round(100 * seq_count / total_gaps, 2),
                        "random_pct": round(100 * rnd_count / total_gaps, 2),
                    }
                del sc_df

    rw_relevant = ["read", "write", "openat", "lseek", "close"]
    rw_df = (pl.scan_parquet(parquet_path)
               .filter(pl.col("syscall").is_in(rw_relevant))
               .select([*id_keys, "event", "syscall", "timestamp_ns", "tid", "fd", "bytes"])
               .collect(engine="streaming"))

    if len(rw_df) > 0:
        for part in rw_df.partition_by(id_keys, maintain_order=False):
            row0 = part.row(0, named=True)
            comm, mntns_id_str = _comm_key(row0, has_mntns)
            entry = ensure_comm_entry(comm, mntns_id_str)
            rw_pattern = compute_rw_access_pattern(
                part.select("event", "syscall", "timestamp_ns", "tid", "fd", "bytes")
            )
            if rw_pattern:
                entry["access_pattern"].setdefault("sc_offsets", {})
                for sc, pat in rw_pattern.items():
                    entry["access_pattern"]["sc_offsets"][sc] = pat
    del rw_df

    return bind_containers(_entries, mntns_map, comm_map), event_counts


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
