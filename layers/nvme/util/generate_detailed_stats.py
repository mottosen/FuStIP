#!/usr/bin/env python3
"""Generate stats JSON from NVMe layer detailed Parquet output.

Reads detailed.parquet from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (Polars-native quantiles, ~2-row result)
  Scan 3: inflight time-series (aggregated per-second)
  Scan 4: access pattern (sector gap analysis)

Container/comm binding is deferred to a final bind_containers() pass over
the small in-memory result — no add_label_column() in any Polars scan.

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_access_pattern,
                                     derive_throughput,
                                     tseries_stats)
from container.labeling import bind_containers, load_comm_label_map, load_mntns_label_map

LAYER_PREFIX = "nvme"


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


def generate_stats(parquet_path):
    """Parse an NVMe layer detailed Parquet and compute stats."""

    results_dir = parquet_path.parent.parent
    mntns_map = load_mntns_label_map(results_dir)
    comm_map = load_comm_label_map(results_dir)
    schema = pl.scan_parquet(parquet_path).collect_schema()
    has_sector = "sector" in schema
    has_mntns = "mntns_id" in schema
    id_keys = ["comm", "mntns_id"] if has_mntns else ["comm"]

    # Entries keyed by (comm, mntns_id_str) — bind_containers maps to labels at the end.
    _entries: dict = {}

    def ensure_comm_entry(comm, mntns_id_str):
        key = (comm, mntns_id_str)
        if key not in _entries:
            _entries[key] = {
                "counters": {},
                "derived": {},
                "distributions": {},
                "tseries": {},
                "access_pattern": {},
            }
        return _entries[key]

    # --- Scan 1: Counters, duration, event counts ---
    # Group by raw (comm, mntns_id) to keep streaming engine effective.
    # ts_min/ts_max and event_counts derived from this result (no separate scan).
    # Explicit select avoids loading 'rq' (~5 GB) and other unreferenced columns.
    comm_agg_raw = (pl.scan_parquet(parquet_path)
                      .select([*id_keys, "event", "op", "bytes", "timestamp_ns"])
                      .filter(pl.col("event").is_in(["setup", "complete"]))
                      .group_by(*id_keys, "event", "op")
                      .agg(
                          pl.len().alias("count"),
                          pl.col("bytes").sum().alias("total_bytes"),
                          pl.col("timestamp_ns").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max"),
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

        complete_rows = part.filter(pl.col("event") == "complete")
        if len(complete_rows) > 0:
            comm_counters["cmd_completed"] = dict(zip(
                complete_rows["op"].to_list(),
                [int(v) for v in complete_rows["count"].to_list()]
            ))
            comm_counters["cmd_total_bytes"] = dict(zip(
                complete_rows["op"].to_list(),
                [int(v) for v in complete_rows["total_bytes"].to_list()]
            ))

        setup_rows = part.filter(pl.col("event") == "setup")
        if len(setup_rows) > 0:
            comm_counters["cmd_setup"] = dict(zip(
                setup_rows["op"].to_list(),
                [int(v) for v in setup_rows["count"].to_list()]
            ))

        comm_ts_min = part["ts_min"].min()
        comm_ts_max = part["ts_max"].max()
        comm_duration_s = (comm_ts_max - comm_ts_min) / 1e9 if (
            comm_ts_min and comm_ts_max and comm_ts_max > comm_ts_min
        ) else 0

        entry["counters"] = comm_counters
        comm_derived = {"duration_s": round(comm_duration_s, 2)}
        comm_derived.update(derive_throughput(
            comm_counters, comm_duration_s, "cmd_completed", "cmd_total_bytes"
        ))
        entry["derived"] = comm_derived

    del comm_agg_raw

    # --- Scan 2: Distributions (per comm, per op) ---
    # Process one op at a time: quantile on ~60M rows uses ~11 GB RSS.
    # Per-op scans reuse allocator memory (~12 GB total vs ~22 GB simultaneous).
    ops = (pl.scan_parquet(parquet_path)
             .filter(pl.col("event") == "complete")
             .select("op")
             .unique()
             .collect()["op"].to_list())

    for op in ops:
        raw_lat_op = (pl.scan_parquet(parquet_path)
                        .select([*id_keys, "event", "op", "latency_ns"])
                        .filter(pl.col("event") == "complete")
                        .filter(pl.col("op") == op)
                        .filter(pl.col("latency_ns").is_not_null())
                        .group_by(*id_keys)
                        .agg(_series_stats_exprs("latency_ns"))
                        .collect(engine="streaming"))
        for row in raw_lat_op.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("cmd_latencies", {})[op] = _row_to_stats(row)
        del raw_lat_op

    for op in ops:
        raw_size_op = (pl.scan_parquet(parquet_path)
                         .select([*id_keys, "event", "op", "bytes"])
                         .filter(pl.col("event") == "complete")
                         .filter(pl.col("op") == op)
                         .group_by(*id_keys)
                         .agg(_series_stats_exprs("bytes"))
                         .collect(engine="streaming"))
        for row in raw_size_op.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("cmd_sizes", {})[op] = _row_to_stats(row)
        del raw_size_op

    # --- Scan 3: Inflight time-series (per comm) ---
    # No add_label_column in the scan — explicit select for projection pushdown.
    # tseries computed per comm; bind_containers keeps dominant comm's for container labels.
    if duration_s > 0:
        window_ns = 1_000_000_000
        per_comm_snap = (pl.scan_parquet(parquet_path)
                           .select([*id_keys, "event", "op", "timestamp_ns", "inflight"])
                           .filter(pl.col("event").is_in(["setup", "complete"]))
                           .with_columns(
                               ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                           )
                           .group_by(*id_keys, "op", "sec")
                           .agg(pl.col("inflight").last())
                           .collect(engine="streaming"))

        for part in per_comm_snap.partition_by(id_keys, maintain_order=False):
            row0 = part.row(0, named=True)
            comm, mntns_id_str = _comm_key(row0, has_mntns)
            entry = ensure_comm_entry(comm, mntns_id_str)
            for op_part in part.partition_by("op", maintain_order=False):
                op = op_part["op"][0]
                points = [
                    {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                    for s, v in zip(op_part["sec"].to_list(), op_part["inflight"].to_list())
                    if v is not None
                ]
                if points:
                    entry["tseries"].setdefault("cmd_inflight", {})[op] = tseries_stats(points)
        del per_comm_snap

    # --- Scan 4: Access pattern (per comm) ---
    # Scan per-comm to avoid partition_by() on a 100M+ row DataFrame, which creates
    # full copies of all partitions simultaneously and spikes RSS to 3× the frame size.
    if has_sector:
        for (comm, mntns_id_str) in list(_entries.keys()):
            if has_mntns and mntns_id_str:
                comm_filter = (pl.col("comm") == comm) & (pl.col("mntns_id") == int(mntns_id_str))
            else:
                comm_filter = (pl.col("comm") == comm)
            setup_df = (pl.scan_parquet(parquet_path)
                          .filter(comm_filter)
                          .filter(pl.col("event") == "setup")
                          .filter(pl.col("sector").is_not_null())
                          .select(["op", "sector", "bytes"])
                          .collect(engine="streaming"))
            if len(setup_df) == 0:
                del setup_df
                continue
            entry = ensure_comm_entry(comm, mntns_id_str)
            entry["access_pattern"].setdefault("cmd_sectors", {})
            for op_part in setup_df.partition_by("op", maintain_order=False):
                op = op_part["op"][0]
                sectors = op_part["sector"].cast(pl.Int64).to_numpy()
                bytes_list = op_part["bytes"].cast(pl.Int64).to_numpy()
                if len(sectors) >= 2:
                    entry["access_pattern"]["cmd_sectors"][op] = compute_access_pattern(
                        sectors, bytes_list
                    )
            del setup_df

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

        for event_type in ("setup", "complete"):
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
        description="Generate stats from NVMe layer detailed Parquet output"
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
