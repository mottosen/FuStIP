#!/usr/bin/env python3
"""Generate stats JSON from block layer detailed Parquet output.

Reads detailed.parquet from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (Polars-native quantiles, ~2-row result)
  Scan 3: inflight time-series (aggregated per-second)
  Scan 4: access pattern (sector gap analysis from issue events)

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
from container.labeling import add_label_column, load_mntns_label_map

LAYER_PREFIX = "block"


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


def generate_stats(parquet_path):
    """Parse a block layer detailed Parquet and compute stats."""

    # Check schema for optional columns
    results_dir = parquet_path.parent.parent
    mntns_map = load_mntns_label_map(results_dir)
    schema = add_label_column(pl.scan_parquet(parquet_path), mntns_map).collect_schema()
    has_sector = "sector" in schema

    # --- Scan 1: Counters, duration, event counts ---
    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)

    agg = (lf.filter(pl.col("event").is_in(["insert", "issue", "complete"]))
             .group_by("event", "op")
             .agg(
                 pl.len().alias("count"),
                 pl.col("bytes").sum().alias("total_bytes"),
                 pl.col("timestamp_ns").min().alias("ts_min"),
                 pl.col("timestamp_ns").max().alias("ts_max"),
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

    complete_rows = agg.filter(pl.col("event") == "complete")
    if len(complete_rows) > 0:
        counters["rq_completed"] = dict(zip(
            complete_rows["op"].to_list(),
            [int(v) for v in complete_rows["count"].to_list()]
        ))
        counters["rq_total_bytes"] = dict(zip(
            complete_rows["op"].to_list(),
            [int(v) for v in complete_rows["total_bytes"].to_list()]
        ))

    issue_rows = agg.filter(pl.col("event") == "issue")
    if len(issue_rows) > 0:
        counters["rq_issued"] = dict(zip(
            issue_rows["op"].to_list(),
            [int(v) for v in issue_rows["count"].to_list()]
        ))

    insert_rows = agg.filter(pl.col("event") == "insert")
    if len(insert_rows) > 0:
        counters["rq_queued"] = dict(zip(
            insert_rows["op"].to_list(),
            [int(v) for v in insert_rows["count"].to_list()]
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

    throughput = derive_throughput(counters, duration_s, "rq_completed", "rq_total_bytes")
    result["derived"].update(throughput)

    del agg

    if "label" in schema:
        per_comm = {}
        comm_agg = (add_label_column(pl.scan_parquet(parquet_path), mntns_map)
                      .filter(pl.col("label").is_not_null())
                      .filter(pl.col("event").is_in(["insert", "issue", "complete"]))
                      .group_by("label", "event", "op")
                      .agg(
                          pl.len().alias("count"),
                          pl.col("bytes").sum().alias("total_bytes"),
                          pl.col("timestamp_ns").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max"),
                      )
                      .collect(engine="streaming"))
        for comm in comm_agg["label"].unique().sort().to_list():
            comm_rows = comm_agg.filter(pl.col("label") == comm)
            comm_counters = {}

            comm_complete = comm_rows.filter(pl.col("event") == "complete")
            if len(comm_complete) > 0:
                comm_counters["rq_completed"] = dict(zip(
                    comm_complete["op"].to_list(),
                    [int(v) for v in comm_complete["count"].to_list()]
                ))
                comm_counters["rq_total_bytes"] = dict(zip(
                    comm_complete["op"].to_list(),
                    [int(v) for v in comm_complete["total_bytes"].to_list()]
                ))

            comm_issue = comm_rows.filter(pl.col("event") == "issue")
            if len(comm_issue) > 0:
                comm_counters["rq_issued"] = dict(zip(
                    comm_issue["op"].to_list(),
                    [int(v) for v in comm_issue["count"].to_list()]
                ))

            comm_insert = comm_rows.filter(pl.col("event") == "insert")
            if len(comm_insert) > 0:
                comm_counters["rq_queued"] = dict(zip(
                    comm_insert["op"].to_list(),
                    [int(v) for v in comm_insert["count"].to_list()]
                ))

            comm_ts_min = comm_rows["ts_min"].min()
            comm_ts_max = comm_rows["ts_max"].max()
            if comm_ts_min is not None and comm_ts_max is not None and comm_ts_max > comm_ts_min:
                comm_duration_s = (comm_ts_max - comm_ts_min) / 1e9
            else:
                comm_duration_s = 0

            comm_derived = {"duration_s": round(comm_duration_s, 2)}
            comm_derived.update(derive_throughput(
                comm_counters, comm_duration_s, "rq_completed", "rq_total_bytes"
            ))
            per_comm[comm] = {"counters": comm_counters, "derived": comm_derived}
        result["per_comm"] = per_comm

    # --- Scan 2: Distributions (Polars-native quantiles, no data in Python) ---
    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    driver_lat_stats = (lf.filter(pl.col("event") == "complete")
                          .filter(pl.col("latency_ns").is_not_null())
                          .group_by("op")
                          .agg(_series_stats_exprs("latency_ns"))
                          .sort("op")
                          .collect(engine="streaming"))
    if len(driver_lat_stats) > 0:
        result["distributions"]["driver_latencies"] = {
            row["op"]: _row_to_stats(row)
            for row in driver_lat_stats.iter_rows(named=True)
        }
    del driver_lat_stats

    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    queue_lat_stats = (lf.filter(pl.col("event") == "issue")
                         .filter(pl.col("latency_ns").is_not_null())
                         .group_by("op")
                         .agg(_series_stats_exprs("latency_ns"))
                         .sort("op")
                         .collect(engine="streaming"))
    if len(queue_lat_stats) > 0:
        result["distributions"]["queue_latencies"] = {
            row["op"]: _row_to_stats(row)
            for row in queue_lat_stats.iter_rows(named=True)
        }
    del queue_lat_stats

    lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
    size_stats = (lf.filter(pl.col("event") == "complete")
                    .group_by("op")
                    .agg(_series_stats_exprs("bytes"))
                    .sort("op")
                    .collect(engine="streaming"))
    if len(size_stats) > 0:
        result["distributions"]["rq_sizes"] = {
            row["op"]: _row_to_stats(row)
            for row in size_stats.iter_rows(named=True)
        }
    del size_stats

    # --- Scan 3: Inflight time-series (aggregated per-second) ---
    if duration_s > 0:
        window_ns = 1_000_000_000

        lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
        inf_df = (lf.filter(pl.col("event").is_in(["insert", "issue", "complete"]))
                    .with_columns(
                        ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                    )
                    .group_by("op", "sec")
                    .agg(
                        pl.col("q_inflight").last(),
                        pl.col("d_inflight").last(),
                    )
                    .sort("op", "sec")
                    .collect(engine="streaming"))

        for stage, col in [("q_inflight", "q_inflight"), ("d_inflight", "d_inflight")]:
            result["tseries"][stage] = {}
            for op in inf_df["op"].unique().sort().to_list():
                op_df = inf_df.filter(pl.col("op") == op)
                points = [
                    {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                    for s, v in zip(op_df["sec"].to_list(), op_df[col].to_list())
                    if v is not None
                ]
                if points:
                    result["tseries"][stage][op] = tseries_stats(points)
        del inf_df

    # --- Scan 4: Access pattern ---
    if has_sector:
        lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
        issue_df = (lf.filter(pl.col("event") == "issue")
                      .filter(pl.col("sector").is_not_null())
                      .select("op", "timestamp_ns", "sector", "bytes")
                      .sort("timestamp_ns")
                      .collect(engine="streaming"))

        if len(issue_df) > 0:
            result["access_pattern"] = {"rq_sectors": {}}
            for op in issue_df["op"].unique().sort().to_list():
                op_df = issue_df.filter(pl.col("op") == op)
                sectors = op_df["sector"].cast(pl.Int64).to_numpy()
                bytes_list = op_df["bytes"].cast(pl.Int64).to_numpy()
                if len(sectors) >= 2:
                    result["access_pattern"]["rq_sectors"][op] = compute_access_pattern(
                        sectors, bytes_list
                    )
        del issue_df

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

        for event_type in ("insert", "issue", "complete"):
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
        description="Generate stats from block layer detailed Parquet output"
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
