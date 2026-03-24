#!/usr/bin/env python3
"""Generate stats JSON from NVMe layer detailed CSV output.

Reads detailed.csv from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (latency/size stats per op)
  Scan 3: inflight time-series
  Scan 4: access pattern (sector gap analysis)

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
                                     series_stats,
                                     tseries_stats)

LAYER_PREFIX = "nvme"


def _sec_to_time(s):
    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
    return f"{h:02d}:{m:02d}:{ss:02d}"


def generate_stats(csv_path):
    """Parse an NVMe layer detailed CSV and compute stats."""

    # Check header for optional columns
    with open(csv_path) as f:
        header = f.readline().strip().split(",")
    has_inflight = "inflight" in header
    has_sector = "sector" in header

    # --- Scan 1: Counters, duration, event counts ---
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "op": pl.Utf8})

    agg = (lf.filter(pl.col("event").is_in(["setup", "complete"]))
             .group_by("event", "op")
             .agg(
                 pl.len().alias("count"),
                 pl.col("bytes").sum().alias("total_bytes"),
                 pl.col("timestamp_ns").min().alias("ts_min"),
                 pl.col("timestamp_ns").max().alias("ts_max"),
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

    complete_rows = agg.filter(pl.col("event") == "complete")
    if len(complete_rows) > 0:
        counters["cmd_completed"] = dict(zip(
            complete_rows["op"].to_list(),
            [int(v) for v in complete_rows["count"].to_list()]
        ))
        counters["cmd_total_bytes"] = dict(zip(
            complete_rows["op"].to_list(),
            [int(v) for v in complete_rows["total_bytes"].to_list()]
        ))

    setup_rows = agg.filter(pl.col("event") == "setup")
    if len(setup_rows) > 0:
        counters["cmd_setup"] = dict(zip(
            setup_rows["op"].to_list(),
            [int(v) for v in setup_rows["count"].to_list()]
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
    throughput = derive_throughput(counters, duration_s, "cmd_completed", "cmd_total_bytes")
    result["derived"].update(throughput)

    del agg

    # --- Scan 2: Distributions ---
    lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "op": pl.Utf8})

    complete_lf = lf.filter(pl.col("event") == "complete")

    # Latencies
    lat_df = (complete_lf
              .filter(pl.col("latency_ns").is_not_null())
              .select("op", "latency_ns")
              .collect())
    if len(lat_df) > 0:
        result["distributions"]["cmd_latencies"] = {}
        for op in lat_df["op"].unique().sort().to_list():
            vals = lat_df.filter(pl.col("op") == op)["latency_ns"].to_numpy()
            result["distributions"]["cmd_latencies"][op] = series_stats(vals)

    # Sizes
    size_df = complete_lf.select("op", "bytes").collect()
    if len(size_df) > 0:
        result["distributions"]["cmd_sizes"] = {}
        for op in size_df["op"].unique().sort().to_list():
            vals = size_df.filter(pl.col("op") == op)["bytes"].to_numpy()
            result["distributions"]["cmd_sizes"][op] = series_stats(vals)

    del lat_df, size_df

    # --- Scan 3: Inflight time-series ---
    if duration_s > 0:
        window_ns = 1_000_000_000
        result["tseries"]["cmd_inflight"] = {}

        if has_inflight:
            lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "op": pl.Utf8})
            inf_df = (lf.filter(pl.col("event").is_in(["setup", "complete"]))
                        .select("op", "timestamp_ns", "inflight")
                        .sort("timestamp_ns")
                        .with_columns(
                            ((pl.col("timestamp_ns") - ts_min) // window_ns).cast(pl.Int64).alias("sec")
                        )
                        .group_by("op", "sec")
                        .agg(pl.col("inflight").last())
                        .sort("op", "sec")
                        .collect())

            for op in inf_df["op"].unique().sort().to_list():
                op_df = inf_df.filter(pl.col("op") == op)
                points = [
                    {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                    for s, v in zip(op_df["sec"].to_list(), op_df["inflight"].to_list())
                ]
                if points:
                    result["tseries"]["cmd_inflight"][op] = tseries_stats(points)
            del inf_df
        else:
            # Fallback: compute from enter/exit event counts
            lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "op": pl.Utf8})
            ev_df = (lf.filter(pl.col("event").is_in(["setup", "complete"]))
                       .select("event", "op", "timestamp_ns")
                       .collect())

            for op in ev_df["op"].unique().sort().to_list():
                enter_ts = ev_df.filter((pl.col("op") == op) & (pl.col("event") == "setup"))["timestamp_ns"].to_numpy()
                exit_ts = ev_df.filter((pl.col("op") == op) & (pl.col("event") == "complete"))["timestamp_ns"].to_numpy()
                if len(enter_ts) == 0:
                    continue
                points = []
                t = ts_min
                sec = 0
                while t <= ts_max:
                    inflight = int((enter_ts <= t).sum() - (exit_ts <= t).sum())
                    points.append({"time": _sec_to_time(sec), "value": max(0, inflight)})
                    t += window_ns
                    sec += 1
                if points:
                    result["tseries"]["cmd_inflight"][op] = tseries_stats(points)
            del ev_df

    # --- Scan 4: Access pattern ---
    if has_sector:
        lf = pl.scan_csv(csv_path, schema_overrides={"event": pl.Utf8, "op": pl.Utf8})
        setup_df = (lf.filter(pl.col("event") == "setup")
                      .filter(pl.col("sector").is_not_null())
                      .select("op", "timestamp_ns", "sector", "bytes")
                      .sort("timestamp_ns")
                      .collect())

        if len(setup_df) > 0:
            result["access_pattern"] = {"cmd_sectors": {}}
            for op in setup_df["op"].unique().sort().to_list():
                op_df = setup_df.filter(pl.col("op") == op)
                sectors = op_df["sector"].cast(pl.Int64).to_numpy()
                bytes_list = op_df["bytes"].cast(pl.Int64).to_numpy()
                if len(sectors) >= 2:
                    result["access_pattern"]["cmd_sectors"][op] = compute_access_pattern(
                        sectors, bytes_list
                    )
        del setup_df

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
        description="Generate stats from NVMe layer detailed CSV output"
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
