#!/usr/bin/env python3
"""Generate stats JSON from NVMe layer detailed CSV output.

Reads detailed.csv from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses two CSV passes to limit peak memory on large files:
  Pass 1: counters, distributions, tseries (no sector/rq/comm columns)
  Pass 2: access pattern (no latency_ns/rq/comm/inflight columns)

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_access_pattern,
                                     derive_throughput,
                                     series_stats,
                                     tseries_stats)

LAYER_PREFIX = "nvme"


def generate_stats(csv_path):
    """Parse an NVMe layer detailed CSV and compute stats."""

    # Check header for optional columns
    with open(csv_path) as f:
        header = f.readline().strip().split(",")
    has_inflight = "inflight" in header
    has_sector = "sector" in header

    # --- Pass 1: Counters, distributions, tseries ---
    main_cols = ["event", "op", "timestamp_ns", "bytes", "latency_ns"]
    if has_inflight:
        main_cols.append("inflight")

    df = pd.read_csv(csv_path, usecols=main_cols,
                     dtype={"event": "category", "op": "category"})

    complete = df[df["event"] == "complete"]
    setup = df[df["event"] == "setup"]
    all_events = df[df["event"].isin(["setup", "complete"])]

    # Duration
    if len(all_events) > 1:
        duration_ns = int(all_events["timestamp_ns"].max() - all_events["timestamp_ns"].min())
        duration_s = duration_ns / 1e9
    else:
        duration_s = 0

    # Build counters
    counters = {}

    counters["cmd_completed"] = complete.groupby("op").size().to_dict()

    byte_sums = complete.groupby("op")["bytes"].sum().to_dict()
    counters["cmd_total_bytes"] = {k: int(v) for k, v in byte_sums.items()}

    if len(setup) > 0:
        counters["cmd_setup"] = setup.groupby("op").size().to_dict()

    result = {
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "distributions": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "cmd_completed", "cmd_total_bytes")
    result["derived"].update(throughput)

    # Distributions (stats only, no histogram bucket data)
    cmd_lat = complete[complete["latency_ns"].notna()]
    if len(cmd_lat) > 0:
        result["distributions"]["cmd_latencies"] = {}
        for op, group in cmd_lat.groupby("op"):
            result["distributions"]["cmd_latencies"][op] = series_stats(
                group["latency_ns"].tolist()
            )

    if len(complete) > 0:
        result["distributions"]["cmd_sizes"] = {}
        for op, group in complete.groupby("op"):
            result["distributions"]["cmd_sizes"][op] = series_stats(
                group["bytes"].tolist()
            )

    # Inflight time-series
    if len(all_events) > 1:
        t_min = all_events["timestamp_ns"].min()
        window_ns = 1_000_000_000

        result["tseries"]["cmd_inflight"] = {}

        if has_inflight and "inflight" in df.columns:
            # Use pre-computed in-kernel inflight column
            for op in all_events["op"].unique():
                op_df = all_events[all_events["op"] == op].sort_values("timestamp_ns")
                secs = ((op_df["timestamp_ns"].values - t_min) / window_ns).astype(int)
                op_df = op_df.assign(sec=secs)
                sampled = op_df.groupby("sec")["inflight"].last()
                points = []
                for s, v in sampled.items():
                    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
                    points.append({"time": f"{h:02d}:{m:02d}:{ss:02d}",
                                   "value": max(0, int(v))})
                if points:
                    result["tseries"]["cmd_inflight"][op] = tseries_stats(points)
        else:
            # Fallback: compute from enter/exit event counts
            t_max = all_events["timestamp_ns"].max()
            for op in setup["op"].unique():
                enter_ts = setup[setup["op"] == op]["timestamp_ns"].values
                exit_ts = complete[complete["op"] == op]["timestamp_ns"].values
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
                    result["tseries"]["cmd_inflight"][op] = tseries_stats(points)

    del df  # Free pass 1 DataFrame

    # --- Pass 2: Access pattern ---
    if has_sector:
        ap_cols = ["event", "op", "timestamp_ns", "sector", "bytes"]
        df = pd.read_csv(csv_path, usecols=ap_cols,
                         dtype={"event": "category", "op": "category"})

        setup = df[df["event"] == "setup"]
        if len(setup) > 0:
            result["access_pattern"] = {"cmd_sectors": {}}
            for op, group in setup.sort_values("timestamp_ns").groupby("op"):
                sectors = group["sector"].dropna().astype(int).tolist()
                bytes_list = group.loc[group["sector"].notna(), "bytes"].astype(int).tolist()
                if len(sectors) >= 2:
                    result["access_pattern"]["cmd_sectors"][op] = compute_access_pattern(
                        sectors, bytes_list
                    )

        del df  # Free pass 2 DataFrame

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

        for event_type in ("setup", "complete"):
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
