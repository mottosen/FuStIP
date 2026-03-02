#!/usr/bin/env python3
"""Generate stats JSON from NVMe layer detailed CSV output.

Reads detailed.csv from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (derive_throughput, histogram_stats,
                                     raw_values_to_hist_buckets,
                                     tseries_stats)

LAYER_PREFIX = "nvme"


def generate_stats(csv_path):
    """Parse an NVMe layer detailed CSV and compute stats."""
    df = pd.read_csv(csv_path)

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
        "source": csv_path.name,
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "histograms": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "cmd_completed", "cmd_total_bytes")
    result["derived"].update(throughput)

    # Histograms
    cmd_lat = complete[complete["latency_ns"].notna()]
    if len(cmd_lat) > 0:
        result["histograms"]["cmd_latencies"] = {}
        for op, group in cmd_lat.groupby("op"):
            buckets = raw_values_to_hist_buckets(group["latency_ns"].tolist())
            result["histograms"]["cmd_latencies"][op] = histogram_stats(buckets)

    if len(complete) > 0:
        result["histograms"]["cmd_sizes"] = {}
        for op, group in complete.groupby("op"):
            buckets = raw_values_to_hist_buckets(group["bytes"].tolist())
            result["histograms"]["cmd_sizes"][op] = histogram_stats(buckets)

    # Inflight time-series
    if len(all_events) > 1:
        t_min = all_events["timestamp_ns"].min()
        t_max = all_events["timestamp_ns"].max()
        window_ns = 1_000_000_000

        result["tseries"]["cmd_inflight"] = {}
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

    return result


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

    output_file = layer_dir / "detailed-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
