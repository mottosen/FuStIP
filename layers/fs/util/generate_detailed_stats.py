#!/usr/bin/env python3
"""Generate stats JSON from filesystem layer detailed CSV output.

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

LAYER_PREFIX = "fs"

# IO syscalls that have meaningful bytes/latency for histograms
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}


def generate_stats(csv_path):
    """Parse an FS layer detailed CSV and compute stats."""
    df = pd.read_csv(csv_path)

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
        "source": csv_path.name,
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "histograms": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "sc_completed", "sc_total_bytes")
    result["derived"].update(throughput)

    # Histograms from IO exit events
    lat_exits = io_exits[io_exits["latency_ns"].notna() & (io_exits["latency_ns"] > 0)]
    if len(lat_exits) > 0:
        result["histograms"]["sc_latencies"] = {}
        for sc, group in lat_exits.groupby("syscall"):
            buckets = raw_values_to_hist_buckets(group["latency_ns"].tolist())
            result["histograms"]["sc_latencies"][sc] = histogram_stats(buckets)

    if len(positive_exits) > 0:
        result["histograms"]["sc_sizes"] = {}
        for sc, group in positive_exits.groupby("syscall"):
            buckets = raw_values_to_hist_buckets(group["bytes"].tolist())
            result["histograms"]["sc_sizes"][sc] = histogram_stats(buckets)

    # Inflight time-series (IO syscalls only)
    if len(io_enters) > 0 and len(io_exits) > 0:
        t_min = df["timestamp_ns"].min()
        t_max = df["timestamp_ns"].max()
        window_ns = 1_000_000_000

        result["tseries"]["sc_inflight"] = {}
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

    return result


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

    output_file = layer_dir / "detailed-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
