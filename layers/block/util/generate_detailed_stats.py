#!/usr/bin/env python3
"""Generate stats JSON from block layer detailed CSV output.

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
from stats_generation.shared import (compute_access_pattern,
                                     derive_throughput,
                                     histogram_with_buckets,
                                     histogram_with_data,
                                     raw_values_to_hist,
                                     raw_values_to_hist_buckets,
                                     tseries_with_points)

LAYER_PREFIX = "block"


def generate_stats(csv_path):
    """Parse a block layer detailed CSV and compute stats."""
    df = pd.read_csv(csv_path)

    complete = df[df["event"] == "complete"]
    all_events = df[df["event"].isin(["insert", "issue", "complete"])]

    # Duration from first to last event
    if len(all_events) > 1:
        duration_ns = int(all_events["timestamp_ns"].max() - all_events["timestamp_ns"].min())
        duration_s = duration_ns / 1e9
    else:
        duration_s = 0

    # Build counters from complete events
    counters = {}

    completed_counts = complete.groupby("op").size().to_dict()
    counters["rq_completed"] = completed_counts

    byte_sums = complete.groupby("op")["bytes"].sum().to_dict()
    counters["rq_total_bytes"] = {k: int(v) for k, v in byte_sums.items()}

    # Issue counts (from issue events)
    issue_events = df[df["event"] == "issue"]
    if len(issue_events) > 0:
        counters["rq_issued"] = issue_events.groupby("op").size().to_dict()

    # Queue counts (from insert events)
    insert_events = df[df["event"] == "insert"]
    if len(insert_events) > 0:
        counters["rq_queued"] = insert_events.groupby("op").size().to_dict()

    result = {
        "source": csv_path.name,
        "counters": counters,
        "derived": {"duration_s": round(duration_s, 2)},
        "histograms": {},
        "tseries": {},
    }

    # Derived throughput
    throughput = derive_throughput(counters, duration_s, "rq_completed", "rq_total_bytes")
    result["derived"].update(throughput)

    # Histograms from raw values
    # Driver latencies (from complete events)
    driver_lat = complete[complete["latency_ns"].notna()]
    if len(driver_lat) > 0:
        result["histograms"]["driver_latencies"] = {}
        for op, group in driver_lat.groupby("op"):
            result["histograms"]["driver_latencies"][op] = histogram_with_buckets(
                raw_values_to_hist_buckets(group["latency_ns"].tolist())
            )

    # Queue latencies (from issue events with latency)
    queue_lat = issue_events[issue_events["latency_ns"].notna()]
    if len(queue_lat) > 0:
        result["histograms"]["queue_latencies"] = {}
        for op, group in queue_lat.groupby("op"):
            result["histograms"]["queue_latencies"][op] = histogram_with_buckets(
                raw_values_to_hist_buckets(group["latency_ns"].tolist())
            )

    # IO sizes
    if len(complete) > 0:
        result["histograms"]["rq_sizes"] = {}
        for op, group in complete.groupby("op"):
            result["histograms"]["rq_sizes"][op] = histogram_with_data(
                raw_values_to_hist(group["bytes"].tolist())
            )

    # Inflight time-series (computed from insert/complete event counts in 1s windows)
    if len(all_events) > 1:
        t_min = all_events["timestamp_ns"].min()
        t_max = all_events["timestamp_ns"].max()
        window_ns = 1_000_000_000  # 1 second

        for stage, enter_evt, exit_evt in [("d_inflight", "issue", "complete"),
                                           ("q_inflight", "insert", "issue")]:
            stage_enter = df[df["event"] == enter_evt]
            stage_exit = df[df["event"] == exit_evt]
            if len(stage_enter) == 0:
                continue

            result["tseries"][stage] = {}
            for op in stage_enter["op"].unique():
                enter_ts = stage_enter[stage_enter["op"] == op]["timestamp_ns"].values
                exit_ts = stage_exit[stage_exit["op"] == op]["timestamp_ns"].values
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
                    result["tseries"][stage][op] = tseries_with_points(points)

    # Access pattern (sequential/random from sector addresses)
    if len(complete) > 0 and "sector" in complete.columns:
        result["access_pattern"] = {"rq_sectors": {}}
        for op, group in complete.sort_values("timestamp_ns").groupby("op"):
            sectors = group["sector"].dropna().astype(int).tolist()
            bytes_list = group.loc[group["sector"].notna(), "bytes"].astype(int).tolist()
            if len(sectors) >= 2:
                result["access_pattern"]["rq_sectors"][op] = compute_access_pattern(
                    sectors, bytes_list
                )

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from block layer detailed CSV output"
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
