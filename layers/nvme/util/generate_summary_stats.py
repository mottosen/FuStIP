#!/usr/bin/env python3
"""Generate stats JSON from NVMe layer bpftrace output.

Reads trace.out from the results directory,
computes aggregate statistics, and writes JSON files.

Usage:
    python ./util/generate_stats.py <results_dir>
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_duration_from_tseries,
                                     derive_throughput,
                                     histogram_stats_only,
                                     parse_counters, parse_histograms,
                                     parse_tseries, tseries_stats)

LAYER_PREFIX = "nvme"

COUNTER_MAPS = [
    "cmd_setup", "cmd_completed", "cmd_untracked", "cmd_total_bytes",
]
HISTOGRAM_MAPS = ["cmd_latencies", "cmd_sizes"]
TSERIES_MAPS = ["cmd_inflight"]


def generate_stats(input_path):
    """Parse an NVMe layer output file and compute stats."""
    counters = parse_counters(input_path)
    histograms = parse_histograms(input_path)
    tseries = parse_tseries(input_path)

    duration_s = compute_duration_from_tseries(tseries)

    result = {
        "counters": {},
        "derived": {"duration_s": duration_s},
        "distributions": {},
        "tseries": {},
    }

    # Counters
    for m in COUNTER_MAPS:
        if m in counters:
            result["counters"][m] = counters[m]

    # Derived throughput
    throughput = derive_throughput(
        counters, duration_s, "cmd_completed", "cmd_total_bytes"
    )
    result["derived"].update(throughput)

    # Distribution stats (aggregate only, no histogram bucket data)
    for m in HISTOGRAM_MAPS:
        if m in histograms:
            result["distributions"][m] = {}
            for key, buckets in histograms[m].items():
                result["distributions"][m][key] = histogram_stats_only(buckets)

    # Time-series stats
    for m in TSERIES_MAPS:
        if m in tseries:
            result["tseries"][m] = {}
            for key, points in tseries[m].items():
                result["tseries"][m][key] = tseries_stats(points)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from NVMe layer bpftrace output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    args = parser.parse_args()

    bpf_dir = args.results_dir / "nvme"
    if not bpf_dir.is_dir():
        print(f"Error: {bpf_dir} not found", file=sys.stderr)
        sys.exit(1)

    input_file = bpf_dir / "trace.out"
    if not input_file.exists():
        print(f"No NVMe layer output found: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {input_file.name}...")
    stats = generate_stats(input_file)

    output_file = bpf_dir / "trace-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
