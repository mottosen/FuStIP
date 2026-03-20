#!/usr/bin/env python3
"""Generate stats JSON from filesystem layer bpftrace output.

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

LAYER_PREFIX = "fs"

COUNTER_MAPS = [
    "sc_entered", "sc_completed", "sc_untracked", "sc_total_bytes",
    "sc_count",
]
HISTOGRAM_MAPS = ["sc_latencies", "sc_sizes"]
TSERIES_MAPS = ["sc_inflight"]


def generate_stats(input_path):
    """Parse an fs layer output file and compute stats."""
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
    throughput = derive_throughput(counters, duration_s, "sc_completed", "sc_total_bytes")
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
        description="Generate stats from fs layer bpftrace output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    args = parser.parse_args()

    fs_dir = args.results_dir / "fs"
    if not fs_dir.is_dir():
        print(f"Error: {fs_dir} not found", file=sys.stderr)
        sys.exit(1)

    input_file = fs_dir / "trace.out"
    if not input_file.exists():
        print(f"No fs layer output found: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {input_file.name}...")
    stats = generate_stats(input_file)

    output_file = fs_dir / "trace-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
