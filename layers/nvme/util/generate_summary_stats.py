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
from stats_generation.shared import (compute_active_duration,
                                     derive_throughput,
                                     histogram_buckets_only,
                                     parse_counters, parse_histograms,
                                     parse_tseries, tseries_stats)

LAYER_PREFIX = "nvme"

COUNTER_MAPS = [
    "cmd_setup", "cmd_completed", "cmd_untracked", "cmd_total_bytes",
]
HISTOGRAM_MAPS = ["cmd_latencies", "cmd_sizes", "cmd_lba_dist"]
TSERIES_MAPS = ["cmd_inflight"]

# Distribution map whose bpftrace buckets are device-space percentages (0..100),
# rescaled back to absolute logical-block (LBA) offsets here so summary LBA data
# matches the units detailed mode reports. See trace.bt's tracepoint:nvme:nvme_setup_cmd.
LBA_DIST_MAP = "cmd_lba_dist"


def _rescale_lba_dist(result, input_path):
    """Convert cmd_lba_dist buckets from device-percent (0..100) to logical blocks.

    bpftrace bins SLBA (in logical-block units) as a percentage of device capacity
    (so the lhist bounds stay literal constants); this maps each [lo%, hi%) bucket
    back to absolute LBA offsets using the device's LBA count (nsze_lbas) from the
    sibling device-info.json, and records that count so consumers can reconstruct the
    full LBA axis. No-op if the map is absent or the capacity is unavailable (buckets
    are then left as percentages).
    """
    dist = result.get("distributions", {}).get(LBA_DIST_MAP)
    if not dist:
        return

    info_path = Path(input_path).parent / "device-info.json"
    try:
        with open(info_path) as f:
            info = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    # Summary mode is single-device (the CLI rejects a multi-device -d in summary
    # mode), so device-info.json holds the one filtered device; the Makefile
    # normalizes SLBA by it. Use the first/only entry to match.
    first = next((v for v in info.values() if isinstance(v, dict)), {})
    dev_lbas = int(first.get("nsze_lbas", 0) or 0)
    if dev_lbas <= 0:
        return

    for entry in dist.values():
        for b in entry.get("buckets", []):
            b["lo"] = int(b["lo"] * dev_lbas // 100)
            b["hi"] = int(b["hi"] * dev_lbas // 100)
        entry["device_lbas"] = dev_lbas


def generate_stats(input_path):
    """Parse an NVMe layer output file and compute stats."""
    counters = parse_counters(input_path)
    histograms = parse_histograms(input_path)
    tseries = parse_tseries(input_path)

    duration_s = compute_active_duration(counters, tseries)

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

    # Distributions: raw bpftrace log2 buckets + exact count only. Estimated
    # aggregates (mean/percentiles/min/max) are omitted in summary mode because
    # they are not reliably derivable from power-of-2 buckets; detailed mode
    # computes those accurately from raw per-event values.
    for m in HISTOGRAM_MAPS:
        if m in histograms:
            result["distributions"][m] = {}
            for key, buckets in histograms[m].items():
                result["distributions"][m][key] = histogram_buckets_only(buckets)

    # LBA distribution arrives as device-space percentages (bpftrace normalizes
    # SLBA so the lhist bounds stay literal); rescale to absolute logical blocks.
    _rescale_lba_dist(result, input_path)

    # Time-series stats. cmd_inflight is keyed by "disk, op" in bpftrace; split it
    # and nest under per-disk to match detailed mode's per_disk[disk][op] layout.
    for m in TSERIES_MAPS:
        if m not in tseries:
            continue
        result["tseries"][m] = {}
        for key, points in tseries[m].items():
            disk, sep, op = key.partition(", ")
            if not sep or not disk:
                # No disk dimension (older trace) or pre-first-IO empty-disk
                # sample — skip the latter, keep the former flat.
                if not disk:
                    continue
                result["tseries"][m][key] = tseries_stats(points)
                continue
            result["tseries"][m].setdefault(disk, {})[op] = tseries_stats(points)

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
