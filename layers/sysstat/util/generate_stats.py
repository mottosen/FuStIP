#!/usr/bin/env python3
"""Generate stats JSON from sysstat (pidstat) CSV output.

Reads cpu.csv, mem.csv, dev.csv from the results directory,
groups by command, computes per-metric aggregate statistics,
and writes sysstat-stats.json.

Usage:
    python ./util/generate_stats.py <results_dir>
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import tseries_stats, _time_to_secs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from container_map import build_label_maps, get_label_order, remap_rows


def parse_csv(path, label_maps=None, processes=None):
    """Read a CSV file and return list of row dicts.

    If label_maps is provided, remap using tgid-first then comm map (unmapped → "other").
    If processes is provided (legacy), remap command names not in the list to "other".
    """
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if processes is not None:
                if row["command"] not in processes:
                    row["command"] = "other"
            rows.append(row)
    remap_rows(rows, label_maps)
    return rows


def compute_duration(rows, time_field="time"):
    """Compute duration in seconds from the wall-clock span of unique timestamps.

    Uses the actual time difference between first and last sample, so gaps in
    pidstat output don't cause undercounting, and the duration correctly covers
    the full collection window (container startup through shutdown).
    """
    times = sorted(set(row[time_field] for row in rows))
    if len(times) < 2:
        return 0
    return _time_to_secs(times[-1]) - _time_to_secs(times[0])


def cpu_stats(rows, duration_s):
    """Compute per-command CPU stats as time-series with AUC.

    CPU rows are per-thread (tid). For each timestamp, sum metrics across
    all threads of the same command, then produce time-series points + stats.
    """
    metrics = ["usr", "system", "guest", "wait", "cpu_pct"]
    max_auc = round(100 * duration_s, 2)

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            stats = tseries_stats(points)
            stats["max_area_under_curve"] = max_auc
            cmd_result[metric] = stats
        result[cmd] = cmd_result

    return result


def mem_stats(rows, duration_s):
    """Compute per-command memory stats as time-series with AUC."""
    metrics = ["minflt_s", "majflt_s", "vsz_kb", "rss_kb", "mem_pct"]
    max_auc = round(100 * duration_s, 2)

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            stats = tseries_stats(points)
            if metric == "mem_pct":
                stats["max_area_under_curve"] = max_auc
            cmd_result[metric] = stats
        result[cmd] = cmd_result

    return result


def _drop_first_tgid_appearances(rows):
    """Drop the first row per tgid from dev rows before aggregation.

    pidstat computes rates as (cumulative_now - cumulative_prev) / interval.
    For a tgid's first appearance, prev=0, so the reported rate equals the
    process's total accumulated I/O since start divided by one second.  For
    long-running processes that pidstat encounters only at the end (e.g. a fio
    master process, or a parent whose children's I/O rolls up on exit), this
    produces a massive single-sample spike that corrupts mean and AUC.

    Dropping the first row per tgid eliminates these artifacts without any
    hardware-specific threshold.  The cost is one data point per process; for
    processes that genuinely just started, the first sample would have been
    valid but losing it is negligible over a full collection window.
    """
    seen = set()
    result = []
    for row in sorted(rows, key=lambda r: _time_to_secs(r["time"])):
        if row["tgid"] not in seen:
            seen.add(row["tgid"])
            continue
        result.append(row)
    return result


def dev_stats(rows):
    """Compute per-command device IO stats as time-series with AUC."""
    rows = _drop_first_tgid_appearances(rows)
    metrics = ["kb_rd_s", "kb_wr_s", "kb_ccwr_s", "iodelay"]

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            cmd_result[metric] = tseries_stats(points)
        result[cmd] = cmd_result

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from sysstat (pidstat) CSV output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    parser.add_argument(
        "--process", "-p",
        type=str.split,
        default=None,
        help="Space-separated list of process names to track individually. "
             "All others are grouped as 'other'.",
    )
    parser.add_argument(
        "--container", "-c",
        type=str.split,
        default=None,
        help="Space-separated container names for container-based grouping.",
    )
    args = parser.parse_args()

    processes = args.process
    containers = args.container
    sysstat_dir = args.results_dir / "sysstat"
    if not sysstat_dir.is_dir():
        print(f"Error: {sysstat_dir} not found", file=sys.stderr)
        sys.exit(1)

    label_maps = build_label_maps(sysstat_dir, processes)

    result = {}

    # Read all CSVs first to compute global duration
    csv_data = {}
    for name, path in [("cpu", sysstat_dir / "cpu.csv"),
                       ("mem", sysstat_dir / "mem.csv"),
                       ("dev", sysstat_dir / "dev.csv")]:
        if path.exists():
            csv_data[name] = parse_csv(path, label_maps=label_maps, processes=processes if label_maps is None else None)
            print(f"  Processed {path.name}: {len(csv_data[name])} rows")

    if not csv_data:
        print(f"No sysstat CSV files found in {sysstat_dir}")
        return

    all_rows = [row for rows in csv_data.values() for row in rows]
    duration_s = compute_duration(all_rows)
    result["duration_s"] = duration_s

    if "cpu" in csv_data:
        result["cpu"] = {"per_command": cpu_stats(csv_data["cpu"], duration_s)}
    if "mem" in csv_data:
        result["mem"] = {"per_command": mem_stats(csv_data["mem"], duration_s)}
    if "dev" in csv_data:
        result["dev"] = {"per_command": dev_stats(csv_data["dev"])}

    result["label_order"] = get_label_order(containers, processes)

    output_file = sysstat_dir / "sysstat-stats.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
