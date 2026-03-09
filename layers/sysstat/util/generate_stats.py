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
from stats_generation.shared import tseries_with_points


def parse_csv(path, processes=None):
    """Read a CSV file and return list of row dicts.

    If processes is provided, remap command names not in the list to "other".
    """
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if processes is not None:
                if row["command"] not in processes:
                    row["command"] = "other"
            rows.append(row)
    return rows


def compute_duration(rows, time_field="time"):
    """Compute duration in seconds from unique timestamps."""
    times = sorted(set(row[time_field] for row in rows))
    if len(times) < 2:
        return 0
    return len(times) - 1


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
            entry = tseries_with_points(points)
            entry["stats"]["max_area_under_curve"] = max_auc
            cmd_result[metric] = entry
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
            entry = tseries_with_points(points)
            if metric == "mem_pct":
                entry["stats"]["max_area_under_curve"] = max_auc
            cmd_result[metric] = entry
        result[cmd] = cmd_result

    return result


def dev_stats(rows):
    """Compute per-command device IO stats as time-series with AUC."""
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
            cmd_result[metric] = tseries_with_points(points)
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
    args = parser.parse_args()

    processes = args.process
    sysstat_dir = args.results_dir / "sysstat"
    if not sysstat_dir.is_dir():
        print(f"Error: {sysstat_dir} not found", file=sys.stderr)
        sys.exit(1)

    result = {"source": []}

    # Read all CSVs first to compute global duration
    csv_data = {}
    for name, path in [("cpu", sysstat_dir / "cpu.csv"),
                       ("mem", sysstat_dir / "mem.csv"),
                       ("dev", sysstat_dir / "dev.csv")]:
        if path.exists():
            result["source"].append(f"{name}.csv")
            csv_data[name] = parse_csv(path, processes)
            print(f"  Processed {path.name}: {len(csv_data[name])} rows")

    if not result["source"]:
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

    output_file = sysstat_dir / "sysstat-stats.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
