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
from stats_generation.shared import series_stats


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


def cpu_stats(rows):
    """Compute per-command CPU stats.

    CPU rows are per-thread (tid). For each timestamp, sum cpu_pct across
    all threads of the same TGID/command, then compute stats across timestamps.
    """
    # Group: command -> time -> list of cpu_pct values (one per thread)
    by_cmd_time = defaultdict(lambda: defaultdict(list))
    for row in rows:
        cmd = row["command"]
        time = row["time"]
        by_cmd_time[cmd][time].append(float(row["cpu_pct"]))

    result = {}
    metrics = ["usr", "system", "guest", "wait", "cpu_pct"]

    for cmd in by_cmd_time:
        # For cpu_pct: sum across threads per timestamp, then stats
        time_sums = {}
        for time, vals in by_cmd_time[cmd].items():
            time_sums[time] = sum(vals)

        summed_values = list(time_sums.values())
        cmd_result = {"cpu_pct": series_stats(summed_values)}

        # For other metrics: also sum across threads per timestamp
        for metric in ["usr", "system", "guest", "wait"]:
            metric_by_time = defaultdict(float)
            for row in rows:
                if row["command"] == cmd:
                    metric_by_time[row["time"]] += float(row[metric])
            vals = list(metric_by_time.values())
            cmd_result[metric] = series_stats(vals)

        result[cmd] = cmd_result

    return result


def mem_stats(rows):
    """Compute per-command memory stats."""
    by_cmd = defaultdict(list)
    for row in rows:
        by_cmd[row["command"]].append(row)

    result = {}
    for cmd, cmd_rows in by_cmd.items():
        cmd_result = {}
        for metric in ["minflt_s", "majflt_s", "vsz_kb", "rss_kb", "mem_pct"]:
            values = [float(r[metric]) for r in cmd_rows]
            cmd_result[metric] = series_stats(values)
        result[cmd] = cmd_result

    return result


def dev_stats(rows):
    """Compute per-command device IO stats."""
    by_cmd = defaultdict(list)
    for row in rows:
        by_cmd[row["command"]].append(row)

    result = {}
    for cmd, cmd_rows in by_cmd.items():
        cmd_result = {}
        for metric in ["kb_rd_s", "kb_wr_s", "kb_ccwr_s", "iodelay"]:
            values = [float(r[metric]) for r in cmd_rows]
            cmd_result[metric] = series_stats(values)
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

    result = {"source": [], "duration_s": 0}

    all_rows = []

    # CPU
    cpu_path = sysstat_dir / "cpu.csv"
    if cpu_path.exists():
        result["source"].append("cpu.csv")
        rows = parse_csv(cpu_path, processes)
        all_rows.extend(rows)
        result["cpu"] = {"per_command": cpu_stats(rows)}
        print(f"  Processed {cpu_path.name}: {len(rows)} rows")

    # Memory
    mem_path = sysstat_dir / "mem.csv"
    if mem_path.exists():
        result["source"].append("mem.csv")
        rows = parse_csv(mem_path, processes)
        all_rows.extend(rows)
        result["mem"] = {"per_command": mem_stats(rows)}
        print(f"  Processed {mem_path.name}: {len(rows)} rows")

    # Device IO
    dev_path = sysstat_dir / "dev.csv"
    if dev_path.exists():
        result["source"].append("dev.csv")
        rows = parse_csv(dev_path, processes)
        all_rows.extend(rows)
        result["dev"] = {"per_command": dev_stats(rows)}
        print(f"  Processed {dev_path.name}: {len(rows)} rows")

    if not result["source"]:
        print(f"No sysstat CSV files found in {sysstat_dir}")
        return

    # Duration from all timestamps across all CSVs
    result["duration_s"] = compute_duration(all_rows)

    output_file = sysstat_dir / "sysstat-stats.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
