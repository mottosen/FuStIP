#!/usr/bin/env python3
"""Generate sysstat visualization dashboard from stats JSON."""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from visualization.shared import build_dashboard, _color_for, DEFAULT_COLOR_CYCLE


def _plot_timeseries(ax, points, ylabel, title, label=None):
    """Plot a simple time-series from points list."""
    times = list(range(len(points)))
    values = [p["value"] for p in points]
    ax.plot(times, values, linewidth=0.8, label=label)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if label:
        ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def _load_cpu_per_core(cpu_csv_path, commands):
    """Load cpu.csv and build per-command, per-core time-series.

    Returns dict: command -> {core_id -> [cpu_pct_per_second]}
    """
    # Read all rows, remapping unknown commands to "other"
    cmd_set = set(commands)
    # Group: (command, time, cpu_core) -> sum of cpu_pct
    grouped = defaultdict(float)
    all_times = set()
    all_cores = defaultdict(set)  # command -> set of core ids

    with open(cpu_csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cmd = row["command"]
            if cmd not in cmd_set:
                cmd = "other"
            if cmd not in cmd_set:
                continue
            time_key = row["time"]
            core = int(row["cpu"])
            cpu_pct = float(row["cpu_pct"])
            grouped[(cmd, time_key, core)] += cpu_pct
            all_times.add(time_key)
            all_cores[cmd].add(core)

    sorted_times = sorted(all_times)
    time_to_sec = {t: i for i, t in enumerate(sorted_times)}

    # Build per-command, per-core arrays
    result = {}
    for cmd in commands:
        cores = sorted(all_cores.get(cmd, []))
        if not cores:
            result[cmd] = None
            continue
        core_data = {}
        for core in cores:
            values = [0.0] * len(sorted_times)
            for t in sorted_times:
                values[time_to_sec[t]] = grouped.get((cmd, t, core), 0.0)
            core_data[core] = values
        result[cmd] = core_data

    return result


def main():
    results_dir = Path(sys.argv[1])
    json_path = results_dir / "sysstat" / "sysstat-stats.json"
    if not json_path.exists():
        print(f"No sysstat stats found: {json_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {json_path.name}...")
    with open(json_path) as f:
        data = json.load(f)

    # Collect all command names across sections
    commands = set()
    for section in ("cpu", "mem", "dev"):
        if section in data:
            commands.update(data[section]["per_command"].keys())
    commands = sorted(commands)

    if not commands:
        print("No per-command data found in sysstat stats", file=sys.stderr)
        sys.exit(1)

    # Try to load per-core CPU data from raw csv
    cpu_csv_path = results_dir / "sysstat" / "cpu.csv"
    cpu_per_core = None
    if cpu_csv_path.exists():
        cpu_per_core = _load_cpu_per_core(cpu_csv_path, commands)

    rows = []
    for cmd in commands:
        mem_points = None
        dev_rd_points = None
        dev_wr_points = None

        if "mem" in data and cmd in data["mem"]["per_command"]:
            mem_points = data["mem"]["per_command"][cmd]["mem_pct"]["points"]
        if "dev" in data and cmd in data["dev"]["per_command"]:
            dev_rd_points = data["dev"]["per_command"][cmd]["kb_rd_s"]["points"]
            dev_wr_points = data["dev"]["per_command"][cmd]["kb_wr_s"]["points"]

        # CPU plot: per-core from csv if available, else aggregated from json
        core_data = cpu_per_core.get(cmd) if cpu_per_core else None
        cpu_points_json = None
        if core_data is None and "cpu" in data and cmd in data["cpu"]["per_command"]:
            cpu_points_json = data["cpu"]["per_command"][cmd]["cpu_pct"]["points"]

        def make_cpu_plot(ax, cd=core_data, pts=cpu_points_json):
            if cd:
                cores = sorted(cd.keys())
                for idx, core in enumerate(cores):
                    color = DEFAULT_COLOR_CYCLE[idx % len(DEFAULT_COLOR_CYCLE)]
                    ax.plot(range(len(cd[core])), cd[core],
                            label=f"core {core}", color=color, linewidth=0.8)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("CPU demand %")
                ax.set_title("CPU Demand (per core)")
                ncol = max(1, (len(cores) + 7) // 8)
                ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0), ncol=ncol)
            elif pts:
                _plot_timeseries(ax, pts, "CPU %", "CPU %")
            else:
                ax.set_title("CPU %")
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)

        def make_mem_plot(ax, pts=mem_points):
            if pts:
                _plot_timeseries(ax, pts, "Memory %", "Memory Usage")
            else:
                ax.set_title("Memory Usage")
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)

        def make_dev_plot(ax, rd=dev_rd_points, wr=dev_wr_points):
            if rd or wr:
                if rd:
                    times = list(range(len(rd)))
                    ax.plot(times, [p["value"] for p in rd],
                            label="read", color="#1f77b4", linewidth=0.8)
                if wr:
                    times = list(range(len(wr)))
                    ax.plot(times, [p["value"] for p in wr],
                            label="write", color="#ff7f0e", linewidth=0.8)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("KB/s")
                ax.set_title("Disk IO")
                ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))
            else:
                ax.set_title("Disk IO")
                ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)

        rows.append({
            "label": cmd,
            "plots": [make_cpu_plot, make_mem_plot, make_dev_plot],
        })

    output = results_dir / "visualizations" / "sysstat-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["CPU %", "Memory %", "Disk IO (KB/s)"],
        title="Sysstat Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
