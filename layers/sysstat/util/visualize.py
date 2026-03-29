#!/usr/bin/env python3
"""Generate sysstat visualization dashboard from raw pidstat CSVs.

Reads cpu.csv, mem.csv, dev.csv from the results directory.
When --process is given, shows those commands individually + 'other'.
Otherwise, shows top N commands by resource usage + 'other'.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))

import matplotlib
matplotlib.use("Agg")

from visualization.shared import build_dashboard, _color_for, DEFAULT_COLOR_CYCLE

MAX_ROWS = 5


def _read_csv(path):
    """Read a CSV file and return list of row dicts."""
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _unique_times(rows):
    """Sorted unique time values from rows."""
    return sorted(set(row["time"] for row in rows))


def _group_timeseries(rows, metric, time_index):
    """Group rows by command, summing metric per time step.

    Returns dict: command -> [value_per_timestep].
    """
    # command -> time -> summed value
    agg = defaultdict(lambda: defaultdict(float))
    for row in rows:
        agg[row["command"]][row["time"]] += float(row[metric])

    result = {}
    for cmd, time_vals in agg.items():
        result[cmd] = [round(time_vals.get(t, 0.0), 2) for t in time_index]
    return result


def _remap_commands(rows, process_filter):
    """Remap commands not in process_filter to 'other'."""
    for row in rows:
        if row["command"] not in process_filter:
            row["command"] = "other"


def _score_commands(cpu_rows, mem_rows, dev_rows):
    """Score each command by combined resource usage (mean values)."""
    scores = defaultdict(float)
    counts = defaultdict(int)
    for row in cpu_rows:
        scores[row["command"]] += float(row["cpu_pct"])
        counts[row["command"]] += 1
    for row in dev_rows:
        scores[row["command"]] += float(row["kb_rd_s"]) / 1024
        scores[row["command"]] += float(row["kb_wr_s"]) / 1024
        counts[row["command"]] += 1

    return {cmd: scores[cmd] / max(counts[cmd], 1) for cmd in scores}


def _select_and_remap(cpu_rows, mem_rows, dev_rows, process_filter):
    """Select commands to display and remap the rest to 'other'.

    If process_filter is set, use those. Otherwise, pick top N by usage.
    """
    if process_filter:
        keep = process_filter
    else:
        all_cmds = set()
        for rows in (cpu_rows, mem_rows, dev_rows):
            for row in rows:
                all_cmds.add(row["command"])
        scores = _score_commands(cpu_rows, mem_rows, dev_rows)
        ranked = sorted(all_cmds, key=lambda c: scores.get(c, 0), reverse=True)
        keep = set(ranked[:MAX_ROWS - 1])

    for rows in (cpu_rows, mem_rows, dev_rows):
        _remap_commands(rows, keep)


def _plot_timeseries(ax, times, values, ylabel, title, label=None):
    """Plot a simple time-series."""
    ax.plot(range(len(values)), values, linewidth=0.8, label=label)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if label:
        ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def main():
    parser = argparse.ArgumentParser(description="Sysstat visualization from raw CSVs")
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("--process", "-p", type=str.split, default=None,
                        help="Process names to show individually (rest grouped as 'other')")
    args = parser.parse_args()

    sysstat_dir = args.results_dir / "sysstat"
    process_filter = set(args.process) if args.process else None

    # Read raw CSVs
    cpu_rows = _read_csv(sysstat_dir / "cpu.csv") if (sysstat_dir / "cpu.csv").exists() else []
    mem_rows = _read_csv(sysstat_dir / "mem.csv") if (sysstat_dir / "mem.csv").exists() else []
    dev_rows = _read_csv(sysstat_dir / "dev.csv") if (sysstat_dir / "dev.csv").exists() else []

    if not cpu_rows and not mem_rows and not dev_rows:
        print("No sysstat CSV files found", file=sys.stderr)
        sys.exit(1)

    print("Reading sysstat CSVs...")

    # Select top commands or use filter, remap rest to "other"
    _select_and_remap(cpu_rows, mem_rows, dev_rows, process_filter)

    # Build time indices
    cpu_times = _unique_times(cpu_rows)
    mem_times = _unique_times(mem_rows)
    dev_times = _unique_times(dev_rows)

    # Group by command
    cpu_by_cmd = _group_timeseries(cpu_rows, "cpu_pct", cpu_times) if cpu_rows else {}
    mem_by_cmd = _group_timeseries(mem_rows, "mem_pct", mem_times) if mem_rows else {}
    dev_rd_by_cmd = _group_timeseries(dev_rows, "kb_rd_s", dev_times) if dev_rows else {}
    dev_wr_by_cmd = _group_timeseries(dev_rows, "kb_wr_s", dev_times) if dev_rows else {}

    # Per-core CPU from raw csv (command -> {core -> [values]})
    cpu_per_core = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in cpu_rows:
        cpu_per_core[row["command"]][row["time"]][int(row["cpu"])] += float(row["cpu_pct"])

    # Collect all commands that appear in any section, sort with "other" last
    commands = sorted(
        set(cpu_by_cmd) | set(mem_by_cmd) | set(dev_rd_by_cmd),
        key=lambda c: (c == "other", c),
    )

    rows = []
    for cmd in commands:
        # CPU plot: per-core heatmap from raw data
        core_data = cpu_per_core.get(cmd)

        def make_cpu_plot(ax, cd=core_data, ct=cpu_times, cmd_ts=cpu_by_cmd.get(cmd)):
            if cd:
                cores = sorted(set(c for t in cd.values() for c in t))
                for idx, core in enumerate(cores):
                    values = [round(cd.get(t, {}).get(core, 0.0), 2) for t in ct]
                    color = DEFAULT_COLOR_CYCLE[idx % len(DEFAULT_COLOR_CYCLE)]
                    ax.plot(range(len(values)), values,
                            label=f"core {core}", color=color, linewidth=0.8)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("CPU demand %")
                ax.set_title("CPU Demand (per core)")
                ncol = max(1, (len(cores) + 7) // 8)
                ax.legend(fontsize="small", loc="upper left",
                          bbox_to_anchor=(1.02, 1.0), ncol=ncol)
            elif cmd_ts:
                ax.plot(range(len(cmd_ts)), cmd_ts, linewidth=0.8)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("CPU %")
                ax.set_title("CPU %")
            else:
                ax.set_title("CPU %")
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes)

        mem_ts = mem_by_cmd.get(cmd)

        def make_mem_plot(ax, pts=mem_ts):
            if pts:
                ax.plot(range(len(pts)), pts, linewidth=0.8)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("Memory %")
                ax.set_title("Memory Usage")
            else:
                ax.set_title("Memory Usage")
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes)

        rd_ts = dev_rd_by_cmd.get(cmd)
        wr_ts = dev_wr_by_cmd.get(cmd)

        def make_dev_plot(ax, rd=rd_ts, wr=wr_ts):
            if rd or wr:
                if rd:
                    ax.plot(range(len(rd)), rd,
                            label="read", color="#1f77b4", linewidth=0.8)
                if wr:
                    ax.plot(range(len(wr)), wr,
                            label="write", color="#ff7f0e", linewidth=0.8)
                ax.set_yscale("symlog", linthresh=1)
                ax.set_xlabel("Time (s)")
                ax.set_ylabel("KB/s")
                ax.set_title("Disk IO")
                ax.legend(fontsize="small", loc="upper left",
                          bbox_to_anchor=(1.02, 1.0))
            else:
                ax.set_yscale("symlog", linthresh=1)
                ax.set_title("Disk IO")
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes)

        rows.append({
            "label": cmd,
            "plots": [make_cpu_plot, make_mem_plot, make_dev_plot],
        })

    output = args.results_dir / "visualizations" / "sysstat-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["CPU %", "Memory %", "Disk IO (KB/s)"],
        title="Sysstat Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
