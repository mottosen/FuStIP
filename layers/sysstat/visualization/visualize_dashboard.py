#!/usr/bin/env python3
"""
System-wide pidstat dashboard: per-container CPU, memory, and disk I/O.

Reads cpu.csv, mem.csv, dev.csv from the input directory (produced by
parse_output.py) and creates a 4-row x 5-column dashboard:
  Rows: milvus, minio, etcd, other
  Cols: CPU usage (line per core), CPU wait (summed), memory RSS,
        disk throughput (read/write), I/O delay (summed)

Usage:
    python syswide_dashboard.py <results_dir>
"""

import argparse
import sys
from pathlib import Path

import matplotlib.cm as cm
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# =============================================================================
# Color configuration
# =============================================================================
COLORS = {
    "read": "#2ecc71",
    "write": "#e74c3c",
    "rss": "#3498db",
    "wait": "#f39c12",
    "iodelay": "#9b59b6",
    "background": "#f8f9fa",
    "grid": "#dee2e6",
    "text": "#212529",
    "title": "#343a40",
}


def get_core_color(core: int, n_cores: int) -> str:
    """Get a distinct color for a CPU core using a colormap."""
    cmap = plt.colormaps.get_cmap("tab20").resampled(max(n_cores, 1))
    return cmap(core % cmap.N)


def load_data(results_dir: Path, commands: [str]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load the three parsed CSV files and normalize time to relative seconds."""
    cpu_file = results_dir / "cpu.csv"
    mem_file = results_dir / "mem.csv"
    dev_file = results_dir / "dev.csv"

    for f in [cpu_file, mem_file, dev_file]:
        if not f.exists():
            raise FileNotFoundError(f"File not found: {f}")

    cpu = pd.read_csv(cpu_file)
    mem = pd.read_csv(mem_file)
    dev = pd.read_csv(dev_file)

    # Convert time strings to datetime for relative time computation
    for df in [cpu, mem, dev]:
        df["timestamp"] = pd.to_datetime(df["time"], format="%I:%M:%S %p")

    # Compute relative seconds from global t0
    t0 = min(df["timestamp"].min() for df in [cpu, mem, dev])
    for df in [cpu, mem, dev]:
        df["time_sec"] = (df["timestamp"] - t0).dt.total_seconds()

    # Assign container label
    for df in [cpu, mem, dev]:
        df["container"] = df["command"].apply(
            lambda c: c if c in commands else "other"
        )

    return cpu, mem, dev


def compute_axis_limits(cpu: pd.DataFrame, mem: pd.DataFrame, dev: pd.DataFrame, commands: [str]) -> dict:
    """Compute shared axis limits across all container rows."""
    limits = {
        "time_x": [0, max(cpu["time_sec"].max(), mem["time_sec"].max(), dev["time_sec"].max())],
        "cpu_y": [0, 105],
        "cpu_wait_y": [0, 105],
        "mem_y": [0, 0],
        "disk_y": [0, 0],
        "iodelay_y": [0, 0],
    }

    for container in commands + ["other"]:
        # Memory: sum of RSS across PIDs
        c_mem = mem[mem["container"] == container]
        if len(c_mem) > 0:
            rss_per_time = c_mem.groupby("time_sec")["rss_kb"].sum() / 1024
            limits["mem_y"][1] = max(limits["mem_y"][1], rss_per_time.max())

        # Disk: sum of read+write rates across PIDs
        c_dev = dev[dev["container"] == container]
        if len(c_dev) > 0:
            rd_per_time = c_dev.groupby("time_sec")["kb_rd_s"].sum() / 1024
            wr_per_time = c_dev.groupby("time_sec")["kb_wr_s"].sum() / 1024
            limits["disk_y"][1] = max(limits["disk_y"][1], rd_per_time.max(), wr_per_time.max())

            # I/O delay: sum across PIDs per timestamp
            iodelay_per_time = c_dev.groupby("time_sec")["iodelay"].sum()
            if len(iodelay_per_time) > 0:
                limits["iodelay_y"][1] = max(limits["iodelay_y"][1], iodelay_per_time.max())

    # Padding
    for key in ["mem_y", "disk_y"]:
        limits[key][1] *= 1.1
    limits["iodelay_y"][1] = max(limits["iodelay_y"][1] * 1.1, 1.0)

    return limits


def plot_cpu(ax, data: pd.DataFrame, container: str, n_cores: int, limits: dict = None):
    """Plot CPU usage over time, one line per core."""
    c_data = data[data["container"] == container]

    if len(c_data) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("CPU")
        return

    # Aggregate cpu_pct per (time, core) across all PIDs in this container
    grouped = c_data.groupby(["time_sec", "cpu"])["cpu_pct"].sum().reset_index()

    cores_used = sorted(grouped["cpu"].unique())
    for core in cores_used:
        core_data = grouped[grouped["cpu"] == core].sort_values("time_sec")
        color = get_core_color(core, n_cores)
        ax.plot(core_data["time_sec"], core_data["cpu_pct"], color=color, label=f"core {core}", linewidth=1)

    if limits:
        ax.set_xlim(limits["time_x"])
        ax.set_ylim(limits["cpu_y"])

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("CPU %")
    ax.set_title("CPU")
    ax.legend(loc="upper left", fontsize=7, ncol=max(1, len(cores_used) // 8))
    ax.grid(True, alpha=0.3, color=COLORS["grid"])


def plot_cpu_wait(ax, data: pd.DataFrame, container: str, limits: dict = None):
    """Plot CPU wait % over time, summed across all threads."""
    c_data = data[data["container"] == container]

    if len(c_data) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("CPU Wait")
        return

    grouped = c_data.groupby("time_sec")["wait"].sum().reset_index()

    ax.plot(grouped["time_sec"], grouped["wait"], color=COLORS["wait"], linewidth=1)

    if limits:
        ax.set_xlim(limits["time_x"])
        ax.set_ylim(limits["cpu_wait_y"])

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Wait %")
    ax.set_title("CPU Wait")
    ax.grid(True, alpha=0.3, color=COLORS["grid"])


def plot_mem(ax, data: pd.DataFrame, container: str, limits: dict = None):
    """Plot memory RSS over time, summed across PIDs."""
    c_data = data[data["container"] == container]

    if len(c_data) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Memory (RSS)")
        return

    # Sum RSS across all PIDs at each timestamp, convert to MB
    grouped = c_data.groupby("time_sec")["rss_kb"].sum().reset_index()
    grouped["rss_mb"] = grouped["rss_kb"] / 1024

    ax.plot(grouped["time_sec"], grouped["rss_mb"], color=COLORS["rss"], linewidth=1)

    if limits:
        ax.set_xlim(limits["time_x"])
        ax.set_ylim(limits["mem_y"])

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("RSS (MB)")
    ax.set_title("Memory (RSS)")
    ax.grid(True, alpha=0.3, color=COLORS["grid"])


def plot_disk(ax, data: pd.DataFrame, container: str, limits: dict = None):
    """Plot disk read/write throughput over time, summed across PIDs."""
    c_data = data[data["container"] == container]

    if len(c_data) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("Disk I/O")
        return

    # Sum rates across all PIDs at each timestamp, convert to MB/s
    grouped = c_data.groupby("time_sec")[["kb_rd_s", "kb_wr_s"]].sum().reset_index()
    grouped["mb_rd_s"] = grouped["kb_rd_s"] / 1024
    grouped["mb_wr_s"] = grouped["kb_wr_s"] / 1024

    ax.plot(grouped["time_sec"], grouped["mb_rd_s"], color=COLORS["read"], label="read", linewidth=1)
    ax.plot(grouped["time_sec"], grouped["mb_wr_s"], color=COLORS["write"], label="write", linewidth=1)

    if limits:
        ax.set_xlim(limits["time_x"])
        ax.set_ylim(limits["disk_y"])

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("MB/s")
    ax.set_title("Disk I/O")
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(True, alpha=0.3, color=COLORS["grid"])


def plot_iodelay(ax, data: pd.DataFrame, container: str, limits: dict = None):
    """Plot I/O delay over time, summed across all PIDs."""
    c_data = data[data["container"] == container]

    if len(c_data) == 0:
        ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title("I/O Delay")
        return

    grouped = c_data.groupby("time_sec")["iodelay"].sum().reset_index()

    ax.plot(grouped["time_sec"], grouped["iodelay"], color=COLORS["iodelay"], linewidth=1)

    if limits:
        ax.set_xlim(limits["time_x"])
        ax.set_ylim(limits["iodelay_y"])

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Clock ticks")
    ax.set_title("I/O Delay")
    ax.grid(True, alpha=0.3, color=COLORS["grid"])


def create_dashboard(
    cpu: pd.DataFrame, mem: pd.DataFrame, dev: pd.DataFrame, output_path: Path, commands: [str] = None
):
    """Create the 4-row x 5-column dashboard."""
    rows = commands + ["other"]
    n_rows = len(rows)
    n_cols = 5

    n_cores = cpu["cpu"].nunique()

    limits = compute_axis_limits(cpu, mem, dev, rows)

    fig, axes = plt.subplots(
        n_rows, n_cols, figsize=(32, 4 * n_rows), facecolor=COLORS["background"]
    )

    fig.suptitle(
        "System-wide Resource Usage (pidstat)",
        fontsize=16,
        fontweight="bold",
        color=COLORS["title"],
        y=0.98,
    )

    for row_idx, container in enumerate(rows):
        # Row label
        axes[row_idx, 0].annotate(
            container,
            xy=(-0.25, 0.5),
            xycoords="axes fraction",
            fontsize=12,
            fontweight="bold",
            color=COLORS["title"],
            ha="center",
            va="center",
            rotation=90,
        )

        plot_cpu(axes[row_idx, 0], cpu, container, n_cores, limits)
        plot_cpu_wait(axes[row_idx, 1], cpu, container, limits)
        plot_mem(axes[row_idx, 2], mem, container, limits)
        plot_disk(axes[row_idx, 3], dev, container, limits)
        plot_iodelay(axes[row_idx, 4], dev, container, limits)

    plt.tight_layout(rect=[0.02, 0, 1, 0.96])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150, facecolor=COLORS["background"], bbox_inches="tight")
    plt.close()

    print(f"Dashboard saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Visualize pidstat data: per-container CPU, memory, and disk I/O"
    )
    parser.add_argument(
        "results_dir", type=Path, help="Directory containing cpu.csv, mem.csv, dev.csv"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output PNG path (default: <results_dir>/visualizations/syswide-dashboard.png)",
    )
    parser.add_argument(
        "--process", "-p",
        type=str.split,
        default=[],
        help="Comma-separated string of processes to watch.",
    )

    args = parser.parse_args()

    if not args.results_dir.is_dir():
        print(f"Error: {args.results_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = args.output
    else:
        viz_dir = args.results_dir / "visualizations"
        output_path = viz_dir / "syswide-dashboard.png"

    try:
        cpu, mem, dev = load_data(args.results_dir, args.process)
        create_dashboard(cpu, mem, dev, output_path, args.process)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
