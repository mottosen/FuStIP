#!/usr/bin/env python3
"""Generate filesystem layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_inflight_over_time, plot_io_latency_cdf,
                                   plot_io_size_cdf, plot_type_distribution)

LAYER = "fs"
USECOLS = ["timestamp_ns", "event", "syscall", "bytes", "latency_ns"]
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}


def _build_row(label, df):
    """Build a dashboard row dict from a dataframe."""
    exits = df[df["event"] == "exit"]
    types = sorted(exits["syscall"].dropna().unique())
    counts = exits.groupby("syscall").size().to_dict()

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            lambda ax, d=df, t=types: plot_inflight_over_time(ax, d, "enter", "exit", "syscall", "timestamp_ns", t),
            lambda ax, d=df, t=types: plot_cumulated_mb_over_time(ax, d, "exit", "syscall", "timestamp_ns", "bytes", t),
            lambda ax, e=exits, t=types: plot_io_size_cdf(ax, e, "syscall", "bytes", t),
            lambda ax, e=exits, t=types: plot_io_latency_cdf(ax, e, "syscall", "latency_ns", t),
        ],
    }


def main():
    results_dir = Path(sys.argv[1])
    csv_path = results_dir / LAYER / "detailed.csv"
    if not csv_path.exists():
        print(f"No detailed output found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {csv_path.name}...")
    header = pd.read_csv(csv_path, nrows=0).columns.tolist()
    has_comm = "comm" in header
    usecols = USECOLS + (["comm"] if has_comm else [])
    df = pd.read_csv(csv_path, usecols=usecols)

    # Filter to IO syscalls only
    df = df[df["syscall"].isin(IO_SYSCALLS)]

    rows = []
    if has_comm:
        for comm_val in sorted(df["comm"].dropna().unique()):
            comm_df = df[df["comm"] == comm_val]
            rows.append(_build_row(comm_val, comm_df))
    else:
        rows.append(_build_row("fs", df))

    output = results_dir / "visualizations" / "fs-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF"],
        title="Filesystem Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
