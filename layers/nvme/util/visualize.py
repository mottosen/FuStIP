#!/usr/bin/env python3
"""Generate NVMe layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_gap_cdf, plot_inflight_from_column,
                                   plot_inflight_over_time, plot_io_latency_cdf,
                                   plot_io_size_cdf, plot_type_distribution)

LAYER = "nvme"
USECOLS = ["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector"]


def _build_row(label, df):
    """Build a dashboard row dict from a dataframe."""
    complete = df.filter(pl.col("event") == "complete")
    setup = df.filter(pl.col("event") == "setup")
    types = sorted(complete.drop_nulls("op")["op"].unique().sort().to_list())
    counts = dict(zip(*complete.group_by("op").len().select("op", "len").get_columns()))
    has_inflight = "inflight" in df.columns

    if has_inflight:
        inflight_fn = lambda ax, d=df, t=types: plot_inflight_from_column(ax, d, "op", "timestamp_ns", t)
    else:
        inflight_fn = lambda ax, d=df, t=types: plot_inflight_over_time(ax, d, "setup", "complete", "op", "timestamp_ns", t)

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            inflight_fn,
            lambda ax, d=df, t=types: plot_cumulated_mb_over_time(ax, d, "complete", "op", "timestamp_ns", "bytes", t),
            lambda ax, c=complete, t=types: plot_io_size_cdf(ax, c, "op", "bytes", t),
            lambda ax, c=complete, t=types: plot_io_latency_cdf(ax, c, "op", "latency_ns", t),
            lambda ax, s=setup, t=types: plot_gap_cdf(ax, s, "op", "sector", "bytes", t),
        ],
    }


def main():
    results_dir = Path(sys.argv[1])
    csv_path = results_dir / LAYER / "detailed.csv"
    if not csv_path.exists():
        print(f"No detailed output found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {csv_path.name}...")
    # Read header to detect optional columns
    with open(csv_path) as f:
        header = f.readline().strip().split(",")
    has_comm = "comm" in header
    has_inflight = "inflight" in header
    usecols = USECOLS + (["comm"] if has_comm else []) + (["inflight"] if has_inflight else [])

    df = pl.read_csv(csv_path, columns=usecols)

    rows = []
    if has_comm:
        for comm_val in sorted(df.drop_nulls("comm")["comm"].unique().sort().to_list()):
            comm_df = df.filter(pl.col("comm") == comm_val)
            rows.append(_build_row(comm_val, comm_df))
    else:
        rows.append(_build_row("nvme", df))

    output = results_dir / "visualizations" / "nvme-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="NVMe Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
