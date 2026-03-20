#!/usr/bin/env python3
"""Generate block layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_gap_cdf, plot_inflight_from_column,
                                   plot_inflight_over_time, plot_io_latency_cdf,
                                   plot_io_size_cdf, plot_type_distribution)

LAYER = "block"
USECOLS = ["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector"]


def _build_row(label, df):
    """Build a dashboard row dict from a dataframe."""
    complete = df[df["event"] == "complete"]
    issue = df[df["event"] == "issue"]
    types = sorted(complete["op"].dropna().unique())
    counts = complete.groupby("op").size().to_dict()
    has_inflight = "q_inflight" in df.columns and "d_inflight" in df.columns

    if has_inflight:
        q_fn = lambda ax, d=df, t=types: plot_inflight_from_column(ax, d, "op", "timestamp_ns", t, inflight_col="q_inflight", title="Queue Inflight")
        d_fn = lambda ax, d=df, t=types: plot_inflight_from_column(ax, d, "op", "timestamp_ns", t, inflight_col="d_inflight", title="Driver Inflight")
    else:
        q_fn = lambda ax, d=df, t=types: plot_inflight_over_time(ax, d, "insert", "issue", "op", "timestamp_ns", t, title="Queue Inflight")
        d_fn = lambda ax, d=df, t=types: plot_inflight_over_time(ax, d, "issue", "complete", "op", "timestamp_ns", t, title="Driver Inflight")

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            q_fn,
            d_fn,
            lambda ax, d=df, t=types: plot_cumulated_mb_over_time(ax, d, "complete", "op", "timestamp_ns", "bytes", t),
            lambda ax, c=complete, t=types: plot_io_size_cdf(ax, c, "op", "bytes", t),
            lambda ax, c=complete, t=types: plot_io_latency_cdf(ax, c, "op", "latency_ns", t),
            lambda ax, s=issue, t=types: plot_gap_cdf(ax, s, "op", "sector", "bytes", t),
        ],
    }


def main():
    results_dir = Path(sys.argv[1])
    csv_path = results_dir / LAYER / "detailed.csv"
    if not csv_path.exists():
        print(f"No detailed output found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading {csv_path.name}...")
    # Check which optional columns exist
    header = pd.read_csv(csv_path, nrows=0).columns.tolist()
    has_comm = "comm" in header
    has_inflight = "q_inflight" in header and "d_inflight" in header
    usecols = USECOLS + (["comm"] if has_comm else []) + (["q_inflight", "d_inflight"] if has_inflight else [])
    cat_cols = {"event": "category", "op": "category"}
    if has_comm:
        cat_cols["comm"] = "category"
    df = pd.read_csv(csv_path, usecols=usecols, dtype=cat_cols)

    rows = []
    if has_comm:
        for comm_val in sorted(df["comm"].dropna().unique()):
            comm_df = df[df["comm"] == comm_val]
            rows.append(_build_row(comm_val, comm_df))
    else:
        rows.append(_build_row("block", df))

    output = results_dir / "visualizations" / "block-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Queue Inflight", "Driver Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="Block Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
