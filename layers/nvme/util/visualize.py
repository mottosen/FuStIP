#!/usr/bin/env python3
"""Generate NVMe layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from container.labeling import add_label_column, load_mntns_label_map
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_gap_cdf, plot_inflight_from_column,
                                   plot_io_latency_cdf, plot_io_size_cdf,
                                   plot_type_distribution, sort_types)

LAYER = "nvme"
WINDOW_NS = 1_000_000_000


def _build_row(label, parquet_path, mntns_map, label_filter=None):
    """Build a dashboard row dict using per-plot Parquet scans."""

    def _scan(cols, event_filter=None):
        """Lazy scan of Parquet with column selection and optional filters."""
        lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
        if label_filter is not None:
            lf = lf.filter(pl.col("label") == label_filter)
        if event_filter is not None:
            lf = lf.filter(pl.col("event") == event_filter)
        return lf.select(cols)

    # Pre-compute type counts (tiny scan)
    counts_df = (_scan(["op"], event_filter="complete")
                 .group_by("op").len()
                 .collect(engine="streaming"))
    counts = dict(zip(*counts_df.select("op", "len").get_columns()))
    types = sort_types(counts.keys())

    # Pre-compute ts_min once (tiny scan)
    ts_min = (_scan(["timestamp_ns"])
              .select(pl.col("timestamp_ns").min())
              .collect(engine="streaming").item())

    def inflight_fn(ax, t=types, ts_min=ts_min):
        df = (_scan(["timestamp_ns", "op", "inflight"])
              .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
              .group_by("op", "sec").agg(pl.col("inflight").last())
              .sort("op", "sec")
              .collect(engine="streaming"))
        plot_inflight_from_column(ax, df, "op", t)

    def cumul_fn(ax, t=types, ts_min=ts_min):
        df = (_scan(["op", "timestamp_ns", "bytes"], event_filter="complete")
              .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
              .group_by("op", "sec").agg(pl.col("bytes").sum())
              .sort("op", "sec")
              .collect(engine="streaming"))
        plot_cumulated_mb_over_time(ax, df, "op", "bytes", t)

    def size_fn(ax, t=types):
        df = _scan(["op", "bytes"], event_filter="complete").collect(engine="streaming")
        plot_io_size_cdf(ax, df, "op", "bytes", t)

    def latency_fn(ax, t=types):
        df = _scan(["op", "latency_ns"], event_filter="complete").collect(engine="streaming")
        plot_io_latency_cdf(ax, df, "op", "latency_ns", t)

    def gap_fn(ax, t=types):
        df = _scan(["op", "sector", "bytes", "timestamp_ns"], event_filter="setup").collect(engine="streaming")
        plot_gap_cdf(ax, df, "op", "sector", "bytes", t)

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            inflight_fn,
            cumul_fn,
            size_fn,
            latency_fn,
            gap_fn,
        ],
    }


def main():
    results_dir = Path(sys.argv[1])
    parquet_path = results_dir / LAYER / "detailed.parquet"
    if not parquet_path.exists():
        csv_path = results_dir / LAYER / "detailed.csv"
        if not csv_path.exists():
            print(f"No detailed output found", file=sys.stderr)
            sys.exit(1)
        print(f"Parquet not found: {parquet_path}", file=sys.stderr)
        sys.exit(1)

    schema = pl.scan_parquet(parquet_path).collect_schema()
    mntns_map = load_mntns_label_map(results_dir)
    has_label = "label" in add_label_column(pl.scan_parquet(parquet_path), mntns_map).collect_schema()

    rows = []
    if has_label:
        labels = (add_label_column(pl.scan_parquet(parquet_path), mntns_map)
                  .select("label").drop_nulls().unique()
                  .collect(engine="streaming"))["label"].sort().to_list()
        for lbl in labels:
            rows.append(_build_row(lbl, parquet_path, mntns_map, label_filter=lbl))
    else:
        rows.append(_build_row("nvme", parquet_path, mntns_map))

    output = results_dir / "visualizations" / "nvme-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="NVMe Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
