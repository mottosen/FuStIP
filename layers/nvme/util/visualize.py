#!/usr/bin/env python3
"""Generate NVMe layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from container.labeling import get_comm_label, load_comm_label_map, load_mntns_label_map
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_gap_cdf, plot_inflight_from_column,
                                   plot_io_latency_cdf, plot_io_size_cdf,
                                   plot_type_distribution, sort_types)

LAYER = "nvme"
WINDOW_NS = 1_000_000_000


def _comm_filter(comm_list, has_mntns):
    """Build a Polars filter expression matching any of the (comm, mntns_id_str) pairs."""
    if not comm_list:
        return pl.lit(True)
    if has_mntns:
        parts = []
        for comm, mntns_id_str in comm_list:
            if mntns_id_str:
                parts.append((pl.col("comm") == comm) & (pl.col("mntns_id") == int(mntns_id_str)))
            else:
                parts.append(pl.col("comm") == comm)
        expr = parts[0]
        for p in parts[1:]:
            expr = expr | p
        return expr
    return pl.col("comm").is_in([c for c, _ in comm_list])


def _build_row(label, parquet_path, comm_filter, ts_min):
    """Build a dashboard row dict using per-plot Parquet scans."""

    def _scan(cols, event_filter=None):
        lf = pl.scan_parquet(parquet_path).filter(comm_filter)
        if event_filter is not None:
            lf = lf.filter(pl.col("event") == event_filter)
        return lf.select(cols)

    # Pre-compute type counts (tiny scan)
    counts_df = (_scan(["op"], event_filter="complete")
                 .group_by("op").len()
                 .collect(engine="streaming"))
    counts = dict(zip(*counts_df.select("op", "len").get_columns()))
    types = sort_types(counts.keys())

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

    def iops_fn(ax, t=types, ts_min=ts_min):
        df = (_scan(["timestamp_ns", "op"], event_filter="complete")
              .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
              .group_by("op", "sec").agg(pl.len().alias("iops"))
              .sort("op", "sec")
              .collect(engine="streaming"))
        plot_inflight_from_column(ax, df, "op", t, inflight_col="iops", title="IOPS")

    def gap_fn(ax, t=types):
        df = _scan(["op", "sector", "bytes", "timestamp_ns"], event_filter="setup").collect(engine="streaming")
        plot_gap_cdf(ax, df, "op", "sector", "bytes", t)

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            inflight_fn,
            iops_fn,
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

    mntns_map = load_mntns_label_map(results_dir)
    comm_map = load_comm_label_map(results_dir)
    schema = pl.scan_parquet(parquet_path).collect_schema()
    has_mntns = "mntns_id" in schema
    id_keys = ["comm", "mntns_id"] if has_mntns else ["comm"]

    # Group (comm, mntns_id) pairs by resolved label — no add_label_column in any scan.
    comm_rows = pl.scan_parquet(parquet_path).select(id_keys).unique().collect(engine="streaming")
    label_to_comms: dict = {}
    for row in comm_rows.iter_rows(named=True):
        comm = row["comm"]
        mntns_id_str = str(row["mntns_id"]) if has_mntns and row.get("mntns_id") is not None else ""
        label = get_comm_label(comm, mntns_id_str, mntns_map, comm_map)
        label_to_comms.setdefault(label, []).append((comm, mntns_id_str))

    global_ts_min = (pl.scan_parquet(parquet_path)
                     .select(pl.col("timestamp_ns").min())
                     .collect(engine="streaming").item())

    rows = []
    for label in sorted(label_to_comms):
        cf = _comm_filter(label_to_comms[label], has_mntns)
        rows.append(_build_row(label, parquet_path, cf, global_ts_min))

    output = results_dir / "visualizations" / "nvme-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "IOPS", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="NVMe Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
