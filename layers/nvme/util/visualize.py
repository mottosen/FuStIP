#!/usr/bin/env python3
"""Generate NVMe layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import numpy as np
import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from container.labeling import get_comm_label, load_comm_label_map, load_mntns_label_map
from visualization.shared import (build_dashboard, plot_cumulated_mb_over_time,
                                   plot_gap_cdf, plot_inflight_from_column,
                                   plot_io_latency_cdf, plot_io_size_cdf,
                                   plot_lba_density, plot_lba_heatmap_2d,
                                   plot_type_distribution, sort_types)

LAYER = "nvme"
WINDOW_NS = 1_000_000_000
N_HEATMAP_LBA_BINS = 256
N_HEATMAP_TIME_BINS = 256


def load_device_sectors(parquet_path, schema):
    """Infer total device sector count from disk_name column via sysfs.

    Reads the most common disk_name from setup events in the Parquet, then
    looks up /sys/block/<disk_name>/size.  Returns None if the column is
    absent (old Parquet without disk_name) or the device is not found.
    """
    if "disk_name" not in schema:
        return None
    result = (pl.scan_parquet(parquet_path)
              .filter(pl.col("event") == "setup")
              .filter(pl.col("disk_name").is_not_null())
              .filter(pl.col("disk_name") != "")
              .select("disk_name")
              .group_by("disk_name")
              .agg(pl.len().alias("count"))
              .sort("count", descending=True)
              .limit(1)
              .collect(engine="streaming"))
    if len(result) == 0:
        return None
    dev = result["disk_name"][0]
    if not dev:
        return None
    size_path = Path(f"/sys/block/{dev}/size")
    if size_path.exists():
        try:
            return int(size_path.read_text().strip())
        except ValueError:
            pass
    return None


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


def _build_row(label, parquet_path, comm_filter, ts_min, device_sectors=None,
               ts_max=None, heatmap_ops=None, lba_min=None, lba_max=None,
               heatmap_vmax_log=None):
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
        plot_inflight_from_column(ax, df, "op", t, inflight_col="iops", title="IOPS", ylabel="IOPS")

    def gap_fn(ax, t=types):
        df = _scan(["op", "sector", "bytes", "timestamp_ns"], event_filter="setup").collect(engine="streaming")
        plot_gap_cdf(ax, df, "op", "sector", "bytes", t)

    # LBA range — use caller-supplied global bounds when available (avoids a redundant
    # scan and ensures all rows share the same axis scale for build_dashboard unification).
    # Falls back to a per-row scan when called without pre-computed bounds.
    if lba_min is not None and lba_max is not None:
        _has_lba = True
        _lba_min = lba_min
        _lba_max = lba_max
    else:
        _lba_df = (_scan(["sector", "bytes"], event_filter="setup")
                   .filter(pl.col("sector").is_not_null())
                   .select([
                       pl.col("sector").min().alias("lba_observed_min"),
                       (pl.col("sector") + pl.col("bytes") // 512).max().alias("lba_observed_max"),
                   ])
                   .collect(engine="streaming"))
        _has_lba = len(_lba_df) > 0 and _lba_df["lba_observed_min"][0] is not None
        _lba_min = int(_lba_df["lba_observed_min"][0]) if _has_lba else 0
        _lba_max = (device_sectors if device_sectors is not None
                    else (int(_lba_df["lba_observed_max"][0]) if _has_lba else 1))
    _lba_range = max(_lba_max - _lba_min, 1)

    # Percentile-based (p1/p99) local bounds — zoomed to where 98% of IOs land.
    # Computed once here and shared by local_density_fn and _make_heatmap_fn.
    _local_lba_min = _lba_min
    _local_lba_max = _lba_max
    if _has_lba:
        _local_bounds_df = (_scan(["sector"], event_filter="setup")
                            .filter(pl.col("sector").is_not_null())
                            .select([
                                pl.col("sector").quantile(0.01).alias("lba_p1"),
                                pl.col("sector").quantile(0.99).alias("lba_p99"),
                            ])
                            .collect(engine="streaming"))
        if len(_local_bounds_df) > 0 and _local_bounds_df["lba_p1"][0] is not None:
            _local_lba_min = int(_local_bounds_df["lba_p1"][0])
            _local_lba_max = int(_local_bounds_df["lba_p99"][0])
    _local_lba_range = max(_local_lba_max - _local_lba_min, 1)

    def density_fn(ax, t=types, lba_min=_lba_min, lba_max=_lba_max,
                   lba_range=_lba_range, has_lba=_has_lba):
        if not has_lba:
            ax.set_title("LBA Density (global)")
            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
            return
        n_bins = 512
        density_df = (_scan(["op", "sector"], event_filter="setup")
                      .filter(pl.col("sector").is_not_null())
                      .with_columns(
                          ((pl.col("sector") - lba_min) * n_bins // lba_range)
                          .clip(0, n_bins - 1).cast(pl.Int32).alias("lba_bin")
                      )
                      .group_by("op", "lba_bin")
                      .agg(pl.len().alias("count"))
                      .collect(engine="streaming"))
        plot_lba_density(ax, density_df, "op", "lba_bin", "count",
                         lba_min, lba_max, t, n_bins=n_bins)
        ax.set_title("LBA Density (global)")

    def local_density_fn(ax, t=types, lba_min=_local_lba_min, lba_max=_local_lba_max,
                         lba_range=_local_lba_range, has_lba=_has_lba):
        if not has_lba:
            ax.set_title("LBA Density (local, p1–p99)")
            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
            return
        n_bins = 512
        density_df = (_scan(["op", "sector"], event_filter="setup")
                      .filter(pl.col("sector").is_not_null())
                      .with_columns(
                          ((pl.col("sector") - lba_min) * n_bins // lba_range)
                          .clip(0, n_bins - 1).cast(pl.Int32).alias("lba_bin")
                      )
                      .group_by("op", "lba_bin")
                      .agg(pl.len().alias("count"))
                      .collect(engine="streaming"))
        plot_lba_density(ax, density_df, "op", "lba_bin", "count",
                         lba_min, lba_max, t, n_bins=n_bins)
        ax.set_title("LBA Density (local, p1–p99)")

    def _make_heatmap_fn(op):
        vmax_log = heatmap_vmax_log.get(op) if heatmap_vmax_log else None

        def heatmap_fn(ax, op=op, lba_min=_local_lba_min, lba_max=_local_lba_max,
                       lba_range=_local_lba_range, has_lba=_has_lba, ts=ts_min, te=ts_max,
                       vmax_log=vmax_log):
            if not has_lba or te is None or te <= ts:
                ax.set_title(f"LBA Heatmap ({op})")
                ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)
                return
            duration_s = (te - ts) / 1e9
            heatmap_df = (_scan(["op", "sector", "timestamp_ns"], event_filter="setup")
                          .filter(pl.col("op") == op)
                          .filter(pl.col("sector").is_not_null())
                          .with_columns([
                              ((pl.col("sector") - lba_min) * N_HEATMAP_LBA_BINS // lba_range)
                              .clip(0, N_HEATMAP_LBA_BINS - 1).cast(pl.Int32).alias("lba_bin"),
                              ((pl.col("timestamp_ns") - ts) * N_HEATMAP_TIME_BINS // (te - ts + 1))
                              .clip(0, N_HEATMAP_TIME_BINS - 1).cast(pl.Int32).alias("time_bin"),
                          ])
                          .group_by("time_bin", "lba_bin")
                          .agg(pl.len().alias("count"))
                          .collect(engine="streaming"))
            plot_lba_heatmap_2d(ax, heatmap_df, op, N_HEATMAP_LBA_BINS, N_HEATMAP_TIME_BINS,
                                lba_min, lba_max, duration_s, vmax_log=vmax_log)
        return heatmap_fn

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
            density_fn,
            local_density_fn,
        ] + [_make_heatmap_fn(op) for op in (heatmap_ops or [])],
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

    ts_bounds = (pl.scan_parquet(parquet_path)
                 .select([pl.col("timestamp_ns").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max")])
                 .collect(engine="streaming"))
    global_ts_min = ts_bounds["ts_min"][0]
    global_ts_max = ts_bounds["ts_max"][0]

    device_sectors = load_device_sectors(parquet_path, schema)

    # Determine global op types for heatmap columns (same set for every row).
    global_ops: list = []
    global_lba_min: int | None = None
    global_lba_max: int | None = None
    if "sector" in schema:
        ops_df = (pl.scan_parquet(parquet_path)
                  .filter(pl.col("event") == "setup")
                  .select("op").unique()
                  .collect(engine="streaming"))
        global_ops = sort_types(ops_df["op"].to_list())

        lba_bounds_df = (pl.scan_parquet(parquet_path)
                         .filter(pl.col("event") == "setup")
                         .filter(pl.col("sector").is_not_null())
                         .select([
                             pl.col("sector").min().alias("lba_min"),
                             (pl.col("sector") + pl.col("bytes") // 512).max().alias("lba_observed_max"),
                         ])
                         .collect(engine="streaming"))
        if len(lba_bounds_df) > 0 and lba_bounds_df["lba_min"][0] is not None:
            global_lba_min = int(lba_bounds_df["lba_min"][0])
            global_lba_max = (device_sectors if device_sectors is not None
                              else int(lba_bounds_df["lba_observed_max"][0]))

    # "per_row" tells build_dashboard to skip cross-row y-axis unification for that column,
    # letting each row auto-scale to its own observed LBA range.
    col_ylims = [None] * 7 + ["per_row"] + ["per_row"] + ["per_row"] * len(global_ops)

    # Pre-compute per-row p1/p99 LBA bounds and the global max bin count per op so that
    # heatmap colour scales are shared across rows (enabling count comparison).
    row_local_lba_bounds: dict = {}  # label -> (lba_min, lba_max)
    if "sector" in schema:
        for label in sorted(label_to_comms):
            cf = _comm_filter(label_to_comms[label], has_mntns)
            b = (pl.scan_parquet(parquet_path)
                 .filter(cf)
                 .filter(pl.col("event") == "setup")
                 .filter(pl.col("sector").is_not_null())
                 .select([pl.col("sector").quantile(0.01).alias("p1"),
                          pl.col("sector").quantile(0.99).alias("p99")])
                 .collect(engine="streaming"))
            if len(b) > 0 and b["p1"][0] is not None:
                row_local_lba_bounds[label] = (int(b["p1"][0]), int(b["p99"][0]))
            else:
                row_local_lba_bounds[label] = (global_lba_min or 0, global_lba_max or 1)

    global_heatmap_vmax_log: dict = {}  # op -> log1p(global max bin count)
    ts_range = max((global_ts_max or 1) - (global_ts_min or 0), 1)
    for op in global_ops:
        op_vmax = 0.0
        for label in sorted(label_to_comms):
            cf = _comm_filter(label_to_comms[label], has_mntns)
            loc_min, loc_max = row_local_lba_bounds.get(label, (global_lba_min or 0, global_lba_max or 1))
            loc_range = max(loc_max - loc_min, 1)
            mc = (pl.scan_parquet(parquet_path)
                  .filter(cf)
                  .filter(pl.col("event") == "setup")
                  .filter(pl.col("op") == op)
                  .filter(pl.col("sector").is_not_null())
                  .with_columns([
                      ((pl.col("sector") - loc_min) * N_HEATMAP_LBA_BINS // loc_range)
                      .clip(0, N_HEATMAP_LBA_BINS - 1).cast(pl.Int32).alias("lba_bin"),
                      ((pl.col("timestamp_ns") - (global_ts_min or 0)) * N_HEATMAP_TIME_BINS // ts_range)
                      .clip(0, N_HEATMAP_TIME_BINS - 1).cast(pl.Int32).alias("time_bin"),
                  ])
                  .group_by("time_bin", "lba_bin")
                  .agg(pl.len().alias("count"))
                  .select(pl.col("count").max())
                  .collect(engine="streaming"))
            if len(mc) > 0 and mc["count"][0] is not None:
                op_vmax = max(op_vmax, float(np.log1p(mc["count"][0])))
        global_heatmap_vmax_log[op] = max(op_vmax, 1e-6)

    rows = []
    for label in sorted(label_to_comms):
        cf = _comm_filter(label_to_comms[label], has_mntns)
        rows.append(_build_row(label, parquet_path, cf, global_ts_min,
                               device_sectors=device_sectors,
                               ts_max=global_ts_max,
                               heatmap_ops=global_ops,
                               lba_min=global_lba_min,
                               lba_max=global_lba_max,
                               heatmap_vmax_log=global_heatmap_vmax_log))

    output = results_dir / "visualizations" / "nvme-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=(["Type Distribution", "Inflight", "IOPS", "Cumul. MB",
                     "IO Size CDF", "Latency CDF", "Gap CDF",
                     "LBA Density (global)", "LBA Density (local, p1–p99)"]
                    + [f"LBA Heatmap ({op})" for op in global_ops]),
        col_ylims=col_ylims,
        title="NVMe Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
