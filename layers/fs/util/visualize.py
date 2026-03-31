#!/usr/bin/env python3
"""Generate filesystem layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
import numpy as np

from container.labeling import add_label_column, load_mntns_label_map
from visualization.shared import (_color_for, _linestyle_for, _subsample_cdf,
                                   build_dashboard, plot_cumulated_mb_over_time,
                                   plot_inflight_from_column, plot_io_latency_cdf,
                                   plot_io_size_cdf, plot_type_distribution,
                                   sort_types)

LAYER = "fs"
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}
# Syscalls needed for FilePositionTracker replay
TRACKER_SYSCALLS = IO_SYSCALLS | {"openat", "close", "lseek"}
WINDOW_NS = 1_000_000_000


def _compute_rw_gaps(tracker_df, sc_type):
    """Compute per-fd gaps for read/write using position tracking.

    Replays openat/close/lseek/read/write events to reconstruct file positions,
    then computes gaps between successive IOs per fd.

    Uses numpy arrays for fast iteration (avoids per-row overhead).
    """
    # Pre-filter to only events that affect position or are target enters
    mask = (
        ((pl.col("event") == "exit") & pl.col("syscall").is_in(["openat", "lseek", sc_type])) |
        ((pl.col("event") == "enter") & pl.col("syscall").is_in([sc_type, "close"]))
    )
    df = tracker_df.filter(mask).sort("timestamp_ns")

    # Extract numpy arrays for fast access (no per-row overhead)
    events = df["event"].to_numpy(allow_copy=True).astype(str)
    syscalls = df["syscall"].to_numpy(allow_copy=True).astype(str)
    tids = df["tid"].to_numpy(allow_copy=True).astype("float64")
    fds = df["fd"].to_numpy(allow_copy=True).astype("float64")
    bytes_arr = df["bytes"].to_numpy(allow_copy=True).astype("float64")

    pos = {}           # (tid, fd) -> current file position
    fd_positions = {}  # fd -> [(position, size), ...]

    for i in range(len(events)):
        ev = events[i]
        sc = syscalls[i]
        tid_f = tids[i]
        fd_f = fds[i]
        bts = bytes_arr[i]

        if tid_f != tid_f:  # NaN check
            continue
        tid_i = int(tid_f)

        if ev == "exit":
            if sc == "openat":
                # openat return value (new fd) is in bytes column
                ret = int(bts) if bts == bts and bts >= 0 else -1
                if ret >= 0:
                    pos[(tid_i, ret)] = 0
            elif sc == "lseek":
                # lseek return value (new position) is in bytes column
                if fd_f == fd_f and fd_f >= 0:
                    ret = int(bts) if bts == bts and bts >= 0 else -1
                    if ret >= 0:
                        pos[(tid_i, int(fd_f))] = ret
            elif sc == sc_type:
                # read/write advances position by bytes returned
                if fd_f == fd_f and fd_f >= 0 and bts == bts and bts > 0:
                    key = (tid_i, int(fd_f))
                    if key in pos:
                        pos[key] += int(bts)
        else:  # enter
            if sc == sc_type:
                # Record current position at read/write entry
                if fd_f == fd_f and fd_f >= 0:
                    key = (tid_i, int(fd_f))
                    if key in pos:
                        size = int(bts) if bts == bts and bts > 0 else 0
                        fd_positions.setdefault(int(fd_f), []).append((pos[key], size))
            elif sc == "close":
                if fd_f == fd_f and fd_f >= 0:
                    pos.pop((tid_i, int(fd_f)), None)

    # Compute per-fd gaps, then aggregate
    all_gaps = []
    for io_list in fd_positions.values():
        if len(io_list) < 2:
            continue
        offsets = np.array([p[0] for p in io_list])
        sizes = np.array([p[1] for p in io_list])
        expected = offsets[:-1] + sizes[:-1]
        all_gaps.append(np.abs(offsets[1:] - expected))

    return np.concatenate(all_gaps) if all_gaps else np.array([])


def _plot_fs_gap_cdf(ax, parquet_path, types, mntns_map, label_filter=None):
    """Plot gap CDF for FS layer using per-source lazy scanning.

    pread64/pwrite64: per-fd gaps using explicit offsets from enter events.
    read/write: per-fd gaps using position tracking (openat/lseek/close replay).
    """
    for i, typ in enumerate(types):
        if typ in ("pread64", "pwrite64"):
            # Load only enter events for this syscall
            lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
            if label_filter is not None:
                lf = lf.filter(pl.col("label") == label_filter)
            df = (lf.filter((pl.col("event") == "enter") & (pl.col("syscall") == typ))
                  .select(["timestamp_ns", "fd", "offset", "bytes"])
                  .collect(engine="streaming")
                  .sort("timestamp_ns"))

            all_gaps = []
            for fd_val in df.drop_nulls("fd")["fd"].unique().to_list():
                fd_group = df.filter(pl.col("fd") == fd_val)
                locations = fd_group.drop_nulls("offset")["offset"].to_numpy()
                sizes = fd_group["bytes"].to_numpy()[:len(locations)]
                if len(locations) < 2:
                    continue
                expected = locations[:-1] + sizes[:len(locations) - 1]
                all_gaps.append(np.abs(locations[1:] - expected))
            del df
            if not all_gaps:
                continue
            gaps = np.concatenate(all_gaps)

        elif typ in ("read", "write"):
            # Load tracker events for position replay
            tracker_syscalls = [typ, "openat", "close", "lseek"]
            lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
            if label_filter is not None:
                lf = lf.filter(pl.col("label") == label_filter)
            tracker_df = (lf.filter(pl.col("syscall").is_in(tracker_syscalls))
                          .select(["event", "syscall", "timestamp_ns", "tid", "fd", "bytes"])
                          .collect(engine="streaming"))

            gaps = _compute_rw_gaps(tracker_df, typ)
            del tracker_df
            if len(gaps) == 0:
                continue
        else:
            continue

        sorted_gaps = np.sort(gaps)
        sorted_gaps, cdf = _subsample_cdf(sorted_gaps)
        ax.plot(sorted_gaps, cdf, label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xscale("symlog")
    ax.set_xlabel("Gap (bytes)")
    ax.set_ylabel("CDF")
    ax.set_title("Gap CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def _build_row(label, parquet_path, mntns_map, label_filter=None):
    """Build a dashboard row dict using per-plot Parquet scans."""

    def _scan(cols, event_filter=None, syscall_filter=None):
        """Lazy scan of Parquet with column selection and optional filters."""
        lf = add_label_column(pl.scan_parquet(parquet_path), mntns_map)
        if label_filter is not None:
            lf = lf.filter(pl.col("label") == label_filter)
        if syscall_filter is not None:
            lf = lf.filter(pl.col("syscall").is_in(syscall_filter))
        if event_filter is not None:
            lf = lf.filter(pl.col("event") == event_filter)
        return lf.select(cols)

    io_list = list(IO_SYSCALLS)

    # Pre-compute type counts (tiny scan)
    counts_df = (_scan(["syscall"], event_filter="exit", syscall_filter=io_list)
                 .group_by("syscall").len()
                 .collect(engine="streaming"))
    counts = dict(zip(*counts_df.select("syscall", "len").get_columns()))
    types = sort_types(counts.keys())

    # Pre-compute ts_min once (tiny scan)
    ts_min = (_scan(["timestamp_ns"], syscall_filter=io_list)
              .select(pl.col("timestamp_ns").min())
              .collect(engine="streaming").item())

    def inflight_fn(ax, t=types, ts_min=ts_min):
        df = (_scan(["timestamp_ns", "syscall", "inflight"], syscall_filter=io_list)
              .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
              .group_by("syscall", "sec").agg(pl.col("inflight").last())
              .sort("syscall", "sec")
              .collect(engine="streaming"))
        plot_inflight_from_column(ax, df, "syscall", t)

    def cumul_fn(ax, t=types, ts_min=ts_min):
        df = (_scan(["syscall", "timestamp_ns", "bytes"], event_filter="exit", syscall_filter=io_list)
              .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
              .group_by("syscall", "sec").agg(pl.col("bytes").sum())
              .sort("syscall", "sec")
              .collect(engine="streaming"))
        plot_cumulated_mb_over_time(ax, df, "syscall", "bytes", t)

    def size_fn(ax, t=types):
        df = (_scan(["syscall", "bytes"], event_filter="exit", syscall_filter=io_list)
              .collect(engine="streaming"))
        plot_io_size_cdf(ax, df, "syscall", "bytes", t)

    def latency_fn(ax, t=types):
        df = (_scan(["syscall", "latency_ns"], event_filter="exit", syscall_filter=io_list)
              .collect(engine="streaming"))
        plot_io_latency_cdf(ax, df, "syscall", "latency_ns", t)

    def gap_fn(ax, t=types):
        _plot_fs_gap_cdf(ax, parquet_path, t, mntns_map, label_filter=label_filter)

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
        rows.append(_build_row("fs", parquet_path, mntns_map))

    output = results_dir / "visualizations" / "fs-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="Filesystem Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
