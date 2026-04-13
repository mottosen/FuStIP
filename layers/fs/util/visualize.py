#!/usr/bin/env python3
"""Generate filesystem layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
import numpy as np

from container.labeling import get_comm_label, load_comm_label_map, load_mntns_label_map
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


def _plot_fs_gap_cdf(ax, parquet_path, types, comm_filter):
    """Plot gap CDF for FS layer using per-source lazy scanning.

    pread64/pwrite64: per-fd gaps using explicit offsets from enter events.
    read/write: per-fd gaps using position tracking (openat/lseek/close replay).

    comm_filter is a pre-built Polars expression (no add_label_column in scan).
    Explicit select keeps only needed columns — critical for 80M-row pread64/pwrite64
    scans (4 cols × 80M rows ≈ 2.5 GB vs 11 cols × 80M rows ≈ 9 GB without it).
    pread64/pwrite64: numpy lexsort by (fd, timestamp_ns) instead of Polars .sort()
    to avoid a 2× full-DataFrame copy (~10 GB peak for 96M rows).
    """
    for i, typ in enumerate(types):
        if typ in ("pread64", "pwrite64"):
            df = (pl.scan_parquet(parquet_path)
                  .filter(comm_filter)
                  .filter((pl.col("event") == "enter") & (pl.col("syscall") == typ))
                  .select(["timestamp_ns", "fd", "offset", "bytes"])
                  .collect(engine="streaming"))

            # Convert to numpy immediately and free the Polars DataFrame.
            # Avoid .sort("timestamp_ns") on the full DataFrame — Polars sort
            # creates a full copy (~2× RSS spike = ~10 GB for 96M rows).
            # Instead, lexsort by (fd, timestamp_ns) via numpy (index only).
            ts_arr = df["timestamp_ns"].to_numpy(allow_copy=True)
            fd_arr = df["fd"].to_numpy(allow_copy=True).astype("float64")
            off_arr = df["offset"].to_numpy(allow_copy=True).astype("float64")
            byt_arr = df["bytes"].to_numpy(allow_copy=True).astype("float64")
            del df

            sort_idx = np.lexsort((ts_arr, fd_arr))
            del ts_arr
            fd_s = fd_arr[sort_idx]
            off_s = off_arr[sort_idx]
            byt_s = byt_arr[sort_idx]
            del fd_arr, off_arr, byt_arr, sort_idx

            # Remove NaN fds; array is sorted by fd then timestamp.
            valid = ~np.isnan(fd_s)
            fd_s = fd_s[valid]
            off_s = off_s[valid]
            byt_s = byt_s[valid]
            del valid

            # np.unique(return_index) gives group-start indices: O(n) slices
            # instead of O(n_fds × n) per-fd mask comparisons.
            _, start_idx = np.unique(fd_s, return_index=True)
            end_idx = np.append(start_idx[1:], len(fd_s))
            del fd_s

            all_gaps = []
            for start, end in zip(start_idx, end_idx):
                locs = off_s[start:end]
                szs = byt_s[start:end]
                valid = ~np.isnan(locs)
                locs = locs[valid]
                szs = szs[valid]
                if len(locs) < 2:
                    continue
                expected = locs[:-1] + szs[:-1]
                all_gaps.append(np.abs(locs[1:] - expected))
            del off_s, byt_s
            if not all_gaps:
                continue
            gaps = np.concatenate(all_gaps)

        elif typ in ("read", "write"):
            tracker_syscalls = [typ, "openat", "close", "lseek"]
            tracker_df = (pl.scan_parquet(parquet_path)
                          .filter(comm_filter)
                          .filter(pl.col("syscall").is_in(tracker_syscalls))
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


def _build_row(label, parquet_path, comm_filter, ts_min):
    """Build a dashboard row dict using lazy-loaded exit_df for size/latency plots.

    Memory design: with multiple labels (comms/containers), eagerly pre-collecting
    exit_df for all rows simultaneously would stack N × ~7 GB in memory before any
    plot is rendered.  Instead:

      Scan 1 (tiny streaming):  counts dict.
      Scan 2 (tiny streaming):  cumul MB per-second (~240 rows).
      Scan 3 (tiny streaming):  inflight per-second (~240 rows).
      Lazy exit_df:  collected on-demand by size_fn, reused by latency_fn, then
                     freed via a mutable cache cleared after latency_fn returns.
                     This ensures exit_df (~7 GB) is in memory for at most two
                     consecutive plot calls and is gone before gap_fn starts.
      Gap scans (Scan 4+):  numpy-based per-syscall scans with lexsort.
    """
    io_list = list(IO_SYSCALLS)

    # === Scan 1: tiny aggregated scan for type counts ===
    counts_and_ts = (pl.scan_parquet(parquet_path)
                     .filter(comm_filter)
                     .filter(pl.col("event") == "exit")
                     .filter(pl.col("syscall").is_in(io_list))
                     .select(["syscall"])
                     .group_by("syscall")
                     .agg(pl.len().alias("cnt"))
                     .collect(engine="streaming"))
    counts = dict(zip(counts_and_ts["syscall"].to_list(), counts_and_ts["cnt"].to_list()))
    types = sort_types(counts.keys())

    # === Scan 2: cumul MB per-second (tiny streaming aggregation) ===
    cumul_df = (pl.scan_parquet(parquet_path)
                .filter(comm_filter)
                .filter(pl.col("event") == "exit")
                .filter(pl.col("syscall").is_in(io_list))
                .select(["syscall", "timestamp_ns", "bytes"])
                .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
                .group_by("syscall", "sec").agg(pl.col("bytes").sum())
                .sort("syscall", "sec")
                .collect(engine="streaming"))

    # === Scan 3: inflight per-second (tiny streaming aggregation) ===
    inflight_df = (pl.scan_parquet(parquet_path)
                   .filter(comm_filter)
                   .filter(pl.col("syscall").is_in(io_list))
                   .select(["syscall", "timestamp_ns", "inflight"])
                   .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
                   .group_by("syscall", "sec").agg(pl.col("inflight").last())
                   .sort("syscall", "sec")
                   .collect(engine="streaming"))

    # === Scan 3b: IOPS per-second (tiny streaming aggregation) ===
    iops_df = (pl.scan_parquet(parquet_path)
               .filter(comm_filter)
               .filter((pl.col("event") == "exit") & pl.col("syscall").is_in(io_list))
               .select(["syscall", "timestamp_ns"])
               .with_columns(((pl.col("timestamp_ns") - ts_min) // WINDOW_NS).cast(pl.Int64).alias("sec"))
               .group_by("syscall", "sec").agg(pl.len().alias("iops"))
               .sort("syscall", "sec")
               .collect(engine="streaming"))

    # === Lazy exit_df: loaded on first call, freed after latency_fn ===
    # Mutable single-element list used as a shared cache between size_fn and
    # latency_fn closures so both share one scan and exit_df is freed before gap_fn.
    _exit_cache = [None]

    def _get_exit_df():
        if _exit_cache[0] is None:
            _exit_cache[0] = (pl.scan_parquet(parquet_path)
                              .filter(comm_filter)
                              .filter(pl.col("event") == "exit")
                              .filter(pl.col("syscall").is_in(io_list))
                              .select(["syscall", "bytes", "latency_ns"])
                              .collect(engine="streaming"))
        return _exit_cache[0]

    def inflight_fn(ax, t=types, df=inflight_df):
        plot_inflight_from_column(ax, df, "syscall", t)

    def iops_fn(ax, t=types, df=iops_df):
        plot_inflight_from_column(ax, df, "syscall", t, inflight_col="iops", title="IOPS", ylabel="IOPS")

    def cumul_fn(ax, t=types, df=cumul_df):
        plot_cumulated_mb_over_time(ax, df, "syscall", "bytes", t)

    def size_fn(ax, t=types, get=_get_exit_df):
        plot_io_size_cdf(ax, get(), "syscall", "bytes", t)

    def latency_fn(ax, t=types, get=_get_exit_df, cache=_exit_cache):
        plot_io_latency_cdf(ax, get(), "syscall", "latency_ns", t)
        cache[0] = None  # Free exit_df after the last plot that uses it

    def gap_fn(ax, t=types, cf=comm_filter):
        _plot_fs_gap_cdf(ax, parquet_path, t, cf)

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

    output = results_dir / "visualizations" / "fs-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "IOPS", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="Filesystem Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
