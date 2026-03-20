#!/usr/bin/env python3
"""Generate filesystem layer visualization dashboard from detailed CSV."""

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
import numpy as np

from visualization.shared import (_color_for, build_dashboard,
                                   plot_cumulated_mb_over_time,
                                   plot_inflight_from_column,
                                   plot_inflight_over_time, plot_io_latency_cdf,
                                   plot_io_size_cdf, plot_type_distribution)

LAYER = "fs"
USECOLS = ["timestamp_ns", "event", "syscall", "bytes", "latency_ns", "offset", "fd", "tid"]
IO_SYSCALLS = {"read", "write", "pread64", "pwrite64"}
# Syscalls needed for FilePositionTracker replay
TRACKER_SYSCALLS = IO_SYSCALLS | {"openat", "close", "lseek"}


def _compute_rw_gaps(tracker_df, sc_type):
    """Compute per-fd gaps for read/write using position tracking.

    Replays openat/close/lseek/read/write events to reconstruct file positions,
    then computes gaps between successive IOs per fd.

    Uses numpy arrays for fast iteration (avoids pandas iterrows overhead).
    """
    # Pre-filter to only events that affect position or are target enters
    mask = (
        ((tracker_df["event"] == "exit") & tracker_df["syscall"].isin({"openat", "lseek", sc_type})) |
        ((tracker_df["event"] == "enter") & tracker_df["syscall"].isin({sc_type, "close"}))
    )
    df = tracker_df[mask].sort_values("timestamp_ns")

    # Extract numpy arrays for fast access (no pandas per-row overhead)
    events = df["event"].to_numpy(dtype=str)
    syscalls = df["syscall"].to_numpy(dtype=str)
    tids = df["tid"].to_numpy(dtype="float64")
    fds = df["fd"].to_numpy(dtype="float64")
    bytes_arr = df["bytes"].to_numpy(dtype="float64")

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


def _plot_fs_gap_cdf(ax, df, types, tracker_df=None):
    """Plot gap CDF for FS layer.

    pread64/pwrite64: per-fd gaps using explicit offsets from enter events.
    read/write: per-fd gaps using position tracking (openat/lseek/close replay).
    """
    enters = df[df["event"] == "enter"]

    for i, typ in enumerate(types):
        if typ in ("pread64", "pwrite64"):
            # Per-fd gap computation using explicit offsets
            sub = enters[enters["syscall"] == typ].sort_values("timestamp_ns")
            all_gaps = []
            for _, fd_group in sub.groupby("fd"):
                locations = fd_group["offset"].dropna().values
                sizes = fd_group["bytes"].values[:len(locations)]
                if len(locations) < 2:
                    continue
                expected = locations[:-1] + sizes[:len(locations) - 1]
                all_gaps.append(np.abs(locations[1:] - expected))
            if not all_gaps:
                continue
            gaps = np.concatenate(all_gaps)
        elif typ in ("read", "write") and tracker_df is not None:
            gaps = _compute_rw_gaps(tracker_df, typ)
            if len(gaps) == 0:
                continue
        else:
            continue

        sorted_gaps = np.sort(gaps)
        cdf = np.arange(1, len(sorted_gaps) + 1) / len(sorted_gaps) * 100
        ax.plot(sorted_gaps, cdf, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xscale("symlog")
    ax.set_xlabel("Gap (bytes)")
    ax.set_ylabel("Cumulative %")
    ax.set_title("Gap CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def _build_row(label, df, tracker_df=None):
    """Build a dashboard row dict from a dataframe.

    df: IO-only events (read/write/pread64/pwrite64)
    tracker_df: all events including openat/close/lseek (for position tracking)
    """
    if tracker_df is None:
        tracker_df = df
    exits = df[df["event"] == "exit"]
    types = sorted(exits["syscall"].dropna().unique())
    counts = exits.groupby("syscall").size().to_dict()
    has_inflight = "inflight" in df.columns

    if has_inflight:
        inflight_fn = lambda ax, d=df, t=types: plot_inflight_from_column(ax, d, "syscall", "timestamp_ns", t)
    else:
        inflight_fn = lambda ax, d=df, t=types: plot_inflight_over_time(ax, d, "enter", "exit", "syscall", "timestamp_ns", t)

    return {
        "label": label,
        "plots": [
            lambda ax, c=counts: plot_type_distribution(ax, c),
            inflight_fn,
            lambda ax, d=df, t=types: plot_cumulated_mb_over_time(ax, d, "exit", "syscall", "timestamp_ns", "bytes", t),
            lambda ax, e=exits, t=types: plot_io_size_cdf(ax, e, "syscall", "bytes", t),
            lambda ax, e=exits, t=types: plot_io_latency_cdf(ax, e, "syscall", "latency_ns", t),
            lambda ax, d=df, t=types, td=tracker_df: _plot_fs_gap_cdf(ax, d, t, td),
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
    has_inflight = "inflight" in header
    usecols = USECOLS + (["comm"] if has_comm else []) + (["inflight"] if has_inflight else [])

    # Use category dtype for string columns to reduce memory
    cat_cols = {"event": "category", "syscall": "category"}
    if has_comm:
        cat_cols["comm"] = "category"

    # Load tracker syscalls (IO + openat/close/lseek for position tracking)
    full_df = pd.read_csv(csv_path, usecols=usecols, dtype=cat_cols)
    full_df = full_df[full_df["syscall"].isin(TRACKER_SYSCALLS)].copy()
    # IO-only view for most plots
    df = full_df[full_df["syscall"].isin(IO_SYSCALLS)]

    rows = []
    if has_comm:
        for comm_val in sorted(df["comm"].dropna().unique()):
            comm_df = df[df["comm"] == comm_val]
            tracker_df = full_df[full_df["comm"] == comm_val]
            rows.append(_build_row(comm_val, comm_df, tracker_df))
    else:
        rows.append(_build_row("fs", df, full_df))

    output = results_dir / "visualizations" / "fs-dashboard.png"
    build_dashboard(
        rows=rows,
        col_titles=["Type Distribution", "Inflight", "Cumul. MB", "IO Size CDF", "Latency CDF", "Gap CDF"],
        title="Filesystem Layer Dashboard",
        output_path=output,
    )


if __name__ == "__main__":
    main()
