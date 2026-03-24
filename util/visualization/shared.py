"""Shared plotting utilities for FuStIP visualization dashboards."""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import polars as pl

TYPE_COLORS = {
    "read": "#cecece",
    "write": "#a559aa",
    "pread64": "#59a89c",
    "pwrite64": "#f0c571",
    "flush": "#e02b35",
    "discard": "#082a54",
    "write_zeros": "#d47264",
}

DEFAULT_COLOR_CYCLE = plt.rcParams["axes.prop_cycle"].by_key()["color"]


def _color_for(typ, idx=0):
    return TYPE_COLORS.get(typ, DEFAULT_COLOR_CYCLE[idx % len(DEFAULT_COLOR_CYCLE)])


def plot_type_distribution(ax, counts_by_type):
    """Pie chart of IO type distribution with side legend."""
    types = list(counts_by_type.keys())
    counts = [counts_by_type[t] for t in types]
    total = sum(counts)
    colors = [_color_for(t, i) for i, t in enumerate(types)]
    labels = [f"{t}: {c} ({c / total * 100:.1f}%)" for t, c in zip(types, counts)]

    wedges, _ = ax.pie(counts, colors=colors, startangle=90)
    ax.legend(wedges, labels, fontsize="small", loc="center left",
              bbox_to_anchor=(1.02, 0.5))
    ax.set_title("Type Distribution")


def plot_inflight_over_time(ax, df, enter_event, exit_event, type_col, ts_col, types, title="Inflight Over Time"):
    """Per-type inflight count in 1-second windows."""
    ts_vals = df[ts_col].to_numpy()
    t_min = int(ts_vals.min())
    t_max = int(ts_vals.max())
    window_ns = 1_000_000_000

    for i, typ in enumerate(types):
        enter_ts = df.filter((pl.col("event") == enter_event) & (pl.col(type_col) == typ))[ts_col].to_numpy()
        exit_ts = df.filter((pl.col("event") == exit_event) & (pl.col(type_col) == typ))[ts_col].to_numpy()
        if len(enter_ts) == 0:
            continue
        times = []
        values = []
        t = t_min
        sec = 0
        while t <= t_max:
            inflight = int((enter_ts <= t).sum() - (exit_ts <= t).sum())
            times.append(sec)
            values.append(max(0, inflight))
            t += window_ns
            sec += 1
        ax.plot(times, values, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Inflight")
    ax.set_title(title)
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_inflight_from_column(ax, df, type_col, ts_col, types,
                              inflight_col="inflight", title="Inflight Over Time"):
    """Plot inflight from pre-computed column in event CSV."""
    t_min = df[ts_col].min()
    window_ns = 1_000_000_000
    for i, typ in enumerate(types):
        typ_df = df.filter(pl.col(type_col) == typ).sort(ts_col)
        if len(typ_df) == 0:
            continue
        ts_arr = typ_df[ts_col].to_numpy()
        secs = ((ts_arr - t_min) / window_ns).astype(int)
        typ_df = typ_df.with_columns(pl.Series("sec", secs))
        sampled = typ_df.group_by("sec").agg(pl.col(inflight_col).last()).sort("sec")
        ax.plot(sampled["sec"].to_numpy(),
                sampled[inflight_col].to_numpy().clip(min=0),
                label=typ, color=_color_for(typ, i), linewidth=0.8)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Inflight")
    ax.set_title(title)
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_cumulated_mb_over_time(ax, df, complete_event, type_col, ts_col, bytes_col, types):
    """Cumulative MB transferred in 1-second windows."""
    completed = df.filter(pl.col("event") == complete_event)
    ts_vals = df[ts_col].to_numpy()
    t_min = int(ts_vals.min())
    t_max = int(ts_vals.max())
    window_ns = 1_000_000_000

    for i, typ in enumerate(types):
        typ_df = completed.filter(pl.col(type_col) == typ)
        if len(typ_df) == 0:
            continue
        ts = typ_df[ts_col].to_numpy()
        bts = typ_df[bytes_col].to_numpy()
        times = []
        cumul = []
        t = t_min
        sec = 0
        total = 0.0
        while t <= t_max:
            mask = ts <= t
            total = bts[mask].sum() / (1024 * 1024)
            times.append(sec)
            cumul.append(total)
            t += window_ns
            sec += 1
        ax.plot(times, cumul, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Cumulative MB")
    ax.set_title("Cumulative MB Over Time")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_io_size_cdf(ax, df, type_col, bytes_col, types):
    """CDF of IO sizes per type, log-scale x-axis."""
    for i, typ in enumerate(types):
        vals = df.filter(pl.col(type_col) == typ).drop_nulls(bytes_col)[bytes_col].to_numpy()
        if len(vals) == 0:
            continue
        sorted_vals = np.sort(vals)
        cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals)
        ax.plot(sorted_vals, cdf, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xscale("log")
    ax.set_xlabel("IO Size (bytes)")
    ax.set_ylabel("CDF")
    ax.set_title("IO Size CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_io_latency_cdf(ax, df, type_col, latency_col, types):
    """CDF of IO latencies per type, log-scale x-axis."""
    for i, typ in enumerate(types):
        vals = df.filter(pl.col(type_col) == typ).drop_nulls(latency_col)[latency_col].to_numpy()
        vals = vals[vals > 0]
        if len(vals) == 0:
            continue
        sorted_vals = np.sort(vals)
        cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals)
        ax.plot(sorted_vals / 1000, cdf, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xscale("log")
    ax.set_xlabel("Latency (us)")
    ax.set_ylabel("CDF")
    ax.set_title("IO Latency CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_gap_cdf(ax, df, type_col, sector_or_offset_col, bytes_col, types,
                 sector_divisor=512, xlabel="Gap (sectors)"):
    """CDF of address gaps between successive IOs per type (submission order).

    sector_divisor: 512 for sector-based (block/nvme), 1 for byte offsets (fs).
    """
    for i, typ in enumerate(types):
        sub = df.filter(pl.col(type_col) == typ).sort("timestamp_ns")
        locations = sub.drop_nulls(sector_or_offset_col)[sector_or_offset_col].to_numpy()
        sizes = sub[bytes_col].to_numpy()[:len(locations)]
        if len(locations) < 2:
            continue
        expected = locations[:-1] + sizes[:len(locations) - 1] // sector_divisor
        gaps = np.abs(locations[1:] - expected)
        sorted_gaps = np.sort(gaps)
        cdf = np.arange(1, len(sorted_gaps) + 1) / len(sorted_gaps) * 100
        ax.plot(sorted_gaps, cdf, label=typ, color=_color_for(typ, i), linewidth=0.8)

    ax.set_xscale("symlog")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Cumulative %")
    ax.set_title("Gap CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def build_dashboard(rows, col_titles, title, output_path):
    """Build a multi-row dashboard.

    Args:
        rows: list of dicts, each with:
            - "label": row label (str)
            - "plots": list of callables, each taking an Axes argument
        col_titles: list of column title strings
        title: overall figure title
        output_path: Path to save PNG
    """
    nrows = len(rows)
    ncols = len(col_titles)
    fig, axes = plt.subplots(nrows, ncols, figsize=(5 * ncols, 4 * nrows),
                             squeeze=False)
    fig.suptitle(title, fontsize=14, fontweight="bold")

    for r, row in enumerate(rows):
        for c, plot_fn in enumerate(row["plots"]):
            ax = axes[r, c]
            plot_fn(ax)

    # Unify y-axes per column, starting at 0 for non-negative data
    for c in range(ncols):
        y_min = min(axes[r, c].get_ylim()[0] for r in range(nrows))
        y_max = max(axes[r, c].get_ylim()[1] for r in range(nrows))
        if y_min >= 0:
            y_min = 0
        for r in range(nrows):
            axes[r, c].set_ylim(y_min, y_max)

    # Leave room at top for suptitle and left for row labels
    fig.tight_layout(pad=1.5, h_pad=3.0, w_pad=2.0,
                     rect=[0.03, 0, 1, 0.96])

    # Add row labels on the far left after layout
    for r, row in enumerate(rows):
        bbox = axes[r, 0].get_position()
        y_center = (bbox.y0 + bbox.y1) / 2
        fig.text(0.005, y_center, row["label"],
                 ha="left", va="center", fontsize=11,
                 fontweight="bold", rotation=90)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  -> {output_path}")
