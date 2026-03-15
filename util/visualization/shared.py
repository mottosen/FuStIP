"""Shared plotting utilities for FuStIP visualization dashboards."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

TYPE_COLORS = {
    "read": "#1f77b4",
    "write": "#ff7f0e",
    "pread64": "#1f77b4",
    "pwrite64": "#ff7f0e",
    "flush": "#2ca02c",
    "discard": "#d62728",
    "write_zeros": "#9467bd",
}

DEFAULT_COLOR_CYCLE = plt.rcParams["axes.prop_cycle"].by_key()["color"]


def _color_for(typ, idx=0):
    return TYPE_COLORS.get(typ, DEFAULT_COLOR_CYCLE[idx % len(DEFAULT_COLOR_CYCLE)])


def plot_type_distribution(ax, counts_by_type):
    """Pie chart of IO type distribution."""
    types = list(counts_by_type.keys())
    counts = [counts_by_type[t] for t in types]
    total = sum(counts)
    colors = [_color_for(t, i) for i, t in enumerate(types)]
    labels = [f"{t}\n{c} ({c / total * 100:.1f}%)" for t, c in zip(types, counts)]

    ax.pie(counts, labels=labels, colors=colors, startangle=90)
    ax.set_title("Type Distribution")


def plot_inflight_over_time(ax, df, enter_event, exit_event, type_col, ts_col, types, title="Inflight Over Time"):
    """Per-type inflight count in 1-second windows."""
    t_min = df[ts_col].min()
    t_max = df[ts_col].max()
    window_ns = 1_000_000_000

    for i, typ in enumerate(types):
        enter_ts = df[(df["event"] == enter_event) & (df[type_col] == typ)][ts_col].values
        exit_ts = df[(df["event"] == exit_event) & (df[type_col] == typ)][ts_col].values
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
        typ_df = df[df[type_col] == typ].sort_values(ts_col)
        if typ_df.empty:
            continue
        secs = ((typ_df[ts_col].values - t_min) / window_ns).astype(int)
        typ_df = typ_df.assign(sec=secs)
        sampled = typ_df.groupby("sec")[inflight_col].last()
        ax.plot(sampled.index, sampled.values.clip(min=0), label=typ,
                color=_color_for(typ, i), linewidth=0.8)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Inflight")
    ax.set_title(title)
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_cumulated_mb_over_time(ax, df, complete_event, type_col, ts_col, bytes_col, types):
    """Cumulative MB transferred in 1-second windows."""
    completed = df[df["event"] == complete_event]
    t_min = df[ts_col].min()
    t_max = df[ts_col].max()
    window_ns = 1_000_000_000

    for i, typ in enumerate(types):
        typ_df = completed[completed[type_col] == typ]
        if len(typ_df) == 0:
            continue
        ts = typ_df[ts_col].values
        bts = typ_df[bytes_col].values
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
        vals = df[df[type_col] == typ][bytes_col].dropna().values
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
        vals = df[df[type_col] == typ][latency_col].dropna().values
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

    # Unify y-axes per column
    for c in range(ncols):
        y_min = min(axes[r, c].get_ylim()[0] for r in range(nrows))
        y_max = max(axes[r, c].get_ylim()[1] for r in range(nrows))
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
