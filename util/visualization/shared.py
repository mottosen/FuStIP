"""Shared plotting utilities for FuStIP visualization dashboards."""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import polars as pl
from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter, NullLocator

TYPE_COLORS = {
    "read": "#007191",
    "write": "#62c8d3",
    "pread64": "#f47a00",
    "pwrite64": "#d31f11",
    "flush": "#e02b35",
    "discard": "#082a54",
    "write_zeros": "#d47264",
}

TYPE_LINESTYLES = {
    "read": "solid",
    "write": "solid",
    "pread64": "solid",
    "pwrite64": "solid",
}

TYPE_ORDER = {
    "read": 0, "write": 1,
    "pread64": 2, "pwrite64": 3,
    "flush": 4, "discard": 5, "write_zeros": 6,
}

DEFAULT_COLOR_CYCLE = plt.rcParams["axes.prop_cycle"].by_key()["color"]

MAX_CDF_POINTS = 10_000


def _color_for(typ, idx=0):
    return TYPE_COLORS.get(typ, DEFAULT_COLOR_CYCLE[idx % len(DEFAULT_COLOR_CYCLE)])


def _linestyle_for(typ):
    return TYPE_LINESTYLES.get(typ, "solid")


def sort_types(types):
    """Sort IO types in canonical order: read, write, pread64, pwrite64, ..."""
    return sorted(types, key=lambda t: TYPE_ORDER.get(t, 99))


def _subsample_cdf(sorted_vals, max_points=MAX_CDF_POINTS):
    """Subsample sorted array for CDF plotting, preserving distribution shape."""
    n = len(sorted_vals)
    if n <= max_points:
        return sorted_vals, np.arange(1, n + 1) / n
    idx = np.linspace(0, n - 1, max_points, dtype=int)
    return sorted_vals[idx], (idx + 1) / n


def _format_gap_axis_exponents(ax):
    """Reduce gap-CDF x-axis clutter by labeling powers of 10 as exponents."""
    x_max = ax.get_xlim()[1]
    if x_max <= 0:
        return

    max_exp = int(np.floor(np.log10(x_max)))
    if max_exp < 0:
        return

    ticks = [float(10 ** exp) for exp in range(0, max_exp + 1)]
    exp_by_tick = {tick: exp for exp, tick in enumerate(ticks)}

    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda x, _pos: str(exp_by_tick.get(float(x), ""))))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.tick_params(axis="x", which="minor", bottom=False, labelbottom=False)
    ax.set_xlabel(f"{ax.get_xlabel()} (10^x)")


def _format_io_size_axis_powers_of_two(ax):
    """Format IO-size CDF axis with explicit binary-size labels (e.g. 4K, 64K)."""
    x_min, x_max = ax.get_xlim()
    if x_max <= 0:
        return

    x_min = max(x_min, 1.0)
    min_exp = int(np.floor(np.log2(x_min)))
    max_exp = int(np.ceil(np.log2(x_max)))
    if max_exp < min_exp:
        return

    span = max_exp - min_exp + 1
    step = 1 if span <= 16 else 2
    exps = list(range(min_exp, max_exp + 1, step))
    ticks = [float(2 ** exp) for exp in exps]

    ax.xaxis.set_major_locator(FixedLocator(ticks))

    def _fmt_size(v):
        v_i = int(round(v))
        units = [("T", 1024 ** 4), ("G", 1024 ** 3), ("M", 1024 ** 2), ("K", 1024)]
        for suffix, scale in units:
            if v_i >= scale and v_i % scale == 0:
                return f"{v_i // scale}{suffix}"
        return str(v_i)

    label_by_tick = {tick: _fmt_size(tick) for tick in ticks if tick > 0}
    ax.xaxis.set_major_formatter(
        FuncFormatter(lambda x, _pos: label_by_tick.get(float(x), ""))
    )
    ax.xaxis.set_minor_locator(NullLocator())
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.tick_params(axis="x", which="minor", bottom=False, labelbottom=False)
    ax.tick_params(axis="x", labelrotation=45)


def _format_log10_exponent_axis(ax, base_xlabel):
    """Format log-scale axis as exponent-only ticks with explicit 10^x label."""
    x_min, x_max = ax.get_xlim()
    if x_max <= 0:
        return

    x_min = max(x_min, np.finfo(float).tiny)
    min_exp = int(np.floor(np.log10(x_min)))
    max_exp = int(np.ceil(np.log10(x_max)))
    if max_exp < min_exp:
        return

    span = max_exp - min_exp + 1
    step = max(1, int(np.ceil(span / 8)))
    exps = list(range(min_exp, max_exp + 1, step))
    ticks = [float(10 ** exp) for exp in exps]
    exp_by_tick = {tick: exp for tick, exp in zip(ticks, exps)}

    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_major_formatter(
        FuncFormatter(lambda x, _pos: str(exp_by_tick.get(float(x), "")) if x > 0 else "")
    )
    ax.xaxis.set_minor_locator(NullLocator())
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.tick_params(axis="x", which="minor", bottom=False, labelbottom=False)
    ax.set_xlabel(f"{base_xlabel} (10^x)")


def plot_type_distribution(ax, counts_by_type):
    """Pie chart of IO type distribution with side legend."""
    types = sort_types(counts_by_type.keys())
    counts = [counts_by_type[t] for t in types]
    total = sum(counts)
    colors = [_color_for(t, i) for i, t in enumerate(types)]
    labels = [f"{t}: {c} ({c / total * 100:.1f}%)" for t, c in zip(types, counts)]

    wedges, _ = ax.pie(counts, colors=colors, startangle=90)
    ax.legend(wedges, labels, fontsize="small", loc="center left",
              bbox_to_anchor=(1.05, 0.5))
    ax.set_title("Type Distribution")


def plot_inflight_from_column(ax, df, type_col, types,
                              inflight_col="inflight", title="Inflight Over Time",
                              ylabel=None):
    """Plot inflight from pre-aggregated per-sec data.

    Expects df with columns: type_col, "sec", inflight_col
    (from group_by(type, sec).agg(inflight.last())).
    """
    for i, typ in enumerate(types):
        typ_df = df.filter(pl.col(type_col) == typ).sort("sec")
        if len(typ_df) == 0:
            continue
        ax.plot(typ_df["sec"].to_numpy(),
                typ_df[inflight_col].to_numpy().clip(min=0),
                label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel(ylabel if ylabel is not None else "Inflight")
    ax.set_title(title)
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_cumulated_mb_over_time(ax, df, type_col, bytes_col, types):
    """Cumulative MB from pre-aggregated per-sec byte sums.

    Expects df with columns: type_col, "sec", bytes_col
    (from group_by(type, sec).agg(bytes.sum()), already filtered to complete events).
    """
    for i, typ in enumerate(types):
        typ_df = df.filter(pl.col(type_col) == typ).sort("sec")
        if len(typ_df) == 0:
            continue
        cum_bytes = typ_df[bytes_col].cum_sum().to_numpy() / (1024 * 1024)
        ax.plot(typ_df["sec"].to_numpy(), cum_bytes,
                label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Cumulative MB")
    ax.set_title("Cumulative MB Over Time")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_io_size_cdf(ax, df, type_col, bytes_col, types):
    """CDF of IO sizes per type, log-scale x-axis."""
    data_min = None
    data_max = None
    for i, typ in enumerate(types):
        vals = df.filter(pl.col(type_col) == typ).drop_nulls(bytes_col)[bytes_col].to_numpy()
        vals = vals[vals > 0]
        if len(vals) == 0:
            continue
        t_min = float(vals.min())
        t_max = float(vals.max())
        data_min = t_min if data_min is None else min(data_min, t_min)
        data_max = t_max if data_max is None else max(data_max, t_max)
        sorted_vals = np.sort(vals)
        sorted_vals, cdf = _subsample_cdf(sorted_vals)
        ax.plot(sorted_vals, cdf, label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xscale("log", base=2)
    ax.set_xlabel("IO Size (bytes)")
    ax.set_ylabel("CDF")
    ax.set_title("IO Size CDF")
    if data_min is not None and data_max is not None:
        min_exp = int(np.floor(np.log2(data_min))) - 1
        max_exp = int(np.ceil(np.log2(data_max))) + 1
        ax.set_xlim(2 ** min_exp, 2 ** max_exp)
    _format_io_size_axis_powers_of_two(ax)
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_io_latency_cdf(ax, df, type_col, latency_col, types):
    """CDF of IO latencies per type, log-scale x-axis."""
    for i, typ in enumerate(types):
        vals = df.filter(pl.col(type_col) == typ).drop_nulls(latency_col)[latency_col].to_numpy()
        vals = vals[vals > 0]
        if len(vals) == 0:
            continue
        sorted_vals = np.sort(vals)
        sorted_vals, cdf = _subsample_cdf(sorted_vals)
        ax.plot(sorted_vals / 1000, cdf, label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xscale("log")
    ax.set_xlabel("Latency (us)")
    ax.set_ylabel("CDF")
    ax.set_title("IO Latency CDF")
    _format_log10_exponent_axis(ax, "Latency (us)")
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
        sorted_gaps, cdf = _subsample_cdf(sorted_gaps)
        ax.plot(sorted_gaps, cdf, label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xscale("symlog")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("CDF")
    ax.set_title("Gap CDF")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def _set_lba_yticks(ax, lba_min, lba_max):
    """Ensure lba_min and lba_max appear as explicit y-axis ticks.

    Keeps matplotlib's auto-generated interior ticks that fall within the range,
    then forces the exact endpoints to be present so the reader can see where the
    data window starts and stops.
    """
    lba_range = lba_max - lba_min
    tol = lba_range * 0.02  # within 2% of range counts as "already there"
    auto = [t for t in ax.get_yticks() if lba_min <= t <= lba_max]
    ticks = []
    if not any(abs(lba_min - t) < tol for t in auto):
        ticks.append(lba_min)
    ticks.extend(auto)
    if not any(abs(lba_max - t) < tol for t in auto):
        ticks.append(lba_max)
    ax.set_yticks(sorted(set(ticks)))
    ax.set_ylim(lba_min, lba_max)


def plot_lba_density(ax, density_df, type_col, lba_bin_col, count_col,
                     lba_min, lba_max, types, n_bins=512):
    """Plot LBA density histogram from pre-binned data.

    density_df: DataFrame with columns [type_col, lba_bin_col (0..n_bins-1), count_col]
    """
    lba_range = max(lba_max - lba_min, 1)
    bin_size = lba_range / n_bins
    x_ticks = np.arange(n_bins) * bin_size + lba_min

    for i, typ in enumerate(types):
        sub = density_df.filter(pl.col(type_col) == typ).sort(lba_bin_col)
        if len(sub) == 0:
            continue
        counts = np.zeros(n_bins, dtype=np.int64)
        for row in sub.iter_rows(named=True):
            counts[row[lba_bin_col]] = row[count_col]
        ax.plot(counts, x_ticks, label=typ, color=_color_for(typ, i),
                linestyle=_linestyle_for(typ), linewidth=0.8)

    ax.set_xlabel("IO Count")
    ax.set_ylabel("LBA")
    ax.set_ylim(lba_min, lba_max)
    _set_lba_yticks(ax, lba_min, lba_max)
    ax.set_title("LBA Density")
    ax.legend(fontsize="small", loc="upper left", bbox_to_anchor=(1.02, 1.0))


def plot_lba_heatmap_2d(ax, heatmap_df, op, n_lba_bins, n_time_bins,
                         lba_min, lba_max, duration_s, vmax_log=None):
    """Plot 2D time×LBA heatmap for a single op type.

    heatmap_df: DataFrame with columns ["time_bin", "lba_bin", "count"] for this op.
    vmax_log: if provided, fixes the colour scale at this log1p(count) value so that
              multiple rows sharing the same op column are comparable.
    """
    mat = np.zeros((n_lba_bins, n_time_bins), dtype=np.float32)
    for row in heatmap_df.iter_rows(named=True):
        mat[row["lba_bin"], row["time_bin"]] = row["count"]

    mat_log = np.log1p(mat)
    local_vmax_log = float(mat_log.max())
    effective_vmax_log = max(vmax_log if vmax_log is not None else local_vmax_log, 1e-6)
    im = ax.imshow(mat_log, aspect="auto", origin="lower", cmap="inferno",
                   extent=[0, duration_s, lba_min, lba_max],
                   vmin=0, vmax=effective_vmax_log)
    cb = ax.figure.colorbar(im, ax=ax, label="IO count")
    # Tick labels show actual IO counts (inverse of log1p), anchored to the shared scale.
    if effective_vmax_log > 0:
        actual_max = float(np.expm1(effective_vmax_log))
        magnitude = max(0, int(np.log10(max(actual_max, 1))))
        raw_ticks = sorted({0} | {10**i for i in range(magnitude + 1)} | {int(actual_max)})
        log_ticks = [np.log1p(v) for v in raw_ticks if np.log1p(v) <= effective_vmax_log * 1.001]
        cb.set_ticks(log_ticks)
        cb.set_ticklabels([str(int(np.expm1(t))) for t in log_ticks])
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("LBA")
    _set_lba_yticks(ax, lba_min, lba_max)
    ax.set_title(f"LBA Heatmap ({op})")


def build_dashboard(rows, col_titles, title, output_path, col_ylims=None):
    """Build a multi-row dashboard.

    Args:
        rows: list of dicts, each with:
            - "label": row label (str)
            - "plots": list of callables, each taking an Axes argument
        col_titles: list of column title strings
        title: overall figure title
        output_path: Path to save PNG
        col_ylims: optional list of (ymin, ymax) tuples per column, or None
            for auto-scaled columns. Length must match col_titles.
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

    # Unify y-axes per column, starting at 0 for non-negative data.
    # col_ylims[c] == "per_row" means skip unification and let each row auto-scale.
    for c in range(ncols):
        if col_ylims and col_ylims[c] == "per_row":
            continue
        if col_ylims and col_ylims[c] is not None:
            y_min, y_max = col_ylims[c]
        else:
            y_min = min(axes[r, c].get_ylim()[0] for r in range(nrows))
            y_max = max(axes[r, c].get_ylim()[1] for r in range(nrows))
            if y_min >= 0:
                y_min = 0
        for r in range(nrows):
            axes[r, c].set_ylim(y_min, y_max)

    # Unify x-axes per column for time-series columns (non-CDF, non-pie)
    for c in range(ncols):
        if "CDF" in col_titles[c] or "Distribution" in col_titles[c]:
            continue
        xlims = [axes[r, c].get_xlim() for r in range(nrows)]
        x_min = min(lim[0] for lim in xlims)
        x_max = max(lim[1] for lim in xlims)
        if x_min < x_max:
            for r in range(nrows):
                axes[r, c].set_xlim(x_min, x_max)

    cdf_cols = [c for c, title_str in enumerate(col_titles) if "CDF" in title_str]
    for c in cdf_cols:
        x_scale_set = {axes[r, c].get_xscale() for r in range(nrows)}
        if len(x_scale_set) != 1:
            continue

        x_scale = x_scale_set.pop()
        x_max = max(axes[r, c].get_xlim()[1] for r in range(nrows))
        x_min_candidates = [axes[r, c].get_xlim()[0] for r in range(nrows)]
        if x_scale == "log":
            pos_mins = [x for x in x_min_candidates if x > 0]
            if not pos_mins:
                continue
            x_min = min(pos_mins)
        elif x_scale == "symlog":
            x_min = min(0.0, *(x for x in x_min_candidates if np.isfinite(x)))
        else:
            x_min = min(x_min_candidates)

        for r in range(nrows):
            axes[r, c].set_xlim(x_min, x_max)
            axes[r, c].set_ylim(0.0, 1.0)
            if "IO Size CDF" in col_titles[c]:
                _format_io_size_axis_powers_of_two(axes[r, c])
            if "Latency CDF" in col_titles[c]:
                _format_log10_exponent_axis(axes[r, c], "Latency (us)")
            if "Gap CDF" in col_titles[c]:
                _format_gap_axis_exponents(axes[r, c])

    # Leave room at top for suptitle and left for row labels
    fig.tight_layout(pad=1.5, h_pad=3.0, w_pad=3.5,
                     rect=[0.03, 0.03, 1, 0.96])

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
