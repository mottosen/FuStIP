#!/usr/bin/env python3
"""Shared parsing and stats computation for bpftrace output files.

Parses three data types from bpftrace text output:
  - Counters:   @map[key]: value
  - Histograms: @map[key]: or @map: followed by [lo, hi) count |bars| lines
  - Time-series: @map[key]: or @map: followed by hh:mm:ss ... | value lines

Unkeyed maps (e.g. @read_latencies:) use "_" as a synthetic key.

Provides stats computation (min, max, mean, percentiles, area under curve)
for histograms and time-series data.
"""

import math
import re

import numpy as np


# ── Suffix parsing ──

_SUFFIXES = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


def parse_value_with_suffix(s):
    """Parse a numeric string with optional K/M/G/T suffix.

    Examples: '4K' -> 4096, '128K' -> 131072, '1M' -> 1048576, '32' -> 32
    """
    s = s.strip()
    if s and s[-1] in _SUFFIXES:
        return int(s[:-1]) * _SUFFIXES[s[-1]]
    return int(s)


# ── Bpftrace output parsing ──

_COUNTER_RE = re.compile(r"^@(\w+)\[([^\]]+)\]:\s+(-?\d+)\s*$")
_KEYED_HEADER_RE = re.compile(r"^@(\w+)\[([^\]]+)\]:\s*$")
_UNKEYED_HEADER_RE = re.compile(r"^@(\w+):\s*$")
_HIST_BUCKET_RE = re.compile(r"^\[(\S+),\s+(\S+)\)\s+(\d+)\s+\|")
_TSERIES_DATA_RE = re.compile(r"^(\d{2}:\d{2}:\d{2})\s+.*[|*]\s*(-?\d+)\s*$")


def parse_counters(path):
    """Parse counter maps from bpftrace output.

    Returns: {"map_name": {"key": value, ...}, ...}
    """
    data = {}
    with open(path) as f:
        for line in f:
            m = _COUNTER_RE.match(line.strip())
            if m:
                map_name, key, value = m.group(1), m.group(2), int(m.group(3))
                data.setdefault(map_name, {})[key] = value
    return data


def parse_histograms(path):
    """Parse histogram maps from bpftrace output.

    Handles both keyed (@map[key]:) and unkeyed (@map:) headers.
    Unkeyed maps use "_" as the key.

    Returns: {"map_name": {"key": [{"lo": int, "hi": int, "count": int}, ...]}}
    """
    data = {}
    current_map = None
    current_key = None

    with open(path) as f:
        for line in f:
            stripped = line.strip()

            header = _KEYED_HEADER_RE.match(stripped)
            if header:
                current_map = header.group(1)
                current_key = header.group(2)
                continue

            unkeyed = _UNKEYED_HEADER_RE.match(stripped)
            if unkeyed:
                current_map = unkeyed.group(1)
                current_key = "_"
                continue

            bucket = _HIST_BUCKET_RE.match(stripped)
            if bucket and current_map is not None:
                lo = parse_value_with_suffix(bucket.group(1))
                hi = parse_value_with_suffix(bucket.group(2))
                count = int(bucket.group(3))
                data.setdefault(current_map, {}).setdefault(current_key, []).append(
                    {"lo": lo, "hi": hi, "count": count}
                )
                continue

            if stripped and not stripped.startswith(("[", "@", "|", "v", "h")):
                current_map = None
                current_key = None

    return data


def parse_tseries(path):
    """Parse time-series maps from bpftrace output.

    Handles both keyed (@map[key]:) and unkeyed (@map:) headers.
    Unkeyed maps use "_" as the key.

    Returns: {"map_name": {"key": [{"time": "HH:MM:SS", "value": int}, ...]}}
    """
    data = {}
    current_map = None
    current_key = None
    in_tseries = False

    with open(path) as f:
        for line in f:
            stripped = line.strip()

            header = _KEYED_HEADER_RE.match(stripped)
            if header:
                current_map = header.group(1)
                current_key = header.group(2)
                in_tseries = False
                continue

            unkeyed = _UNKEYED_HEADER_RE.match(stripped)
            if unkeyed:
                current_map = unkeyed.group(1)
                current_key = "_"
                in_tseries = False
                continue

            if current_map is not None and "hh:mm:ss" in stripped:
                in_tseries = True
                continue

            if in_tseries and current_map is not None:
                ts_match = _TSERIES_DATA_RE.match(stripped)
                if ts_match:
                    time_str = ts_match.group(1)
                    value = int(ts_match.group(2))
                    data.setdefault(current_map, {}).setdefault(
                        current_key, []
                    ).append({"time": time_str, "value": value})
                    continue

                if stripped.startswith("v") or stripped == "":
                    in_tseries = False
                    current_map = None
                    current_key = None

    return data


# ── Stats computation ──


def percentile(sorted_values, p):
    """Compute the p-th percentile from a sorted list of values."""
    if not sorted_values:
        return 0
    n = len(sorted_values)
    idx = p / 100.0 * (n - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_values[lo]
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def histogram_stats(hist_data):
    """Compute stats from histogram data (points + ranges).

    Input: {"points": [{"value": int, "count": int}, ...],
            "ranges": [{"lo": int, "hi": int, "count": int}, ...]}
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99"}

    Points are exact 2^i values (no estimation needed).
    Ranges use geometric midpoint for mean and log-scale interpolation for percentiles.
    """
    points = hist_data.get("points", [])
    ranges = hist_data.get("ranges", [])

    total = (sum(p["count"] for p in points)
             + sum(r["count"] for r in ranges))
    if total == 0:
        return {"count": 0, "min": 0, "max": 0, "mean": 0,
                "p1": 0, "p5": 0, "p50": 0, "p95": 0, "p99": 0}

    # Find min/max
    nz_points = [p for p in points if p["count"] > 0]
    nz_ranges = [r for r in ranges if r["count"] > 0]
    mins, maxs = [], []
    if nz_points:
        mins.append(nz_points[0]["value"])
        maxs.append(nz_points[-1]["value"])
    if nz_ranges:
        mins.append(nz_ranges[0]["lo"])
        maxs.append(nz_ranges[-1]["hi"])
    bmin = min(mins)
    bmax = max(maxs)

    # Mean: exact for points, geometric midpoint for ranges
    weighted_sum = 0.0
    for p in points:
        weighted_sum += p["value"] * p["count"]
    for r in ranges:
        if r["count"] > 0:
            if r["lo"] > 0:
                midpoint = math.sqrt(r["lo"] * r["hi"])
            else:
                midpoint = r["hi"] / 2.0
            weighted_sum += midpoint * r["count"]
    mean = weighted_sum / total

    # Merge points and ranges into sorted order for percentile walk.
    # A point at value V sorts before a range starting at V.
    entries = []
    for p in points:
        if p["count"] > 0:
            entries.append(("point", p["value"], p["count"]))
    for r in ranges:
        if r["count"] > 0:
            entries.append(("range", r["lo"], r["hi"], r["count"]))
    entries.sort(key=lambda e: (e[1], 0 if e[0] == "point" else 1))

    def hist_percentile(p_val):
        target = p_val / 100.0 * total
        cumulative = 0
        for entry in entries:
            prev_cumulative = cumulative
            if entry[0] == "point":
                _, value, count = entry
                cumulative += count
                if cumulative >= target:
                    return value
            else:
                _, lo, hi, count = entry
                cumulative += count
                if cumulative >= target:
                    fraction = (target - prev_cumulative) / count
                    if lo > 0:
                        return lo * math.pow(hi / lo, fraction)
                    else:
                        return hi * fraction
        return bmax

    return {
        "count": total,
        "min": bmin,
        "max": bmax,
        "mean": round(mean, 2),
        "p1": round(hist_percentile(1), 2),
        "p5": round(hist_percentile(5), 2),
        "p50": round(hist_percentile(50), 2),
        "p95": round(hist_percentile(95), 2),
        "p99": round(hist_percentile(99), 2),
    }


def _trapezoidal_auc(values):
    """Trapezoidal integration for uniformly-spaced (1-second) samples."""
    if len(values) <= 1:
        return sum(values)
    return values[0] / 2 + sum(values[1:-1]) + values[-1] / 2


def tseries_stats(points):
    """Compute stats from a time-series point list.

    Input: [{"time": str, "value": int}, ...]
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99",
             "area_under_curve"}

    area_under_curve uses trapezoidal rule (1-second intervals assumed).
    """
    if not points:
        return {"count": 0, "min": 0, "max": 0, "mean": 0,
                "p1": 0, "p5": 0, "p50": 0, "p95": 0, "p99": 0,
                "area_under_curve": 0}

    values = [p["value"] for p in points]
    sorted_vals = sorted(values)
    n = len(values)
    total = sum(values)

    return {
        "count": n,
        "min": min(values),
        "max": max(values),
        "mean": round(total / n, 2),
        "p1": round(percentile(sorted_vals, 1), 2),
        "p5": round(percentile(sorted_vals, 5), 2),
        "p50": round(percentile(sorted_vals, 50), 2),
        "p95": round(percentile(sorted_vals, 95), 2),
        "p99": round(percentile(sorted_vals, 99), 2),
        "area_under_curve": _trapezoidal_auc(values),
    }


def compute_duration_from_tseries(tseries_data):
    """Infer collection duration in seconds from tseries timestamps.

    Looks across all tseries maps/keys to find the widest time range.
    Returns duration in seconds, or 0 if no tseries data.
    """
    all_times = []
    for map_data in tseries_data.values():
        for points in map_data.values():
            for p in points:
                all_times.append(p["time"])

    if len(all_times) < 2:
        return 0

    def time_to_secs(t):
        parts = t.split(":")
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])

    secs = [time_to_secs(t) for t in all_times]
    return max(secs) - min(secs)


def derive_throughput(counters, duration_s, count_map, bytes_map):
    """Compute IOPS and throughput from counters.

    Args:
        counters: parsed counter data
        duration_s: collection duration in seconds
        count_map: name of the counter map for IO counts (e.g. "rq_issued")
        bytes_map: name of the counter map for total bytes (e.g. "rq_total_bytes")

    Returns: {"iops": {"read": N, ...}, "throughput_mb_s": {"read": N, ...}}
    """
    if duration_s <= 0:
        return {"iops": {}, "throughput_mb_s": {}}

    counts = counters.get(count_map, {})
    byte_totals = counters.get(bytes_map, {})

    iops = {}
    throughput = {}
    all_keys = set(list(counts.keys()) + list(byte_totals.keys()))

    for key in all_keys:
        count = counts.get(key, 0)
        total_bytes = byte_totals.get(key, 0)
        iops[key] = round(count / duration_s, 2)
        throughput[key] = round(total_bytes / duration_s / (1024 * 1024), 2)

    return {"iops": iops, "throughput_mb_s": throughput}


def histogram_stats_only(buckets):
    """Compute stats from histogram buckets without preserving bucket data.

    Input: [{"lo": int, "hi": int, "count": int}, ...]
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99"}
    """
    return histogram_stats({"points": [], "ranges": buckets})


def raw_values_to_hist(values):
    """Bin raw numeric values into exact 2^i points and inter-power ranges.

    Values that are exactly a power of 2 become points; all others fall into
    the range (2^i, 2^(i+1)) between the two nearest powers.

    Returns: {"points": [{"value": int, "count": int}, ...],
              "ranges": [{"lo": int, "hi": int, "count": int}, ...]}
    """
    if not values:
        return {"points": [], "ranges": []}

    pts = {}
    rngs = {}
    for v in values:
        if v <= 0:
            rngs[(0, 1)] = rngs.get((0, 1), 0) + 1
        else:
            exp = int(math.floor(math.log2(v)))
            power = 1 << exp
            if v == power:
                pts[v] = pts.get(v, 0) + 1
            else:
                hi = 1 << (exp + 1)
                rngs[(power, hi)] = rngs.get((power, hi), 0) + 1

    return {
        "points": [{"value": v, "count": c}
                    for v, c in sorted(pts.items())],
        "ranges": [{"lo": lo, "hi": hi, "count": c}
                    for (lo, hi), c in sorted(rngs.items())],
    }


def raw_values_to_hist_buckets(values):
    """Bin raw numeric values into power-of-2 histogram buckets.

    All values in [2^i, 2^(i+1)) go into one bucket (no point/range split).
    Use for latency histograms where exact-power hits are not meaningful.

    Returns: [{"lo": int, "hi": int, "count": int}, ...]
    """
    if not values:
        return []

    buckets = {}
    for v in values:
        if v <= 0:
            lo, hi = 0, 1
        else:
            exp = int(math.floor(math.log2(v)))
            lo = 1 << exp
            hi = 1 << (exp + 1)
        key = (lo, hi)
        buckets[key] = buckets.get(key, 0) + 1

    return [{"lo": lo, "hi": hi, "count": c}
            for (lo, hi), c in sorted(buckets.items())]


def series_stats(values):
    """Compute stats from a list or numpy array of numeric values.

    Input: list/array of numbers
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99"}
    """
    arr = np.asarray(values, dtype=np.float64)
    if len(arr) == 0:
        return {"count": 0, "min": 0, "max": 0, "mean": 0,
                "p1": 0, "p5": 0, "p50": 0, "p95": 0, "p99": 0}

    pcts = np.percentile(arr, [1, 5, 50, 95, 99])
    return {
        "count": len(arr),
        "min": round(float(arr.min()), 2),
        "max": round(float(arr.max()), 2),
        "mean": round(float(arr.mean()), 2),
        "p1": round(float(pcts[0]), 2),
        "p5": round(float(pcts[1]), 2),
        "p50": round(float(pcts[2]), 2),
        "p95": round(float(pcts[3]), 2),
        "p99": round(float(pcts[4]), 2),
    }


# ── Wrappers that preserve raw data alongside stats ──


def histogram_with_data(hist_data):
    """Wrap histogram data (points + ranges) with computed stats.

    Input: {"points": [...], "ranges": [...]}
    Returns: {"points": [...], "ranges": [...], "stats": {...}}
    """
    return {
        "points": hist_data["points"],
        "ranges": hist_data["ranges"],
        "stats": histogram_stats(hist_data),
    }


def histogram_with_buckets(buckets):
    """Wrap bucket-only histogram data with computed stats.

    For histograms where point/range splitting is not meaningful (e.g. latencies).
    Input: [{"lo": int, "hi": int, "count": int}, ...]
    Returns: {"buckets": [...], "stats": {...}}
    """
    return {
        "buckets": buckets,
        "stats": histogram_stats({"points": [], "ranges": buckets}),
    }


def _time_to_secs(t):
    """Parse a 24-hour time string HH:MM:SS to seconds."""
    h, m, s = (int(x) for x in t.strip().split(":"))
    return h * 3600 + m * 60 + s


def _sort_times_chronological(time_strings):
    """Sort HH:MM:SS strings chronologically, handling midnight crossings.

    Sorts by numeric value, then detects a gap > 12 hours between consecutive
    entries — the signature of a midnight boundary.  The sequence is rotated at
    that point so the chronological start (pre-midnight values) comes first.
    """
    times = sorted(set(time_strings), key=_time_to_secs)
    if len(times) < 2:
        return times
    secs = [_time_to_secs(t) for t in times]
    max_gap_idx = max(range(len(secs) - 1), key=lambda i: secs[i + 1] - secs[i])
    if secs[max_gap_idx + 1] - secs[max_gap_idx] > 43200:  # > 12 h → midnight
        split = max_gap_idx + 1
        times = times[split:] + times[:split]
    return times


def _normalize_times(points):
    """Convert time-series points to relative timestamps starting at 00:00:00."""
    if not points:
        return points
    base = _time_to_secs(points[0]["time"])
    result = []
    for p in points:
        offset = _time_to_secs(p["time"]) - base
        if offset < 0:
            offset += 86400  # run crossed midnight
        h, rem = divmod(offset, 3600)
        m, s = divmod(rem, 60)
        result.append({"time": f"{h:02d}:{m:02d}:{s:02d}", "value": p["value"]})
    return result


def tseries_with_points(points):
    """Wrap tseries_stats with the raw point data.

    Timestamps are normalized to be relative to 0 (00:00:00).
    Returns: {"points": [...], "stats": {...}}
    """
    normalized = _normalize_times(points)
    return {"points": normalized, "stats": tseries_stats(normalized)}


# ── Access pattern analysis ──


def compute_access_pattern(sectors, bytes_list):
    """Compute sequential/random access pattern from sector addresses.

    For consecutive IOs (already sorted by timestamp):
      gap = abs(sector[i+1] - (sector[i] + bytes[i] // 512))
      gap == 0 → sequential, gap > 0 → random

    Accepts lists or numpy arrays.

    Returns: {"total_ios", "sequential_count", "random_count",
              "sequential_pct", "random_pct"}
    """
    s = np.asarray(sectors, dtype=np.int64)
    b = np.asarray(bytes_list, dtype=np.int64)
    n = len(s)
    if n < 2:
        return {"total_ios": n, "sequential_count": 0, "random_count": 0,
                "sequential_pct": 0, "random_pct": 0}

    expected_next = s[:-1] + b[:-1] // 512
    gaps = np.abs(s[1:] - expected_next)
    seq_count = int((gaps == 0).sum())
    total_gaps = len(gaps)
    rnd_count = total_gaps - seq_count

    return {
        "total_ios": n,
        "sequential_count": seq_count,
        "random_count": rnd_count,
        "sequential_pct": round(100 * seq_count / total_gaps, 2),
        "random_pct": round(100 * rnd_count / total_gaps, 2),
    }


def compute_lba_distribution(sectors, bytes_list, device_sectors=None, n_bins=512):
    """Compute LBA space distribution histogram.

    For each IO, the start LBA (sector) is binned into one of n_bins buckets
    spanning [lba_min, lba_max).  lba_max is the total device size in sectors
    when device_sectors is provided, otherwise the observed maximum end-LBA.

    Accepts lists or numpy arrays.

    Returns: {"lba_min": int, "lba_max": int, "device_sectors": int|None,
              "n_bins": int,
              "bins": [{"lba_start": int, "count": int}, ...]}  # non-zero only
    """
    s = np.asarray(sectors, dtype=np.int64)
    b = np.asarray(bytes_list, dtype=np.int64)
    if len(s) == 0:
        return {"lba_min": 0, "lba_max": device_sectors or 0,
                "device_sectors": device_sectors, "n_bins": n_bins, "bins": []}
    lba_min = int(s.min())
    lba_observed_max = int((s + b // 512).max())
    lba_max = device_sectors if device_sectors is not None else lba_observed_max
    lba_range = max(lba_max - lba_min, 1)

    bin_idx = np.clip((s - lba_min) * n_bins // lba_range, 0, n_bins - 1).astype(np.int64)
    counts = np.bincount(bin_idx, minlength=n_bins)
    bin_lba_size = lba_range / n_bins

    return {
        "lba_min": lba_min,
        "lba_max": lba_max,
        "device_sectors": device_sectors,
        "n_bins": n_bins,
        "bins": [
            {"lba_start": int(lba_min + i * bin_lba_size), "count": int(counts[i])}
            for i in range(n_bins) if counts[i] > 0
        ],
    }


def compute_fs_access_pattern(offsets, bytes_list):
    """Compute sequential/random access pattern from byte offsets.

    Same logic as compute_access_pattern but uses byte offsets directly
    (for pread64/pwrite64 which have explicit file offsets).

    gap = abs(offset[i+1] - (offset[i] + bytes[i]))

    Accepts lists or numpy arrays.

    Returns: same structure as compute_access_pattern.
    """
    o = np.asarray(offsets, dtype=np.int64)
    b = np.asarray(bytes_list, dtype=np.int64)
    n = len(o)
    if n < 2:
        return {"total_ios": n, "sequential_count": 0, "random_count": 0,
                "sequential_pct": 0, "random_pct": 0}

    expected_next = o[:-1] + b[:-1]
    gaps = np.abs(o[1:] - expected_next)
    seq_count = int((gaps == 0).sum())
    total_gaps = len(gaps)
    rnd_count = total_gaps - seq_count

    return {
        "total_ios": n,
        "sequential_count": seq_count,
        "random_count": rnd_count,
        "sequential_pct": round(100 * seq_count / total_gaps, 2),
        "random_pct": round(100 * rnd_count / total_gaps, 2),
    }
