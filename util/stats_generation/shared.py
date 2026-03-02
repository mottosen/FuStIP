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


def histogram_stats(buckets):
    """Compute stats from a histogram bucket list.

    Input: [{"lo": int, "hi": int, "count": int}, ...]
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99"}

    Uses geometric midpoint for mean estimation (appropriate for power-of-2 buckets).
    Percentiles use linear interpolation within the target bucket on log scale.
    """
    total = sum(b["count"] for b in buckets)
    if total == 0:
        return {"count": 0, "min": 0, "max": 0, "mean": 0,
                "p1": 0, "p5": 0, "p50": 0, "p95": 0, "p99": 0}

    # Find min/max from first/last non-zero bucket
    non_zero = [b for b in buckets if b["count"] > 0]
    bmin = non_zero[0]["lo"]
    bmax = non_zero[-1]["hi"]

    # Mean using geometric midpoint
    weighted_sum = 0.0
    for b in buckets:
        if b["count"] > 0:
            if b["lo"] > 0:
                midpoint = math.sqrt(b["lo"] * b["hi"])
            else:
                midpoint = b["hi"] / 2.0
            weighted_sum += midpoint * b["count"]
    mean = weighted_sum / total

    # Percentiles via CDF interpolation
    def hist_percentile(p_val):
        target = p_val / 100.0 * total
        cumulative = 0
        for b in buckets:
            prev_cumulative = cumulative
            cumulative += b["count"]
            if cumulative >= target and b["count"] > 0:
                fraction = (target - prev_cumulative) / b["count"]
                if b["lo"] > 0:
                    return b["lo"] * math.pow(b["hi"] / b["lo"], fraction)
                else:
                    return b["hi"] * fraction
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


def tseries_stats(points):
    """Compute stats from a time-series point list.

    Input: [{"time": str, "value": int}, ...]
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99",
             "area_under_curve"}

    area_under_curve = sum of values (1-second intervals assumed).
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
        "area_under_curve": total,
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


def raw_values_to_hist_buckets(values):
    """Bin raw numeric values into power-of-2 histogram buckets.

    Matches the bucket format used by bpftrace's hist() function.
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

    result = []
    for (lo, hi), count in sorted(buckets.items()):
        result.append({"lo": lo, "hi": hi, "count": count})
    return result


def series_stats(values):
    """Compute stats from a plain list of numeric values.

    Input: list of numbers
    Output: {"count", "min", "max", "mean", "p1", "p5", "p50", "p95", "p99"}
    """
    if not values:
        return {"count": 0, "min": 0, "max": 0, "mean": 0,
                "p1": 0, "p5": 0, "p50": 0, "p95": 0, "p99": 0}

    sorted_vals = sorted(values)
    n = len(values)
    total = sum(values)

    return {
        "count": n,
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "mean": round(total / n, 2),
        "p1": round(percentile(sorted_vals, 1), 2),
        "p5": round(percentile(sorted_vals, 5), 2),
        "p50": round(percentile(sorted_vals, 50), 2),
        "p95": round(percentile(sorted_vals, 95), 2),
        "p99": round(percentile(sorted_vals, 99), 2),
    }
