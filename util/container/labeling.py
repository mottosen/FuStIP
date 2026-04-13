#!/usr/bin/env python3
"""Shared container label helpers for detailed layer stats/visualizations."""

import json
from pathlib import Path

import polars as pl


def load_mntns_label_map(results_dir: Path) -> dict[str, str]:
    """Load results/container_map.json as {mntns_id_str: container_label}."""
    path = results_dir / "container_map.json"
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    mapping: dict[str, str] = {}
    for cname, payload in data.get("containers", {}).items():
        if not isinstance(payload, dict):
            continue
        for ns in payload.get("mntns_ids", []):
            mapping[str(ns)] = cname
    return mapping


def load_comm_label_map(results_dir: Path) -> dict[str, str]:
    """Load results/container_map.json as {comm: container_label} for containers
    whose mntns_ids are empty (mntns-based labeling not available for them)."""
    path = results_dir / "container_map.json"
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    mapping: dict[str, str] = {}
    for cname, payload in data.get("containers", {}).items():
        if not isinstance(payload, dict):
            continue
        if payload.get("mntns_ids"):
            continue  # covered by mntns-based labeling
        for comm in payload.get("comms", []):
            mapping[comm] = cname
    return mapping


def get_comm_label(comm: str, mntns_id_str: str,
                   mntns_map: dict[str, str],
                   comm_map: dict[str, str] | None = None) -> str:
    """Resolve label for a (comm, mntns_id_str) pair.

    Priority: mntns-based container label > comm-based container label > raw comm.
    """
    if mntns_map and mntns_id_str:
        label = mntns_map.get(str(mntns_id_str))
        if label:
            return label
    if comm_map:
        label = comm_map.get(comm)
        if label:
            return label
    return comm


def _merge_stats(dominant: dict, other: dict) -> dict:
    """Merge two series_stats dicts. dominant's quantiles are kept."""
    total = dominant["count"] + other["count"]
    mean = (
        round((dominant["mean"] * dominant["count"] + other["mean"] * other["count"]) / total, 2)
        if total > 0 else 0.0
    )
    return {
        "count": total,
        "min": min(dominant["min"], other["min"]),
        "max": max(dominant["max"], other["max"]),
        "mean": mean,
        "p1": dominant["p1"],
        "p5": dominant["p5"],
        "p50": dominant["p50"],
        "p95": dominant["p95"],
        "p99": dominant["p99"],
    }


def _total_io_count(entry: dict) -> int:
    """Sum all per-op counter values — used to rank dominant comm."""
    total = 0
    for ops in entry.get("counters", {}).values():
        if isinstance(ops, dict):
            total += sum(v for v in ops.values() if isinstance(v, (int, float)))
    return total


def _merge_entry_list(entries: list[dict]) -> dict:
    """Merge a list of per-comm entries (dominant first) into one.

    - counters: sum per-op values across all entries
    - distributions: merge stats (sum count/min/max/mean; dominant's quantiles)
    - tseries: keep dominant comm's (background comms have negligible inflight)
    - access_pattern: keep dominant comm's
    """
    if len(entries) == 1:
        return entries[0]

    merged: dict = {
        "counters": {},
        "distributions": {},
        "tseries": entries[0].get("tseries", {}),
        "access_pattern": entries[0].get("access_pattern", {}),
    }

    for entry in entries:
        for metric, ops_dict in entry.get("counters", {}).items():
            if metric not in merged["counters"]:
                merged["counters"][metric] = dict(ops_dict)
            else:
                for op, v in ops_dict.items():
                    merged["counters"][metric][op] = merged["counters"][metric].get(op, 0) + v

        for metric, ops_dict in entry.get("distributions", {}).items():
            merged["distributions"].setdefault(metric, {})
            for op, stats in ops_dict.items():
                if op not in merged["distributions"][metric]:
                    merged["distributions"][metric][op] = dict(stats)
                else:
                    merged["distributions"][metric][op] = _merge_stats(
                        merged["distributions"][metric][op], stats
                    )

    return merged


def bind_containers(entries: dict, mntns_map: dict[str, str],
                    comm_map: dict[str, str] | None = None) -> dict:
    """Map {(comm, mntns_id_str): entry} → {per_comm: ..., per_container: ...}.

    Groups entries by resolved label (container name or raw comm), merges
    multiple comms mapping to the same container, and splits into
    per_comm (host processes) vs per_container buckets.
    """
    container_labels = set(mntns_map.values()) | set((comm_map or {}).values())

    label_groups: dict[str, list] = {}
    for (comm, mntns_id_str), entry in entries.items():
        label = get_comm_label(comm, mntns_id_str, mntns_map, comm_map)
        label_groups.setdefault(label, []).append((_total_io_count(entry), entry))

    result: dict = {"per_comm": {}, "per_container": {}}
    for label, count_entries in label_groups.items():
        sorted_entries = [e for _, e in sorted(count_entries, key=lambda x: x[0], reverse=True)]
        merged = _merge_entry_list(sorted_entries)
        bucket = "per_container" if label in container_labels else "per_comm"
        result[bucket][label] = merged

    return result


def add_label_column(lf: pl.LazyFrame, mntns_map: dict[str, str],
                     comm_map: dict[str, str] | None = None) -> pl.LazyFrame:
    """Add a 'label' column: container label by mntns, then by comm (for containers
    whose mntns_ids were not collected), else raw comm, else 'other'."""
    schema = lf.collect_schema()
    if "label" in schema:
        return lf
    if "comm" not in schema:
        return lf.with_columns(pl.lit("other").alias("label"))
    if not mntns_map or "mntns_id" not in schema:
        if comm_map:
            comm_keys = list(comm_map.keys())
            comm_container = (
                pl.when(pl.col("comm").is_in(comm_keys))
                .then(pl.col("comm").replace(comm_map))
                .otherwise(None)
            )
            return lf.with_columns(
                pl.coalesce([comm_container, pl.col("comm"), pl.lit("other")]).alias("label")
            )
        return lf.with_columns(pl.col("comm").fill_null("other").alias("label"))

    ns_keys = list(mntns_map.keys())
    ns_str = pl.col("mntns_id").cast(pl.Utf8)
    container_label = (
        pl.when(ns_str.is_in(ns_keys))
        .then(ns_str.replace(mntns_map))
        .otherwise(None)
    )
    if comm_map:
        comm_keys = list(comm_map.keys())
        comm_container = (
            pl.when(pl.col("comm").is_in(comm_keys))
            .then(pl.col("comm").replace(comm_map))
            .otherwise(None)
        )
        return lf.with_columns(
            pl.coalesce([container_label, comm_container, pl.col("comm"), pl.lit("other")]).alias("label")
        )
    return lf.with_columns(
        pl.coalesce([container_label, pl.col("comm"), pl.lit("other")]).alias("label")
    )

