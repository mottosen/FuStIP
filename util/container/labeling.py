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

