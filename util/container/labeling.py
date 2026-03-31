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


def add_label_column(lf: pl.LazyFrame, mntns_map: dict[str, str]) -> pl.LazyFrame:
    """Add a 'label' column: container label by mntns, else comm, else 'other'."""
    schema = lf.collect_schema()
    if "label" in schema:
        return lf
    if "comm" not in schema:
        return lf.with_columns(pl.lit("other").alias("label"))
    if not mntns_map or "mntns_id" not in schema:
        return lf.with_columns(pl.col("comm").fill_null("other").alias("label"))

    ns_keys = list(mntns_map.keys())
    ns_str = pl.col("mntns_id").cast(pl.Utf8)
    container_label = (
        pl.when(ns_str.is_in(ns_keys))
        .then(ns_str.replace(mntns_map))
        .otherwise(None)
    )
    return lf.with_columns(
        pl.coalesce([container_label, pl.col("comm"), pl.lit("other")]).alias("label")
    )

