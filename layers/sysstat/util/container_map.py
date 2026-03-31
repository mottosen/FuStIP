#!/usr/bin/env python3
"""Shared utility: build comm→label map from container_map.json + COMM_FILTER.

Imported by both generate_stats.py and visualize.py.
"""

import json
import sys
from pathlib import Path


def build_label_map(sysstat_dir: Path, comm_filter: list | None,
                    container_filter: list | None) -> dict | None:
    """Return {raw_comm: display_label} or None if no filtering configured.

    Priority: container_map.json entries first (first container wins on conflict),
    then COMM_FILTER host processes (identity mapping), rest → "other" at call site.
    """
    container_map_path = sysstat_dir / "container_map.json"
    has_map = container_map_path.exists()
    has_comms = bool(comm_filter)

    if not has_map and not has_comms:
        return None

    label_map: dict[str, str] = {}

    if has_map:
        data = json.loads(container_map_path.read_text())
        for cname, comms in data["containers"].items():
            for comm in comms:
                if comm not in label_map:
                    label_map[comm] = cname
                else:
                    print(f"Warning: comm '{comm}' already mapped to "
                          f"'{label_map[comm]}', skipping for '{cname}'",
                          file=sys.stderr)

    if has_comms:
        for comm in comm_filter:
            if comm not in label_map:
                label_map[comm] = comm  # host process: identity label

    return label_map


def get_label_order(container_filter: list | None,
                    comm_filter: list | None) -> list:
    """Canonical label ordering: containers first (CONTAINER_FILTER order),
    then host processes (COMM_FILTER order). 'other' always last (handled by callers)."""
    order = []
    for lbl in (container_filter or []):
        if lbl not in order:
            order.append(lbl)
    for lbl in (comm_filter or []):
        if lbl not in order:
            order.append(lbl)
    return order
