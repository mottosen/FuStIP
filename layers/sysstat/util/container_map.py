#!/usr/bin/env python3
"""Shared utility: build label maps from container_map.json + COMM/CONTAINER filters.

Imported by both generate_stats.py and visualize.py.
"""

import json
import sys
from pathlib import Path


def _load_container_data(sysstat_dir: Path) -> dict[str, dict[str, set]]:
    """Return normalized container data: {container: {"comms": set, "tgids": set}}."""
    # Prefer shared root-level map; fallback to legacy sysstat-local map.
    candidates = [sysstat_dir.parent / "container_map.json", sysstat_dir / "container_map.json"]
    data = None
    for container_map_path in candidates:
        if container_map_path.exists():
            data = json.loads(container_map_path.read_text())
            break
    if data is None:
        return {}
    containers = {}
    for cname, raw in data.get("containers", {}).items():
        if isinstance(raw, dict):
            comms = set(raw.get("comms", []))
            tgids = set(str(v) for v in raw.get("tgids", raw.get("pids", [])))
        else:
            # Backward compatibility with v1 format: {"containers": {"name": ["comm", ...]}}
            comms = set(raw or [])
            tgids = set()
        containers[cname] = {"comms": comms, "tgids": tgids}
    return containers


def build_label_maps(sysstat_dir: Path, comm_filter: list | None) -> tuple[dict, dict] | None:
    """Return (tgid_map, comm_map) or None if no filtering configured."""
    containers = _load_container_data(sysstat_dir)
    has_comms = bool(comm_filter)
    if not containers and not has_comms:
        return None

    tgid_map: dict[str, str] = {}
    comm_map: dict[str, str] = {}

    for cname, payload in containers.items():
        for tgid in payload["tgids"]:
            if tgid not in tgid_map:
                tgid_map[tgid] = cname
            else:
                print(f"Warning: tgid '{tgid}' already mapped to "
                      f"'{tgid_map[tgid]}', skipping for '{cname}'",
                      file=sys.stderr)
        for comm in payload["comms"]:
            if comm not in comm_map:
                comm_map[comm] = cname
            else:
                print(f"Warning: comm '{comm}' already mapped to "
                      f"'{comm_map[comm]}', skipping for '{cname}'",
                      file=sys.stderr)

    if has_comms:
        for comm in comm_filter:
            if comm not in comm_map:
                comm_map[comm] = comm  # host process: identity label

    return tgid_map, comm_map


def remap_rows(rows: list[dict], label_maps: tuple[dict, dict] | None) -> bool:
    """Apply tgid-first then comm-based remapping. Returns True if mapping applied."""
    if label_maps is None:
        return False

    tgid_map, comm_map = label_maps
    for row in rows:
        tgid = row.get("tgid")
        if tgid in tgid_map:
            row["command"] = tgid_map[tgid]
        else:
            row["command"] = comm_map.get(row["command"], "other")
    return True


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
