#!/usr/bin/env python3
"""Write a short human-readable overview of a FuStIP detailed/container run.

Scans <results_dir> for per-layer `detailed-stats.json` (block, nvme, fs) and
`sysstat/sysstat-stats.json`, and writes a concise `fustip_overview.txt` next to
them. Read-only over the stats JSON — it reports what the stats generators
produced, no recomputation.

Only meaningful for detailed/container mode (summary mode produces different
stats files and is intentionally not summarized here).

Usage:
    python util/generate_overview.py <results_dir>
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Layers in presentation order; only those present in results_dir are shown.
LAYERS = ("sysstat", "fs", "block", "nvme")


def _human_bytes(n):
    n = float(n)
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        n /= 1024
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}"
    return f"{n:.1f} TiB"


def _human_count(n):
    return f"{int(n):,}"


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        return None


def _entities(stats):
    """Yield (label, disk, node) for each per_comm / per_container entry.

    nvme detailed mode nests per-disk nodes under each label
    (per_comm[label].per_disk[disk]); expand those to (label@disk, disk, node) so each
    device is reported separately. Labels without per_disk yield (label, None, node)."""
    for bucket in ("per_comm", "per_container"):
        for label, node in (stats.get(bucket) or {}).items():
            per_disk = node.get("per_disk") if isinstance(node, dict) else None
            if per_disk:
                for disk, disk_node in per_disk.items():
                    yield f"{label} @ {disk}", disk, disk_node
            else:
                yield label, None, node


def _find_map(counters, suffix):
    """Return the first counter map whose key ends with suffix (e.g. _completed)."""
    for key, val in counters.items():
        if key.endswith(suffix):
            return val
    return {}


def _access_pct(access_pattern, op):
    """Return (seq_pct, rnd_pct) for an op from an access_pattern dict, or None."""
    for sect in (access_pattern or {}).values():
        ap = sect.get(op)
        if ap:
            return ap.get("sequential_pct"), ap.get("random_pct")
    return None


def _peak_iops(node, op):
    iops = ((node.get("tseries") or {}).get("iops") or {}).get(op) or {}
    return iops.get("max")


def _derived(node, op):
    """(avg_iops, throughput_mb_s) for an op from the derived scalar, or (None, None)."""
    d = node.get("derived") or {}
    return (d.get("iops") or {}).get(op), (d.get("throughput_mb_s") or {}).get(op)


def _io_layer_lines(stats):
    """Lines for a block/nvme/fs layer (counts, bytes, peak IOPS, pattern)."""
    lines = []
    # nvme detailed keeps access_pattern at top-level per_device[disk] (device-merged
    # across issuers); other layers keep it per-comm on the node itself.
    per_device = stats.get("per_device") or {}
    for label, disk, node in _entities(stats):
        counters = node.get("counters") or {}
        completed = _find_map(counters, "_completed")
        total_bytes = _find_map(counters, "_total_bytes")
        if not completed:
            continue
        if disk is not None and disk in per_device:
            access_pattern = per_device[disk].get("access_pattern") or {}
        else:
            access_pattern = node.get("access_pattern") or {}
        lines.append(f"  [{label}]")
        for op in sorted(completed):
            cnt = completed[op]
            if not cnt:
                continue
            parts = [f"{_human_count(cnt)} completed",
                     _human_bytes(total_bytes.get(op, 0))]
            # Lead with the trustworthy avg (total ÷ active duration ≈ FIO),
            # corroborated by the peak second from the tseries.
            avg_iops, tput = _derived(node, op)
            peak = _peak_iops(node, op)
            if avg_iops is not None:
                seg = f"{_human_count(avg_iops)} IOPS"
                if tput is not None:
                    seg += f" / {tput:.0f} MiB/s"
                if peak:
                    seg += f" (peak {_human_count(peak)})"
                parts.append(seg)
            elif peak:
                parts.append(f"peak {_human_count(peak)} IOPS")
            ap = _access_pct(access_pattern, op)
            if ap and ap[1] is not None:
                parts.append(f"{ap[1]:.0f}% random")
            lines.append(f"    {op:8} {', '.join(parts)}")
    return lines


def _quality_lines(stats):
    """Lines for data_quality: drop_pct and untracked completions."""
    dq = stats.get("data_quality") or {}
    lines = []
    drop = dq.get("drop_pct")
    if drop is not None:
        dropped = dq.get("total_dropped", 0)
        lines.append(f"    data quality: {drop:.2f}% dropped ({_human_count(dropped)} events)")
    unt = dq.get("untracked_completions")
    if unt:
        total = unt.get("total", 0)
        per = unt.get("per_disk_op") or {}
        detail = "; ".join(f"{k}={_human_count(v)}" for k, v in sorted(per.items()))
        lines.append(f"    untracked completions: {_human_count(total)} "
                     f"(excluded/other-disk or probe-miss) [{detail}]")
    else:
        lines.append("    untracked completions: none")
    return lines


def _sysstat_lines(stats):
    lines = []
    dur = stats.get("duration_s")
    if dur is not None:
        lines.append(f"  collection window: {dur}s")
    order = stats.get("label_order")
    if order:
        lines.append(f"  commands tracked: {', '.join(order)}")
    return lines


def main():
    if len(sys.argv) != 2:
        print("usage: generate_overview.py <results_dir>", file=sys.stderr)
        sys.exit(2)
    results_dir = Path(sys.argv[1])
    if not results_dir.is_dir():
        print(f"Error: {results_dir} not found", file=sys.stderr)
        sys.exit(1)

    out = [
        "FuStIP results overview",
        f"  dir:       {results_dir}",
        f"  generated: {datetime.now().isoformat(timespec='seconds')}",
    ]

    found = False
    for layer in LAYERS:
        layer_dir = results_dir / layer
        if not layer_dir.is_dir():
            continue
        if layer == "sysstat":
            stats = _load(layer_dir / "sysstat-stats.json")
            if not stats:
                continue
            found = True
            out.append("")
            out.append("[sysstat]")
            out.extend(_sysstat_lines(stats))
        else:
            stats = _load(layer_dir / "detailed-stats.json")
            if not stats:
                continue
            found = True
            out.append("")
            out.append(f"[{layer}]")
            out.extend(_io_layer_lines(stats))
            out.extend(_quality_lines(stats))

    if not found:
        out.append("")
        out.append("(no detailed layer stats found)")

    output_file = results_dir / "fustip_overview.txt"
    output_file.write_text("\n".join(out) + "\n")
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
