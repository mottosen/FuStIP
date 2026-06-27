#!/usr/bin/env python3
"""Capture NVMe device metadata at collection time into device-info.json.

Run at the start of detailed nvme collection so the device fingerprint is
recorded on the *capture* host (where the device and its sysfs/identify data
actually exist), rather than inferred at analysis time — which may run on a
different machine. The result feeds the nvme LBA-distribution normalisation
(`load_device_sectors`) and documents the device behind a run.

Sources, in order of privilege required:
  - `nvme list -o json`        — no root: model, serial, firmware, sector size,
                                 total bytes, MaximumLBA.
  - `/sys/block/<dev>/...`     — no root: 512B sector count, logical/physical
                                 block size (canonical for sector math).
  - `nvme id-ctrl` / `id-ns`   — privileged (via `sudo -n`, using the cached
                                 sudo session the collection already holds):
                                 MDTS (max transfer per command) and namespace
                                 size. Skipped silently if unavailable.

Note: NVMe does not report a maximum throughput/bandwidth figure anywhere; MDTS
(max data transfer size per command) is the closest device-reported capability.

Degrades gracefully and never fails the run: missing `nvme` CLI, missing sysfs,
or insufficient privilege simply omit the corresponding fields.

Usage:
    python collect_device_info.py <results_dir> <dev_filter_csv>
"""

import json
import re
import subprocess
import sys
from pathlib import Path


def _run_json(cmd):
    """Run a command and parse stdout as JSON; return None on any failure."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout.strip():
        return None
    try:
        return json.loads(out.stdout)
    except ValueError:
        return None


def _all_nvme_namespaces():
    """Every NVMe namespace block device on the host (e.g. nvme0n1, nvme1n1).

    Used when no device filter is given (container/comm/pid-scoped runs) so the
    fingerprint still covers whichever device the workload hits. Namespace devices
    match nvmeXnY; partitions (nvmeXnYpZ) are excluded.
    """
    try:
        names = [p.name for p in Path("/sys/block").glob("nvme*")]
    except OSError:
        return []
    return sorted(n for n in names if re.match(r"^nvme\d+n\d+$", n))


def _sysfs_int(dev, rel):
    try:
        return int(Path(f"/sys/block/{dev}/{rel}").read_text().strip())
    except (OSError, ValueError):
        return None


def _sysfs_mq_count(dev):
    """Number of hardware (I/O) queues: count numeric subdirs in /sys/block/<dev>/mq."""
    try:
        return sum(1 for p in Path(f"/sys/block/{dev}/mq").iterdir() if p.name.isdigit())
    except OSError:
        return None


def _sysfs_str(dev, rel):
    try:
        return Path(f"/sys/block/{dev}/{rel}").read_text().strip() or None
    except OSError:
        return None


def _nvme_list_index():
    """Map device name (e.g. 'nvme1n1') -> its `nvme list -o json` entry."""
    data = _run_json(["nvme", "list", "-o", "json"]) or {}
    idx = {}
    for d in data.get("Devices", []):
        name = str(d.get("DevicePath", "")).replace("/dev/", "")
        if name:
            idx[name] = d
    return idx


def collect_device(dev, nvme_list):
    """Build the metadata dict for one device, omitting unavailable fields."""
    info = {
        "device": dev,
        # /sys/block/<dev>/size is always in 512-byte units — the unit the block
        # and nvme tracepoints report sectors in, so it's the canonical count
        # for LBA-distribution normalisation.
        "sectors_512b": _sysfs_int(dev, "size"),
        "logical_block_bytes": _sysfs_int(dev, "queue/logical_block_size"),
        "physical_block_bytes": _sysfs_int(dev, "queue/physical_block_size"),
        "model": _sysfs_str(dev, "device/model"),
        "serial": _sysfs_str(dev, "device/serial"),
        # Queue geometry for on-device queue-distribution analysis: hw_queues is
        # the I/O queue count, hw_queue_depth the per-queue tag depth (NVMe SQ
        # depth), block_nr_requests the block-layer scheduler queue depth.
        "hw_queues": _sysfs_mq_count(dev),
        "hw_queue_depth": _sysfs_int(dev, "mq/0/nr_tags"),
        "block_nr_requests": _sysfs_int(dev, "queue/nr_requests"),
    }

    # nvme list (no root) — richer/cleaner identity + sizing.
    li = nvme_list.get(dev, {})
    if li:
        info["model"] = li.get("ModelNumber") or info["model"]
        info["serial"] = li.get("SerialNumber") or info["serial"]
        info["firmware"] = li.get("Firmware")
        info["lba_size_bytes"] = li.get("SectorSize")
        info["max_lba"] = li.get("MaximumLBA")
        info["total_bytes"] = li.get("PhysicalSize")
        info["used_bytes"] = li.get("UsedBytes")

    # If sysfs was unavailable, derive the 512B sector count from nvme list.
    if info["sectors_512b"] is None and info.get("max_lba") and info.get("lba_size_bytes"):
        info["sectors_512b"] = info["max_lba"] * info["lba_size_bytes"] // 512

    # Privileged identify data via the cached sudo session (skip if unavailable).
    ctrl_match = re.match(r"^(nvme\d+)n\d+$", dev)
    if ctrl_match:
        idc = _run_json(["sudo", "-n", "nvme", "id-ctrl",
                         f"/dev/{ctrl_match.group(1)}", "-o", "json"])
        if idc and idc.get("mdts") is not None:
            mdts = idc["mdts"]
            info["mdts"] = mdts
            # MDTS is a power-of-two multiple of the minimum memory page size
            # (commonly 4096; 0 means "no limit"). Best-effort, page size assumed.
            info["max_transfer_bytes"] = (1 << mdts) * 4096 if mdts else None
    idn = _run_json(["sudo", "-n", "nvme", "id-ns", f"/dev/{dev}", "-o", "json"])
    if idn:
        info["nsze_lbas"] = idn.get("nsze")
        info["ncap_lbas"] = idn.get("ncap")

    return {k: v for k, v in info.items() if v not in (None, "")}


def main():
    if len(sys.argv) != 3:
        print("usage: collect_device_info.py <results_dir> <dev_filter_csv>",
              file=sys.stderr)
        return
    results_dir = Path(sys.argv[1])
    devs = [d.strip() for d in sys.argv[2].split(",") if d.strip()]
    if not devs:
        # No device filter (container/comm/pid-scoped run): fingerprint every NVMe
        # namespace so post-processing has geometry for whichever device the workload
        # actually hit, regardless of -d.
        devs = _all_nvme_namespaces()
    if not devs:
        return

    nvme_list = _nvme_list_index()
    out = {dev: collect_device(dev, nvme_list) for dev in devs}

    nvme_dir = results_dir / "nvme"
    nvme_dir.mkdir(parents=True, exist_ok=True)
    (nvme_dir / "device-info.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"  -> {nvme_dir / 'device-info.json'} ({', '.join(devs)})")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # never break the collection run over device metadata
        print(f"collect_device_info: skipped ({e})", file=sys.stderr)
