#!/usr/bin/env python3
"""Preflight safety check for the nvme_direct (io_uring_cmd passthrough) suite.

Passthrough writes are issued straight to the NVMe driver and hit the *whole
namespace* from LBA 0 — they ignore partitions and filesystems. Running this
suite against an in-use device therefore destroys data. This script refuses to
proceed unless the target namespace is free:

  * no mounted partitions, and
  * no partition-table / filesystem signatures.

The argument may be the generic char device (/dev/ngXnY), the block device
(/dev/nvmeXnY), or a bare namespace name (nvme0n1) — all resolve to the same
block device, which is what we inspect with lsblk.

Override with ALLOW_NONEMPTY_DEVICE=1 only if you are certain the device is
disposable (e.g. a leftover signature on a genuine scratch namespace). Mounted
partitions are never overridable.
"""

import json
import os
import subprocess
import sys


def resolve_block_device(target):
    """Map /dev/ngXnY (char) | /dev/nvmeXnY (block) | nvmeXnY -> /dev/nvmeXnY."""
    name = os.path.basename(target)
    if name.startswith("ng"):
        name = "nvme" + name[len("ng"):]
    return f"/dev/{name}"


def main():
    if len(sys.argv) < 2:
        print("usage: assert_device_free.py <device>", file=sys.stderr)
        sys.exit(2)

    blk = resolve_block_device(sys.argv[1])
    if not os.path.exists(blk):
        print(f"[device-check] block device {blk} not found (from '{sys.argv[1]}')",
              file=sys.stderr)
        sys.exit(2)

    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-o", "NAME,MOUNTPOINT,FSTYPE,PTTYPE,SIZE", blk],
            text=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[device-check] lsblk failed: {e}", file=sys.stderr)
        sys.exit(2)

    tree = json.loads(out).get("blockdevices", [])
    mounts, sigs = [], []

    def walk(node):
        mp = node.get("mountpoint")
        if mp:
            mounts.append((node["name"], mp))
        if node.get("fstype"):
            sigs.append((node["name"], "fs:" + node["fstype"]))
        if node.get("pttype"):
            sigs.append((node["name"], "pt:" + node["pttype"]))
        for child in node.get("children", []):
            walk(child)

    for node in tree:
        walk(node)

    if mounts:
        print(f"\n[device-check] REFUSING to run: {blk} has MOUNTED partitions:",
              file=sys.stderr)
        for name, mp in mounts:
            print(f"    /dev/{name} -> {mp}", file=sys.stderr)
        print("  This suite issues raw NVMe passthrough writes to the whole namespace\n"
              "  and WILL destroy these filesystems. Unmount and use a scratch device.",
              file=sys.stderr)
        sys.exit(1)

    if sigs and os.environ.get("ALLOW_NONEMPTY_DEVICE") != "1":
        print(f"\n[device-check] REFUSING to run: {blk} carries data signatures:",
              file=sys.stderr)
        for name, sig in sigs:
            print(f"    /dev/{name}: {sig}", file=sys.stderr)
        print("  Passthrough writes start at LBA 0 and will overwrite this.\n"
              "  If this device is genuinely disposable, re-run with "
              "ALLOW_NONEMPTY_DEVICE=1.", file=sys.stderr)
        sys.exit(1)

    print(f"[device-check] OK: {blk} has no mounts or data signatures — safe to run.")


if __name__ == "__main__":
    main()
