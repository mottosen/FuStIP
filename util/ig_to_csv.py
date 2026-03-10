#!/usr/bin/env python3
"""Convert Inspektor Gadget columns output to CSV.

Parses whitespace-delimited columns output (header + data rows) and
produces the same CSV format as each layer's standalone loader.c,
so generate_detailed_stats.py can process it unchanged.

Usage:
    python ig_to_csv.py <input.columns> <output.csv> <layer>

Layers: block, nvme, fs
"""

import csv
import sys

# ── String mappings (must match loader.c) ──

BLOCK_EVENT_NAMES = {0: "insert", 1: "issue", 2: "complete"}
BLOCK_OP_NAMES = {0: "read", 1: "write", 2: "flush", 3: "discard", 9: "write_zeros"}

NVME_EVENT_NAMES = {0: "setup", 1: "complete"}
NVME_OP_NAMES = BLOCK_OP_NAMES  # same mapping

FS_EVENT_NAMES = {0: "enter", 1: "exit"}
FS_SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "pread64", 3: "pwrite64",
    4: "openat", 5: "close", 6: "lseek",
    7: "newfstatat", 8: "newfstat",
    9: "unlinkat", 10: "mkdirat",
    11: "mmap", 12: "munmap",
}


def parse_columns(input_path):
    """Parse IG columns output into list of dicts keyed by header names."""
    rows = []
    headers = None
    with open(input_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            fields = line.split()
            if headers is None:
                # First non-empty line is the header
                headers = [h.lower() for h in fields]
                continue
            if len(fields) != len(headers):
                print(f"Warning: skipping line {line_num}: "
                      f"expected {len(headers)} fields, got {len(fields)}",
                      file=sys.stderr)
                continue
            rows.append(dict(zip(headers, fields)))
    return rows


def convert_block(rows, writer):
    """CSV: timestamp_ns,event,op,bytes,latency_ns,sector,rq"""
    writer.writerow(["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector", "rq"])
    for obj in rows:
        event_type = int(obj.get("event_type", 0))
        op = int(obj.get("op", 0))
        latency = int(obj.get("latency_ns", 0))
        writer.writerow([
            obj.get("timestamp_ns", 0),
            BLOCK_EVENT_NAMES.get(event_type, "unknown"),
            BLOCK_OP_NAMES.get(op, "unknown"),
            obj.get("bytes", 0),
            latency if latency else "",
            obj.get("sector", 0),
            f"0x{int(obj.get('rq', 0)):x}",
        ])


def convert_nvme(rows, writer):
    """CSV: timestamp_ns,event,op,bytes,latency_ns,sector,rq"""
    writer.writerow(["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector", "rq"])
    for obj in rows:
        event_type = int(obj.get("event_type", 0))
        op = int(obj.get("op", 0))
        latency = int(obj.get("latency_ns", 0))
        writer.writerow([
            obj.get("timestamp_ns", 0),
            NVME_EVENT_NAMES.get(event_type, "unknown"),
            NVME_OP_NAMES.get(op, "unknown"),
            obj.get("bytes", 0),
            latency if latency else "",
            obj.get("sector", 0),
            f"0x{int(obj.get('rq', 0)):x}",
        ])


def convert_fs(rows, writer):
    """CSV: timestamp_ns,event,syscall,bytes,latency_ns,fd,offset,tid"""
    writer.writerow(["timestamp_ns", "event", "syscall", "bytes", "latency_ns", "fd", "offset", "tid"])
    for obj in rows:
        event_type = int(obj.get("event_type", 0))
        syscall = int(obj.get("syscall", 0))
        bytes_val = int(obj.get("bytes", 0))
        latency = int(obj.get("latency_ns", 0))
        fd = int(obj.get("fd", -1))
        offset = int(obj.get("offset", -1))
        writer.writerow([
            obj.get("timestamp_ns", 0),
            FS_EVENT_NAMES.get(event_type, "unknown"),
            FS_SYSCALL_NAMES.get(syscall, "unknown"),
            bytes_val if bytes_val != 0 else "",
            latency if latency else "",
            fd if fd != -1 else "",
            offset if offset != -1 else "",
            obj.get("tid", 0),
        ])


CONVERTERS = {
    "block": convert_block,
    "nvme": convert_nvme,
    "fs": convert_fs,
}


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input.columns> <output.csv> <layer>",
              file=sys.stderr)
        print(f"  Layers: {', '.join(CONVERTERS.keys())}", file=sys.stderr)
        sys.exit(1)

    input_path, output_path, layer = sys.argv[1], sys.argv[2], sys.argv[3]

    if layer not in CONVERTERS:
        print(f"Unknown layer: {layer}. Must be one of: {', '.join(CONVERTERS.keys())}",
              file=sys.stderr)
        sys.exit(1)

    rows = parse_columns(input_path)

    # Write CSV
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        CONVERTERS[layer](rows, writer)

    print(f"Converted {len(rows)} events -> {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
