#!/usr/bin/env python3
"""Convert Inspektor Gadget newline-delimited JSON output to CSV.

Produces the same CSV format as each layer's standalone loader.c,
so generate_detailed_stats.py can process it unchanged.

Usage:
    python ig_json_to_csv.py <input.jsonl> <output.csv> <layer>

Layers: block, nvme, fs
"""

import csv
import json
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


def convert_block(rows, writer):
    """CSV: timestamp_ns,event,op,bytes,latency_ns,sector,rq"""
    writer.writerow(["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector", "rq"])
    for obj in rows:
        event_type = obj.get("event_type", 0)
        op = obj.get("op", 0)
        latency = obj.get("latency_ns", 0)
        writer.writerow([
            obj.get("timestamp_ns", 0),
            BLOCK_EVENT_NAMES.get(event_type, "unknown"),
            BLOCK_OP_NAMES.get(op, "unknown"),
            obj.get("bytes", 0),
            latency if latency else "",
            obj.get("sector", 0),
            f"0x{obj.get('rq', 0):x}",
        ])


def convert_nvme(rows, writer):
    """CSV: timestamp_ns,event,op,bytes,latency_ns,sector,rq"""
    writer.writerow(["timestamp_ns", "event", "op", "bytes", "latency_ns", "sector", "rq"])
    for obj in rows:
        event_type = obj.get("event_type", 0)
        op = obj.get("op", 0)
        latency = obj.get("latency_ns", 0)
        writer.writerow([
            obj.get("timestamp_ns", 0),
            NVME_EVENT_NAMES.get(event_type, "unknown"),
            NVME_OP_NAMES.get(op, "unknown"),
            obj.get("bytes", 0),
            latency if latency else "",
            obj.get("sector", 0),
            f"0x{obj.get('rq', 0):x}",
        ])


def convert_fs(rows, writer):
    """CSV: timestamp_ns,event,syscall,bytes,latency_ns,fd,offset,tid"""
    writer.writerow(["timestamp_ns", "event", "syscall", "bytes", "latency_ns", "fd", "offset", "tid"])
    for obj in rows:
        event_type = obj.get("event_type", 0)
        syscall = obj.get("syscall", 0)
        bytes_val = obj.get("bytes", 0)
        latency = obj.get("latency_ns", 0)
        fd = obj.get("fd", -1)
        offset = obj.get("offset", -1)
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
        print(f"Usage: {sys.argv[0]} <input.jsonl> <output.csv> <layer>",
              file=sys.stderr)
        print(f"  Layers: {', '.join(CONVERTERS.keys())}", file=sys.stderr)
        sys.exit(1)

    input_path, output_path, layer = sys.argv[1], sys.argv[2], sys.argv[3]

    if layer not in CONVERTERS:
        print(f"Unknown layer: {layer}. Must be one of: {', '.join(CONVERTERS.keys())}",
              file=sys.stderr)
        sys.exit(1)

    # Read all JSON lines
    rows = []
    with open(input_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Warning: skipping line {line_num}: {e}", file=sys.stderr)

    # Write CSV
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        CONVERTERS[layer](rows, writer)

    print(f"Converted {len(rows)} events → {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
