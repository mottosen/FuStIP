#!/usr/bin/env python3
"""Convert a detailed CSV to Parquet for efficient column-level reads.

Streaming conversion: pl.scan_csv().sink_parquet() — constant memory.
Idempotent: skips if .parquet exists and mtime >= .csv mtime.
Graceful: exits 0 if CSV doesn't exist (safe to call unconditionally).

Usage:
    python util/csv_to_parquet.py <csv_path>
"""

import os
import sys
from pathlib import Path

import polars as pl

STRING_COLS = {"event", "op", "syscall", "comm", "rq"}

# Columns that can be empty (nullable) but must be numeric, not Utf8.
# Polars infers Utf8 when a numeric column has empty cells in CSV.
INT_COLS = {"latency_ns", "timestamp_ns", "bytes", "sector",
            "q_inflight", "d_inflight", "offset", "count", "mntns_id"}


def _trim_incomplete_last_line(csv_path: Path) -> bool:
    """If the file doesn't end with '\\n', drop the partial last line.

    Guards against the BPF collector being killed without flushing its stdio
    buffers (e.g. SIGKILL or crash). Under normal SIGTERM shutdown all loaders
    call fclose() so the file is always clean — this is a defensive fallback.
    Returns True if a partial line was removed.
    """
    with open(csv_path, "rb+") as f:
        size = f.seek(0, 2)  # seek to end; returns new position == file size
        if size == 0:
            return False
        f.seek(-1, 2)
        if f.read(1) == b"\n":
            return False  # clean termination — nothing to do
        # Scan backwards (up to 64 KB) for the last complete newline.
        search_back = min(size, 1 << 16)
        f.seek(size - search_back)
        chunk = f.read(search_back)
        nl_pos = chunk.rfind(b"\n")
        if nl_pos >= 0:
            f.truncate(size - search_back + nl_pos + 1)
        else:
            # No newline anywhere in the tail — retain only the header line.
            f.seek(0)
            data = f.read()
            header_end = data.find(b"\n")
            f.truncate(header_end + 1 if header_end >= 0 else 0)
    return True


def convert(csv_path):
    csv_path = Path(csv_path)
    if not csv_path.exists():
        return

    parquet_path = csv_path.with_suffix(".parquet")

    if parquet_path.exists():
        if os.path.getmtime(parquet_path) >= os.path.getmtime(csv_path):
            print(f"Parquet up-to-date: {parquet_path.name}")
            return
        parquet_path.unlink()

    if _trim_incomplete_last_line(csv_path):
        print(f"  Warning: trimmed incomplete last line from {csv_path.name}")

    # Read header to build schema overrides: strings stay Utf8, numeric cols
    # that can be empty are forced to Int64 so Polars doesn't infer Utf8.
    with open(csv_path) as f:
        header = f.readline().strip().split(",")
    overrides = {}
    for col in header:
        if col in STRING_COLS:
            overrides[col] = pl.Utf8
        elif col in INT_COLS:
            overrides[col] = pl.Int64

    print(f"Converting {csv_path.name} -> {parquet_path.name}...")
    pl.scan_csv(csv_path, schema_overrides=overrides).sink_parquet(parquet_path)
    print(f"  Done ({parquet_path.stat().st_size / 1e9:.1f} GB)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <csv_path>", file=sys.stderr)
        sys.exit(1)
    convert(sys.argv[1])
