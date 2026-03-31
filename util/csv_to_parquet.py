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
            "q_inflight", "d_inflight", "offset", "count"}


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
