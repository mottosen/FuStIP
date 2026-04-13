#!/usr/bin/env python3
"""
Parse pidstat output into separate CSV files.

Expects per-thread output (pidstat -t flag) with TGID/TID columns.

Reads pidstat.out from the input directory and splits into:
  - cpu.csv  (thread-level rows: per-thread CPU with core assignment, 0-100%)
  - mem.csv  (process-level rows: per-process memory, avoids double-counting shared RSS)
  - dev.csv  (process-level rows: per-process disk I/O)

Usage:
    python parse_output.py <input_dir>
"""

import argparse
import sys
from pathlib import Path

# CSV headers for each section
CSV_HEADERS = {
    "cpu": "time,uid,tgid,tid,usr,system,guest,wait,cpu_pct,cpu,command",
    "mem": "time,uid,tgid,minflt_s,majflt_s,vsz_kb,rss_kb,mem_pct,command",
    "dev": "time,uid,tgid,kb_rd_s,kb_wr_s,kb_ccwr_s,iodelay,command",
}

# Minimum field count per section (including command)
# CPU: time uid tgid tid usr system guest wait cpu_pct cpu command = 11
# MEM: time uid tgid tid minflt majflt vsz rss mem_pct command = 10
# DEV: time uid tgid tid kb_rd kb_wr kb_ccwr iodelay command = 9
FIELD_COUNTS = {"cpu": 11, "mem": 10, "dev": 9}


def detect_section(line: str) -> str | None:
    """Detect which pidstat section a header line belongs to."""
    if "%usr" in line:
        return "cpu"
    if "minflt/s" in line:
        return "mem"
    if "kB_rd/s" in line:
        return "dev"
    return None


def parse_pidstat(input_file: Path, output_dir: Path) -> dict[str, int]:
    """Parse pidstat -t output into separate CSV files.

    For CPU: emits thread-level rows (TID is numeric) so each row represents
    a single thread with a specific core and 0-100% CPU.

    For MEM/DEV: emits process-level rows (TGID is numeric) to avoid
    double-counting shared resources.

    Thread rows use their parent process command for consistent container mapping.
    """
    records: dict[str, list[str]] = {"cpu": [], "mem": [], "dev": []}
    current_section: str | None = None

    # Track parent process context for associating threads with their command
    # Keyed per section since they repeat independently
    parent_context: dict[str, tuple[str, str]] = {}  # section -> (tgid, command)

    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            # Skip Linux header and Average lines
            if line.startswith("Linux") or line.startswith("Average"):
                continue

            # Check for section header
            section = detect_section(line)
            if section is not None:
                current_section = section
                continue

            if current_section is None:
                continue

            parts = line.split()

            n_fields = FIELD_COUNTS[current_section]

            if len(parts) < n_fields:
                continue

            # First field must be a timestamp (HH:MM:SS)
            if not parts[0][0].isdigit():
                continue

            time_str = parts[0]
            uid = parts[1]
            tgid = parts[2]
            tid = parts[3]

            # Determine row type
            tgid_is_num = tgid != "-"
            tid_is_num = tid != "-"

            # Extract command (last field, may contain spaces)
            command = " ".join(parts[n_fields - 1:])
            # Strip |__ prefix from thread commands
            if command.startswith("|__"):
                command = command[3:]

            # Track parent process context from process-level rows
            if tgid_is_num:
                parent_context[current_section] = (tgid, command)

            if current_section == "cpu":
                # Only emit thread-level rows (TID is numeric)
                if not tid_is_num:
                    continue

                # Use parent command for container mapping
                if tgid_is_num:
                    # Both set: single-threaded process, use its own command
                    ctx_tgid, ctx_command = tgid, command
                else:
                    # Thread row: use parent context
                    ctx = parent_context.get(current_section)
                    if ctx is None:
                        continue
                    ctx_tgid, ctx_command = ctx

                # Fields: time uid tgid tid usr system guest wait cpu_pct cpu command
                numeric_fields = parts[:n_fields - 1]
                # Replace tgid/tid and command with resolved values
                record = f"{time_str},{uid},{ctx_tgid},{tid}"
                record += "," + ",".join(numeric_fields[4:])
                record += f",{ctx_command}"
                records["cpu"].append(record)

            else:
                # MEM/DEV: only emit process-level rows (TGID is numeric)
                if not tgid_is_num:
                    continue

                # Fields vary by section but structure is:
                # time uid tgid tid <data fields...> command
                data_fields = parts[4:n_fields - 1]
                record = f"{time_str},{uid},{tgid}"
                record += "," + ",".join(data_fields)
                record += f",{command}"
                records[current_section].append(record)

    counts = {}
    for section, header in CSV_HEADERS.items():
        output_file = output_dir / f"{section}.csv"
        with open(output_file, "w") as f:
            f.write(header + "\n")
            for record in records[section]:
                f.write(record + "\n")
        counts[section] = len(records[section])
        print(f"  -> {output_file.name}: {counts[section]} records")

    return counts


def main():
    parser = argparse.ArgumentParser(
        description="Parse pidstat output into separate CSV files"
    )
    parser.add_argument(
        "input_dir", type=Path, help="Directory containing pidstat.out"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: same as input)",
    )

    args = parser.parse_args()

    if not args.input_dir.is_dir():
        print(f"Error: {args.input_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    input_file = args.input_dir / "pidstat.out"
    if not input_file.exists():
        print(f"Error: {input_file} not found", file=sys.stderr)
        sys.exit(1)

    output_dir = args.output_dir or args.input_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Parsing {input_file}:")
    counts = parse_pidstat(input_file, output_dir)
    print(f"\nTotal: {sum(counts.values())} records")


if __name__ == "__main__":
    main()
