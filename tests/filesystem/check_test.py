#!/usr/bin/env python3
"""Compare FIO JSON output against bpftrace FS profiler output.

Asserts that profiler metrics match FIO-reported numbers within tolerance.
Validates per-syscall counters based on the FIO engine used by each job.
Supports both bpftrace (summary) and detailed (CSV) modes.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "util"))
from stats_generation.shared import parse_counters


def parse_fio_json(path):
    """Extract per-direction IO stats from FIO JSON output."""
    with open(path) as f:
        raw = json.load(f)

    job = raw["jobs"][0]
    return {
        "job_name": job["jobname"],
        "read_ios": job["read"]["total_ios"],
        "read_bytes": job["read"]["io_bytes"],
        "write_ios": job["write"]["total_ios"],
        "write_bytes": job["write"]["io_bytes"],
    }


def parse_detailed_stats(path):
    """Parse detailed-stats.json into the same dict format as parse_counters().

    The stats JSON has: {"counters": {"sc_completed": {"pread64": N}, ...}}
    We flatten to: {"sc_completed": {"pread64": N}, ...}
    """
    with open(path) as f:
        stats = json.load(f)
    return stats.get("counters", {})


def get_val(data, map_name, key, default=0):
    """Safely get a value from parsed bpftrace data."""
    return data.get(map_name, {}).get(key, default)


def check_approx(label, actual, expected, tolerance):
    """Check that actual ~ expected within tolerance."""
    if expected == 0:
        pct = 0.0 if actual == 0 else float("inf")
    else:
        pct = abs(actual - expected) / expected

    passed = pct <= tolerance
    tag = "PASS" if passed else "FAIL"
    direction = "over" if actual > expected else "under" if actual < expected else "exact"
    msg = f"[{tag}] {label}: {actual} vs {expected} ({pct:.2%} error, {direction})"
    if not passed:
        msg += f" — exceeds {tolerance:.0%} tolerance"
    return passed, msg


def check_near_zero(label, actual, max_allowed=200):
    """Check that a counter is near zero."""
    passed = actual <= max_allowed
    tag = "PASS" if passed else "FAIL"
    msg = f"[{tag}] {label}: {actual} (expected ~0, limit {max_allowed})"
    return passed, msg


def syscall_keys_for_job(job_name):
    """Determine which syscall counters to validate based on job name.

    sync engine (val_seq*) -> read()/write() syscalls
    psync engine (val_rand*, work_*) -> pread64()/pwrite64() syscalls
    """
    if job_name.startswith("val_seq"):
        return "read", "write"
    else:
        return "pread64", "pwrite64"


def classify_job(fio):
    """Classify a job as read-only, write-only, or mixed based on FIO data."""
    has_reads = fio["read_ios"] > 0
    has_writes = fio["write_ios"] > 0

    if has_reads and has_writes:
        return "mixed"
    elif has_writes:
        return "write"
    else:
        return "read"


def validate_completed_vs_fio(fio, fs, tolerance, read_key, write_key, kind):
    """Check completed counts and bytes against FIO."""
    results = []

    if kind in ("read", "mixed"):
        results.append(check_approx(
            f"fs {read_key} completed",
            get_val(fs, "sc_completed", read_key),
            fio["read_ios"], tolerance))
        results.append(check_approx(
            f"fs {read_key} bytes",
            get_val(fs, "sc_total_bytes", read_key),
            fio["read_bytes"], tolerance))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            f"fs {write_key} completed",
            get_val(fs, "sc_completed", write_key),
            fio["write_ios"], tolerance))
        results.append(check_approx(
            f"fs {write_key} bytes",
            get_val(fs, "sc_total_bytes", write_key),
            fio["write_bytes"], tolerance))

    # Near-zero checks for inactive direction
    if kind == "read":
        results.append(check_near_zero(
            f"fs {write_key} completed",
            get_val(fs, "sc_completed", write_key)))
    elif kind == "write":
        results.append(check_near_zero(
            f"fs {read_key} completed",
            get_val(fs, "sc_completed", read_key)))

    return results


def validate_consistency(fs, tolerance, read_key, write_key):
    """Check entered~completed consistency for active IO syscalls."""
    results = []

    for sc in (read_key, write_key):
        entered = get_val(fs, "sc_entered", sc)
        completed = get_val(fs, "sc_completed", sc)
        if entered > 0 or completed > 0:
            results.append(check_approx(
                f"fs {sc} entered~completed",
                entered, completed, tolerance))

    return results


AUXILIARY_SYSCALLS = [
    "openat", "close", "lseek", "newfstatat", "newfstat",
    "unlinkat", "mkdirat", "mmap", "munmap",
]


def main():
    parser = argparse.ArgumentParser(description="Check FS profiler output against FIO results")
    parser.add_argument("--job", required=True, help="FIO job name")
    parser.add_argument("--fio-json", required=True, help="Path to FIO JSON output")
    parser.add_argument("--fs-out", required=True, help="Path to FS layer output")
    parser.add_argument("--mode", default="summary", choices=["summary", "detailed"],
                        help="Profiling mode (default: summary)")
    parser.add_argument("--tolerance", type=float, default=0.02, help="Tolerance for count checks (default: 0.02)")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)

    if args.mode == "detailed":
        fs = parse_detailed_stats(args.fs_out)
    else:
        fs = parse_counters(args.fs_out)

    read_key, write_key = syscall_keys_for_job(args.job)
    kind = classify_job(fio)

    print(f"\n=== {args.job} (mode={args.mode}) ===")

    print(f"  FIO:   read_ios={fio['read_ios']}  read_bytes={fio['read_bytes']}"
          f"  write_ios={fio['write_ios']}  write_bytes={fio['write_bytes']}")

    for i, sc in enumerate((read_key, write_key)):
        prefix = "  FS:   " if i == 0 else "        "
        print(f"{prefix}{sc}:  "
              f"  entered={get_val(fs, 'sc_entered', sc)}"
              f"  completed={get_val(fs, 'sc_completed', sc)}"
              f"  bytes={get_val(fs, 'sc_total_bytes', sc)}")

    # Display auxiliary syscall counts
    aux_parts = [f"{sc}={get_val(fs, 'sc_count', sc)}" for sc in AUXILIARY_SYSCALLS
                 if get_val(fs, "sc_count", sc) > 0]
    if aux_parts:
        print(f"  AUX:   {', '.join(aux_parts)}")

    print()

    results = validate_completed_vs_fio(fio, fs, args.tolerance, read_key, write_key, kind)
    results += validate_consistency(fs, args.tolerance, read_key, write_key)

    all_passed = True
    for passed, msg in results:
        print(f"  {msg}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("  RESULT: PASS")
    else:
        print("  RESULT: FAIL")

    print()


if __name__ == "__main__":
    main()
