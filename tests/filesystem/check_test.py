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


def _iter_label_entries(stats):
    """Yield all per-comm and per-container label entries from stats JSON."""
    for label_entry in stats.get("per_comm", {}).values():
        yield label_entry
    for label_entry in stats.get("per_container", {}).values():
        yield label_entry


def parse_detailed_stats(path):
    """Parse detailed-stats.json into the same dict format as parse_counters().

    The stats JSON has: {"per_comm": {"fio": {"counters": {"sc_completed": {"pread64": N}}}}}
    We aggregate counters across all labels by summing inner values.
    """
    with open(path) as f:
        stats = json.load(f)
    merged = {}
    for entry in _iter_label_entries(stats):
        for counter_name, op_dict in entry.get("counters", {}).items():
            if counter_name not in merged:
                merged[counter_name] = {}
            for op, val in op_dict.items():
                merged[counter_name][op] = merged[counter_name].get(op, 0) + val
    return merged


def parse_access_pattern(path):
    """Extract access_pattern section from detailed-stats.json.

    Merges access patterns across all per-comm and per-container labels.
    In tests there is typically one label, so last-write-wins is fine.
    """
    with open(path) as f:
        stats = json.load(f)
    merged = {}
    for entry in _iter_label_entries(stats):
        for key, val in entry.get("access_pattern", {}).items():
            if key not in merged:
                merged[key] = {}
            merged[key].update(val)
    return merged


SEQUENTIAL_JOBS = {"val_seqread", "val_seqwrite", "work_bulk_insert", "work_scan"}


def expected_access_pattern(job_name):
    """Return 'sequential' or 'random' based on job's FIO rw type."""
    return "sequential" if job_name in SEQUENTIAL_JOBS else "random"


def validate_access_pattern(job_name, access_pattern, label, ops, tolerance,
                            lookup_key=None):
    """Check rnd/seq classification matches expected pattern.

    Uses the same tolerance as count checks: dominant pattern must be
    >= (1 - tolerance) * 100 percent.  Default 2% -> requires >= 98%.
    """
    expected = expected_access_pattern(job_name)
    threshold_pct = (1.0 - tolerance) * 100
    results = []
    pattern_data = access_pattern.get(lookup_key or label, {})

    for op in ops:
        entry = pattern_data.get(op, {})
        seq_pct = entry.get("sequential_pct", 0)
        rnd_pct = entry.get("random_pct", 0)
        actual_pct = seq_pct if expected == "sequential" else rnd_pct

        passed = actual_pct >= threshold_pct
        tag = "PASS" if passed else "FAIL"
        msg = (f"[{tag}] {label} {op} access pattern: "
               f"expected={expected}, seq={seq_pct:.1f}%, rnd={rnd_pct:.1f}%")
        results.append((passed, msg))

    return results


def get_val(data, map_name, key, default=0):
    """Safely get a value from parsed bpftrace data."""
    return data.get(map_name, {}).get(key, default)


def check_approx(label, actual, expected, tolerance, allow_over=False):
    """Check that actual ~ expected within tolerance."""
    if expected == 0:
        pct = 0.0 if actual == 0 else float("inf")
    else:
        pct = abs(actual - expected) / expected

    over = actual > expected
    passed = pct <= tolerance or (allow_over and over)
    tag = "PASS" if passed else "FAIL"
    note = f"{pct:.2%} over" if over else f"{pct:.2%} under" if actual < expected else "exact"
    msg = f"[{tag}] {label}: {actual} vs {expected} ({note})"
    if not passed:
        msg += f" — exceeds {tolerance:.0%} tolerance"
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


def validate_completed_vs_fio(fio, fs, tolerance, read_key, write_key, kind,
                              allow_over=False):
    """Check completed counts and bytes against FIO."""
    results = []

    if kind in ("read", "mixed"):
        results.append(check_approx(
            f"fs {read_key} completed",
            get_val(fs, "sc_completed", read_key),
            fio["read_ios"], tolerance, allow_over))
        results.append(check_approx(
            f"fs {read_key} bytes",
            get_val(fs, "sc_total_bytes", read_key),
            fio["read_bytes"], tolerance, allow_over))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            f"fs {write_key} completed",
            get_val(fs, "sc_completed", write_key),
            fio["write_ios"], tolerance, allow_over))
        results.append(check_approx(
            f"fs {write_key} bytes",
            get_val(fs, "sc_total_bytes", write_key),
            fio["write_bytes"], tolerance, allow_over))

    return results


def validate_consistency(fs, tolerance, read_key, write_key, kind):
    """Check entered~completed consistency for active IO syscalls."""
    results = []

    if kind == "mixed":
        keys = (read_key, write_key)
    elif kind == "read":
        keys = (read_key,)
    else:
        keys = (write_key,)
    for sc in keys:
        entered = get_val(fs, "sc_entered", sc)
        completed = get_val(fs, "sc_completed", sc)
        if entered > 0 and completed > 0:
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
    parser.add_argument("--container", action="store_true", help="Container mode: allow profiler counts above FIO")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)

    if args.mode == "detailed":
        fs = parse_detailed_stats(args.fs_out)
    else:
        fs = parse_counters(args.fs_out)

    read_key, write_key = syscall_keys_for_job(args.job)
    kind = classify_job(fio)

    print(f"\n=== {args.job} (mode={args.mode}) ===")

    print(f"  FIO:  read_ios={fio['read_ios']}  read_bytes={fio['read_bytes']}"
          f"  write_ios={fio['write_ios']}  write_bytes={fio['write_bytes']}")

    print("")
    for i, sc in enumerate((read_key, write_key)):
        prefix = "FS:" if i == 0 else ""
        print(f"  {prefix:6}{sc + ':':9}"
              f"  entered={get_val(fs, 'sc_entered', sc)}"
              f"  completed={get_val(fs, 'sc_completed', sc)}"
              f"  bytes={get_val(fs, 'sc_total_bytes', sc)}")

    # Display auxiliary syscall counts
    aux_parts = [f"{sc}={get_val(fs, 'sc_count', sc)}" for sc in AUXILIARY_SYSCALLS
                 if get_val(fs, "sc_count", sc) > 0]
    if aux_parts:
        print(f"        {', '.join(aux_parts)}")

    print()

    results = validate_completed_vs_fio(fio, fs, args.tolerance, read_key, write_key, kind,
                                        args.container)
    results += validate_consistency(fs, args.tolerance, read_key, write_key, kind)

    all_passed = True
    for passed, msg in results:
        print(f"  {msg}")
        if not passed:
            all_passed = False

    if args.mode == "detailed":
        ops = {"read": [read_key], "write": [write_key], "mixed": [read_key, write_key]}[kind]
        fs_ap = parse_access_pattern(args.fs_out)
        for passed, msg in validate_access_pattern(args.job, fs_ap, "fs", ops, args.tolerance,
                                                   lookup_key="sc_offsets"):
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
