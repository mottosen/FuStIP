#!/usr/bin/env python3
"""Compare FIO JSON output against bpftrace block/nvme profiler output.

Asserts that profiler metrics match FIO-reported numbers within tolerance.
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

    The stats JSON has: {"counters": {"rq_completed": {"read": N}, ...}}
    We flatten to: {"rq_completed": {"read": N}, ...}
    """
    with open(path) as f:
        stats = json.load(f)
    return stats.get("counters", {})


def parse_access_pattern(path):
    """Extract access_pattern section from detailed-stats.json."""
    with open(path) as f:
        stats = json.load(f)
    return stats.get("access_pattern", {})


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


def validate_blk(fio, blk, tolerance, kind, allow_over=False):
    """Block layer: completed vs FIO, then issued~completed consistency."""
    results = []

    # Completed vs FIO
    if kind in ("read", "mixed"):
        results.append(check_approx(
            "blk read completed",
            get_val(blk, "rq_completed", "read"),
            fio["read_ios"], tolerance, allow_over))
        results.append(check_approx(
            "blk read bytes",
            get_val(blk, "rq_total_bytes", "read"),
            fio["read_bytes"], tolerance, allow_over))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            "blk write completed",
            get_val(blk, "rq_completed", "write"),
            fio["write_ios"], tolerance, allow_over))
        results.append(check_approx(
            "blk write bytes",
            get_val(blk, "rq_total_bytes", "write"),
            fio["write_bytes"], tolerance, allow_over))

    # Consistency: issued~completed, queued~queue_done
    ops = ("read", "write") if kind == "mixed" else (kind,)
    for op in ops:
        issued = get_val(blk, "rq_issued", op)
        completed = get_val(blk, "rq_completed", op)
        if issued > 0 and completed > 0:
            results.append(check_approx(
                f"blk {op} issued~completed",
                issued, completed, tolerance))

        queued = get_val(blk, "rq_queued", op)
        queue_done = get_val(blk, "rq_queue_done", op)
        if queued > 0 and queue_done > 0:
            results.append(check_approx(
                f"blk {op} queued~queue_done",
                queued, queue_done, tolerance))

    return results


def validate_nvme(fio, nvme, tolerance, kind, allow_over=False):
    """NVMe layer: completed vs FIO, then setup~completed consistency."""
    results = []

    # Completed vs FIO
    if kind in ("read", "mixed"):
        results.append(check_approx(
            "nvme read completed",
            get_val(nvme, "cmd_completed", "read"),
            fio["read_ios"], tolerance, allow_over))
        results.append(check_approx(
            "nvme read bytes",
            get_val(nvme, "cmd_total_bytes", "read"),
            fio["read_bytes"], tolerance, allow_over))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            "nvme write completed",
            get_val(nvme, "cmd_completed", "write"),
            fio["write_ios"], tolerance, allow_over))
        results.append(check_approx(
            "nvme write bytes",
            get_val(nvme, "cmd_total_bytes", "write"),
            fio["write_bytes"], tolerance, allow_over))

    # Consistency: setup~completed
    ops = ("read", "write") if kind == "mixed" else (kind,)
    for op in ops:
        setup = get_val(nvme, "cmd_setup", op)
        completed = get_val(nvme, "cmd_completed", op)
        if setup > 0 and completed > 0:
            results.append(check_approx(
                f"nvme {op} setup~completed",
                setup, completed, tolerance))

    return results


def main():
    parser = argparse.ArgumentParser(description="Check profiler output against FIO results")
    parser.add_argument("--job", required=True, help="FIO job name")
    parser.add_argument("--fio-json", required=True, help="Path to FIO JSON output")
    parser.add_argument("--block-out", required=True, help="Path to block layer output")
    parser.add_argument("--nvme-out", required=True, help="Path to NVMe layer output")
    parser.add_argument("--mode", default="summary", choices=["summary", "detailed"],
                        help="Profiling mode (default: summary)")
    parser.add_argument("--tolerance", type=float, default=0.02, help="Tolerance for count checks (default: 0.02)")
    parser.add_argument("--container", action="store_true", help="Container mode: allow profiler counts above FIO")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)

    if args.mode == "detailed":
        blk = parse_detailed_stats(args.block_out)
        nvme = parse_detailed_stats(args.nvme_out)
    else:
        blk = parse_counters(args.block_out)
        nvme = parse_counters(args.nvme_out)

    kind = classify_job(fio)
    if args.mode == "detailed":
        ops = {"read": ["read"], "write": ["write"], "mixed": ["read", "write"]}[kind]

    print(f"\n=== {args.job} (mode={args.mode}) ===")

    print(f"  FIO:  read_ios={fio['read_ios']}  read_bytes={fio['read_bytes']}"
          f"  write_ios={fio['write_ios']}  write_bytes={fio['write_bytes']}")

    print("")
    for op in ("read", "write"):
        prefix = "BLK:" if op == "read" else ""
        print(f"  {prefix:6}{op + ':':6}"
              f"  queued={get_val(blk, 'rq_queued', op)}"
              f"  issued={get_val(blk, 'rq_issued', op)}"
              f"  completed={get_val(blk, 'rq_completed', op)}"
              f"  bytes={get_val(blk, 'rq_total_bytes', op)}")

    print("")
    for op in ("read", "write"):
        prefix = "NVME:" if op == "read" else ""
        print(f"  {prefix:6}{op + ':':6}"
              f"  setup={get_val(nvme, 'cmd_setup', op)}"
              f"  completed={get_val(nvme, 'cmd_completed', op)}"
              f"  bytes={get_val(nvme, 'cmd_total_bytes', op)}")

    print()

    all_passed = True

    blk_results = validate_blk(fio, blk, args.tolerance, kind, args.container)
    for passed, msg in blk_results:
        print(f"  {msg}")
        if not passed:
            all_passed = False

    if args.mode == "detailed":
        blk_ap = parse_access_pattern(args.block_out)
        for passed, msg in validate_access_pattern(args.job, blk_ap, "blk", ops, args.tolerance,
                                                   lookup_key="rq_sectors"):
            print(f"  {msg}")
            if not passed:
                all_passed = False

    print()

    nvme_results = validate_nvme(fio, nvme, args.tolerance, kind, args.container)
    for passed, msg in nvme_results:
        print(f"  {msg}")
        if not passed:
            all_passed = False

    if args.mode == "detailed":
        nvme_ap = parse_access_pattern(args.nvme_out)
        for passed, msg in validate_access_pattern(args.job, nvme_ap, "nvme", ops, args.tolerance,
                                                   lookup_key="cmd_sectors"):
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
