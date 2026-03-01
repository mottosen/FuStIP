#!/usr/bin/env python3
"""Compare FIO JSON output against bpftrace block/nvme profiler output.

Asserts that profiler metrics match FIO-reported numbers within tolerance.
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


def check_near_zero(label, actual, max_allowed=10):
    """Check that a counter is near zero."""
    passed = actual <= max_allowed
    tag = "PASS" if passed else "FAIL"
    msg = f"[{tag}] {label}: {actual} (expected ~0, limit {max_allowed})"
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


def validate_blk(fio, blk, tolerance, kind):
    """Block layer: completed vs FIO, then issued~completed consistency."""
    results = []

    # Completed vs FIO
    if kind in ("read", "mixed"):
        results.append(check_approx(
            "blk read completed",
            get_val(blk, "rq_completed", "read"),
            fio["read_ios"], tolerance))
        results.append(check_approx(
            "blk read bytes",
            get_val(blk, "rq_total_bytes", "read"),
            fio["read_bytes"], tolerance))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            "blk write completed",
            get_val(blk, "rq_completed", "write"),
            fio["write_ios"], tolerance))
        results.append(check_approx(
            "blk write bytes",
            get_val(blk, "rq_total_bytes", "write"),
            fio["write_bytes"], tolerance))

    if kind == "read":
        results.append(check_near_zero(
            "blk write completed",
            get_val(blk, "rq_completed", "write")))
    elif kind == "write":
        results.append(check_near_zero(
            "blk read completed",
            get_val(blk, "rq_completed", "read")))

    # Consistency: issued~completed, queued~queue_done
    for op in ("read", "write"):
        issued = get_val(blk, "rq_issued", op)
        completed = get_val(blk, "rq_completed", op)
        if issued > 0 or completed > 0:
            results.append(check_approx(
                f"blk {op} issued~completed",
                issued, completed, tolerance))

        queued = get_val(blk, "rq_queued", op)
        queue_done = get_val(blk, "rq_queue_done", op)
        if queued > 0 or queue_done > 0:
            results.append(check_approx(
                f"blk {op} queued~queue_done",
                queued, queue_done, tolerance))

    return results


def validate_nvme(fio, nvme, tolerance, kind):
    """NVMe layer: completed vs FIO, then setup~completed consistency."""
    results = []

    # Completed vs FIO
    if kind in ("read", "mixed"):
        results.append(check_approx(
            "nvme read completed",
            get_val(nvme, "cmd_completed", "read"),
            fio["read_ios"], tolerance))
        results.append(check_approx(
            "nvme read bytes",
            get_val(nvme, "cmd_total_bytes", "read"),
            fio["read_bytes"], tolerance))

    if kind in ("write", "mixed"):
        results.append(check_approx(
            "nvme write completed",
            get_val(nvme, "cmd_completed", "write"),
            fio["write_ios"], tolerance))
        results.append(check_approx(
            "nvme write bytes",
            get_val(nvme, "cmd_total_bytes", "write"),
            fio["write_bytes"], tolerance))

    # Consistency: setup~completed
    for op in ("read", "write"):
        setup = get_val(nvme, "cmd_setup", op)
        completed = get_val(nvme, "cmd_completed", op)
        if setup > 0 or completed > 0:
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
    parser.add_argument("--tolerance", type=float, default=0.02, help="Tolerance for count checks (default: 0.02)")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)
    blk = parse_counters(args.block_out)
    nvme = parse_counters(args.nvme_out)
    kind = classify_job(fio)

    print(f"\n=== {args.job} ===")

    print(f"  FIO:   read_ios={fio['read_ios']}  read_bytes={fio['read_bytes']}"
          f"  write_ios={fio['write_ios']}  write_bytes={fio['write_bytes']}")

    for op in ("read", "write"):
        prefix = "  BLK:  " if op == "read" else "        "
        print(f"{prefix}{op}:  "
              f"  queued={get_val(blk, 'rq_queued', op)}"
              f"  issued={get_val(blk, 'rq_issued', op)}"
              f"  completed={get_val(blk, 'rq_completed', op)}"
              f"  bytes={get_val(blk, 'rq_total_bytes', op)}")

    for op in ("read", "write"):
        prefix = "  NVME: " if op == "read" else "        "
        print(f"{prefix}{op}:  "
              f"  setup={get_val(nvme, 'cmd_setup', op)}"
              f"  completed={get_val(nvme, 'cmd_completed', op)}"
              f"  bytes={get_val(nvme, 'cmd_total_bytes', op)}")

    print()

    results = validate_blk(fio, blk, args.tolerance, kind)
    results += validate_nvme(fio, nvme, args.tolerance, kind)

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
