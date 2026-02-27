#!/usr/bin/env python3
"""Compare FIO JSON output against bpftrace block/nvme profiler output.

Asserts that profiler metrics match FIO-reported numbers within tolerance.
"""

import argparse
import json
import re


def parse_bpftrace_output(path):
    """Parse bpftrace text output into nested dict.

    Lines like '@rq_issued[read]: 485313' become:
        {"rq_issued": {"read": 485313}}
    """
    data = {}
    pattern = re.compile(r"^@(\w+)\[([^\]]+)\]:\s+(-?\d+)")

    with open(path) as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                map_name, key, value = m.group(1), m.group(2), int(m.group(3))
                data.setdefault(map_name, {})[key] = value

    return data


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
    """Check that actual ≈ expected within tolerance."""
    if expected == 0:
        pct = 0.0 if actual == 0 else float("inf")
    else:
        pct = abs(actual - expected) / expected

    passed = pct <= tolerance
    tag = "PASS" if passed else "FAIL"
    msg = f"[{tag}] {label}: {actual} vs {expected} ({pct:.2%} missing)"
    if not passed:
        msg += f" — exceeds {tolerance:.0%} tolerance"
    return passed, msg


def check_near_zero(label, actual, max_allowed=10):
    """Check that a counter is near zero."""
    passed = actual <= max_allowed
    tag = "PASS" if passed else "FAIL"
    msg = f"[{tag}] {label}: {actual} (expected ~0, limit {max_allowed})"
    return passed, msg


def validate_read_job(fio, blk, nvme, tolerance, mode):
    """Checks for read-only jobs."""
    results = []

    results.append(check_approx(
        "blk read issued",
        get_val(blk, "rq_issued", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "blk read completed",
        get_val(blk, "rq_completed", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "blk read bytes",
        get_val(blk, "rq_total_bytes", "read"),
        fio["read_bytes"], tolerance))

    results.append(check_near_zero(
        "blk write issued",
        get_val(blk, "rq_issued", "write")))

    results.append(check_approx(
        "nvme read setup",
        get_val(nvme, "cmd_setup", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "nvme read completed",
        get_val(nvme, "cmd_completed", "read"),
        fio["read_ios"], tolerance))

    if mode == "summary":
        results.append(check_approx(
            "nvme read bytes",
            get_val(nvme, "cmd_total_bytes", "read"),
            fio["read_bytes"], tolerance))

    return results


def validate_write_job(fio, blk, nvme, tolerance, mode):
    """Checks for write-only jobs."""
    results = []

    results.append(check_approx(
        "blk write issued",
        get_val(blk, "rq_issued", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "blk write completed",
        get_val(blk, "rq_completed", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "blk write bytes",
        get_val(blk, "rq_total_bytes", "write"),
        fio["write_bytes"], tolerance))

    results.append(check_near_zero(
        "blk read issued",
        get_val(blk, "rq_issued", "read")))

    results.append(check_approx(
        "nvme write setup",
        get_val(nvme, "cmd_setup", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "nvme write completed",
        get_val(nvme, "cmd_completed", "write"),
        fio["write_ios"], tolerance))

    if mode == "summary":
        results.append(check_approx(
            "nvme write bytes",
            get_val(nvme, "cmd_total_bytes", "write"),
            fio["write_bytes"], tolerance))

    return results


def validate_randrw_job(fio, blk, nvme, tolerance, mode):
    """Checks for mixed read/write jobs."""
    results = []

    results.append(check_approx(
        "blk read issued",
        get_val(blk, "rq_issued", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "blk read completed",
        get_val(blk, "rq_completed", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "blk write issued",
        get_val(blk, "rq_issued", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "blk write completed",
        get_val(blk, "rq_completed", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "blk read bytes",
        get_val(blk, "rq_total_bytes", "read"),
        fio["read_bytes"], tolerance))

    results.append(check_approx(
        "blk write bytes",
        get_val(blk, "rq_total_bytes", "write"),
        fio["write_bytes"], tolerance))

    results.append(check_approx(
        "nvme read setup",
        get_val(nvme, "cmd_setup", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "nvme read completed",
        get_val(nvme, "cmd_completed", "read"),
        fio["read_ios"], tolerance))

    results.append(check_approx(
        "nvme write setup",
        get_val(nvme, "cmd_setup", "write"),
        fio["write_ios"], tolerance))

    results.append(check_approx(
        "nvme write completed",
        get_val(nvme, "cmd_completed", "write"),
        fio["write_ios"], tolerance))

    if mode == "summary":
        results.append(check_approx(
            "nvme read bytes",
            get_val(nvme, "cmd_total_bytes", "read"),
            fio["read_bytes"], tolerance))

        results.append(check_approx(
            "nvme write bytes",
            get_val(nvme, "cmd_total_bytes", "write"),
            fio["write_bytes"], tolerance))

    return results


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


def validate_job(fio, blk, nvme, tolerance, mode):
    """Dispatch to the right validator based on FIO data."""
    kind = classify_job(fio)
    if kind == "read":
        return validate_read_job(fio, blk, nvme, tolerance, mode)
    elif kind == "write":
        return validate_write_job(fio, blk, nvme, tolerance, mode)
    else:
        return validate_randrw_job(fio, blk, nvme, tolerance, mode)


def main():
    parser = argparse.ArgumentParser(description="Check profiler output against FIO results")
    parser.add_argument("--job", required=True, help="FIO job name")
    parser.add_argument("--fio-json", required=True, help="Path to FIO JSON output")
    parser.add_argument("--block-out", required=True, help="Path to block layer output")
    parser.add_argument("--nvme-out", required=True, help="Path to NVMe layer output")
    parser.add_argument("--mode", choices=["legacy", "summary"], default="summary", help="Tool runtime mode")
    parser.add_argument("--tolerance", type=float, default=0.02, help="Tolerance for count checks (default: 0.02)")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)
    blk = parse_bpftrace_output(args.block_out) if args.mode in ["legacy", "summary"] else {}
    nvme = parse_bpftrace_output(args.nvme_out) if args.mode in ["legacy", "summary"] else {}

    print(f"\n=== {args.job} (mode={args.mode}) ===")

    print(f"  FIO:  read_ios={fio['read_ios']}  read_bytes={fio['read_bytes']}"
          f"  write_ios={fio['write_ios']}  write_bytes={fio['write_bytes']}")
    print(f"  BLK:  rq_issued[read]={get_val(blk, 'rq_issued', 'read')}"
          f"  rq_completed[read]={get_val(blk, 'rq_completed', 'read')}"
          f"  rq_total_bytes[read]={get_val(blk, 'rq_total_bytes', 'read')}")
    print(f"        rq_issued[write]={get_val(blk, 'rq_issued', 'write')}"
          f"  rq_completed[write]={get_val(blk, 'rq_completed', 'write')}"
          f"  rq_total_bytes[write]={get_val(blk, 'rq_total_bytes', 'write')}")
    print(f"  NVME: cmd_setup[read]={get_val(nvme, 'cmd_setup', 'read')}"
          f"  cmd_completed[read]={get_val(nvme, 'cmd_completed', 'read')}")
    print(f"        cmd_setup[write]={get_val(nvme, 'cmd_setup', 'write')}"
          f"  cmd_completed[write]={get_val(nvme, 'cmd_completed', 'write')}")
    if args.mode == "summary":
        print(f"        cmd_total_bytes[read]={get_val(nvme, 'cmd_total_bytes', 'read')}"
              f"  cmd_total_bytes[write]={get_val(nvme, 'cmd_total_bytes', 'write')}")
    print()

    results = validate_job(fio, blk, nvme, args.tolerance, args.mode)
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
