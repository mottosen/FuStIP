#!/usr/bin/env python3
"""Compare FIO JSON output against the nvme profiler output (io_uring_cmd path).

Same checks as tests/block_nvme/check_test.py, but for the NVMe passthrough
suite (io_uring_cmd / nvme), which bypasses the block layer entirely. Only the
nvme layer is profiled here, so only nvme counters/access patterns are validated.

Asserts that profiler metrics match FIO-reported numbers within tolerance.
Supports both bpftrace (summary) and detailed (CSV) modes.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "util"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from stats_generation.shared import (parse_counters, print_data_quality,
                                     check_data_quality, check_stage_consistency)
from report import (active_ops, print_group, print_numbers, print_result,
                    schema_summary, strip_prefix)


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
    """Yield all stat entries (counters/access_pattern/...) from the stats JSON.

    nvme detailed mode nests per-disk entries under each label
    (per_comm[label].per_disk[disk]); descend into those so counts sum across
    all disks. Labels without per_disk (other layers) are yielded directly.
    """
    for bucket in ("per_comm", "per_container"):
        for label_entry in stats.get(bucket, {}).values():
            per_disk = label_entry.get("per_disk") if isinstance(label_entry, dict) else None
            if per_disk:
                yield from per_disk.values()
            else:
                yield label_entry


def parse_detailed_stats(path):
    """Parse detailed-stats.json into the same dict format as parse_counters().

    The stats JSON has: {"per_comm": {"fio": {"counters": {"cmd_completed": {"read": N}}}}}
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

    Access pattern is per (process, device): nvme detailed nests it under
    per_comm[label].per_disk[disk].access_pattern. A single job can touch more than one
    device — e.g. a container run issues its data I/O to one device while paging its
    binary/libraries in from the image overlay on another — so an op can appear under
    several disk/label entries. Pool the raw sequential/random counts across them and
    recompute the percentages (mirroring how counters are summed), so a small
    cross-device entry can't overwrite the dominant data device's classification.
    """
    with open(path) as f:
        stats = json.load(f)
    merged = {}
    for entry in _iter_label_entries(stats):
        for key, ops in entry.get("access_pattern", {}).items():
            dst = merged.setdefault(key, {})
            for op, ap in ops.items():
                _pool_access_pattern(dst, op, ap)
    return merged


def _pool_access_pattern(dst, op, ap):
    """Accumulate one op's access-pattern entry into dst[op] by summing raw counts.

    Falls back to keeping the existing (or first) entry when the raw
    sequential/random counts are not both present to pool with.
    """
    cur = dst.get(op)
    if cur is None:
        dst[op] = dict(ap)
        return
    if "sequential_count" not in ap or "sequential_count" not in cur:
        return  # counts unavailable on one side — keep the existing entry
    seq = cur["sequential_count"] + ap["sequential_count"]
    rnd = cur["random_count"] + ap["random_count"]
    tot = seq + rnd
    dst[op] = {
        "total_ios": cur.get("total_ios", 0) + ap.get("total_ios", 0),
        "sequential_count": seq,
        "random_count": rnd,
        "sequential_pct": round(100 * seq / tot, 2) if tot else 0,
        "random_pct": round(100 * rnd / tot, 2) if tot else 0,
    }


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

    # Stage consistency is checked by check_stage_consistency() against the BPF stage
    # counters in data_quality: with one row per command there are no setup rows to
    # count, so there is no per-op cmd_setup to compare against.

    return results


def main():
    parser = argparse.ArgumentParser(description="Check nvme profiler output against FIO results")
    parser.add_argument("--job", required=True, help="FIO job name")
    parser.add_argument("--fio-json", required=True, help="Path to FIO JSON output")
    parser.add_argument("--nvme-out", required=True, help="Path to NVMe layer output")
    parser.add_argument("--mode", default="summary", choices=["summary", "detailed"],
                        help="Profiling mode (default: summary)")
    parser.add_argument("--tolerance", type=float, default=0.02, help="Tolerance for count checks (default: 0.02)")
    parser.add_argument("--container", action="store_true", help="Container mode: allow profiler counts above FIO")
    parser.add_argument("--max-drop-pct", type=float, default=0.0,
                        help="Fail if the BPF ring buffer dropped more than this %% of "
                             "events (default: 0.0 — any drop is a regression)")
    args = parser.parse_args()

    fio = parse_fio_json(args.fio_json)

    if args.mode == "detailed":
        nvme = parse_detailed_stats(args.nvme_out)
    else:
        nvme = parse_counters(args.nvme_out)

    kind = classify_job(fio)
    if args.mode == "detailed":
        ops = {"read": ["read"], "write": ["write"], "mixed": ["read", "write"]}[kind]

    print(f"\n=== {args.job} (mode={args.mode}, io_uring_cmd / nvme passthrough) ===\n")

    rows = [("FIO", op, [("ios", fio[f"{op}_ios"]), ("bytes", fio[f"{op}_bytes"])])
            for op in ("read", "write") if fio[f"{op}_ios"]]
    rows += [("NVME", op, [("ios", get_val(nvme, "cmd_completed", op)),
                              ("bytes", get_val(nvme, "cmd_total_bytes", op))])
             for op in active_ops(nvme, "cmd_completed", fio)]
    print_numbers(rows)

    if args.mode == "detailed":
        print("")
        print_data_quality(args.nvme_out, label="NVME", width=len("NVME DROPS:"))

    checks = [(ok, strip_prefix(m, "nvme")) for ok, m in
              validate_nvme(fio, nvme, args.tolerance, kind, args.container)]
    if args.mode == "detailed":
        ap = parse_access_pattern(args.nvme_out)
        checks += [(ok, strip_prefix(m, "nvme")) for ok, m in
                   validate_access_pattern(args.job, ap, "nvme", ops, args.tolerance,
                                           lookup_key="cmd_sectors")]
        # Structure before values: a malformed capture would otherwise be reported as
        # a pile of odd numbers rather than as the one problem it is.
        sok, smsgs = schema_summary(args.nvme_out, "nvme", "NVME")
        checks += [(sok, m) for m in smsgs]
        # Ring-buffer drops are a correctness failure, not a diagnostic: a short
        # capture looks entirely normal, just smaller.
        checks.append(check_data_quality(args.nvme_out, label="NVME",
                                         max_drop_pct=args.max_drop_pct))
        checks += check_stage_consistency(args.nvme_out, label="NVME",
                                          tolerance=args.tolerance)
        checks = [(ok, strip_prefix(m, "NVME")) for ok, m in checks]

    all_passed = print_group("NVME", checks)

    return print_result(all_passed)


if __name__ == "__main__":
    sys.exit(main())
