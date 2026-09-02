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
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from stats_generation.shared import (parse_counters, print_data_quality,
                                     check_data_quality, check_stage_consistency,
                                     device_access_pattern, load_device_geometry)
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
    """Yield all per-comm and per-container label entries from stats JSON.

    nvme detailed mode nests per-disk entries under each label
    (per_comm[label].per_disk[disk]); descend into those so counts sum across
    all disks. Labels without per_disk (the block layer) are yielded directly.
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

    The stats JSON has: {"per_comm": {"fio": {"counters": {"rq_completed": {"read": N}}}}}
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


def parse_access_pattern(path, layer=None, lookup_key=None):
    """Access pattern for the whole capture, as {lookup_key: {op: pattern}}.

    What fio asserts when it says a job is sequential is a property of the stream the
    DEVICE saw. The stats JSON stores the pattern per (comm, disk) instead, which is a
    different question — "was this thread's stream sequential?" — and the two answers
    diverge whenever one logical stream is issued by more than one thread. A sequential
    fio write job is exactly that case: io_uring offloads part of the submissions to
    `iou-wrk-*` kernel workers, so the device sees one perfect ramp while `fio` and
    `iou-wrk` each see a subsequence full of holes.

    Summing the per-comm counts does not recover it either. Sequentiality is adjacency
    within an ORDERED stream, so counts computed over different streams are not
    addable — pooling them reports a job that was 100 % sequential at the device as
    89.9 %. Derive it from the parquet instead, over all comms at once and in
    reconstructed submission order.

    Falls back to the pooled JSON figure when there is no parquet to read (summary
    mode), which keeps the old behaviour where it is the only thing available.
    """
    pq = Path(path).parent / "detailed.parquet"
    if layer and pq.exists():
        geom = load_device_geometry(pq) if layer == "nvme" else None
        by_disk = device_access_pattern(pq, sector_bytes_for=geom)
        # One job can touch several devices (a container pages its image in from the
        # overlay while its data I/O goes elsewhere). Report the busiest, rather than
        # pooling across devices — which would reintroduce the same addition error.
        if by_disk:
            disk = max(by_disk, key=lambda d: sum(v["total_ios"] for v in by_disk[d].values()))
            return {lookup_key: by_disk[disk]}

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

    # Stage consistency is checked by check_stage_consistency() against the BPF stage
    # counters in data_quality: with one row per request there are no insert/issue
    # rows to count, so there is no per-op rq_issued/rq_queued to compare against.

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

    # Stage consistency is checked by check_stage_consistency() against the BPF stage
    # counters in data_quality: with one row per command there are no setup rows to
    # count, so there is no per-op cmd_setup to compare against.

    return results



def main():
    parser = argparse.ArgumentParser(description="Check profiler output against FIO results")
    parser.add_argument("--job", required=True, help="FIO job name")
    parser.add_argument("--fio-json", required=True, help="Path to FIO JSON output")
    parser.add_argument("--block-out", required=True, help="Path to block layer output")
    parser.add_argument("--nvme-out", required=True, help="Path to NVMe layer output")
    parser.add_argument("--fs-out", default=None,
                        help="Optional fs layer output. Counts are validated by the "
                             "filesystem suite; what fs adds here is a third concurrent "
                             "consumer, so only its drop rate is asserted.")
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
        blk = parse_detailed_stats(args.block_out)
        nvme = parse_detailed_stats(args.nvme_out)
    else:
        blk = parse_counters(args.block_out)
        nvme = parse_counters(args.nvme_out)

    kind = classify_job(fio)
    if args.mode == "detailed":
        ops = {"read": ["read"], "write": ["write"], "mixed": ["read", "write"]}[kind]

    print(f"\n=== {args.job} (mode={args.mode}) ===\n")

    # ── numbers ──
    rows = [("FIO", op, [("ios", fio[f"{op}_ios"]), ("bytes", fio[f"{op}_bytes"])])
            for op in ("read", "write") if fio[f"{op}_ios"]]
    rows += [("BLK", op, [("ios", get_val(blk, "rq_completed", op)),
                              ("bytes", get_val(blk, "rq_total_bytes", op))])
             for op in active_ops(blk, "rq_completed", fio)]
    rows += [("NVME", op, [("ios", get_val(nvme, "cmd_completed", op)),
                              ("bytes", get_val(nvme, "cmd_total_bytes", op))])
             for op in active_ops(nvme, "cmd_completed", fio)]
    print_numbers(rows)

    if args.mode == "detailed":
        print("")
        w = len("NVME DROPS:")
        print_data_quality(args.block_out, label="BLK", width=w)
        print_data_quality(args.nvme_out, label="NVME", width=w)
        if args.fs_out:
            print_data_quality(args.fs_out, label="FS", width=w)

    # ── assertions, grouped per layer ──
    all_passed = True

    for label, prefix, stats_path, counters, layer, ap_key in (
            ("BLK", "blk", args.block_out, blk, "block", "rq_sectors"),
            ("NVME", "nvme", args.nvme_out, nvme, "nvme", "cmd_sectors")):
        checks = [(ok, strip_prefix(m, prefix)) for ok, m in
                  (validate_blk if layer == "block" else validate_nvme)(
                      fio, counters, args.tolerance, kind, args.container)]
        if args.mode == "detailed":
            ap = parse_access_pattern(stats_path, layer, ap_key)
            checks += [(ok, strip_prefix(m, prefix)) for ok, m in
                       validate_access_pattern(args.job, ap, prefix, ops, args.tolerance,
                                               lookup_key=ap_key)]
            # Structure before values: a malformed capture would otherwise be reported
            # as a pile of odd numbers rather than as the one problem it is.
            sok, smsgs = schema_summary(stats_path, layer, label)
            checks += [(sok, m) for m in smsgs]
            # Ring-buffer drops are a correctness failure, not a diagnostic: a short
            # capture looks entirely normal, just smaller.
            checks.append(check_data_quality(stats_path, label=label,
                                             max_drop_pct=args.max_drop_pct))
            checks += check_stage_consistency(stats_path, label=label,
                                              tolerance=args.tolerance)
            checks = [(ok, strip_prefix(m, label)) for ok, m in checks]
        all_passed = print_group(label, checks) and all_passed

    # fs contributes a third concurrent consumer rather than counts of its own —
    # those belong to the filesystem suite — so only its drop rate is asserted here.
    if args.mode == "detailed" and args.fs_out:
        fs_checks = [check_data_quality(args.fs_out, label="FS",
                                        max_drop_pct=args.max_drop_pct)]
        fs_checks += check_stage_consistency(args.fs_out, label="FS",
                                             tolerance=args.tolerance)
        fs_checks = [(ok, strip_prefix(m, "FS")) for ok, m in fs_checks]
        all_passed = print_group("FS", fs_checks) and all_passed

    return print_result(all_passed)


if __name__ == "__main__":
    sys.exit(main())
