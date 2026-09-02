#!/usr/bin/env python3
"""Check the sysstat layer's cgroup memory output against a known workload.

The other suites validate against FIO's own accounting. There is no equivalent
external oracle for memory, so this suite manufactures the ground truth instead:
workload.sh allocates exactly the amounts the Makefile asks for, `docker run
--memory` sets an exactly-known cap, and the kernel supplies one identity the
other sysstat sections have no analogue for:

    memory.current ~= anon + file + kernel

Checks, per job:

  * anon / file match what the workload allocated (the page-cache check is the
    one that matters — `file` is the memory pidstat's rss_kb structurally
    cannot see, which is the whole reason this collector exists)
  * memory.max matches `--memory` exactly, when a cap was set
  * the reclaim counters fire when, and only when, the workload was capped
  * memory.current reconciles with its components on every sample
  * sampling ran at 1 Hz over the collection window
  * the window agrees with pidstat's cpu.csv, when pidstat also ran

Usage:
    python check_test.py --job val_page_cache --results-dir DIR --label NAME \
        [--expect-anon-mb N] [--expect-file-mb N] [--expect-max-mb N] \
        [--expect-reclaim] [--duration N] [--host-cgroup]
"""

import argparse
import csv
import json
import sys
from pathlib import Path

MB = 1024 * 1024


# ── loading ──


def load_stats(results_dir: Path) -> dict:
    path = results_dir / "sysstat" / "sysstat-stats.json"
    if not path.exists():
        print(f"  [FAIL] {path} not found — sysstat stats were not generated")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def load_samples(results_dir: Path) -> list[dict]:
    path = results_dir / "sysstat" / "cgroup_mem.csv"
    if not path.exists():
        print(f"  [FAIL] {path} not found — the cgroup collector produced nothing")
        sys.exit(1)
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def cpu_csv_times(results_dir: Path) -> list[str]:
    """pidstat's sample timestamps, or [] when pidstat did not run."""
    path = results_dir / "sysstat" / "cpu.csv"
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return sorted({row["time"] for row in csv.DictReader(f)})


# ── assertions (same [PASS]/[FAIL] line shape as the other suites) ──


def check_approx(label, actual, expected, tolerance, unit=""):
    if expected == 0:
        pct = 0.0 if actual == 0 else float("inf")
    else:
        pct = abs(actual - expected) / expected
    passed = pct <= tolerance
    tag = "PASS" if passed else "FAIL"
    msg = f"[{tag}] {label}: {actual:.1f}{unit} vs {expected:.1f}{unit} ({pct:.2%} off)"
    if not passed:
        msg += f" — exceeds {tolerance:.0%} tolerance"
    return passed, msg


def check_negligible(label, actual, floor, unit=""):
    """For components the job allocated none of.

    Never exactly zero: the container's own shell holds a little anon, and its
    image pages land in `file`. What matters is that the component stays far
    below anything the workload would have produced, so the dominance checks
    below mean something.
    """
    passed = actual < floor
    tag = "PASS" if passed else "FAIL"
    return passed, (f"[{tag}] {label}: {actual:.1f}{unit} "
                    f"(expected negligible, < {floor:.0f}{unit})")


def check_exact(label, actual, expected):
    passed = actual == expected
    tag = "PASS" if passed else "FAIL"
    return passed, f"[{tag}] {label}: {actual} vs {expected}"


def check_true(label, passed, detail=""):
    tag = "PASS" if passed else "FAIL"
    return passed, f"[{tag}] {label}{': ' + detail if detail else ''}"


def validate_allocations(gauges, args):
    """anon / file against what workload.sh actually allocated."""
    results = []
    if args.expect_file_mb is not None:
        actual = gauges.get("file", {}).get("max", 0) / MB
        if args.expect_file_mb == 0:
            results.append(check_negligible("cgroup file (page cache)", actual,
                                            args.negligible_mb, " MB"))
        else:
            results.append(check_approx("cgroup file (page cache)", actual,
                                        args.expect_file_mb, args.tolerance, " MB"))
    if args.expect_anon_mb is not None:
        actual = gauges.get("anon", {}).get("max", 0) / MB
        if args.expect_anon_mb == 0:
            results.append(check_negligible("cgroup anon", actual,
                                            args.negligible_mb, " MB"))
        else:
            results.append(check_approx("cgroup anon", actual,
                                        args.expect_anon_mb, args.tolerance, " MB"))

    # The discriminator itself: a page-cache workload must not look like an
    # anonymous one, and vice versa. This is what regresses if cgroup path
    # resolution silently starts pointing at the wrong cgroup.
    if args.expect_file_mb is not None and args.expect_anon_mb is not None:
        file_mb = gauges.get("file", {}).get("max", 0) / MB
        anon_mb = gauges.get("anon", {}).get("max", 0) / MB
        if args.expect_file_mb > args.expect_anon_mb:
            results.append(check_true(
                "file dominates anon", file_mb > anon_mb,
                f"file={file_mb:.1f} MB > anon={anon_mb:.1f} MB"))
        elif args.expect_anon_mb > args.expect_file_mb:
            results.append(check_true(
                "anon dominates file", anon_mb > file_mb,
                f"anon={anon_mb:.1f} MB > file={file_mb:.1f} MB"))
    return results


def validate_limit(gauges, args):
    """memory.max against `docker run --memory`, exactly."""
    if args.expect_max_mb is None:
        return []
    results = [check_exact("memory.max (bytes)",
                           gauges.get("limit_bytes"),
                           int(args.expect_max_mb * MB))]
    results.append(check_true(
        "limit_source is the cgroup cap",
        gauges.get("limit_source") == "memory.max",
        f"got {gauges.get('limit_source')!r}"))
    return results


def validate_reclaim(events, args):
    """Reclaim counters must fire under a cap and stay silent without one.

    This is the plumbing the memory-cap experiments depend on: without it a
    capped run cannot distinguish "index pages were evicted" from "page cache
    shrank". Asserted in both directions so a counter wired to a constant would
    still fail.
    """
    hi = events.get("ev_high", {}).get("delta", 0)
    mx = events.get("ev_max", {}).get("delta", 0)
    scanned = events.get("pgscan", {}).get("delta", 0)
    fired = hi + mx + scanned

    if args.expect_reclaim:
        return [check_true(
            "reclaim counters fired under the cap", fired > 0,
            f"ev_high={hi} ev_max={mx} pgscan={scanned}")]
    return [check_true(
        "no reclaim without a cap", fired == 0,
        f"ev_high={hi} ev_max={mx} pgscan={scanned}")]


def validate_identity(samples, label, tolerance):
    """memory.current ~= anon + file + kernel, on every sample.

    Note `shmem` is deliberately absent: cgroup v2 already counts it inside
    `file`, so adding it double-counts. `kernel` (not `slab`) is the correct
    third term — it also covers pagetables, percpu and vmalloc.
    """
    worst = 0.0
    checked = 0
    for row in samples:
        if row["label"] != label:
            continue
        current = int(row["memory_current"])
        if current <= 0:  # root cgroup does not expose memory.current
            continue
        parts = sum(int(row[k]) for k in ("anon", "file", "kernel"))
        worst = max(worst, abs(current - parts) / current)
        checked += 1
    if not checked:
        return [check_true("memory.current identity", False,
                           "no samples with memory.current")]
    return [check_true(
        "memory.current ~= anon+file+kernel",
        worst <= tolerance,
        f"worst residual {worst:.2%} over {checked} samples "
        f"(tolerance {tolerance:.0%})")]


def validate_cadence(samples, label, stats, args):
    """1 Hz sampling across the collection window."""
    results = []
    times = [r["time"] for r in samples if r["label"] == label]
    n = len(times)
    unique = len(set(times))

    results.append(check_true("one sample per second (no duplicates)",
                              n == unique, f"{n} rows, {unique} distinct timestamps"))
    if args.duration:
        # Allow a sample either side: collection start/stop do not align to the
        # workload's own second boundaries.
        lo, hi = args.duration - 2, args.duration + 2
        results.append(check_true(
            "sample count matches collection window",
            lo <= n <= hi, f"{n} samples for a {args.duration}s window"))

    cpu_times = cpu_csv_times(args.results_dir)
    if cpu_times and times:
        # pidstat's first sample lands one interval in, so the cgroup collector
        # legitimately starts earlier; only the spans should agree closely.
        cg_span = _span(sorted(set(times)))
        cpu_span = _span(cpu_times)
        results.append(check_true(
            "window agrees with pidstat cpu.csv",
            abs(cg_span - cpu_span) <= 3,
            f"cgroup span {cg_span}s vs cpu.csv span {cpu_span}s"))
        # duration_s must remain pidstat-defined, not widened by this collector.
        results.append(check_true(
            "duration_s stays pidstat-defined",
            stats.get("duration_s") == cpu_span,
            f"duration_s={stats.get('duration_s')} cpu.csv span={cpu_span}"))
    else:
        print("  [SKIP] pidstat cpu.csv absent — window cross-check not run")
    return results


def _span(sorted_times: list[str]) -> int:
    def secs(t):
        h, m, s = (int(x) for x in t.split(":"))
        return h * 3600 + m * 60 + s
    if len(sorted_times) < 2:
        return 0
    start, end = secs(sorted_times[0]), secs(sorted_times[-1])
    if end < start:
        end += 86400
    return end - start


def validate_resolution(gauges, args):
    """The label resolved to a real, plausible cgroup."""
    paths = gauges.get("cgroup_paths") or []
    if not paths:
        return [check_true("cgroup path resolved", False, "no cgroup_paths recorded")]
    results = [check_true("exactly one cgroup for the label",
                          len(paths) == 1, f"{paths}")]
    if not args.host_cgroup:
        # Container mode: must land on the container's own cgroup, not a parent
        # slice — resolving to a parent would silently report the wrong scope's
        # memory and still look plausible.
        results.append(check_true(
            "resolved to the container's own cgroup",
            "docker" in paths[0],
            paths[0]))
    else:
        results.append(check_true(
            "resolved below the cgroup root", paths[0] != "/sys/fs/cgroup", paths[0]))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Check sysstat cgroup memory output against a known workload")
    parser.add_argument("--job", required=True, help="Job name")
    parser.add_argument("--results-dir", required=True, type=Path,
                        help="Results dir containing sysstat/")
    parser.add_argument("--label", required=True,
                        help="Expected label (container name or comm)")
    parser.add_argument("--expect-anon-mb", type=float, default=None)
    parser.add_argument("--expect-file-mb", type=float, default=None)
    parser.add_argument("--expect-max-mb", type=float, default=None,
                        help="Expected memory.max in MB (from docker --memory)")
    parser.add_argument("--expect-reclaim", action="store_true",
                        help="Require the reclaim counters to have fired")
    parser.add_argument("--duration", type=int, default=0,
                        help="Expected collection window in seconds")
    parser.add_argument("--host-cgroup", action="store_true",
                        help="Comm mode: the cgroup is a host scope, not a container")
    parser.add_argument("--tolerance", type=float, default=0.15,
                        help="Tolerance for size checks (default: 0.15)")
    parser.add_argument("--negligible-mb", type=float, default=16.0,
                        help="Upper bound in MB for a component the job did not "
                             "allocate (default: 16)")
    parser.add_argument("--identity-tolerance", type=float, default=0.05,
                        help="Tolerance for the memory.current identity (default: 0.05)")
    args = parser.parse_args()

    stats = load_stats(args.results_dir)
    samples = load_samples(args.results_dir)

    print(f"\n=== {args.job} ===")

    section = stats.get("cgroup_mem", {}).get("per_command", {})
    if args.label not in section:
        print(f"  [FAIL] label {args.label!r} absent from cgroup_mem "
              f"(saw: {sorted(section) or 'nothing'})")
        print("\n  RESULT: FAIL\n")
        sys.exit(1)

    gauges = section[args.label]
    events = stats.get("cgroup_mem_events", {}).get("per_command", {}).get(args.label, {})

    print(f"  cgroup: {(gauges.get('cgroup_paths') or ['?'])[0]}")
    print(f"  peak:   current={gauges.get('memory_current', {}).get('max', 0) / MB:.1f} MB"
          f"  anon={gauges.get('anon', {}).get('max', 0) / MB:.1f} MB"
          f"  file={gauges.get('file', {}).get('max', 0) / MB:.1f} MB"
          f"  kernel={gauges.get('kernel', {}).get('max', 0) / MB:.1f} MB")
    if events:
        deltas = {k: v["delta"] for k, v in events.items() if v.get("delta")}
        print(f"  events: {deltas or 'none fired'}")
    print()

    results = []
    results += validate_allocations(gauges, args)
    results += validate_limit(gauges, args)
    results += validate_reclaim(events, args)
    results += validate_identity(samples, args.label, args.identity_tolerance)
    results += validate_cadence(samples, args.label, stats, args)
    results += validate_resolution(gauges, args)

    all_passed = True
    for passed, msg in results:
        print(f"  {msg}")
        if not passed:
            all_passed = False

    print()
    print(f"  RESULT: {'PASS' if all_passed else 'FAIL'}")
    print()

    # Unlike the fio-driven suites this exits non-zero on failure, so a broken
    # collector actually fails the run. cli_parser wraps each suite in
    # `|| echo '!! ... suite failed'`, so a failure is reported without
    # aborting the other suites.
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
