#!/usr/bin/env python3
"""Generate stats JSON from sysstat (pidstat) CSV output.

Reads cpu.csv, mem.csv, dev.csv from the results directory,
groups by command, computes per-metric aggregate statistics,
and writes sysstat-stats.json.

cgroup_mem.csv, when present, is folded in as two further sections
(cgroup_mem, cgroup_mem_events) covering what pidstat's process-resident
figures cannot see — page cache in particular. It is optional: runs predating
the collector, and layers configured without it, simply omit both sections.

Usage:
    python ./util/generate_stats.py <results_dir>
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import tseries_stats, _time_to_secs, _sort_times_chronological

sys.path.insert(0, str(Path(__file__).resolve().parent))
from container_map import build_label_maps, get_label_order, remap_rows


def parse_csv(path, label_maps=None, processes=None, pids=None):
    """Read a CSV file and return list of row dicts.

    If label_maps is provided, remap using tgid-first then comm map (unmapped → "other").
    Otherwise, when processes and/or pids are set, keep rows matching the command list
    (comm) or the tgid list (pid) — the union of both — and remap the rest to "other".
    """
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if processes is not None or pids is not None:
                in_proc = processes is not None and row["command"] in processes
                in_pid = pids is not None and row["tgid"] in pids
                if not (in_proc or in_pid):
                    row["command"] = "other"
            rows.append(row)
    remap_rows(rows, label_maps)
    return rows


def compute_duration(rows, time_field="time"):
    """Compute duration in seconds from the wall-clock span of unique timestamps.

    Uses the actual time difference between first and last sample, so gaps in
    pidstat output don't cause undercounting, and the duration correctly covers
    the full collection window (container startup through shutdown).
    """
    times = _sort_times_chronological(row[time_field] for row in rows)
    if len(times) < 2:
        return 0
    start = _time_to_secs(times[0])
    end = _time_to_secs(times[-1])
    if end < start:
        end += 86400  # end is next day
    return end - start


def cpu_stats(rows, duration_s):
    """Compute per-command CPU stats as time-series with AUC.

    CPU rows are per-thread (tid). For each timestamp, sum metrics across
    all threads of the same command, then produce time-series points + stats.
    """
    metrics = ["usr", "system", "guest", "wait", "cpu_pct"]
    max_auc = round(100 * duration_s, 2)

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            stats = tseries_stats(points)
            stats["max_area_under_curve"] = max_auc
            cmd_result[metric] = stats
        result[cmd] = cmd_result

    return result


def cpu_per_core_stats(rows):
    """Compute per-core CPU AUC per container.

    For each (command, core), sums cpu_pct across all threads on that core at
    each timestamp, then computes the area under the resulting time series.

    Returns: {"per_command": {"container": {"0": {"area_under_curve": float}, ...}}}
    """
    # Aggregate: command -> core -> time -> summed cpu_pct
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, core, time = row["command"], row["cpu"], row["time"]
        agg[cmd][core][time] += float(row["cpu_pct"])

    result = {}
    for cmd, cores in agg.items():
        cmd_result = {}
        for core, times in cores.items():
            points = [{"time": t, "value": round(times[t], 2)}
                      for t in sorted(times)]
            stats = tseries_stats(points)
            cmd_result[core] = {"area_under_curve": stats["area_under_curve"]}
        result[cmd] = cmd_result

    return {"per_command": result}


def mem_stats(rows, duration_s):
    """Compute per-command memory stats as time-series with AUC."""
    metrics = ["minflt_s", "majflt_s", "vsz_kb", "rss_kb", "mem_pct"]
    max_auc = round(100 * duration_s, 2)

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            stats = tseries_stats(points)
            if metric == "mem_pct":
                stats["max_area_under_curve"] = max_auc
            cmd_result[metric] = stats
        result[cmd] = cmd_result

    return result


def _drop_first_tgid_appearances(rows):
    """Drop the first row per tgid from dev rows before aggregation.

    pidstat computes rates as (cumulative_now - cumulative_prev) / interval.
    For a tgid's first appearance, prev=0, so the reported rate equals the
    process's total accumulated I/O since start divided by one second.  For
    long-running processes that pidstat encounters only at the end (e.g. a fio
    master process, or a parent whose children's I/O rolls up on exit), this
    produces a massive single-sample spike that corrupts mean and AUC.

    Dropping the first row per tgid eliminates these artifacts without any
    hardware-specific threshold.  The cost is one data point per process; for
    processes that genuinely just started, the first sample would have been
    valid but losing it is negligible over a full collection window.
    """
    seen = set()
    result = []
    for row in sorted(rows, key=lambda r: _time_to_secs(r["time"])):
        if row["tgid"] not in seen:
            seen.add(row["tgid"])
            continue
        result.append(row)
    return result


def dev_stats(rows):
    """Compute per-command device IO stats as time-series with AUC."""
    rows = _drop_first_tgid_appearances(rows)
    metrics = ["kb_rd_s", "kb_wr_s", "kb_ccwr_s", "iodelay"]

    # Aggregate: command -> time -> {metric: summed_value}
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(float)))
    for row in rows:
        cmd, time = row["command"], row["time"]
        for metric in metrics:
            agg[cmd][time][metric] += float(row[metric])

    result = {}
    for cmd, times in agg.items():
        cmd_result = {}
        for metric in metrics:
            points = [{"time": t, "value": round(times[t][metric], 2)}
                      for t in sorted(times)]
            cmd_result[metric] = tseries_stats(points)
        result[cmd] = cmd_result

    return result


# ── cgroup memory (cgroup_mem.csv) ──

# Sentinel written by collect_cgroup_mem.py for a field the kernel does not expose
# on that cgroup (the root cgroup has memory.stat but no memory.current/.events/
# .peak/.max, and memory.peak is missing on older kernels).
CGROUP_ABSENT = -1

CGROUP_GAUGES = [
    "memory_current", "memory_peak",
    "anon", "file", "active_file", "inactive_file", "file_mapped",
    "shmem", "slab", "kernel", "pagetables", "percpu", "sock",
]
# Cumulative-since-cgroup-creation counters. Percentiles of a monotone counter are
# meaningless, so these get first/last/delta instead of a stat block.
CGROUP_COUNTERS = [
    "ev_low", "ev_high", "ev_max", "ev_oom", "ev_oom_kill",
    "pgmajfault", "pgscan", "pgsteal",
    "workingset_refault_file", "workingset_refault_anon",
]
CGROUP_LIMITS = ["memory_max", "memory_high"]


def parse_cgroup_csv(path):
    """Read cgroup_mem.csv into row dicts with the numeric fields coerced.

    No container_map remapping: the collector already emits the same label space
    that cpu/mem/dev are bucketed into (container name, comm, or "system").
    """
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            parsed = {
                "time": row["time"],
                "label": row["label"],
                "cgroup_path": row["cgroup_path"],
            }
            for field in CGROUP_GAUGES + CGROUP_COUNTERS + CGROUP_LIMITS:
                try:
                    parsed[field] = int(row[field])
                except (KeyError, TypeError, ValueError):
                    parsed[field] = CGROUP_ABSENT
            rows.append(parsed)
    return rows


def _cgroup_paths(rows):
    """Return {label: [cgroup_path, ...]} — which cgroups each label resolved to."""
    paths = defaultdict(set)
    for row in rows:
        paths[row["label"]].add(row["cgroup_path"])
    return {label: sorted(p) for label, p in paths.items()}


def _host_mem_total():
    """Total host RAM in bytes from /proc/meminfo, or 0 if unreadable."""
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, IndexError, ValueError):
        pass
    return 0


def _sum_across_cgroups(rows, fields):
    """Aggregate label -> time -> {field: summed value}, plus which fields exist.

    A label can span several cgroups (the same comm in different slices); they are
    disjoint, so summing them is correct. A field is "present" for a label only if
    some sample carried a real value — an all-ABSENT field is dropped by the
    callers rather than reported as a run of -1s.
    """
    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    present = defaultdict(set)
    for row in rows:
        label, time = row["label"], row["time"]
        for field in fields:
            value = row[field]
            if value == CGROUP_ABSENT:
                continue
            agg[label][time][field] += value
            present[label].add(field)
    return agg, present


def cgroup_mem_stats(rows, duration_s):
    """Per-label cgroup memory gauges as time-series with AUC.

    Byte-valued levels, so they take the same stat block shape as the pidstat
    sections. max_area_under_curve uses the cgroup's own memory.max when one is
    set (the interesting case for capped runs) and falls back to host RAM;
    limit_source records which, so no consumer has to guess the denominator.
    """
    agg, present = _sum_across_cgroups(rows, CGROUP_GAUGES)

    # Highest limit observed per label — a cgroup's limit can change mid-run, and
    # the ceiling that matters for normalisation is the one it could have reached.
    limits = defaultdict(int)
    for row in rows:
        if row["memory_max"] != CGROUP_ABSENT:
            limits[row["label"]] = max(limits[row["label"]], row["memory_max"])
    mem_total = _host_mem_total()

    result = {}
    for label, times in agg.items():
        if limits.get(label):
            limit, limit_source = limits[label], "memory.max"
        else:
            limit, limit_source = mem_total, "MemTotal"

        label_result = {}
        for metric in CGROUP_GAUGES:
            if metric not in present[label]:
                continue  # kernel does not expose it here
            points = [{"time": t, "value": times[t][metric]} for t in sorted(times)]
            stats = tseries_stats(points)
            stats["max_area_under_curve"] = round(limit * duration_s, 2)
            label_result[metric] = stats

        if not label_result:
            continue
        label_result["limit_bytes"] = limit
        label_result["limit_source"] = limit_source
        label_result["cgroup_paths"] = _cgroup_paths(rows).get(label, [])
        result[label] = label_result

    return result


def cgroup_mem_event_stats(rows):
    """Per-label first/last/delta for the cumulative cgroup counters.

    memory.events (reclaim/throttle/OOM) and the pg*/workingset_* counters are
    monotone totals since cgroup creation, so the useful per-run figure is the
    delta. first/last are kept so a cgroup that outlives the run stays traceable.
    """
    agg, present = _sum_across_cgroups(rows, CGROUP_COUNTERS)

    result = {}
    for label, times in agg.items():
        ordered = _sort_times_chronological(times.keys())
        if not ordered:
            continue
        label_result = {}
        for counter in CGROUP_COUNTERS:
            if counter not in present[label]:
                continue
            first = times[ordered[0]][counter]
            last = times[ordered[-1]][counter]
            label_result[counter] = {
                "first": first,
                "last": last,
                "delta": last - first,
            }
        if label_result:
            result[label] = label_result

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from sysstat (pidstat) CSV output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    parser.add_argument(
        "--process", "-p",
        type=str.split,
        default=None,
        help="Space-separated list of process names to track individually. "
             "All others are grouped as 'other'.",
    )
    parser.add_argument(
        "--pid", "-P",
        type=str.split,
        default=None,
        help="Space-separated process IDs (tgid) to track individually. "
             "Unioned with --process; all others grouped as 'other'.",
    )
    parser.add_argument(
        "--container", "-c",
        type=str.split,
        default=None,
        help="Space-separated container names for container-based grouping.",
    )
    args = parser.parse_args()

    processes = args.process
    pids = set(args.pid) if args.pid else None
    containers = args.container
    sysstat_dir = args.results_dir / "sysstat"
    if not sysstat_dir.is_dir():
        print(f"Error: {sysstat_dir} not found", file=sys.stderr)
        sys.exit(1)

    label_maps = build_label_maps(sysstat_dir, processes)

    result = {}

    # Read all CSVs first to compute global duration
    csv_data = {}
    for name, path in [("cpu", sysstat_dir / "cpu.csv"),
                       ("mem", sysstat_dir / "mem.csv"),
                       ("dev", sysstat_dir / "dev.csv")]:
        if path.exists():
            csv_data[name] = parse_csv(
                path,
                label_maps=label_maps,
                processes=processes if label_maps is None else None,
                pids=pids if label_maps is None else None,
            )
            print(f"  Processed {path.name}: {len(csv_data[name])} rows")

    # Optional: cgroup memory, collected alongside pidstat over the same window.
    cgroup_path = sysstat_dir / "cgroup_mem.csv"
    cgroup_rows = []
    if cgroup_path.exists():
        cgroup_rows = parse_cgroup_csv(cgroup_path)
        print(f"  Processed {cgroup_path.name}: {len(cgroup_rows)} rows")

    if not csv_data and not cgroup_rows:
        print(f"No sysstat CSV files found in {sysstat_dir}")
        return

    # duration_s stays defined by the pidstat window, not the union of both
    # collectors. It is the denominator for cpu/mem max_area_under_curve and for
    # the consumers' AUC-per-second normalisation, so letting a second collector
    # widen it would silently shift existing metrics — the cgroup sampler emits
    # its first sample immediately where pidstat's comes one interval later, so
    # the union is reliably ~1s longer. cgroup rows are used only when there is
    # no pidstat data at all (collector run standalone).
    all_rows = [row for rows in csv_data.values() for row in rows]
    duration_s = compute_duration(all_rows if all_rows else cgroup_rows)
    result["duration_s"] = duration_s

    if "cpu" in csv_data:
        result["cpu"] = {"per_command": cpu_stats(csv_data["cpu"], duration_s)}
        result["cpu_per_core"] = cpu_per_core_stats(csv_data["cpu"])
    if "mem" in csv_data:
        result["mem"] = {"per_command": mem_stats(csv_data["mem"], duration_s)}
    if "dev" in csv_data:
        result["dev"] = {"per_command": dev_stats(csv_data["dev"])}
    if cgroup_rows:
        gauges = cgroup_mem_stats(cgroup_rows, duration_s)
        events = cgroup_mem_event_stats(cgroup_rows)
        if gauges:
            result["cgroup_mem"] = {"per_command": gauges}
        if events:
            result["cgroup_mem_events"] = {"per_command": events}

    result["label_order"] = get_label_order(containers, processes)

    output_file = sysstat_dir / "sysstat-stats.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
