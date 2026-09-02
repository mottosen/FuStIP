#!/usr/bin/env python3
"""Generate stats JSON from block layer detailed Parquet output.

Reads detailed.parquet from the results directory, computes aggregate
statistics matching the summary stats JSON structure, and writes JSON.

Uses multiple independent Polars lazy scans with projection pushdown
to limit peak memory on large files (100M+ rows):
  Scan 1: counters, duration, event counts (streamable)
  Scan 2: distributions (Polars-native quantiles, ~2-row result)
  Scan 3: inflight time-series (aggregated per-second)
  Scan 4: access pattern (sector gap analysis from issue events)

Container/comm binding is deferred to a final bind_containers() pass over
the small in-memory result — no add_label_column() in any Polars scan.
Critical for block layer: the unique 'rq' column (~5.6 GB for 234M rows)
would be force-loaded by add_label_column's with_columns, OOMing Scan 3.

Usage:
    python ./util/generate_detailed_stats.py <results_dir>
"""

import argparse
import json
import math
import sys
from pathlib import Path

import polars as pl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent / "util"))
from stats_generation.shared import (compute_access_pattern,
                                     derive_throughput, tseries_stats)
from container.labeling import bind_containers, load_comm_label_map, load_mntns_label_map

LAYER_PREFIX = "block"

# On-disk format this reader implements; must match the collector's counters.json.
SCHEMA_VERSION = 2


# The tracer writes (u64)-1 when it could not read a sector -- a request with no LBA, or one
# whose bio was gone by the time the probe ran. It is "no sector", exactly like a null, and must
# be excluded from the access pattern: the cast to Int64 below raises on it rather than producing
# a nonsense LBA. The nvme layer has always filtered this; block did not.
SECTOR_UNSET = (1 << 64) - 1


def _sec_to_time(s):
    h, m, ss = s // 3600, (s % 3600) // 60, s % 60
    return f"{h:02d}:{m:02d}:{ss:02d}"


def _series_stats_exprs(col):
    """Polars aggregation expressions for distribution stats."""
    c = pl.col(col)
    return [
        c.count().alias("count"),
        c.min().alias("min"),
        c.max().alias("max"),
        c.mean().alias("mean"),
        c.quantile(0.01, interpolation="linear").alias("p1"),
        c.quantile(0.05, interpolation="linear").alias("p5"),
        c.quantile(0.50, interpolation="linear").alias("p50"),
        c.quantile(0.95, interpolation="linear").alias("p95"),
        c.quantile(0.99, interpolation="linear").alias("p99"),
    ]


def _row_to_stats(row):
    """Convert a Polars agg row dict to series_stats-compatible dict."""
    def _val(v):
        return round(float(v), 2) if v is not None else 0.0
    return {
        "count": int(row["count"]) if row["count"] is not None else 0,
        "min": _val(row["min"]),
        "max": _val(row["max"]),
        "mean": _val(row["mean"]),
        "p1": _val(row["p1"]),
        "p5": _val(row["p5"]),
        "p50": _val(row["p50"]),
        "p95": _val(row["p95"]),
        "p99": _val(row["p99"]),
    }


def _comm_key(row, has_mntns):
    """Extract (comm, mntns_id_str) key from a row dict."""
    mntns_id = row.get("mntns_id") if has_mntns else None
    return row["comm"], (str(mntns_id) if mntns_id is not None else "")


def generate_stats(parquet_path):
    """Parse a block layer detailed Parquet and compute stats."""

    results_dir = parquet_path.parent.parent
    mntns_map = load_mntns_label_map(results_dir)
    comm_map = load_comm_label_map(results_dir)
    schema = pl.scan_parquet(parquet_path).collect_schema()
    has_sector = "sector" in schema
    has_mntns = "mntns_id" in schema
    id_keys = ["comm", "mntns_id"] if has_mntns else ["comm"]

    # Entries keyed by (comm, mntns_id_str) — bind_containers maps to labels at the end.
    _entries: dict = {}

    def ensure_comm_entry(comm, mntns_id_str):
        key = (comm, mntns_id_str)
        if key not in _entries:
            _entries[key] = {
                "counters": {},
                "distributions": {},
                "tseries": {},
                "access_pattern": {},
            }
        return _entries[key]

    # --- Scan 1: Counters, duration, event counts ---
    # Group by raw (comm, mntns_id) — streaming engine stays effective.
    # ts_min/ts_max and event_counts derived from this result (no separate scan).
    # Explicit select avoids loading 'rq' (~5 GB) and other unreferenced columns.
    # One row per request, all completions. The active span runs from the first
    # request ENTERING the block layer to the last completion, so ts_min comes from
    # the reconstructed insert time (issue - queue_latency, which equals issue for
    # direct-dispatched requests); using completion timestamps would shorten the
    # window by a request's full service time and inflate the derived IOPS.
    comm_agg_raw = (pl.scan_parquet(parquet_path)
                      .select([*id_keys, "op", "bytes", "timestamp_ns",
                               "latency_ns", "queue_latency_ns"])
                      .with_columns(
                          (pl.col("timestamp_ns") - pl.col("latency_ns")
                           - pl.col("queue_latency_ns")).alias("enter_ts")
                      )
                      .group_by(*id_keys, "op")
                      .agg(
                          pl.len().alias("count"),
                          pl.col("bytes").sum().alias("total_bytes"),
                          pl.col("enter_ts").min().alias("ts_min"),
                          pl.col("timestamp_ns").max().alias("ts_max"),
                      )
                      .collect(engine="streaming"))

    ts_min = comm_agg_raw["ts_min"].min()
    ts_max = comm_agg_raw["ts_max"].max()
    duration_s = (ts_max - ts_min) / 1e9 if ts_min and ts_max and ts_max > ts_min else 0
    # Received-record count, for the data_quality cross-check against counters.json.
    event_counts = {"request": int(comm_agg_raw["count"].sum())}

    for part in comm_agg_raw.partition_by(id_keys, maintain_order=False):
        row0 = part.row(0, named=True)
        comm, mntns_id_str = _comm_key(row0, has_mntns)
        entry = ensure_comm_entry(comm, mntns_id_str)
        comm_counters = {}

        # Every row is a completed request.
        #
        # rq_issued / rq_queued are deliberately NOT emitted per (comm, op): the BPF
        # stage counters have no op breakdown, and deriving them from the completion
        # count would make the issued~completed consistency check compare a number
        # against itself. The totals, and the direct-dispatch count they imply, are
        # reported once under data_quality.
        comm_counters["rq_completed"] = dict(zip(
            part["op"].to_list(),
            [int(v) for v in part["count"].to_list()]
        ))
        comm_counters["rq_total_bytes"] = dict(zip(
            part["op"].to_list(),
            [int(v) for v in part["total_bytes"].to_list()]
        ))

        entry["counters"] = comm_counters
        # Trustworthy iops/throughput = completed ÷ active duration (the
        # first→last I/O-event span), matching FIO's average over its runtime.
        # tseries.iops.max remains the corroborating peak second.
        entry["derived"] = derive_throughput(
            comm_counters, duration_s, "rq_completed", "rq_total_bytes")

    del comm_agg_raw

    # --- Scan 2: Distributions (per comm, per op) ---
    # Process one op at a time: quantile on ~60M rows uses ~11 GB RSS.
    # Per-op scans reuse allocator memory (~12 GB total vs ~22 GB simultaneous).
    ops = (pl.scan_parquet(parquet_path)
             .select("op")
             .unique()
             .collect()["op"].to_list())

    for op in ops:
        raw_dlat_op = (pl.scan_parquet(parquet_path)
                         .select([*id_keys, "op", "latency_ns"])
                         .filter(pl.col("op") == op)
                         .filter(pl.col("latency_ns").is_not_null())
                         .group_by(*id_keys)
                         .agg(_series_stats_exprs("latency_ns"))
                         .collect(engine="streaming"))
        for row in raw_dlat_op.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("driver_latencies", {})[op] = _row_to_stats(row)
        del raw_dlat_op

    issue_ops = ops

    for op in issue_ops:
        # Select on `queued`, not on a positive latency. Direct-dispatched requests
        # never entered the scheduler queue (no block_rq_insert — the common case
        # with the 'none' scheduler and io_uring) and must stay out of this
        # distribution; the old test for latency_ns > 0 also silently discarded
        # genuinely-queued requests whose wait rounded to zero.
        raw_qlat_op = (pl.scan_parquet(parquet_path)
                         .select([*id_keys, "op", "queued", "queue_latency_ns"])
                         .filter(pl.col("op") == op)
                         .filter(pl.col("queued") == 1)
                         .filter(pl.col("queue_latency_ns").is_not_null())
                         .group_by(*id_keys)
                         .agg(_series_stats_exprs("queue_latency_ns"))
                         .collect(engine="streaming"))
        for row in raw_qlat_op.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("queue_latencies", {})[op] = _row_to_stats(row)
        del raw_qlat_op

    for op in ops:
        raw_size_op = (pl.scan_parquet(parquet_path)
                         .select([*id_keys, "op", "bytes"])
                         .filter(pl.col("op") == op)
                         .group_by(*id_keys)
                         .agg(_series_stats_exprs("bytes"))
                         .collect(engine="streaming"))
        for row in raw_size_op.iter_rows(named=True):
            comm, mntns_id_str = _comm_key(row, has_mntns)
            ensure_comm_entry(comm, mntns_id_str)["distributions"].setdefault("rq_sizes", {})[op] = _row_to_stats(row)
        del raw_size_op

    # --- Scan 3: Inflight time-series (per comm) ---
    # Explicit select for projection pushdown: block parquet has a unique 'rq'
    # string column (~5.6 GB) that would be force-loaded without explicit select.
    # tseries computed per comm; bind_containers keeps dominant comm's for container labels.
    if duration_s > 0:
        window_ns = 1_000_000_000
        # Each request contributes a depth sample at every stage transition it
        # actually made:
        #
        #   insert (queued only) -> q_inflight_at_insert
        #   issue                -> q_inflight_at_issue (queued only), d_inflight_at_issue
        #   complete             -> d_inflight_at_complete
        #
        # The old rows also carried the *other* counter as a bare snapshot (driver
        # depth at insert, queue depth at complete). Those are re-reads of a shared
        # counter that say nothing about this request's own transition, so they are
        # not reproduced; the transitions carry the information.
        #
        # Sampling only at completion would leave every second that contained
        # submissions but no completions with no sample, flattening ramp-up spikes.
        base = (pl.scan_parquet(parquet_path)
                  .select([*id_keys, "op", "timestamp_ns", "latency_ns",
                           "queue_latency_ns", "queued",
                           "q_inflight_at_insert", "q_inflight_at_issue",
                           "d_inflight_at_issue", "d_inflight_at_complete"]))
        issue_ts = pl.col("timestamp_ns") - pl.col("latency_ns")
        insert_ts = issue_ts - pl.col("queue_latency_ns")
        null_i32 = pl.lit(None, dtype=pl.Int32)

        def _sec(ts_expr):
            return ((ts_expr - ts_min) // window_ns).cast(pl.Int64).alias("sec")

        at_insert = base.filter(pl.col("queued") == 1).select([
            *id_keys, "op", _sec(insert_ts),
            pl.col("q_inflight_at_insert").cast(pl.Int32).alias("q_inflight"),
            null_i32.alias("d_inflight"),
            pl.lit(0, dtype=pl.Int32).alias("is_completion"),
        ])
        at_issue = base.select([
            *id_keys, "op", _sec(issue_ts),
            pl.when(pl.col("queued") == 1)
              .then(pl.col("q_inflight_at_issue").cast(pl.Int32))
              .otherwise(null_i32).alias("q_inflight"),
            pl.col("d_inflight_at_issue").cast(pl.Int32).alias("d_inflight"),
            pl.lit(0, dtype=pl.Int32).alias("is_completion"),
        ])
        at_complete = base.select([
            *id_keys, "op", _sec(pl.col("timestamp_ns")),
            null_i32.alias("q_inflight"),
            pl.col("d_inflight_at_complete").cast(pl.Int32).alias("d_inflight"),
            pl.lit(1, dtype=pl.Int32).alias("is_completion"),
        ])
        per_comm_snap = (pl.concat([at_insert, at_issue, at_complete])
                           .group_by(*id_keys, "op", "sec")
                           .agg(
                               pl.col("q_inflight").drop_nulls().last(),
                               pl.col("d_inflight").drop_nulls().last(),
                               pl.col("is_completion").sum().alias("io_count"),
                           )
                           .collect(engine="streaming"))

        total_secs = math.ceil(duration_s)
        for part in per_comm_snap.partition_by(id_keys, maintain_order=False):
            row0 = part.row(0, named=True)
            comm, mntns_id_str = _comm_key(row0, has_mntns)
            entry = ensure_comm_entry(comm, mntns_id_str)
            for op_part in part.partition_by("op", maintain_order=False):
                op = op_part["op"][0]
                for stage, col in [("q_inflight", "q_inflight"), ("d_inflight", "d_inflight")]:
                    points = [
                        {"time": _sec_to_time(int(s)), "value": max(0, int(v))}
                        for s, v in zip(op_part["sec"].to_list(), op_part[col].to_list())
                        if v is not None
                    ]
                    if points:
                        entry["tseries"].setdefault(stage, {})[op] = tseries_stats(points)
                # IOPS time series: zero-filled over the global profiling window
                sec_to_iops = {
                    int(s): int(v)
                    for s, v in zip(op_part["sec"].to_list(), op_part["io_count"].to_list())
                    if v is not None
                }
                iops_points = [
                    {"time": _sec_to_time(s), "value": sec_to_iops.get(s, 0)}
                    for s in range(total_secs)
                ]
                if iops_points:
                    entry["tseries"].setdefault("iops", {})[op] = tseries_stats(iops_points)
        del per_comm_snap

    # --- Scan 4: Access pattern (per comm, per op, submission-ordered) ---
    # The gap test asks whether request i+1 starts where request i ended, which is
    # only meaningful in the order the DRIVER received them — i.e. issue order.
    # Rows are now completions, and completions reorder under any queue depth above
    # one, so sorting by the row's own timestamp_ns would feed the gap test a
    # sequence that never happened and report sequential I/O as random. Sort by the
    # reconstructed issue time (timestamp_ns - latency_ns) instead. The parquet is
    # also physically unordered (multi-CPU ring buffer), so an explicit sort is
    # required either way. shared.py cannot detect a violation of this contract.
    if has_sector:
        has_ts = "timestamp_ns" in schema
        cols = (["timestamp_ns", "latency_ns"] if has_ts else []) + ["sector", "bytes"]
        for (comm, mntns_id_str) in list(_entries.keys()):
            if has_mntns and mntns_id_str:
                comm_filter = (pl.col("comm") == comm) & (pl.col("mntns_id") == int(mntns_id_str))
            else:
                comm_filter = (pl.col("comm") == comm)
            base = (pl.scan_parquet(parquet_path)
                      .filter(comm_filter)
                      .filter(pl.col("sector").is_not_null()
                              & (pl.col("sector") != SECTOR_UNSET)))
            ops = base.select("op").unique().collect(engine="streaming")["op"].to_list()
            if not ops:
                continue
            entry = ensure_comm_entry(comm, mntns_id_str)
            entry["access_pattern"].setdefault("rq_sectors", {})
            for op in ops:
                op_df = (base.filter(pl.col("op") == op)
                             .select(cols)
                             .collect(engine="streaming"))
                if len(op_df) < 2:
                    del op_df
                    continue
                if has_ts:
                    op_df = (op_df
                             .with_columns((pl.col("timestamp_ns") - pl.col("latency_ns"))
                                           .alias("issue_ts"))
                             .sort("issue_ts"))
                sectors = op_df["sector"].cast(pl.Int64).to_numpy()
                bytes_list = op_df["bytes"].cast(pl.Int64).to_numpy()
                entry["access_pattern"]["rq_sectors"][op] = compute_access_pattern(
                    sectors, bytes_list
                )
                del op_df

    result = bind_containers(_entries, mntns_map, comm_map)
    result["derived"] = {"duration_s": round(duration_s, 2)}
    return result, event_counts


def load_data_quality(layer_dir, event_counts):
    """Load per-type counters.json and compute data quality metrics."""
    counters_file = layer_dir / "counters.json"
    if not counters_file.exists():
        return None
    try:
        with open(counters_file) as f:
            counters = json.load(f)

        # This reader implements SCHEMA_VERSION. A capture written to any other
        # version is refused rather than summed as if it were this one: the counter
        # names are the same but their meaning is not, so the failure would surface
        # as a quietly wrong drop_pct rather than as an error.
        version = counters.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"{counters_file} declares schema_version "
                f"{version if version is not None else '<unset>'}; this tool reads "
                f"v{SCHEMA_VERSION} only."
            )

        queued = counters.get("insert", {}).get("generated", 0)
        issued = counters.get("issue", {}).get("generated", 0)
        completed = counters.get("complete", {})
        gen = completed.get("generated", 0)
        drop = completed.get("dropped", 0)
        # Rows actually in the parquet — an independent cross-check of gen - drop.
        received = int(event_counts.get("request", 0))
        direct = counters.get("direct_dispatch", max(0, issued - queued))

        result = {
            "schema_version": SCHEMA_VERSION,
            "total_generated": gen,
            "total_dropped": drop,
            "total_received": received,
            "drop_pct": round(100 * drop / gen, 4) if gen > 0 else 0.0,
            # Single-entry mapping so consumers that iterate per_event_type
            # (print_data_quality, the overview) keep working unchanged.
            "per_event_type": {
                "request": {
                    "generated": gen,
                    "dropped": drop,
                    "received": received,
                    "drop_pct": round(100 * drop / gen, 4) if gen > 0 else 0.0,
                }
            },
            # Stage totals. The BPF counters have no op breakdown, so they are
            # reported once here rather than per (comm, op).
            "requests_queued": queued,
            "requests_issued": issued,
            "requests_incomplete": counters.get("incomplete", max(0, issued - gen)),
            "direct_dispatch": direct,
            "direct_dispatch_pct": round(100 * direct / issued, 4) if issued > 0 else 0.0,
        }

        # Untracked completions: completions whose request was never tracked at
        # issue — excluded by the device/proc/container filter (e.g. other-disk
        # traffic) or, rarely, an issue-probe miss. Informational only; NOT folded
        # into drop_pct, since excluded traffic is correct behavior, not loss.
        untracked = counters.get("untracked", {})
        if untracked:
            result["untracked_completions"] = {
                "per_disk_op": untracked,
                "total": sum(untracked.values()),
            }
        return result
    except (json.JSONDecodeError, OSError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate stats from block layer detailed Parquet output"
    )
    parser.add_argument("results_dir", type=Path, help="Results directory")
    args = parser.parse_args()

    layer_dir = args.results_dir / LAYER_PREFIX
    if not layer_dir.is_dir():
        print(f"Error: {layer_dir} not found", file=sys.stderr)
        sys.exit(1)

    parquet_file = layer_dir / "detailed.parquet"
    if not parquet_file.exists():
        print(f"No detailed output found: {parquet_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {parquet_file.name}...")
    stats, event_counts = generate_stats(parquet_file)

    dq = load_data_quality(layer_dir, event_counts)
    if dq:
        stats["data_quality"] = dq
    # Always remove counters.json — transient file consumed by stats generation
    counters_file = layer_dir / "counters.json"
    counters_file.unlink(missing_ok=True)

    output_file = layer_dir / "detailed-stats.json"
    with open(output_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"  -> {output_file.name}")


if __name__ == "__main__":
    main()
