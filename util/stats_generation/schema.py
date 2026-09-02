#!/usr/bin/env python3
"""Structural validation of a detailed capture's on-disk schema.

The nvme and block layers emit ONE record per operation, at completion, carrying the
fields describing the stages that precede it. Most of that carry-forward happens in
BPF across probes that fire in different contexts, and if a field is dropped on the
way the result is not an error — it is a plausible-looking column full of zeros. A
queue-latency distribution computed from such a column has a mean, a p99 and a shape;
nothing about it says the data is wrong.

So the invariants below are deliberately mechanical and sharp. Each one is false for
a specific way the carry-forward can break:

  * latency always present    - every row is a completion, not a stray stage record.
  * inflight_at_setup >= 1    - it is a POST-increment, so a real capture can never
                                contain 0. All-zero means the setup probe's value
                                never reached the completion probe.
  * d_inflight_at_issue >= 1  - same reasoning on the block side.
  * queued in {0, 1}          - the flag survived as a flag.
  * !queued => queue_latency 0 - a request that never entered the scheduler queue
                                cannot have waited in it. Non-zero here means the
                                issue probe wrote a latency for a request whose
                                insert never fired, i.e. the flag and the latency
                                disagree about the same request.
  * submit time > 0           - timestamp_ns - latency_ns is what every consumer
                                sorts and bins by; a negative value means the two
                                fields came from different clocks or different rows.

Usable standalone against any results tree, so a migrated capture can be checked
without re-running a workload.
"""
import polars as pl

# Columns every one-record-per-operation layer must carry. A capture that predates
# a field, or was written by a different tool, fails here rather than being read
# with the missing column silently treated as absent data.
REQUIRED = {
    "nvme": ["timestamp_ns", "op", "bytes", "latency_ns", "sector", "rq", "tid",
             "comm", "inflight_at_setup", "inflight", "disk_name", "qid"],
    "block": ["timestamp_ns", "op", "queued", "bytes", "latency_ns",
              "queue_latency_ns", "sector", "rq", "tid", "comm",
              "q_inflight_at_insert", "q_inflight_at_issue",
              "d_inflight_at_issue", "d_inflight_at_complete"],
}


def _r(ok, msg):
    return (ok, f"[{'PASS' if ok else 'FAIL'}] {msg}")


def validate_layer_schema(parquet_path, layer, label=""):
    """Check one layer's parquet against the on-disk schema. -> [(passed, msg)]"""
    tag = f"{label} " if label else f"{layer} "
    if layer not in REQUIRED:
        return [(True, f"[SKIP] {tag}schema: layer '{layer}' has no record schema")]
    try:
        schema = pl.scan_parquet(parquet_path).collect_schema()
    except Exception as exc:                                  # noqa: BLE001
        return [(False, f"[FAIL] {tag}schema: cannot read {parquet_path}: {exc}")]

    cols = set(schema.names())
    out = []

    missing = [c for c in REQUIRED[layer] if c not in cols]
    out.append(_r(not missing,
                  f"{tag}schema: required columns present"
                  + (f" — missing {missing}" if missing else "")))

    if missing:
        # Value checks below would raise on the missing columns; the structural
        # failure above is the actionable one.
        return out

    lf = pl.scan_parquet(parquet_path)
    aggs = [
        pl.len().alias("n"),
        pl.col("latency_ns").null_count().alias("lat_null"),
        (pl.col("timestamp_ns") - pl.col("latency_ns")).min().alias("submit_min"),
    ]
    if layer == "nvme":
        aggs += [pl.col("inflight_at_setup").min().alias("ifs_min"),
                 pl.col("inflight_at_setup").max().alias("ifs_max")]
    else:
        aggs += [pl.col("queued").min().alias("q_min"),
                 pl.col("queued").max().alias("q_max"),
                 pl.col("d_inflight_at_issue").min().alias("dii_min"),
                 pl.col("d_inflight_at_issue").max().alias("dii_max"),
                 ((pl.col("queued") == 0) & (pl.col("queue_latency_ns") != 0))
                 .sum().alias("bad_direct"),
                 (pl.col("queued") == 1).sum().alias("n_queued")]
    s = lf.select(aggs).collect().row(0, named=True)

    n = s["n"]
    if not n:
        out.append((False, f"[FAIL] {tag}schema: capture is empty"))
        return out

    out.append(_r(s["lat_null"] == 0,
                  f"{tag}schema: latency present on every row"
                  + ("" if s["lat_null"] == 0 else f" — {s['lat_null']} null")))
    out.append(_r(s["submit_min"] is not None and s["submit_min"] > 0,
                  f"{tag}schema: reconstructed submit time positive "
                  f"(min {s['submit_min']})"))

    if layer == "nvme":
        # Post-increment: a captured command is in flight, so the floor is 1.
        out.append(_r(s["ifs_min"] is not None and s["ifs_min"] >= 1,
                      f"{tag}schema: inflight_at_setup >= 1 "
                      f"(min {s['ifs_min']}, max {s['ifs_max']})"
                      + ("" if (s["ifs_min"] or 0) >= 1 else
                         " — 0 means the setup depth never reached the completion probe")))
    else:
        out.append(_r(s["q_min"] in (0, 1) and s["q_max"] in (0, 1),
                      f"{tag}schema: queued is a flag "
                      f"(min {s['q_min']}, max {s['q_max']})"))
        out.append(_r(s["bad_direct"] == 0,
                      f"{tag}schema: direct-dispatched requests have no queue latency"
                      + ("" if s["bad_direct"] == 0 else
                         f" — {s['bad_direct']} rows say queued=0 with a non-zero wait")))
        out.append(_r(s["dii_min"] is not None and s["dii_min"] >= 1,
                      f"{tag}schema: d_inflight_at_issue >= 1 "
                      f"(min {s['dii_min']}, max {s['dii_max']})"
                      + ("" if (s["dii_min"] or 0) >= 1 else
                         " — 0 means the issue depth never reached the completion probe")))
        frac = s["n_queued"] / n
        out.append((True, f"[INFO] {tag}schema: {s['n_queued']}/{n} requests queued "
                          f"({100 * frac:.1f}%), {100 * (1 - frac):.1f}% direct-dispatched"))
    return out
