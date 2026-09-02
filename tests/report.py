#!/usr/bin/env python3
"""Shared output layout for the fio validation suites.

Every suite prints the same two things: a block of numbers to compare by eye, then
a set of assertions. As the number of assertions grew, the second half turned into
an undifferentiated wall — one layer's schema checks sitting between another layer's
counts and its drop rate — so the shape is defined once, here, and the suites feed
it rather than each formatting their own.

The layout:

    === <job> (mode=<mode>) ===

      FIO:        read:  ios=…  bytes=…          numbers, aligned so the three
      BLK:        read:  ios=…  bytes=…          lines can be read as a column
      NVME:       read:  ios=…  bytes=…

      BLK DROPS:  0/… events dropped (0.000%)
      NVME DROPS: 0/… events dropped (0.000%)

      BLK                                        assertions, grouped per layer
        [PASS] read completed: …
        …

      RESULT: PASS

Three rules keep it legible however many checks are added:

  * Nothing prints for an op or a layer with no data. A read-only job says nothing
    about writes — but an op the PROFILER saw and fio did not still appears, because
    that discrepancy is exactly what these suites exist to catch.
  * A layer's name is dropped from its own lines. Under a `BLK` heading,
    "[PASS] blk read completed" says it twice.
  * The schema validator collapses to one line while it passes. Its per-invariant
    detail is the subject of tests/schema; here it only needs to say whether the
    capture is structurally sound. A failure prints in full, since then the detail
    IS the finding.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "util"))
from stats_generation.schema import validate_layer_schema  # noqa: E402


def strip_prefix(msg, prefix):
    """Drop the layer name from a message already printed under that layer's heading."""
    return msg.replace(f"] {prefix} ", "] ", 1)


def active_ops(counters, completed_key, fio=None, ops=("read", "write")):
    """Ops worth printing: fio asked for them, or the profiler saw them anyway.

    The second half is not symmetry for its own sake. A read-only job that produced
    write records means something is issuing I/O nobody asked for, and suppressing
    the row because fio reported zero would hide precisely that.
    """
    def seen(op):
        from_fio = fio.get(f"{op}_ios", 0) if fio else 0
        return from_fio or counters.get(completed_key, {}).get(op, 0)
    return [op for op in ops if seen(op)]


def print_numbers(rows, label_width=12):
    """Print the aligned number block. `rows` is [(label, name, [(field, value), …])].

    The fields differ per layer — block/nvme report ios and bytes, fs reports entered,
    completed and bytes — so the caller supplies them and this only handles alignment.
    The label prints once per source, so consecutive rows from one layer line up under
    it rather than repeating it, and the name column is sized to the longest name so a
    syscall like `pwrite64` does not push its row out of the column.
    """
    if not rows:
        return
    w = max(len(name) for _, name, _ in rows) + 2
    last = None
    for label, name, fields in rows:
        shown = "" if label == last else f"{label}:"
        last = label
        tail = "  ".join(f"{k}={v}" for k, v in fields)
        print(f"  {shown:<{label_width}}{name + ':':<{w}}{tail}")


def schema_summary(stats_path, layer, label):
    """Structural check, one line while it holds. -> (passed, [msg])"""
    pq = Path(stats_path).parent / "detailed.parquet"
    results = validate_layer_schema(pq, layer, label=label)
    failed = [m for ok, m in results if not ok]
    if failed:
        return False, [strip_prefix(m, label) for m in failed]
    info = [strip_prefix(m, label) for _, m in results if m.startswith("[INFO]")]
    n = sum(1 for ok, m in results if ok and not m.startswith("[INFO]"))
    return True, [f"[PASS] schema: {n} invariants hold"] + info


def print_group(name, results):
    """Print one layer's assertions under a heading. -> all passed

    An empty group prints nothing at all rather than an empty heading: a layer with
    no assertions was not exercised, and a bare heading reads as one that passed.
    """
    if not results:
        return True
    print(f"\n  {name}")
    ok = True
    for passed, msg in results:
        print(f"    {msg}")
        ok = ok and passed
    return ok


def print_result(all_passed):
    """Print the verdict. -> process exit code"""
    print()
    print("  RESULT: PASS" if all_passed else "  RESULT: FAIL")
    print()
    return 0 if all_passed else 1
