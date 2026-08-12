#!/usr/bin/env python3
"""Validate a results tree against the collapsed on-disk schema.

Standalone counterpart to the schema checks the fio suites run after a capture.
This one needs no root, no device and no workload — it reads parquets that already
exist, which makes it the tool for two jobs the fio suites cannot do:

  * checking a capture produced on another machine, and
  * checking a tree after `migrate_event_schema.py` has rewritten it, where the
    question is precisely whether the rewrite produced the same shape a live
    collector would have.

Exits non-zero if any layer fails, so it can gate a migration.

    python3 tests/schema/check_test.py <results_dir> [<results_dir> ...]

A results dir is any directory holding <layer>/detailed.parquet. Several can be
given, so a caller with its own directory layout globs for them itself.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "util"))
from stats_generation.schema import validate_layer_schema

LAYERS = ("nvme", "block")


def check_tree(root: Path) -> tuple[int, int, int]:
    """Validate every collapsed layer under `root`. -> (checked, failed, skipped)"""
    checked = failed = skipped = 0
    for layer in LAYERS:
        pq = root / layer / "detailed.parquet"
        if not pq.exists():
            skipped += 1
            continue
        checked += 1
        print(f"  {pq}")
        for ok, msg in validate_layer_schema(pq, layer, label=layer):
            print(f"    {msg}")
            if not ok:
                failed += 1
    return checked, failed, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results_dirs", type=Path, nargs="+",
                    help="Results directory containing <layer>/detailed.parquet")
    args = ap.parse_args()

    total_checked = total_failed = total_skipped = 0
    for root in args.results_dirs:
        if not root.is_dir():
            print(f"  skip {root} — not a directory", file=sys.stderr)
            continue
        print(f"=== {root} ===")
        c, f, s = check_tree(root)
        total_checked += c
        total_failed += f
        total_skipped += s

    print()
    if total_checked == 0:
        # Nothing found is not success: a typo in the path would otherwise report
        # a clean run over zero files.
        print("  RESULT: FAIL — no detailed.parquet found under any given path")
        return 1
    print(f"  {total_checked} layer capture(s) checked, {total_skipped} absent")
    print("  RESULT: PASS" if total_failed == 0 else f"  RESULT: FAIL ({total_failed} problems)")
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
