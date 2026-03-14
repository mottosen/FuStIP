#!/usr/bin/env python3
"""CLI parser for FuStIP — generates bash commands for profiling and testing."""

import argparse
import os
import sys

ALL_LAYERS = ["sysstat", "nvme", "block", "fs"]

PROFILE_START_ORDER = ["sysstat", "nvme", "block", "fs"]
PROFILE_STOP_ORDER = list(reversed(PROFILE_START_ORDER))

# Map CLI layer selections → test suite directories
TEST_SUITES = {
    "block_nvme": {"block", "nvme"},
    "filesystem": {"fs", "sysstat"},
}


def parse_args(argv=None):
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-l", "--layers",
        action="append",
        choices=ALL_LAYERS + ["all"],
        default=None,
        help="Layers to target (repeatable, default: all)",
    )
    parent.add_argument("-m", "--mode", choices=["summary", "detailed"], default="summary")
    parent.add_argument("-p", "--comm-filter", help="Process/command name filter (block, fs)")
    parent.add_argument("-c", "--container-filter", help="Container name filter (forces detailed)")
    parent.add_argument("-d", "--dev-filter", help="NVMe device filter (e.g. nvme0n1)")
    parent.add_argument("--clean", action="store_true", help="Clean results directory first")
    parent.add_argument("--debug", action="store_true", help="Enable verbose Makefile output (DEBUG=1)")
    parent.add_argument("--dry", action="store_true", help="Print commands instead of executing")

    parser = argparse.ArgumentParser(
        prog="run.sh",
        description="FuStIP — Full-Stack IO Profiling CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action_sub = parser.add_subparsers(dest="action", required=True)

    profile_parser = action_sub.add_parser("profile", help="Start/stop profiling")
    profile_sub = profile_parser.add_subparsers(dest="sub_action", required=True)
    profile_sub.add_parser("start", parents=[parent], help="Start profiling")
    profile_sub.add_parser("stop", parents=[parent], help="Stop profiling")

    action_sub.add_parser("test", parents=[parent], help="Run test suite(s)")

    args = parser.parse_args(argv)

    # Normalise layers
    if args.layers is None:
        args.layers = list(ALL_LAYERS)
    elif "all" in args.layers:
        args.layers = list(ALL_LAYERS)
    else:
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for l in args.layers:
            if l not in seen:
                seen.add(l)
                unique.append(l)
        args.layers = unique

    return args


def validate(args):
    if args.comm_filter and args.container_filter:
        print("Error: -p/--comm-filter and -c/--container-filter are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    if args.container_filter:
        args.mode = "detailed"

    is_test = args.action == "test"

    if not args.container_filter:
        if "nvme" in args.layers:
            if not args.dev_filter:
                print("Error: nvme layer requires -d/--dev-filter", file=sys.stderr)
                sys.exit(1)

        if not is_test and ("block" in args.layers or "fs" in args.layers):
            if not args.comm_filter:
                needed = [l for l in args.layers if l in ("block", "fs")]
                print(f"Error: {', '.join(needed)} layer(s) require -p/--comm-filter", file=sys.stderr)
                sys.exit(1)



def resolve_env(args):
    """Resolve required environment variables onto args."""
    results_dir = os.environ.get("RESULTS_DIR")
    if not results_dir:
        print("Error: RESULTS_DIR is not set", file=sys.stderr)
        sys.exit(1)
    args.results_dir = results_dir

    if args.action == "test":
        fio_file = os.environ.get("FIO_FILE")
        if not fio_file:
            print("Error: FIO_FILE is not set", file=sys.stderr)
            sys.exit(1)
        args.fio_file = fio_file


def build_layer_vars(layer, args):
    vs = []
    if args.debug:
        vs.append("DEBUG=1")
    if layer == "sysstat":
        vs.append(f"RESULTS_DIR={args.results_dir}")
        return vs

    if args.container_filter:
        vs.append(f"CONTAINER_FILTER={args.container_filter}")
    else:
        vs.append(f"MODE={args.mode}")
        if layer == "nvme":
            vs.append(f"DEV_FILTER={args.dev_filter}")
        elif layer in ("block", "fs"):
            vs.append(f"COMM_FILTER={args.comm_filter}")

    vs.append(f"RESULTS_DIR={args.results_dir}")
    return vs


def generate_profile_commands(args):
    order = PROFILE_START_ORDER if args.sub_action == "start" else PROFILE_STOP_ORDER
    target = "start-collection" if args.sub_action == "start" else "stop-collection"
    cmds = []
    for layer in order:
        if layer in args.layers:
            vs = build_layer_vars(layer, args)
            cmds.append(f"make -C layers/{layer} {target} {' '.join(vs)}")
    return cmds


def generate_test_commands(args):
    selected = set(args.layers)
    cmds = []

    # Determine which layers within each suite are selected
    block_nvme_layers = sorted(TEST_SUITES["block_nvme"] & selected)
    filesystem_layers = sorted(TEST_SUITES["filesystem"] & selected)

    if block_nvme_layers:
        vs = []
        if args.debug:
            vs.append("DEBUG=1")
        if args.container_filter:
            vs.append(f"CONTAINER_FILTER={args.container_filter}")
        else:
            vs.append(f"MODE={args.mode}")
            vs.append("COMM_FILTER=fio")
            if args.dev_filter:
                vs.append(f"DEV_FILTER={args.dev_filter}")
        if block_nvme_layers != sorted(TEST_SUITES["block_nvme"]):
            vs.append(f"LAYERS={' '.join(block_nvme_layers)}")
        vs.append(f"FIO_FILE={args.fio_file}")
        vs.append(f"RESULTS_DIR={args.results_dir}")
        cmds.append(f"make -C tests/block_nvme all {' '.join(vs)}")

    if filesystem_layers:
        vs = []
        if args.debug:
            vs.append("DEBUG=1")
        if args.container_filter:
            vs.append(f"CONTAINER_FILTER={args.container_filter}")
        else:
            vs.append(f"MODE={args.mode}")
            vs.append("COMM_FILTER=fio")
        if filesystem_layers != sorted(TEST_SUITES["filesystem"]):
            vs.append(f"LAYERS={' '.join(filesystem_layers)}")
        vs.append(f"FIO_FILE={args.fio_file}")
        vs.append(f"RESULTS_DIR={args.results_dir}")
        cmds.append(f"make -C tests/filesystem all {' '.join(vs)}")

    return cmds


def main(argv=None):
    args = parse_args(argv)
    validate(args)
    resolve_env(args)

    cmds = ["clear"]

    if args.clean:
        cmds.append(f"rm -rf {args.results_dir}/*")

    if args.action == "profile":
        cmds.extend(generate_profile_commands(args))
    elif args.action == "test":
        cmds.extend(generate_test_commands(args))

    for cmd in cmds:
        print(cmd)


if __name__ == "__main__":
    main()
