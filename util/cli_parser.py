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


def _as_csv(val):
    if isinstance(val, list):
        return ",".join(str(v) for v in val)
    return str(val)


def _load_config(path):
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML is required for --config (pip install pyyaml)", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _apply_config_defaults(args, cfg):
    if args.layers is None and "layers" in cfg:
        args.layers = [_as_csv(cfg["layers"])]
    if args.mode is None and "mode" in cfg:
        args.mode = cfg["mode"]
    if args.comm_filter is None and "comm_filter" in cfg:
        args.comm_filter = _as_csv(cfg["comm_filter"])
    if args.pid_filter is None and "pid_filter" in cfg:
        args.pid_filter = _as_csv(cfg["pid_filter"])
    if args.container_filter is None and "container_filter" in cfg:
        args.container_filter = _as_csv(cfg["container_filter"])
    if args.dev_filter is None and "dev_filter" in cfg:
        args.dev_filter = _as_csv(cfg["dev_filter"])


def parse_args(argv=None):
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-l", "--layers",
        action="append",
        default=None,
        help="Layers to target, comma-separated and/or repeatable (default: all) [config: layers]",
    )
    parent.add_argument("-m", "--mode", choices=["summary", "detailed"], default=None,
                        help="Profiling mode: summary or detailed (default: summary). "
                             "container_filter requires detailed (summary errors out) [config: mode]")
    parent.add_argument("-c", "--container-filter", help="Container name filter, comma-separated for multiple. "
                             "Top of the filter hierarchy: restricts to these containers, forces detailed [config: container_filter]")
    parent.add_argument("-d", "--dev-filter", help="Device filter, comma-separated for multiple (e.g. nvme0n1,nvme1n1). "
                             "Narrows within any container (nvme, block) [config: dev_filter]")
    parent.add_argument("-p", "--comm-filter", help="Process/command name filter, comma-separated for multiple. "
                             "Narrows within any container/device; system-wide if it is the only filter [config: comm_filter]")
    parent.add_argument("-P", "--pid-filter", help="Process ID (tgid) filter, comma-separated for multiple. "
                             "Peer of comm-filter (union); system-wide if no container/device set [config: pid_filter]")
    parent.add_argument("--config", metavar="FILE", help="YAML config file; CLI flags override file values [CLI only]")
    parent.add_argument("--results-dir", dest="results_dir", help="Results directory for stats and visualizations (overrides RESULTS_DIR env var) [CLI only]")
    parent.add_argument("--tmp-dir", "--data-dir", dest="tmp_dir", default=None,
                        help="Temporary directory for raw trace data (overrides FUSTIP_TMP_DIR env var). "
                             "On profile stop, stats JSON and visualizations are copied to --results-dir and "
                             "raw trace data is deleted. Defaults to --results-dir when unset. [CLI only]")
    parent.add_argument("--clean", action="store_true", help="Clean each selected layer's results subdirectory [CLI only]")
    parent.add_argument("--visualize", action="store_true", help="Generate visualization dashboards (detailed mode only) [CLI only]")
    parent.add_argument("--debug", action="store_true", help="Enable verbose Makefile output (DEBUG=1) [CLI only]")
    parent.add_argument("--dry", action="store_true", help="Print commands instead of executing [CLI only]")

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

    test_parser = action_sub.add_parser("test", help="Run test suite(s)")
    test_sub = test_parser.add_subparsers(dest="sub_action", required=True)
    test_sub.add_parser("validate", parents=[parent], help="Run validation jobs")
    test_sub.add_parser("vdb", parents=[parent], help="Run VDB-like workload jobs")
    test_sub.add_parser("stress", parents=[parent], help="Run stress (long-duration) jobs")
    test_sub.add_parser("all", parents=[parent], help="Run all test jobs")

    args = parser.parse_args(argv)

    # Apply config file defaults (CLI flags win: they set args away from sentinel)
    if args.config:
        _apply_config_defaults(args, _load_config(args.config))

    # NOTE: the mode default ("summary") is resolved in validate(), after the
    # container_filter conflict check, so an explicit `mode: summary` alongside a
    # container_filter can be distinguished from an unset mode and rejected.

    # Flatten comma-separated values from repeated -l flags
    if args.layers is None:
        args.layers = list(ALL_LAYERS)
        return args

    raw = []
    for item in args.layers:
        raw.extend(item.split(","))

    # Validate each token
    valid = set(ALL_LAYERS + ["all"])
    for token in raw:
        if token not in valid:
            parser.error(f"invalid layer: '{token}' (choose from {', '.join(sorted(valid))})")

    if "all" in raw:
        args.layers = list(ALL_LAYERS)
    else:
        seen = set()
        unique = []
        for l in raw:
            if l not in seen:
                seen.add(l)
                unique.append(l)
        args.layers = unique

    return args


def _data_dir(args):
    """Return the directory to use for raw trace data collection."""
    return args.tmp_dir if args.tmp_dir else args.results_dir


def validate(args):
    # container_filter forces detailed mode. Reject an explicit `mode: summary`
    # instead of silently overriding it (mode is still None when never set).
    if args.container_filter:
        if args.mode == "summary":
            print("Error: container_filter requires detailed mode; remove 'mode: summary' "
                  "(container filtering is only available in detailed mode)", file=sys.stderr)
            sys.exit(1)
        args.mode = "detailed"

    # Resolve the built-in default now that the conflict check has run.
    if args.mode is None:
        args.mode = "summary"

    if args.visualize and args.mode != "detailed":
        print("Error: --visualize requires detailed mode (-m detailed)", file=sys.stderr)
        sys.exit(1)

    is_test = args.action == "test"

    # Filter hierarchy: container > device > {comm, pid}. Without a container,
    # each eBPF layer still needs at least one filter to avoid tracing the whole
    # system. comm/pid are peers (union); device applies to nvme and block.
    if not args.container_filter:
        has_proc = bool(args.comm_filter or args.pid_filter)
        if "nvme" in args.layers and not (args.dev_filter or has_proc):
            print("Error: nvme layer requires -d/--dev-filter, -p/--comm-filter, or "
                  "-P/--pid-filter (or -c/--container-filter)", file=sys.stderr)
            sys.exit(1)
        if not is_test:
            if "block" in args.layers and not (args.dev_filter or has_proc):
                print("Error: block layer requires -d/--dev-filter, -p/--comm-filter, or "
                      "-P/--pid-filter (or -c/--container-filter)", file=sys.stderr)
                sys.exit(1)
            if "fs" in args.layers and not has_proc:
                print("Error: fs layer requires -p/--comm-filter or -P/--pid-filter "
                      "(or -c/--container-filter)", file=sys.stderr)
                sys.exit(1)



def resolve_env(args):
    """Resolve required environment variables onto args."""
    if not args.results_dir:
        args.results_dir = os.environ.get("RESULTS_DIR")
    if not args.results_dir:
        print("Error: results dir not set (use --results-dir or RESULTS_DIR env var)", file=sys.stderr)
        sys.exit(1)

    if not args.tmp_dir:
        args.tmp_dir = os.environ.get("FUSTIP_TMP_DIR") or args.results_dir

    if args.action == "test":
        fio_file = os.environ.get("FIO_FILE")
        if not fio_file:
            print("Error: FIO_FILE is not set", file=sys.stderr)
            sys.exit(1)
        args.fio_file = fio_file


def build_layer_vars(layer, args, data_dir=None):
    """Build make variable list for a layer target.

    data_dir: directory passed as RESULTS_DIR to the layer Makefile.
    Defaults to _data_dir(args) (tmp_dir when set, else results_dir).
    Pass args.results_dir explicitly for generate-stats and visualize targets
    so that stats and visualizations are written directly to the experiment dir.
    """
    target_dir = data_dir if data_dir is not None else _data_dir(args)
    vs = []
    if args.debug:
        vs.append("DEBUG=1")
    if layer == "sysstat":
        if args.comm_filter:
            vs.append(f"COMM_FILTER={args.comm_filter}")
        if args.pid_filter:
            vs.append(f"PID_FILTER={args.pid_filter}")
        if args.container_filter:
            vs.append(f"CONTAINER_FILTER={args.container_filter}")
        vs.append(f"RESULTS_DIR={target_dir}")
        return vs

    if args.container_filter:
        vs.append(f"CONTAINER_FILTER={args.container_filter}")
    if not args.container_filter:
        vs.append(f"MODE={args.mode}")

    # Device filter applies to the disk-aware layers (nvme, block).
    if layer in ("nvme", "block") and args.dev_filter:
        vs.append(f"DEV_FILTER={args.dev_filter}")
    # Process tier (comm/pid) applies to every eBPF layer.
    if args.comm_filter:
        vs.append(f"COMM_FILTER={args.comm_filter}")
    if args.pid_filter:
        vs.append(f"PID_FILTER={args.pid_filter}")

    vs.append(f"RESULTS_DIR={target_dir}")
    return vs


def _concurrent(cmds):
    """Wrap commands to run concurrently (background + wait)."""
    if len(cmds) <= 1:
        return cmds
    return [f"{cmd} &" for cmd in cmds] + ["wait"]


def _concurrent_isolated(cmds):
    """Run commands concurrently inside a subshell, isolating wait from prior jobs."""
    if len(cmds) <= 1:
        return cmds
    body = " ".join(f"{cmd} &" for cmd in cmds) + " wait"
    return [f"( {body} )"]


def _container_map_start_cmd(args):
    if not args.container_filter:
        return None
    return (
        f"python ./util/container/generate_container_map.py "
        f"\"{_data_dir(args)}\" \"{args.container_filter}\" >/dev/null 2>&1 "
        f"& echo $! > /tmp/fustip-container-map.pid"
    )


def _container_map_stop_cmd():
    return (
        "if [ -f /tmp/fustip-container-map.pid ]; then "
        "pid=$(cat /tmp/fustip-container-map.pid); "
        "kill $pid 2>/dev/null || true; "
        "i=0; while [ -d /proc/$pid ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; "
        "rm -f /tmp/fustip-container-map.pid; "
        "fi"
    )


def generate_profile_commands(args):
    if args.sub_action == "start":
        cmds = []
        map_cmd = _container_map_start_cmd(args)
        if map_cmd:
            cmds.append(map_cmd)
        layer_cmds = []
        for layer in PROFILE_START_ORDER:
            if layer in args.layers:
                vs = build_layer_vars(layer, args)
                layer_cmds.append(f"make -C layers/{layer} start-collection {' '.join(vs)}")
        # Keep container-map detached from shell wait; otherwise profile start hangs.
        return cmds + _concurrent_isolated(layer_cmds)

    # stop: parallel stop-profiling, then sequential csv-to-parquet, then generate-stats
    stop_cmds = [_container_map_stop_cmd()] if args.container_filter else []
    for layer in PROFILE_STOP_ORDER:
        if layer in args.layers:
            vs = build_layer_vars(layer, args)
            stop_cmds.append(f"make -C layers/{layer} stop-profiling {' '.join(vs)}")

    seq_cmds = []

    # csv-to-parquet: raw CSV lives in tmp_dir, parquet stays there
    for layer in args.layers:
        vs = build_layer_vars(layer, args)  # RESULTS_DIR = tmp_dir
        seq_cmds.append(f"make -C layers/{layer} csv-to-parquet {' '.join(vs)}")

    # If tmp_dir differs from results_dir: copy the specific expected output files
    # for each layer to results_dir, then clean up tmp_dir to prevent contamination
    # of subsequent runs.
    if args.tmp_dir and args.tmp_dir != args.results_dir:
        td = args.tmp_dir
        rd = args.results_dir
        is_detailed = bool(args.container_filter) or args.mode == "detailed"

        # container_map.json lives at the top level of tmp_dir alongside layer dirs.
        seq_cmds.append(f'cp "{td}/container_map.json" "{rd}/" 2>/dev/null || true')

        for layer in args.layers:
            seq_cmds.append(f'mkdir -p "{rd}/{layer}"')
            if layer == "sysstat":
                # parse_output.py emits cpu.csv/mem.csv/dev.csv as final output.
                for fname in ("cpu.csv", "mem.csv", "dev.csv"):
                    seq_cmds.append(
                        f'cp "{td}/{layer}/{fname}" "{rd}/{layer}/" 2>/dev/null || true'
                    )
            elif is_detailed:
                # detailed mode: parquet (converted from CSV) + per-layer json artifacts
                seq_cmds.append(
                    f'cp "{td}/{layer}/detailed.parquet" "{rd}/{layer}/" 2>/dev/null || true'
                )
                seq_cmds.append(
                    f'cp "{td}/{layer}/counters.json" "{rd}/{layer}/" 2>/dev/null || true'
                )
            else:
                # summary mode: bpftrace output
                seq_cmds.append(
                    f'cp "{td}/{layer}/trace.out" "{rd}/{layer}/" 2>/dev/null || true'
                )
            # nvme device-info.json is device-filter-gated and mode-independent.
            if layer == "nvme":
                seq_cmds.append(
                    f'cp "{td}/{layer}/device-info.json" "{rd}/{layer}/" 2>/dev/null || true'
                )

        # Remove layer subdirs from tmp_dir — data is now in results_dir.
        for layer in args.layers:
            seq_cmds.append(f'rm -rf "{td}/{layer}"')
        seq_cmds.append(f'rm -f "{td}/container_map.json" 2>/dev/null || true')

    else:
        # tmp_dir == results_dir: csv-to-parquet already deletes the CSV on success,
        # but if conversion failed the CSV would silently linger. Explicitly remove
        # detailed.csv from block/nvme/fs layer dirs so it can never persist there.
        if bool(args.container_filter) or args.mode == "detailed":
            for layer in args.layers:
                if layer != "sysstat":
                    seq_cmds.append(
                        f'rm -f "{args.results_dir}/{layer}/detailed.csv" 2>/dev/null || true'
                    )

    # generate-stats: reads processed data from results_dir, writes stats JSON there
    for layer in args.layers:
        vs = build_layer_vars(layer, args, data_dir=args.results_dir)
        seq_cmds.append(f"make -C layers/{layer} generate-stats {' '.join(vs)}")

    # Detailed/container mode: write a consolidated human-readable overview of the
    # per-layer stats JSON. Summary mode produces different stats files and is
    # intentionally not summarized here.
    if bool(args.container_filter) or args.mode == "detailed":
        seq_cmds.append(f'python util/generate_overview.py "{args.results_dir}"')

    return _concurrent(stop_cmds) + seq_cmds


TEST_TARGET_MAP = {
    "validate": "validate",
    "vdb": "workload",
    "stress": "stress",
    "all": "all",
}


def generate_test_commands(args):
    selected = set(args.layers)
    target = TEST_TARGET_MAP[args.sub_action]
    cmds = []
    map_cmd = _container_map_start_cmd(args)
    if map_cmd:
        cmds.append(map_cmd)

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
        # comm is always forced to fio (the test workload), regardless of any -p
        # the user passed. Device/pid filters from the test command are honored in
        # every mode — including container — so container runs scope by
        # container ∩ device ∩ comm like the other modes, not container-only.
        vs.append("COMM_FILTER=fio")
        if args.dev_filter:
            vs.append(f"DEV_FILTER={args.dev_filter}")
        if args.pid_filter:
            vs.append(f"PID_FILTER={args.pid_filter}")
        if block_nvme_layers != sorted(TEST_SUITES["block_nvme"]):
            vs.append(f"LAYERS={' '.join(block_nvme_layers)}")
        vs.append(f"FIO_FILE={args.fio_file}")
        vs.append(f"RESULTS_DIR={args.results_dir}")
        cmds.append(f"make -C tests/block_nvme {target} {' '.join(vs)} || echo '!! block_nvme suite failed'")

    if filesystem_layers:
        vs = []
        if args.debug:
            vs.append("DEBUG=1")
        if args.container_filter:
            vs.append(f"CONTAINER_FILTER={args.container_filter}")
        else:
            vs.append(f"MODE={args.mode}")
        # comm is always forced to fio, regardless of any -p the user passed; pid
        # from the test command is honored in every mode. (fs has no device tier,
        # so no DEV_FILTER here.)
        vs.append("COMM_FILTER=fio")
        if args.pid_filter:
            vs.append(f"PID_FILTER={args.pid_filter}")
        if filesystem_layers != sorted(TEST_SUITES["filesystem"]):
            vs.append(f"LAYERS={' '.join(filesystem_layers)}")
        vs.append(f"FIO_FILE={args.fio_file}")
        vs.append(f"RESULTS_DIR={args.results_dir}")
        cmds.append(f"make -C tests/filesystem {target} {' '.join(vs)} || echo '!! filesystem suite failed'")

    if args.container_filter:
        cmds.append(_container_map_stop_cmd())

    # Detailed/container mode: write a consolidated overview of the final
    # per-layer stats left in the results dir (same as profile stop). Summary
    # mode produces different stats files and is intentionally not summarized.
    if bool(args.container_filter) or args.mode == "detailed":
        cmds.append(f'python util/generate_overview.py "{args.results_dir}"')
    return cmds


def generate_visualize_commands(args):
    cmds = []
    for layer in args.layers:
        vs = build_layer_vars(layer, args, data_dir=args.results_dir)
        cmds.append(f"make -C layers/{layer} visualize {' '.join(vs)}")
    return cmds



def main(argv=None):
    args = parse_args(argv)
    validate(args)
    resolve_env(args)

    cmds = ["clear"]

    if args.clean:
        for layer in args.layers:
            cmds.append(f"rm -rf {_data_dir(args)}/{layer}")

    if args.action == "profile":
        cmds.extend(generate_profile_commands(args))
    elif args.action == "test":
        cmds.extend(generate_test_commands(args))

    if args.visualize:
        cmds.extend(generate_visualize_commands(args))

    for cmd in cmds:
        print(cmd)


if __name__ == "__main__":
    main()
