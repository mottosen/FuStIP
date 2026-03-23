#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${RESULTS_DIR:-}" ]; then
    echo "Error: RESULTS_DIR is not set" >&2; exit 1
fi

DRY=false
for arg in "$@"; do
    case "$arg" in
        --dry)    DRY=true ;;
        -h|--help) exec python "$SCRIPT_DIR/util/cli_parser.py" "$@" ;;
    esac
done

CMDS="$(python "$SCRIPT_DIR/util/cli_parser.py" "$@")"

if [ "$DRY" = true ]; then
    echo "$CMDS"
else
    # ensure sudo is available
    sudo -v

    # Keep sudo credentials alive throughout the session
    ( while true; do sudo -v; sleep 50; done ) &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null' EXIT

    bash -c "$CMDS"
fi
