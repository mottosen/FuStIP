#!/usr/bin/env bash
# Download the Inspektor Gadget (ig) binary to bin/ig
set -euo pipefail

IG_VERSION="${IG_VERSION:-v0.38.0}"
IG_ARCH="${IG_ARCH:-amd64}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IG_BIN="$ROOT_DIR/bin/ig"

if [ -x "$IG_BIN" ]; then
	echo "ig already installed at $IG_BIN"
	"$IG_BIN" version
	exit 0
fi

echo "Downloading ig ${IG_VERSION} (${IG_ARCH})..."
mkdir -p "$ROOT_DIR/bin"
curl -sL "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz" \
	| tar -C "$ROOT_DIR/bin" -xzf - ig
chmod +x "$IG_BIN"

echo "Installed ig to $IG_BIN"
"$IG_BIN" version
