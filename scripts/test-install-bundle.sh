#!/usr/bin/env bash
# Source-only staging regression entry point; never invokes a host deployment.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
python3 -B "$SCRIPT_DIR/test-install-bundle-safety.py"
printf '[test-install-bundle] ok (source-only; not installed acceptance)\n'
