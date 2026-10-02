#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
target="$SCRIPT_DIR/host/update-deploy.sh"

python3 - "$target" <<'PY'
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
required = {
    "candidate full verification": 'deploy_installed_release "$DEPLOY_ROOT" full',
    "rollback readiness-only verification": 'deploy_installed_release "$deploy_root" ready-only',
    "full-suite command": './verify.sh --command all',
    "failure evidence": 'record_failure "$exit_code"',
    "success after verification": 'record_success "$deploy_key"',
}
for label, needle in required.items():
    if needle not in text:
        raise SystemExit(f"missing {label}: {needle}")

full = text.index('deploy_installed_release "$DEPLOY_ROOT" full')
clear = text.index('rollback_needed=0', full)
success = text.index('record_success "$deploy_key"', clear)
if not full < clear < success:
    raise SystemExit("candidate verification must complete before rollback is disarmed and success is recorded")
PY

printf '[update-deploy-release-gate-test] ok\n'
