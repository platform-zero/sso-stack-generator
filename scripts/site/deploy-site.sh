#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
BUNDLE="" LOCK="" HOST="gerald@192.168.0.11" REMOTE_ROOT='${HOME}/webservices'
usage() { echo "Usage: $0 --bundle-dir <directory> --site-lock <site.lock.json> [--host gerald@192.168.0.11]" >&2; }
while [ "$#" -gt 0 ]; do case "$1" in --bundle-dir) BUNDLE="$2"; shift;; --site-lock) LOCK="$2"; shift;; --host) HOST="$2"; shift;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; shift; done
[ -n "$BUNDLE" ] && [ -n "$LOCK" ] || { usage; exit 2; }
BUNDLE="$(realpath "$BUNDLE")"; LOCK="$(realpath "$LOCK")"; hash="$(sha256sum "$LOCK" | awk '{print $1}')"; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
ssh "$HOST" "mkdir -p $REMOTE_ROOT/incoming/$stamp"
scp "$BUNDLE/bundle.tar" "$BUNDLE/bundle.tar.sha256" "$BUNDLE/bundle.json" "$HOST:$REMOTE_ROOT/incoming/$stamp/"
scp "$ROOT/scripts/site/activate-release.sh" "$HOST:$REMOTE_ROOT/incoming/$stamp/activate-release.sh"
ssh "$HOST" "chmod +x $REMOTE_ROOT/incoming/$stamp/activate-release.sh && WEBSERVICES_RELEASE_ROOT=$REMOTE_ROOT $REMOTE_ROOT/incoming/$stamp/activate-release.sh --incoming $REMOTE_ROOT/incoming/$stamp --site-lock-sha256 $hash"
