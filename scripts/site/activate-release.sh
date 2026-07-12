#!/usr/bin/env bash
set -euo pipefail

# This command runs on the host after upload.  It does no source resolution,
# cloning, compilation, or bundle generation.
ROOT="${WEBSERVICES_RELEASE_ROOT:-$HOME/webservices}"
INCOMING="" EXPECTED_LOCK="" READINESS="${WEBSERVICES_READINESS_COMMAND:-}"
SECRET_RENDER="${WEBSERVICES_SECRET_RENDER_COMMAND:-}"
usage() { echo "Usage: $0 --incoming <directory> --site-lock-sha256 <hash> [--readiness-command <command>]" >&2; }
while [ "$#" -gt 0 ]; do case "$1" in --incoming) INCOMING="$2"; shift;; --site-lock-sha256) EXPECTED_LOCK="$2"; shift;; --readiness-command) READINESS="$2"; shift;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; shift; done
[ -n "$INCOMING" ] && [ -n "$EXPECTED_LOCK" ] || { usage; exit 2; }
INCOMING="$(realpath "$INCOMING")"; mkdir -p "$ROOT/releases"
[ -f "$INCOMING/bundle.tar" ] && [ -f "$INCOMING/bundle.tar.sha256" ] && [ -f "$INCOMING/bundle.json" ] || { echo 'incomplete bundle' >&2; exit 1; }
(cd "$INCOMING" && sha256sum -c bundle.tar.sha256)
python3 - "$INCOMING/bundle.json" "$EXPECTED_LOCK" "$INCOMING/bundle.tar" <<'PY'
import hashlib,json,sys
manifest, expected, artifact=sys.argv[1:]
data=json.load(open(manifest))
actual=hashlib.sha256(open(artifact,'rb').read()).hexdigest()
if data.get('schemaVersion') != 1 or data.get('siteLockSha256') != expected or data.get('artifactSha256') != actual: raise SystemExit('bundle manifest or site lock hash verification failed')
PY
release="$ROOT/releases/$(date -u +%Y%m%dT%H%M%SZ)-$(sha256sum "$INCOMING/bundle.tar" | cut -c1-12)"
release="$(mktemp -d "${release}.XXXXXX")"
python3 - "$INCOMING/bundle.tar" "$release" <<'PY'
import pathlib, sys, tarfile
archive, destination=sys.argv[1:]
with tarfile.open(archive) as bundle:
    for member in bundle.getmembers():
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or member.isdev():
            raise SystemExit('unsafe path in bundle')
    bundle.extractall(destination, filter='data')
PY
[ -f "$release/resolved-modules.json" ] || { rm -rf "$release"; echo 'invalid release payload' >&2; exit 1; }
# Secrets are rendered only into this release after artifact verification. The
# command is host-provided so no plaintext secret source enters the bundle.
if [ -n "$SECRET_RENDER" ]; then (cd "$release" && sh -c "$SECRET_RENDER"); fi
if [ -n "$READINESS" ]; then (cd "$release" && sh -c "$READINESS"); fi
previous=""; [ -L "$ROOT/current" ] && previous="$(basename "$(readlink "$ROOT/current")")"
cp "$INCOMING/bundle.json" "$release/bundle.json"
printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$release/verified-release"
ln -s "releases/$(basename "$release")" "$ROOT/.current.next"; mv -Tf "$ROOT/.current.next" "$ROOT/current"
printf '%s\n' "$previous" > "$release/previous-release"
echo "activated $release" >&2
