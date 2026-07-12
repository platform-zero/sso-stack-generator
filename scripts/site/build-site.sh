#!/usr/bin/env bash
set -euo pipefail

# A clean builder.  It intentionally has no dependency on dist/, out/, a
# deployment host, or a checkout cache.  All mutable state is under one mktemp
# directory which is removed on exit.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
LOCK="" OUTPUT="" METADATA_ONLY=0
usage() { echo "Usage: $0 --site-lock <site.lock.json> --output <directory> [--metadata-only]" >&2; }
while [ "$#" -gt 0 ]; do case "$1" in --site-lock) LOCK="$2"; shift;; --output) OUTPUT="$2"; shift;; --metadata-only) METADATA_ONLY=1;; -h|--help) usage; exit 0;; *) usage; exit 2;; esac; shift; done
[ -n "$LOCK" ] && [ -n "$OUTPUT" ] || { usage; exit 2; }
LOCK="$(realpath "$LOCK")"; mkdir -p "$OUTPUT"; OUTPUT="$(realpath "$OUTPUT")"
command -v git >/dev/null; command -v python3 >/dev/null; command -v tar >/dev/null
tmp="$(mktemp -d "${TMPDIR:-/tmp}/webservices-site-build.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
workspace="$tmp/modules" resolved="$tmp/resolved.json" payload="$tmp/payload" tests="$tmp/tests.json"
python3 "$ROOT/scripts/site/resolve-site-lock.py" --site-lock "$LOCK" --workspace "$workspace" --resolved "$resolved"

# Copy only source inputs.  In particular, stale generator output and local
# caches are never candidates for a release input.
mkdir -p "$payload"
tar -C "$ROOT" --exclude=.git --exclude=dist --exclude=out --exclude=build --exclude=.gradle --exclude=bazel-bin --exclude=bazel-out --exclude=bazel-testlogs --exclude=__pycache__ --exclude=node_modules --exclude=.pytest_cache -cf - . | tar -C "$payload" -xf -

python3 - "$workspace" "$resolved" "$payload" "$tests" <<'PY'
import json, os, shutil, subprocess, sys
from pathlib import Path
workspace, resolved_path, payload, tests_path = map(Path, sys.argv[1:])
resolved=json.loads(resolved_path.read_text()); results=[]
allowed=('global.settings/','stack.compose/','stack.config/','stack.containers/','stack.kotlin/','stack.js/','stack.systemd/','scripts/lib/','scripts/modules/','docs/modules/')
for entry in resolved['modules']:
    source=workspace/entry['id']/entry['path']; descriptor=json.loads((source/'module.json').read_text())
    for overlay in descriptor.get('overlays',[]):
        path=(source/overlay).resolve()
        if source.resolve() not in (path,*path.parents): raise SystemExit('unsafe overlay')
        sources=[path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file())
        for file in sources:
            rel=file.relative_to(source).as_posix()
            if not rel.startswith(allowed): raise SystemExit(f"module '{entry['id']}' overlay is not allowed: {rel}")
            # Catalog fragments are merged deterministically below.  Treating
            # them as ordinary overlays would silently discard earlier modules.
            if rel in ('stack.config/components.json','stack.config/components.overlay.json'):
                dest=payload/'stack.config'/'components.external'/f"{entry['id']}.json"
            elif rel == 'stack.config/service-contracts.json':
                dest=payload/'stack.config'/'service-contracts.external'/f"{entry['id']}.json"
            else:
                dest=payload/rel
            dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(file,dest)
    for command in entry.get('verificationCommands',[]):
        if not isinstance(command,str) or not command: raise SystemExit(f"module '{entry['id']}' has an invalid verification command")
        cache=workspace.parent/'test-cache'/entry['id']
        scratch=workspace.parent/'test-tmp'/entry['id']
        cache.mkdir(parents=True,exist_ok=True); scratch.mkdir(parents=True,exist_ok=True)
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(source), 'TMPDIR':str(scratch), 'XDG_CACHE_HOME':str(cache)}
        result=subprocess.run(['sh','-c',command],cwd=source,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        results.append({'module':entry['id'],'command':command,'exitCode':result.returncode,'output':result.stdout[-4000:]})
        if result.returncode: raise SystemExit(f"verification failed for module '{entry['id']}': {command}")
Path(tests_path).write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
PY

if [ "$METADATA_ONLY" = "0" ]; then
  # Site inputs remain outside generator source.  The lock is the sole input;
  # this creates a private, compatibility-only manifest for the established
  # renderer without discovering any legacy manifest or pin file.
  python3 - "$LOCK" "$payload/site/manifest.json" "$payload/site" <<'PY'
import json, shutil, sys
from pathlib import Path
lock_path, manifest_path, site_dir=map(Path,sys.argv[1:])
lock=json.loads(lock_path.read_text())
manifest={key:lock[key] for key in ('site','components','stackConfig','secretStore') if key in lock}
if not isinstance(manifest.get('site'),str): raise SystemExit('site lock must declare site for runtime rendering')
site_dir.mkdir(parents=True,exist_ok=True)
for key in ('stackConfig','secretStore'):
    value=manifest.get(key)
    if not isinstance(value,str): raise SystemExit(f'site lock must declare {key} for runtime rendering')
    source=(lock_path.parent/value).resolve()
    if lock_path.parent.resolve() not in (source,*source.parents) or not source.is_file(): raise SystemExit(f'unsafe or missing {key}: {value}')
    relative=Path(value)
    if relative.is_absolute() or '..' in relative.parts: raise SystemExit(f'unsafe {key}: {value}')
    target=site_dir/relative
    target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
PY
  # Existing generation code correctly owns Compose/systemd rendering.  Run it
  # only inside this fresh tree and package its output, never a source snapshot.
  # Reuse the generator-owned, deterministic catalog merger before any build
  # tests resolve selected components.
  source "$payload/scripts/lib/common.sh"
  source "$payload/scripts/lib/components.sh"
  component_catalog_merge_external "$payload/stack.config/components.json"
  service_contracts_merge_external "$payload/stack.config/service-contracts.json"
  python3 - "$payload/stack.config/components.json" "$payload/stack.config/components.external" <<'PY'
import json, sys
from pathlib import Path
catalog, fragments = map(Path, sys.argv[1:])
merged = {"schemaVersion": 1, "defaultComponents": [], "components": {}}
for path in [catalog, *sorted(fragments.glob("*.json"))]:
    data = json.loads(path.read_text())
    merged["defaultComponents"] = sorted(set(merged["defaultComponents"] + data.get("defaultComponents", [])))
    merged["components"].update(data.get("components", {}))
catalog.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
PY
  git -C "$payload" init -q
  git -C "$payload" add -A
  git -C "$payload" -c user.name=site-builder -c user.email=site-builder@invalid commit -qm 'clean site build input'
  "$payload/build.sh" --manifest "$payload/site/manifest.json"
  rendered="$tmp/rendered"
  mv "$payload/dist" "$rendered"
  payload="$rendered"
fi
cp "$resolved" "$payload/resolved-modules.json"
cp "$tests" "$payload/test-results.json"
site_hash="$(sha256sum "$LOCK" | awk '{print $1}')"
artifact="$OUTPUT/bundle.tar"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -C "$payload" -cf "$artifact" .
artifact_hash="$(sha256sum "$artifact" | awk '{print $1}')"
printf '%s  %s\n' "$artifact_hash" "bundle.tar" > "$OUTPUT/bundle.tar.sha256"
python3 - "$OUTPUT/bundle.json" "$site_hash" "$artifact_hash" "$resolved" "$tests" <<'PY'
import json,sys
out, lock_hash, artifact_hash, resolved, tests=sys.argv[1:]
data={'schemaVersion':1,'siteLockSha256':lock_hash,'artifactSha256':artifact_hash,'resolvedModules':json.load(open(resolved))['modules'],'testResults':json.load(open(tests))}
open(out,'w').write(json.dumps(data,indent=2,sort_keys=True)+'\n')
PY
echo "bundle ready: $OUTPUT/bundle.tar" >&2
