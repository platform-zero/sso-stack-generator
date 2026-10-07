#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/site" "$work/modules/example/stack.config/example"

printf '%s\n' 'fixture' > "$work/modules/example/stack.config/example/value.txt"
printf '%s\n' 'schemaVersion: 1' 'module: example' 'target: core' 'services:' \
  '  caddy:' '    image: docker.io/library/caddy:2' '    lifecycle: daemon' '    networks:' '      caddy: {}' \
  '  worker:' '    image: docker.io/library/alpine:3' '    lifecycle: daemon' '    networks:' '      caddy: {}' \
  'networks:' '  caddy:' '    driver: bridge' > "$work/modules/example/stack.runtime.yaml"
printf '%s\n' '{"schemaVersion":1,"id":"example","dependencies":[],"overlays":["stack.config/example"]}' > "$work/modules/example/stack.module.json"
printf '%s\n' '{"schemaVersion":2,"site":"test","stackConfig":"stack.config.yaml","secretStore":"secrets.json","modules":["example"]}' > "$work/site/manifest.json"
printf '%s\n' 'storage:' '  volume_root: /tmp/provenance-test' \
  'podman:' '  rootful_modules: []' '  rootful_services: [caddy]' '  domains:' '    test:' \
  '      user: webservices-test' '      modules: [example]' > "$work/site/stack.config.yaml"
printf '%s\n' '{}' > "$work/site/secrets.json"
for dir in "$work/site" "$work/modules/example"; do
  git -C "$dir" init -q
  git -C "$dir" add .
  git -C "$dir" -c user.name=ProvenanceTest -c user.email=test@example.invalid commit -qm fixture
done
git -C "$work/modules/example" remote add origin https://example.invalid/example.git
git -C "$work/site" remote add origin https://example.invalid/site.git

STACK_GENERATOR_BUILD_LOCAL_ARTIFACTS=0 "$ROOT_DIR/generate.sh" \
  --site "$work/site/manifest.json" --modules-dir "$work/modules" \
  --backend podman --output "$work/bundle" >/dev/null

jq -e --arg generator "$(git -C "$ROOT_DIR" rev-parse HEAD)" \
  --arg site "$(git -C "$work/site" rev-parse HEAD)" \
  --arg module "$(git -C "$work/modules/example" rev-parse HEAD)" \
  --arg manifest "$(sha256sum "$work/site/manifest.json" | cut -d' ' -f1)" \
  --arg secret "$(sha256sum "$work/site/secrets.json" | cut -d' ' -f1)" \
  '.schemaVersion == 1 and .generatorCommit == $generator and .siteCommit == $site and
   .manifestSha256 == $manifest and .secretStoreSha256 == $secret and .siteDirty == false and
   (.modules | length == 1) and .modules[0].commit == $module and .modules[0].dirty == false' \
  "$work/bundle/source-provenance.json" >/dev/null
jq -e --arg hash "$(sha256sum "$work/bundle/source-provenance.json" | cut -d' ' -f1)" \
  '.sourceProvenanceSha256 == $hash' "$work/bundle/bundle.json" >/dev/null

# Exact pinned module sources can be separate Git worktrees (.git is a file).
mkdir -p "$work/linked"
git -C "$work/modules/example" worktree add --quiet --detach "$work/linked/example" HEAD
STACK_GENERATOR_BUILD_LOCAL_ARTIFACTS=0 "$ROOT_DIR/generate.sh" \
  --site "$work/site/manifest.json" --modules-dir "$work/linked" \
  --backend podman --output "$work/linked-bundle" >/dev/null
jq -e --arg module "$(git -C "$work/linked/example" rev-parse HEAD)" \
  '.modules[0].commit == $module and .modules[0].dirty == false' \
  "$work/linked-bundle/source-provenance.json" >/dev/null

printf '%s\n' 'uncommitted fixture change' > "$work/modules/example/untracked.txt"
STACK_GENERATOR_BUILD_LOCAL_ARTIFACTS=0 "$ROOT_DIR/generate.sh" \
  --site "$work/site/manifest.json" --modules-dir "$work/modules" \
  --backend podman --output "$work/dirty-bundle" >/dev/null
jq -e '.modules[0].dirty == true and .siteDirty == false' \
  "$work/dirty-bundle/source-provenance.json" >/dev/null
printf '[provenance-test] passed\n'
