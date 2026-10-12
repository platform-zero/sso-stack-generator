#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/json" "$work/yaml/runtime.overlays"
printf '%s\n' '{"id":"first","id":"shadow"}' > "$work/json/stack.module.json"
printf '%s\n' '{"id":"duplicate-runtime-test"}' > "$work/yaml/stack.module.json"
printf 'volumes:\n  public_anchor: {}\nvolumes: {}\n' > "$work/yaml/runtime.overlays/duplicate.yml"
for kind in json yaml; do
    printf 'protected-output-sentinel\n' > "$work/$kind/stack.runtime.yaml"
    if "$ROOT_DIR/generate.sh" import-runtime-overlays --module "$work/$kind" > "$work/$kind.log" 2>&1; then
        printf '[runtime-input-test] duplicate %s input accepted\n' "$kind" >&2
        exit 1
    fi
    grep -Fq 'Duplicate field' "$work/$kind.log" || {
        printf '[runtime-input-test] expected duplicate-key rejection absent for %s\n' "$kind" >&2
        exit 1
    }
    grep -Fxq 'protected-output-sentinel' "$work/$kind/stack.runtime.yaml"
done
printf '[runtime-input-test] JSON/YAML duplicate keys refuse before output replacement\n'
