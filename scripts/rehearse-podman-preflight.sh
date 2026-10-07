#!/usr/bin/env bash
# Two or more independent synthetic, offline first-install preflights on local SSD.
# This NEVER activates units or creates a VM; it is not a full install rehearsal.
set -Eeuo pipefail
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
site=""
modules=""
output=""
runs=2
while [ "$#" -gt 0 ]; do
  case "$1" in
    --site) site="$2"; shift 2 ;;
    --modules-dir) modules="$2"; shift 2 ;;
    --output-root) output="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    *) echo "usage: $0 --site SITE_DIR --modules-dir PINNED_MODULES --output-root NEW_SSD_DIR [--runs N]" >&2; exit 2 ;;
  esac
done
[[ "$runs" =~ ^[1-9][0-9]*$ ]] || { echo 'runs must be positive' >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo 'refusing to run as root' >&2; exit 2; }
if ! { [ -n "$site" ] && [ -n "$modules" ] && [ -n "$output" ]; }; then
  echo 'missing required argument' >&2; exit 2
fi
site="$(realpath -e "$site")"
modules="$(realpath -e "$modules")"
if ! { [ -f "$site/manifest.json" ] && [ -f "$site/.webservices-generator.json" ]; }; then
  echo 'invalid site' >&2; exit 2
fi
parent="$(realpath -e "$(dirname "$output")")"
case "$parent/$(basename "$output")" in
  /var/lib/*|/mnt/stack/*|/mnt/lab_debian/*) echo 'refusing production storage' >&2; exit 2 ;;
esac
[ ! -e "$output" ] || { echo 'output must not exist (each rehearsal uses a fresh directory)' >&2; exit 2; }
source_device="$(df -P "$parent" | awk 'END {print $1}')"
[[ "$source_device" == /dev/nvme* ]] || { echo "output parent is not on verified local NVMe: $source_device" >&2; exit 2; }
site_repo="$(git -C "$site" rev-parse --show-toplevel)"
site_relative="$(realpath --relative-to="$site_repo" "$site")"
site_commit="$(git -C "$site_repo" rev-parse HEAD)"
[ -z "$(git -C "$site_repo" status --porcelain --untracked-files=all)" ] || { echo 'site source is dirty' >&2; exit 2; }
[ -z "$(git -C "$root" status --porcelain --untracked-files=all)" ] || { echo 'generator source is dirty' >&2; exit 2; }
mkdir -m 700 "$output"
output="$(realpath -e "$output")"
for ((run=1; run<=runs; run++)); do
  dir="$output/run-$run"
  mkdir -m 700 "$dir"
  git clone --quiet --no-local "$site_repo" "$dir/site-repo"
  git -C "$dir/site-repo" checkout -q --detach "$site_commit"
  run_site="$dir/site-repo/$site_relative"
  key="$dir/age/keys.txt"
  SECRET_FILE="$run_site/global.settings/webservices.sops.json" SOPS_AGE_KEY_FILE="$key" \
    "$dir/site-repo/scripts/generate-secrets.sh" >"$dir/secrets.log"
  "$root/generate.sh" --site "$run_site/manifest.json" --modules-dir "$modules" \
    --backend podman --output "$dir/bundle" >"$dir/generate.log"
  python3 "$root/scripts/verify-podman-source.py" --bundle "$dir/bundle" --site "$run_site" >"$dir/source-gate.log"
  SOPS_AGE_KEY_FILE="$key" "$root/runtime-generator/podman-ops/install-podman-bundle.sh" \
    --bundle "$dir/bundle" >"$dir/preflight.log"
  sha256sum "$dir/bundle/stack.ir.json" | awk '{print $1}' > "$dir/source-hashes.txt"
  jq -S 'del(.secretStoreSha256)' "$dir/bundle/source-provenance.json" \
    | sha256sum | awk '{print $1}' >> "$dir/source-hashes.txt"
  printf '[preflight-rehearsal] %s accepted (synthetic secrets, no activation)\n' "$dir"
done
if [ "$runs" -gt 1 ]; then
  for ((run=2; run<=runs; run++)); do
    cmp "$output/run-1/source-hashes.txt" "$output/run-$run/source-hashes.txt"
    first_secret="$(jq -r .secretStoreSha256 "$output/run-1/bundle/source-provenance.json")"
    next_secret="$(jq -r .secretStoreSha256 "$output/run-$run/bundle/source-provenance.json")"
    [ "$first_secret" != "$next_secret" ] || { echo 'synthetic secret stores were reused' >&2; exit 1; }
  done
fi
printf '[preflight-rehearsal] %s independent clean NVMe preflights; NOT a VM install\n' "$runs"
