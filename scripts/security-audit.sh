#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"

have() {
  command -v "$1" >/dev/null 2>&1
}

section() {
  printf '\n== %s ==\n' "$1"
}

cd "$ROOT_DIR"

section "Repository"
git status --short
if have podman; then
  podman version --format '[podman] Client={{.Client.Version}} Server={{.Server.Version}}' || true
fi

section "Secret-like files"
if have rg; then
  secret_files=()
  while IFS= read -r secret_file; do
    secret_files+=("$secret_file")
  done < <(
    rg -l -i \
      --glob '!**/.git/**' \
      --glob '!**/.gradle/**' \
      --glob '!**/build/**' \
      --glob '!**/dist/**' \
      --glob '!**/node_modules/**' \
      --glob '!**/out/**' \
      '(password|passwd|secret|token|api[_-]?key|private[_-]?key|BEGIN .*PRIVATE KEY|client_secret|jwt|cookie|session)' \
      . || true
  )
  printf '[secret-like] %s files matched; values are not printed\n' "${#secret_files[@]}"
  for secret_file in "${secret_files[@]:0:80}"; do
    printf '%s\n' "$secret_file"
  done
  if [ "${#secret_files[@]}" -gt 80 ]; then
    printf '[secret-like] output truncated; rerun rg locally to inspect all path-only matches\n'
  fi
else
  printf '[skip] rg is not installed; secret-like scan not run\n'
fi

section "Mutable image tags"
if have rg; then
  image_roots=()
  for root in runtime.overlays global.settings stack.config; do
    [ -e "$root" ] && image_roots+=( "$root" )
  done
  if [ "${#image_roots[@]}" -gt 0 ]; then
    rg -n '^\s*image:\s*\S+:latest(\s|$)' "${image_roots[@]}" 2>/dev/null || true
  fi
  containerfile_roots=()
  for root in stack.containers stack.config; do
    [ -e "$root" ] && containerfile_roots+=( "$root" )
  done
  if [ "${#containerfile_roots[@]}" -gt 0 ]; then
    rg -n '^FROM\s+\S+:latest(\s|$)' "${containerfile_roots[@]}" 2>/dev/null || true
  fi
else
  printf '[skip] rg is not installed; image tag scan not run\n'
fi

section "High-risk container options"
if have rg; then
  option_roots=()
  for root in runtime.overlays global.settings; do
    [ -e "$root" ] && option_roots+=( "$root" )
  done
  if [ "${#option_roots[@]}" -gt 0 ]; then
    rg -n '^\s*(privileged:\s*true|network_mode:\s*host|-\s*/run/podman/podman\.sock:)' "${option_roots[@]}" 2>/dev/null || true
  fi
else
  printf '[skip] rg is not installed; container option scan not run\n'
fi

section "Runtime model syntax"
if [ -d runtime.overlays ]; then
  runtime_model_files=()
  while IFS= read -r runtime_model_file; do
    runtime_model_files+=("$runtime_model_file")
  done < <(find runtime.overlays -maxdepth 1 -type f -name '*.yml' | sort)
  if [ "${#runtime_model_files[@]}" -gt 0 ]; then
    for runtime_model_file in "${runtime_model_files[@]}"; do
      awk '
        /^services:[[:space:]]*$/ { in_services = 1; next }
        in_services && /^[^[:space:]]/ { in_services = 0 }
        in_services && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { count++ }
        END { exit(count > 0 ? 0 : 1) }
      ' "$runtime_model_file" || {
        printf '[runtime-model] missing services section: %s\n' "$runtime_model_file" >&2
        exit 1
      }
    done
    printf '[runtime-model] ok\n'
  else
    printf '[skip] no runtime.overlays files in this checkout\n'
  fi
else
  printf '[skip] no runtime.overlays directory in this checkout\n'
fi

section "Shell syntax"
shell_files=()
while IFS= read -r -d '' shell_file; do
  shell_files+=("$shell_file")
done < <(find . \( -path '*/.git' -o -path '*/.gradle' -o -path '*/build' -o -path '*/dist' -o -path '*/node_modules' -o -path '*/out' \) -prune -o -type f -name '*.sh' -print0)
if [ "${#shell_files[@]}" -gt 0 ]; then
  bash -n "${shell_files[@]}"
  printf '[bash -n] ok\n'
fi

section "Language dependency audits"
if have npm; then
  npm_locks=()
  while IFS= read -r -d '' npm_lock; do
    npm_locks+=("$npm_lock")
  done < <(find . \( -path '*/.git' -o -path '*/.gradle' -o -path '*/build' -o -path '*/dist' -o -path '*/node_modules' -o -path '*/out' \) -prune -o -type f -name 'package-lock.json' -print0)
  for npm_lock in "${npm_locks[@]}"; do
    npm_dir="$(dirname "$npm_lock")"
    printf '[npm audit] %s\n' "$npm_dir"
    (cd "$npm_dir" && npm audit --audit-level=moderate)
  done
else
  printf '[skip] npm is not installed\n'
fi
if have osv-scanner; then
  osv-scanner -r .
else
  printf '[skip] osv-scanner is not installed\n'
fi

section "Optional security tools"
for tool in trivy grype gitleaks shellcheck hadolint yamllint pip-audit cargo-audit govulncheck; do
  if have "$tool"; then
    printf '[found] %s\n' "$tool"
  else
    printf '[missing] %s\n' "$tool"
  fi
done
