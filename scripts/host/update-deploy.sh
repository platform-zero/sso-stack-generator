#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"

CONFIG_FILE="${WEBSERVICES_STABLE_UPDATE_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/webservices/stable-update.env}"
STATE_ROOT="${WEBSERVICES_UPDATE_DEPLOY_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/webservices/update-deploy}"
BUILD_WORKSPACE="${WEBSERVICES_UPDATE_BUILD_WORKSPACE:-$HOME/webservices-builder}"
LOG_DIR="$STATE_ROOT/logs"
LOCK_FILE="$STATE_ROOT/update-deploy.lock"
LAST_SUCCESS_FILE="$STATE_ROOT/last-success.json"

mkdir -p "$STATE_ROOT" "$LOG_DIR" "$BUILD_WORKSPACE"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  printf '[webservices-update] another update deploy is already running\n' >&2
  exit 0
fi

log_file="$LOG_DIR/$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log_file") 2>&1

die_update() {
  printf '[webservices-update] ERROR: %s\n' "$*" >&2
  exit 1
}

log_update() {
  printf '[webservices-update] %s\n' "$*" >&2
}

safe_source_config() {
  [ -f "$CONFIG_FILE" ] || die_update "missing stable update config: $CONFIG_FILE"
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

require_config() {
  local name="$1"
  [ -n "${!name:-}" ] || die_update "stable update config must set $name"
}

repo_slug_from_url() {
  local url="$1" slug
  case "$url" in
    git@github.com:*) slug="${url#git@github.com:}" ;;
    ssh://git@github.com/*) slug="${url#ssh://git@github.com/}" ;;
    https://github.com/*) slug="${url#https://github.com/}" ;;
    http://github.com/*) slug="${url#http://github.com/}" ;;
    *) return 1 ;;
  esac
  slug="${slug%.git}"
  case "$slug" in
    */*) printf '%s\n' "$slug" ;;
    *) return 1 ;;
  esac
}

checkout_repo() {
  local url="$1" branch="$2" dest="$3"
  if [ -d "$dest/.git" ]; then
    git -C "$dest" remote set-url origin "$url"
    git -C "$dest" fetch --prune origin "$branch"
    git -C "$dest" checkout -q "$branch"
    git -C "$dest" reset --hard "origin/$branch"
  else
    rm -rf "$dest"
    git clone --branch "$branch" --single-branch "$url" "$dest"
  fi
  git -C "$dest" rev-parse HEAD
}

github_checks_passed() {
  local repo_url="$1" sha="$2" slug check_runs statuses check_count status_count
  slug="$(repo_slug_from_url "$repo_url")" || {
    log_update "repository is not a GitHub URL gh can check: $repo_url"
    return 1
  }
  command -v gh >/dev/null 2>&1 || {
    log_update "gh is unavailable; skipping deploy"
    return 1
  }
  gh auth status >/dev/null 2>&1 || {
    log_update "gh is not authenticated; skipping deploy"
    return 1
  }

  check_runs="$(gh api --paginate "repos/$slug/commits/$sha/check-runs" --jq '.check_runs[] | [.name, .status, (.conclusion // "")] | @tsv')" || {
    log_update "GitHub check runs are inaccessible for $slug@$sha"
    return 1
  }
  statuses="$(gh api "repos/$slug/commits/$sha/status" --jq '.statuses[] | [.context, .state] | @tsv')" || {
    log_update "GitHub commit statuses are inaccessible for $slug@$sha"
    return 1
  }
  check_count="$(printf '%s\n' "$check_runs" | sed '/^$/d' | wc -l | tr -d ' ')"
  status_count="$(printf '%s\n' "$statuses" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [ "$check_count" -eq 0 ] && [ "$status_count" -eq 0 ]; then
    log_update "no GitHub checks or statuses found for $slug@$sha"
    return 1
  fi
  if [ "$check_count" -gt 0 ] && printf '%s\n' "$check_runs" | awk -F '\t' 'NF && ($2 != "completed" || $3 != "success") { bad=1 } END { exit bad ? 0 : 1 }'; then
    log_update "one or more GitHub check runs are not completed successfully for $slug@$sha"
    return 1
  fi
  if [ "$status_count" -gt 0 ] && printf '%s\n' "$statuses" | awk -F '\t' 'NF && $2 != "success" { bad=1 } END { exit bad ? 0 : 1 }'; then
    log_update "one or more GitHub commit statuses are not successful for $slug@$sha"
    return 1
  fi
}

last_deployed_key() {
  if [ -f "$LAST_SUCCESS_FILE" ]; then
    jq -r '.deployKey // empty' "$LAST_SUCCESS_FILE" 2>/dev/null || true
  fi
}

record_success() {
  local deploy_key="$1" generator_sha="$2" site_sha="$3" lock_hash="$4"
  jq -n \
    --arg deployKey "$deploy_key" \
    --arg generatorSha "$generator_sha" \
    --arg siteConfigSha "$site_sha" \
    --arg siteLockSha256 "$lock_hash" \
    --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{deployKey:$deployKey,generatorSha:$generatorSha,siteConfigSha:$siteConfigSha,siteLockSha256:$siteLockSha256,deployedAt:$deployedAt}' \
    > "$LAST_SUCCESS_FILE.tmp"
  mv -f "$LAST_SUCCESS_FILE.tmp" "$LAST_SUCCESS_FILE"
}

install_current_release() {
  local release="$1" deploy_root="$2"
  if [ -x "$release/install.sh" ]; then
    "$release/install.sh" --target "$deploy_root"
  elif [ -x "$release/build/scripts/install-bundle.sh" ]; then
    "$release/build/scripts/install-bundle.sh" --dist-root "$release" --target "$deploy_root"
  else
    die_update "active release has no install entrypoint: $release"
  fi
}

deploy_installed_release() {
  local deploy_root="$1"
  (cd "$deploy_root" && ./deploy.sh)
  (cd "$deploy_root" && ./verify.sh --ready-only)
}

rollback_release() {
  local release_root="$1" deploy_root="$2"
  log_update "rolling back to previous verified release"
  WEBSERVICES_RELEASE_ROOT="$release_root" "$ROOT/scripts/site/rollback-release.sh"
  [ -L "$release_root/current" ] || die_update "rollback did not restore current release"
  install_current_release "$(realpath "$release_root/current")" "$deploy_root"
  deploy_installed_release "$deploy_root"
}

safe_source_config
GENERATOR_BRANCH="${GENERATOR_BRANCH:-stable}"
SITE_CONFIG_BRANCH="${SITE_CONFIG_BRANCH:-stable}"
require_config GENERATOR_REPO
require_config SITE_CONFIG_REPO
require_config SITE_LOCK_PATH
require_config RELEASE_ROOT
require_config DEPLOY_ROOT

RELEASE_ROOT="${RELEASE_ROOT/#%h/$HOME}"
DEPLOY_ROOT="${DEPLOY_ROOT/#%h/$HOME}"
case "$RELEASE_ROOT" in /*) ;; *) die_update "RELEASE_ROOT must be absolute" ;; esac
case "$DEPLOY_ROOT" in /*) ;; *) die_update "DEPLOY_ROOT must be absolute" ;; esac

require_cmd git
require_cmd jq
require_cmd sha256sum
require_cmd flock

generator_dir="$BUILD_WORKSPACE/generator"
site_dir="$BUILD_WORKSPACE/site-config"
bundle_dir="$BUILD_WORKSPACE/bundle"
incoming_dir="$BUILD_WORKSPACE/incoming"

log_update "checking out generator $GENERATOR_BRANCH"
generator_sha="$(checkout_repo "$GENERATOR_REPO" "$GENERATOR_BRANCH" "$generator_dir")"
log_update "checking out site config $SITE_CONFIG_BRANCH"
site_sha="$(checkout_repo "$SITE_CONFIG_REPO" "$SITE_CONFIG_BRANCH" "$site_dir")"

github_checks_passed "$GENERATOR_REPO" "$generator_sha" || {
  log_update "generator checks are not passing; skipping deploy"
  exit 0
}
github_checks_passed "$SITE_CONFIG_REPO" "$site_sha" || {
  log_update "site config checks are not passing; skipping deploy"
  exit 0
}

site_lock="$site_dir/$SITE_LOCK_PATH"
[ -f "$site_lock" ] || die_update "missing site lock: $site_lock"
site_lock_hash="$(sha256sum "$site_lock" | awk '{print $1}')"
deploy_key="$generator_sha:$site_sha:$site_lock_hash"
if [ "$(last_deployed_key)" = "$deploy_key" ]; then
  log_update "branch heads and site lock already deployed; no action"
  exit 0
fi

rm -rf "$bundle_dir" "$incoming_dir"
mkdir -p "$bundle_dir" "$incoming_dir"
log_update "building bundle from site lock"
"$generator_dir/scripts/site/build-site.sh" --site-lock "$site_lock" --output "$bundle_dir"

cp "$bundle_dir/bundle.tar" "$bundle_dir/bundle.tar.sha256" "$bundle_dir/bundle.json" "$incoming_dir/"
site_lock_hash="$(sha256sum "$site_lock" | awk '{print $1}')"

activated=0
rollback_needed=0
on_failure() {
  local exit_code=$?
  if [ "$rollback_needed" = "1" ]; then
    rollback_release "$RELEASE_ROOT" "$DEPLOY_ROOT" || true
  fi
  exit "$exit_code"
}
trap on_failure ERR

log_update "activating release"
WEBSERVICES_RELEASE_ROOT="$RELEASE_ROOT" \
  WEBSERVICES_READINESS_COMMAND='test -f resolved-modules.json' \
  "$generator_dir/scripts/site/activate-release.sh" \
    --incoming "$incoming_dir" \
    --site-lock-sha256 "$site_lock_hash"
activated=1
rollback_needed=1

[ -L "$RELEASE_ROOT/current" ] || die_update "activation did not create current release"
active_release="$(realpath "$RELEASE_ROOT/current")"
log_update "installing activated release into $DEPLOY_ROOT"
install_current_release "$active_release" "$DEPLOY_ROOT"

log_update "deploying and verifying activated release"
deploy_installed_release "$DEPLOY_ROOT"
rollback_needed=0
trap - ERR

record_success "$deploy_key" "$generator_sha" "$site_sha" "$site_lock_hash"
log_update "deploy complete"
