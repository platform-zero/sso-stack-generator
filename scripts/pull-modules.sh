#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[pull-modules] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEFAULT_WORKSPACE="${SSO_STACK_MODULES_WORKSPACE:-$ROOT_DIR/modules-workspace}"

workspace="$DEFAULT_WORKSPACE"
catalog_dir="$ROOT_DIR/modules"
dry_run=false
group_name=""

usage() {
  cat >&2 <<'EOF'
Usage: scripts/pull-modules.sh [--workspace DIR] [--catalog-dir DIR] [--dry-run] GROUP

Examples:
  scripts/pull-modules.sh dev-all
  scripts/pull-modules.sh core
  scripts/pull-modules.sh custom
  scripts/pull-modules.sh --workspace /path/to/workspace dev-all
  scripts/pull-modules.sh --dry-run dev-all
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --workspace)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      workspace="$2"
      shift 2
      ;;
    --catalog-dir)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      catalog_dir="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf '[pull-modules] unknown option: %s\n' "$1" >&2
      usage
      exit 2
      ;;
    *)
      if [ -n "$group_name" ]; then
        printf '[pull-modules] only one group may be specified\n' >&2
        usage
        exit 2
      fi
      group_name="$1"
      shift
      ;;
  esac
done

[ -n "$group_name" ] || { usage; exit 2; }
command -v git >/dev/null 2>&1 || { printf '[pull-modules] missing required command: git\n' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf '[pull-modules] missing required command: python3\n' >&2; exit 1; }

catalog_file="$catalog_dir/catalog.json"
group_file="$catalog_dir/groups/$group_name.json"
[ -f "$catalog_file" ] || { printf '[pull-modules] catalog not found: %s\n' "$catalog_file" >&2; exit 1; }
[ -f "$group_file" ] || { printf '[pull-modules] group not found: %s\n' "$group_name" >&2; exit 1; }

mapfile -t repos < <(python3 - "$catalog_file" "$group_file" <<'PY'
import json
import sys

catalog_path, group_path = sys.argv[1], sys.argv[2]
with open(catalog_path, encoding="utf-8") as handle:
    catalog = json.load(handle)
with open(group_path, encoding="utf-8") as handle:
    group = json.load(handle)

default_remote_base = catalog.get("defaultRemoteBase", "").rstrip("/")
default_branch = catalog.get("defaultBranch") or "main"
repositories = catalog.get("repositories")
if not isinstance(repositories, list):
    raise SystemExit("catalog repositories must be an array")

by_name = {}
ordered = []
for repo in repositories:
    name = repo.get("name")
    if not isinstance(name, str) or not name:
        raise SystemExit("catalog repository is missing name")
    if name in by_name:
        raise SystemExit(f"duplicate repository name: {name}")
    by_name[name] = repo
    ordered.append(repo)

selected_names = []
seen = set()

def add_name(name):
    if name not in by_name:
        raise SystemExit(f"group references unknown repository: {name}")
    if name not in seen:
        seen.add(name)
        selected_names.append(name)

for name in group.get("repositories") or []:
    if not isinstance(name, str) or not name:
        raise SystemExit("group repositories entries must be non-empty strings")
    add_name(name)

include_groups = group.get("includeCatalogGroups") or []
if not isinstance(include_groups, list):
    raise SystemExit("includeCatalogGroups must be an array")
include_groups = set(include_groups)
repository_kinds = group.get("repositoryKinds") or []
if not isinstance(repository_kinds, list) or any(not isinstance(kind, str) or not kind for kind in repository_kinds):
    raise SystemExit("repositoryKinds must be an array of non-empty strings")
repository_kinds = set(repository_kinds)
for repo in ordered:
    repo_groups = repo.get("groups") or []
    if (
        repo.get("lifecycle") != "retired"
        and any(repo_group in include_groups for repo_group in repo_groups)
        and (not repository_kinds or repo.get("kind") in repository_kinds)
    ):
        add_name(repo["name"])

for name in selected_names:
    repo = by_name[name]
    branch = repo.get("defaultBranch") or default_branch
    local_only = "true" if repo.get("localOnly") else "false"
    remote = repo.get("remote")
    if not remote and not repo.get("localOnly"):
        if not default_remote_base:
            raise SystemExit(f"repository {name} has no remote and no defaultRemoteBase is configured")
        remote = f"{default_remote_base}/{name}.git"
    print("\t".join([name, remote or "-", branch, local_only]))
PY
)

if [ "${#repos[@]}" -eq 0 ]; then
  printf '[pull-modules] group has no repositories: %s\n' "$group_name" >&2
  exit 1
fi

if [ "$dry_run" = true ]; then
  printf '[pull-modules] dry run: group=%s workspace=%s\n' "$group_name" "$workspace"
else
  mkdir -p "$workspace"
fi

cloned=()
updated=()
skipped=()
dirty=()
failed=()

record_failure() {
  local name="$1"
  local reason="$2"
  failed+=("$name ($reason)")
  printf '[pull-modules] failed: %s: %s\n' "$name" "$reason" >&2
}

checkout_default_branch() {
  local repo_dir="$1"
  local branch="$2"

  if git -C "$repo_dir" show-ref --verify --quiet "refs/heads/$branch"; then
    git -C "$repo_dir" checkout -q "$branch" >/dev/null
  elif git -C "$repo_dir" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    git -C "$repo_dir" checkout -q -b "$branch" --track "origin/$branch" >/dev/null
  else
    return 1
  fi
}

for repo_line in "${repos[@]}"; do
  IFS=$'\t' read -r name remote branch local_only <<<"$repo_line"
  [ "$remote" != "-" ] || remote=""
  repo_dir="$workspace/$name"

  if [ "$local_only" = "true" ]; then
    skipped+=("$name (local-only)")
    printf '[pull-modules] skipped local-only inventory: %s\n' "$name"
    continue
  fi

  if [ "$dry_run" = true ]; then
    if [ -d "$repo_dir/.git" ] && [ -n "$(git -C "$repo_dir" status --porcelain)" ]; then
      dirty+=("$name")
      printf '[pull-modules] dirty: %s\n' "$name"
    elif [ -d "$repo_dir/.git" ]; then
      skipped+=("$name (would fetch)")
      printf '[pull-modules] would fetch: %s (%s %s)\n' "$name" "$remote" "$branch"
    else
      skipped+=("$name (would clone)")
      printf '[pull-modules] would clone: %s (%s %s)\n' "$name" "$remote" "$branch"
    fi
    continue
  fi

  if [ -e "$repo_dir" ] && [ ! -d "$repo_dir/.git" ]; then
    record_failure "$name" "path exists but is not a git repository: $repo_dir"
    continue
  fi

  if [ ! -d "$repo_dir/.git" ]; then
    printf '[pull-modules] cloning: %s\n' "$name"
    if git clone --branch "$branch" "$remote" "$repo_dir" >/dev/null 2>&1; then
      cloned+=("$name")
    else
      record_failure "$name" "clone failed"
      rm -rf "$repo_dir"
    fi
    continue
  fi

  if [ -n "$(git -C "$repo_dir" status --porcelain)" ]; then
    dirty+=("$name")
    printf '[pull-modules] dirty: %s\n' "$name" >&2
    continue
  fi

  current_remote="$(git -C "$repo_dir" remote get-url origin 2>/dev/null || true)"
  if [ "$current_remote" != "$remote" ]; then
    record_failure "$name" "origin remote mismatch: $current_remote"
    continue
  fi

  printf '[pull-modules] fetching: %s\n' "$name"
  if ! git -C "$repo_dir" fetch --prune origin >/dev/null 2>&1; then
    record_failure "$name" "fetch failed"
    continue
  fi
  if ! checkout_default_branch "$repo_dir" "$branch"; then
    record_failure "$name" "default branch not found: $branch"
    continue
  fi
  if ! git -C "$repo_dir" merge --ff-only "origin/$branch" >/dev/null 2>&1; then
    record_failure "$name" "fast-forward failed"
    continue
  fi
  updated+=("$name")
done

print_summary_line() {
  local label="$1"
  shift
  if [ "$#" -eq 0 ]; then
    printf '[pull-modules] %s: none\n' "$label"
  else
    printf '[pull-modules] %s: %s\n' "$label" "$*"
  fi
}

print_summary_line "cloned" "${cloned[@]}"
print_summary_line "updated" "${updated[@]}"
print_summary_line "skipped" "${skipped[@]}"
print_summary_line "dirty" "${dirty[@]}"
print_summary_line "failed" "${failed[@]}"

if [ "${#dirty[@]}" -gt 0 ] || [ "${#failed[@]}" -gt 0 ]; then
  exit 1
fi
