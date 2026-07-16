#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[pull-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"

git_commit_all() {
  local repo_dir="$1"
  local message="$2"
  git -C "$repo_dir" add .
  git -C "$repo_dir" \
    -c user.name="Pull Modules Test" \
    -c user.email="pull-modules-test@example.invalid" \
    commit -m "$message" >/dev/null
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  if ! grep -Eq "$pattern" "$file"; then
    printf '[pull-modules-test] missing pattern %s in %s\n' "$pattern" "$file" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  if grep -Eq "$pattern" "$file"; then
    printf '[pull-modules-test] unexpected pattern %s in %s\n' "$pattern" "$file" >&2
    cat "$file" >&2
    exit 1
  fi
}

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

catalog_dir="$tmp_root/catalog"
remotes_dir="$tmp_root/remotes"
workspace="$tmp_root/workspace"
mkdir -p "$catalog_dir/groups" "$remotes_dir" "$workspace"

repo_a="$remotes_dir/repo-a"
repo_b="$remotes_dir/repo-b"
repo_c="$remotes_dir/repo-c"
mkdir -p "$repo_a" "$repo_b" "$repo_c"
git -C "$repo_a" init -b main >/dev/null
git -C "$repo_b" init -b main >/dev/null
git -C "$repo_c" init -b main >/dev/null
printf 'one\n' > "$repo_a/value.txt"
printf 'two\n' > "$repo_b/value.txt"
printf 'three\n' > "$repo_c/value.txt"
git_commit_all "$repo_a" "Initial repo a"
git_commit_all "$repo_b" "Initial repo b"
git_commit_all "$repo_c" "Initial repo c"

cat > "$catalog_dir/catalog.json" <<EOF_CATALOG
{
  "schemaVersion": 1,
  "defaultBranch": "main",
  "repositories": [
    {"name": "repo-a", "kind": "stack-module", "remote": "$repo_a", "groups": ["dev-all"], "lifecycle": "active"},
    {"name": "repo-b", "kind": "source", "remote": "$repo_b", "groups": ["dev-all"], "lifecycle": "active"},
    {"name": "repo-c", "kind": "source", "remote": "$repo_c", "groups": ["dev-all"], "lifecycle": "active"},
    {"name": "retired-local", "groups": ["destruction"], "lifecycle": "retired", "localOnly": true}
  ]
}
EOF_CATALOG
cat > "$catalog_dir/groups/dev-all.json" <<'EOF_GROUP'
{
  "schemaVersion": 1,
  "includeCatalogGroups": ["dev-all"]
}
EOF_GROUP
cat > "$catalog_dir/groups/module-ci.json" <<'EOF_MODULE_CI'
{
  "schemaVersion": 1,
  "repositories": ["repo-b"],
  "includeCatalogGroups": ["dev-all"],
  "repositoryKinds": ["stack-module"]
}
EOF_MODULE_CI
cat > "$catalog_dir/groups/destruction.json" <<'EOF_DESTRUCTION'
{
  "schemaVersion": 1,
  "repositories": ["retired-local"]
}
EOF_DESTRUCTION

dry_log="$tmp_root/dry.log"
"$ROOT_DIR/scripts/pull-modules.sh" --catalog-dir "$catalog_dir" --workspace "$workspace" --dry-run dev-all >"$dry_log"
assert_contains "$dry_log" 'would clone: repo-a'
assert_contains "$dry_log" 'would clone: repo-b'
assert_contains "$dry_log" 'would clone: repo-c'
[ ! -d "$workspace/repo-a" ] || {
  printf '[pull-modules-test] dry run created repo-a\n' >&2
  exit 1
}

clone_log="$tmp_root/clone.log"
"$ROOT_DIR/scripts/pull-modules.sh" --catalog-dir "$catalog_dir" --workspace "$workspace" dev-all >"$clone_log"
assert_contains "$clone_log" 'cloned: repo-a repo-b repo-c'
test -f "$workspace/repo-a/value.txt"
test -f "$workspace/repo-b/value.txt"
test -f "$workspace/repo-c/value.txt"

module_ci_log="$tmp_root/module-ci.log"
"$ROOT_DIR/scripts/pull-modules.sh" \
  --catalog-dir "$catalog_dir" \
  --workspace "$tmp_root/module-ci-workspace" \
  --dry-run module-ci >"$module_ci_log"
assert_contains "$module_ci_log" 'would clone: repo-a'
assert_contains "$module_ci_log" 'would clone: repo-b'
assert_not_contains "$module_ci_log" 'repo-c'

printf 'one updated\n' > "$repo_a/value.txt"
git_commit_all "$repo_a" "Update repo a"
update_log="$tmp_root/update.log"
"$ROOT_DIR/scripts/pull-modules.sh" --catalog-dir "$catalog_dir" --workspace "$workspace" dev-all >"$update_log"
assert_contains "$update_log" 'updated: repo-a repo-b repo-c'
grep -qx 'one updated' "$workspace/repo-a/value.txt"

printf 'dirty\n' > "$workspace/repo-a/dirty.txt"
dirty_log="$tmp_root/dirty.log"
trap - ERR
set +e
"$ROOT_DIR/scripts/pull-modules.sh" --catalog-dir "$catalog_dir" --workspace "$workspace" dev-all >"$dirty_log" 2>&1
dirty_status=$?
set -e
trap 'status=$?; printf "[pull-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$dirty_status" -eq 0 ]; then
  printf '[pull-modules-test] dirty repository was accepted\n' >&2
  exit 1
fi
assert_contains "$dirty_log" 'dirty: repo-a'

destruction_log="$tmp_root/destruction.log"
"$ROOT_DIR/scripts/pull-modules.sh" --catalog-dir "$catalog_dir" --workspace "$workspace" destruction >"$destruction_log"
assert_contains "$destruction_log" 'skipped local-only inventory: retired-local'

printf '[pull-modules-test] ok\n' >&2
