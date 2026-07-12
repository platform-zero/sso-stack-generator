#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
git config --global user.email >/dev/null 2>&1 || git config --global user.email test@example.invalid
git config --global user.name >/dev/null 2>&1 || git config --global user.name test
make_module() {
  local name="$1"
  local descriptor="$2"
  local repo="$tmp/$name"
  mkdir -p "$repo"; git init -q "$repo"; printf '%s\n' "$descriptor" > "$repo/module.json"
  git -C "$repo" add module.json; git -C "$repo" commit -qm initial; git -C "$repo" rev-parse HEAD
}
provider='{"schemaVersion":1,"id":"provider","provides":[{"capability":"database","version":"1"}],"services":[{"name":"db","routes":["db.test"],"volumes":["db-data"]}],"configuration":{"schema":{"type":"object","additionalProperties":false,"properties":{"enabled":{"type":"boolean"}},"required":["enabled"]}},"verification":{"commands":["test -f module.json"]}}'
consumer='{"schemaVersion":1,"id":"consumer","requires":[{"capability":"database","version":"1"}],"services":[{"name":"app","routes":["app.test"],"volumes":["app-data"]}],"overlays":[]}'
pcommit="$(make_module provider "$provider")"; ccommit="$(make_module consumer "$consumer")"
cat > "$tmp/site.lock.json" <<EOF
{"schemaVersion":1,"modules":[{"id":"provider","git":"$tmp/provider","commit":"$pcommit","config":{"enabled":true}},{"id":"consumer","git":"$tmp/consumer","commit":"$ccommit"}]}
EOF
mkdir -p "$tmp/stale/dist"; echo stale > "$tmp/stale/dist/should-not-be-read"
"$ROOT/site-build.sh" --site-lock "$tmp/site.lock.json" --output "$tmp/a" >/dev/null
"$ROOT/site-build.sh" --site-lock "$tmp/site.lock.json" --output "$tmp/b" >/dev/null
cmp "$tmp/a/bundle.tar" "$tmp/b/bundle.tar"
cmp "$tmp/a/bundle.json" "$tmp/b/bundle.json"

sed -i 's/"version":"1"/"version":"2"/' "$tmp/consumer/module.json"
git -C "$tmp/consumer" add module.json; git -C "$tmp/consumer" commit -qm incompatible
bad_commit="$(git -C "$tmp/consumer" rev-parse HEAD)"
bad="$tmp/bad.lock.json"; sed "s/$ccommit/$bad_commit/" "$tmp/site.lock.json" > "$bad"
if "$ROOT/scripts/site/resolve-site-lock.py" --site-lock "$bad" --workspace "$tmp/bad-workspace" --resolved "$tmp/bad.json" 2>/dev/null; then echo 'capability mismatch was accepted' >&2; exit 1; fi

release_root="$tmp/host"
WEBSERVICES_RELEASE_ROOT="$release_root" "$ROOT/scripts/site/activate-release.sh" --incoming "$tmp/a" --site-lock-sha256 "$(sha256sum "$tmp/site.lock.json" | awk '{print $1}')" --readiness-command 'test -f resolved-modules.json' >/dev/null
[ -L "$release_root/current" ]
[ -f "$(realpath "$release_root/current")/verified-release" ]
first="$(basename "$(realpath "$release_root/current")")"
WEBSERVICES_RELEASE_ROOT="$release_root" "$ROOT/scripts/site/activate-release.sh" --incoming "$tmp/b" --site-lock-sha256 "$(sha256sum "$tmp/site.lock.json" | awk '{print $1}')" --readiness-command 'test -f resolved-modules.json' >/dev/null
WEBSERVICES_RELEASE_ROOT="$release_root" "$ROOT/scripts/site/rollback-release.sh" >/dev/null
[ "$(basename "$(realpath "$release_root/current")")" = "$first" ]
cp -a "$tmp/a" "$tmp/tampered"; printf x >> "$tmp/tampered/bundle.tar"
if WEBSERVICES_RELEASE_ROOT="$release_root" "$ROOT/scripts/site/activate-release.sh" --incoming "$tmp/tampered" --site-lock-sha256 "$(sha256sum "$tmp/site.lock.json" | awk '{print $1}')" 2>/dev/null; then echo 'tampered bundle was accepted' >&2; exit 1; fi
echo '[test-site-lock] ok'
