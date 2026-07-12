#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

dist_root="$tmp_dir/dist"
target_root="$tmp_dir/deploy"
mkdir -p "$dist_root/build/scripts" "$target_root/build" "$target_root/runtime" "$target_root/keep"

printf 'old\n' > "$target_root/build/old.txt"
printf 'keep\n' > "$target_root/keep/file.txt"
printf 'new\n' > "$dist_root/build/payload.txt"
printf '#!/usr/bin/env bash\n' > "$dist_root/build/scripts/deploy.sh"
for wrapper in deploy.sh verify.sh run-tests.sh stackctl install.sh; do
  printf '#!/usr/bin/env bash\nprintf "wrapper %s\\n"\n' "$wrapper" > "$dist_root/$wrapper"
  chmod +x "$dist_root/$wrapper"
done

"$SCRIPT_DIR/install-bundle.sh" --dist-root "$dist_root" --target "$target_root" >"$tmp_dir/out" 2>"$tmp_dir/err"

[ "$(cat "$target_root/build/payload.txt")" = "new" ] || {
  printf '[test-install-bundle] bundle payload was not staged\n' >&2
  exit 1
}
[ ! -e "$target_root/build/old.txt" ] || {
  printf '[test-install-bundle] old build payload was not replaced\n' >&2
  exit 1
}
[ "$(cat "$target_root/keep/file.txt")" = "keep" ] || {
  printf '[test-install-bundle] unrelated target content was modified\n' >&2
  exit 1
}
[ -x "$target_root/deploy.sh" ] && [ -x "$target_root/install.sh" ] || {
  printf '[test-install-bundle] top-level wrappers were not installed executable\n' >&2
  exit 1
}
[ -d "$target_root/runtime" ] && [ -d "$target_root/repos/source" ] || {
  printf '[test-install-bundle] expected deploy root directories were not created\n' >&2
  exit 1
}

printf '[test-install-bundle] ok\n'
