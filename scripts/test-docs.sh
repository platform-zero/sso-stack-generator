#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [ "${WEBSERVICES_SKIP_DOCS_TEST:-}" = "1" ]; then
  printf '[docs-test] skipped via WEBSERVICES_SKIP_DOCS_TEST=1\n' >&2
  exit 0
fi

required_files=(
  "README.md"
  "CONTRIBUTING.md"
  "SECURITY.md"
  "docs/README.md"
  "modules/README.md"
)

for path in "${required_files[@]}"; do
  if [ ! -f "$ROOT_DIR/$path" ]; then
    printf '[docs-test] missing required docs file: %s\n' "$path" >&2
    exit 1
  fi
done

python3 - "$ROOT_DIR" <<'PY'
import pathlib
import re
import sys
from urllib.parse import unquote

root = pathlib.Path(sys.argv[1])
markdown_files = [
    root / "README.md",
    root / "CONTRIBUTING.md",
    root / "SECURITY.md",
    root / "modules" / "README.md",
    *sorted((root / "docs").glob("*.md")),
]

link_pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
missing = []

for markdown_path in markdown_files:
    text = markdown_path.read_text(encoding="utf-8")
    for match in link_pattern.finditer(text):
        raw_link = match.group(1).strip()
        if not raw_link or raw_link.startswith("#"):
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*:", raw_link):
            continue
        target = raw_link.split()[0].strip("<>")
        target = target.split("#", 1)[0]
        if not target:
            continue
        candidate = (markdown_path.parent / unquote(target)).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            missing.append((markdown_path.relative_to(root), raw_link, "escapes repository"))
            continue
        if not candidate.exists():
            missing.append((markdown_path.relative_to(root), raw_link, "missing target"))

if missing:
    for source, link, reason in missing:
        print(f"[docs-test] {source}: {link} ({reason})", file=sys.stderr)
    sys.exit(1)
PY

printf '[docs-test] ok\n' >&2
