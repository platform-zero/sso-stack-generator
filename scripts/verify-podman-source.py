#!/usr/bin/env python3
"""Reject Podman release candidates that cannot be reproduced from site pins."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def fail(message):
    raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def checked_rows(rows, key):
    result = {}
    for row in rows:
        name = row[key]
        if name in result:
            fail(f"duplicate module {name}")
        result[name] = row
    return result


def verify(bundle, site):
    provenance_path = bundle / "source-provenance.json"
    provenance = load(provenance_path)
    metadata = load(bundle / "bundle.json")
    if metadata.get("sourceProvenanceSha256") != hashlib.sha256(provenance_path.read_bytes()).hexdigest():
        fail("bundle source-provenance hash does not match")
    if metadata.get("irSha256") != hashlib.sha256((bundle / "stack.ir.json").read_bytes()).hexdigest():
        fail("bundle runtime IR hash does not match")
    if provenance.get("schemaVersion") != 1 or metadata.get("backend") != "podman":
        fail("unsupported provenance or backend")
    for source in ("generator", "site"):
        commit = provenance.get(source + "Commit")
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            fail(f"{source} commit missing or invalid")
        if provenance.get(source + "Dirty") is not False:
            fail(f"{source} source was dirty or status unknown at build time")
    site_manifest = site / "manifest.json"
    manifest = load(site_manifest)
    config = (site / manifest["stackConfig"]).resolve()
    if not config.is_relative_to(site.resolve()) or not config.is_file():
        fail("site stack config escapes site directory or is missing")
    if provenance.get("manifestSha256") != hashlib.sha256(site_manifest.read_bytes()).hexdigest():
        fail("site manifest differs from built input")
    if provenance.get("stackConfigSha256") != hashlib.sha256(config.read_bytes()).hexdigest():
        fail("site stack config differs from built input")
    pins = load(site / ".webservices-generator.json")
    if provenance["generatorCommit"] != pins["generatorCommit"]:
        fail("generator checkout does not match the site pin")
    locked = checked_rows(load(site / "module-lock.v2.json")["modules"], "id")
    selected = checked_rows(load(site / "modules.json")["modules"], "name")
    built = checked_rows(provenance["modules"], "id")
    ir = checked_rows(load(bundle / "stack.ir.json")["modules"], "id")
    requested = [row if isinstance(row, str) else row["id"] for row in manifest["modules"]]
    if len(requested) != len(set(requested)) or set(requested) != set(built) or set(requested) != set(selected) or set(requested) != set(locked) or set(requested) != set(ir):
        fail("site selection, locks, provenance, and runtime IR differ")
    for name in requested:
        row = built[name]
        expected = locked[name]
        selected_row = selected[name]
        if row.get("dirty") is not False:
            fail(f"module {name} was dirty or status unknown at build time")
        if not isinstance(row.get("commit"), str) or not COMMIT.fullmatch(row["commit"]):
            fail(f"module {name} commit missing or invalid")
        if any(row.get("commit") != item.get("commit") or row.get("remote") != item.get("git")
               for item in (expected, selected_row)):
            fail(f"module {name} does not match site locks")
        if ir[name].get("commit") != row["commit"] or ir[name].get("remote") != row["remote"]:
            fail(f"module {name} does not match runtime IR")
    return len(requested)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--site", required=True, type=Path, help="site directory containing manifest.json and pins")
    args = parser.parse_args()
    try:
        count = verify(args.bundle, args.site)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"[source-gate] rejected: {exc}", file=sys.stderr)
        return 1
    print(f"[source-gate] accepted: {count} pinned clean modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
