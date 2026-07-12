#!/usr/bin/env python3
"""Create a v1 module.json from a module's existing stack.module.json.

This is deliberately a one-time migration utility.  It copies no deployment
state; its output is committed by the owning module repository.
"""
import argparse
import json
from pathlib import Path


def compose_services(root: Path, overlays: list[str]) -> list[dict]:
    """Inventory service names without interpreting a Compose file at build time."""
    found: set[str] = set()
    for overlay in overlays:
        path = root / overlay
        candidates = [path] if path.is_file() else list(path.rglob("*.yml")) if path.is_dir() else []
        for candidate in candidates:
            if "stack.compose" not in candidate.parts:
                continue
            in_services = False
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                if line == "services:":
                    in_services = True
                    continue
                if in_services and line and not line.startswith((" ", "\t", "#")):
                    in_services = False
                if in_services and line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
                    found.add(line.strip()[:-1])
    return [{"name": name, "routes": [], "volumes": []} for name in sorted(found)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module-root", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--output", default="module.json")
    args = parser.parse_args()
    root = Path(args.module_root)
    legacy_path = root / "stack.module.json"
    if not legacy_path.is_file():
        raise SystemExit(f"missing legacy descriptor: {legacy_path}")
    legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
    if legacy.get("id") != args.id:
        raise SystemExit(f"legacy descriptor id mismatch: {legacy.get('id')}")
    overlays = legacy.get("overlays", [])
    if not isinstance(overlays, list) or not all(isinstance(item, str) for item in overlays):
        raise SystemExit("legacy overlays must be a string array")
    dependencies = legacy.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(isinstance(item, str) for item in dependencies):
        raise SystemExit("legacy dependencies must be a string array")
    command = "test -f stack.module.json && test -f module.json"
    descriptor = {
        "schemaVersion": 1,
        "id": args.id,
        "provides": [{"capability": f"module:{args.id}", "version": "1"}],
        "requires": [{"capability": f"module:{dep}", "version": "1"} for dep in dependencies],
        "services": compose_services(root, overlays),
        "configuration": {"schema": {"type": "object", "additionalProperties": False, "properties": {}}},
        "overlays": overlays,
        "verification": {"commands": [command]},
    }
    output = root / args.output
    output.write_text(json.dumps(descriptor, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
