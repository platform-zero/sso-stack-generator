#!/usr/bin/env python3
"""Validate security-sensitive module configuration and explicit exceptions."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


RULES = {
    "added-capabilities",
    "container-root-default",
    "container-socket-mount",
    "host-network",
    "privileged-container",
}


def fail(message: str) -> None:
    raise SystemExit(f"[module-security] {message}")


def final_container_user(path: Path) -> str | None:
    user: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, value = line.partition(" ")
        instruction = instruction.upper()
        if instruction == "FROM":
            user = None
        elif instruction == "USER":
            user = value.strip().strip('"\'')
    return user


def find_findings(root: Path) -> set[tuple[str, str]]:
    findings: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        if path.name in {"Containerfile", "Dockerfile"}:
            user = final_container_user(path)
            if user is None or re.fullmatch(r"(?:root|0)(?::(?:root|0))?", user, re.I):
                findings.add(("container-root-default", relative))
        if path.suffix not in {".yaml", ".yml"}:
            continue
        text = path.read_text(encoding="utf-8")
        checks = {
            "container-root-default": r"(?m)^\s*user:\s*[\"']?(?:root|0)(?::(?:root|0))?[\"']?\s*(?:#.*)?$",
            "privileged-container": r"(?m)^\s*privileged:\s*true\s*(?:#.*)?$",
            "host-network": r"(?m)^\s*(?:network_mode|networkMode):\s*[\"']?host[\"']?\s*(?:#.*)?$",
            "added-capabilities": r"(?m)^\s*(?:cap_add|capAdd):\s*(?:#.*)?$",
            "container-socket-mount": r"/(?:run/podman/podman|var/run/docker)\.sock",
        }
        for rule, pattern in checks.items():
            if re.search(pattern, text):
                findings.add((rule, relative))
    return findings


def load_exceptions(root: Path) -> set[tuple[str, str]]:
    path = root / "security-exceptions.json"
    if not path.exists():
        return set()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid security-exceptions.json: {exc}")
    if set(document) != {"schemaVersion", "exceptions"}:
        fail("security-exceptions.json must contain only schemaVersion and exceptions")
    if document["schemaVersion"] != 1 or not isinstance(document["exceptions"], list):
        fail("security-exceptions.json requires schemaVersion 1 and an exceptions array")
    result: set[tuple[str, str]] = set()
    for index, exception in enumerate(document["exceptions"]):
        if not isinstance(exception, dict) or set(exception) != {"rule", "path", "reason", "mitigations"}:
            fail(f"exception {index} has an invalid shape")
        rule = exception["rule"]
        relative = exception["path"]
        reason = exception["reason"]
        mitigations = exception["mitigations"]
        if rule not in RULES:
            fail(f"exception {index} has unknown rule: {rule}")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or not (root / candidate).is_file():
            fail(f"exception {index} has an unsafe or missing path: {relative}")
        if not isinstance(reason, str) or len(reason.strip()) < 20:
            fail(f"exception {index} requires a specific reason of at least 20 characters")
        if not isinstance(mitigations, list) or not mitigations or any(
            not isinstance(item, str) or len(item.strip()) < 10 for item in mitigations
        ):
            fail(f"exception {index} requires one or more specific mitigations")
        key = (rule, candidate.as_posix())
        if key in result:
            fail(f"duplicate exception for {rule}: {relative}")
        result.add(key)
    return result


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: security-policy.py /path/to/module")
    root = Path(sys.argv[1]).resolve()
    if not root.is_dir():
        fail(f"module directory not found: {root}")
    findings = find_findings(root)
    exceptions = load_exceptions(root)
    missing = sorted(findings - exceptions)
    stale = sorted(exceptions - findings)
    if missing:
        fail("undeclared security findings: " + ", ".join(f"{rule}:{path}" for rule, path in missing))
    if stale:
        fail("stale security exceptions: " + ", ".join(f"{rule}:{path}" for rule, path in stale))
    print(f"[module-security] ok ({len(findings)} reviewed finding(s))", file=sys.stderr)


if __name__ == "__main__":
    main()
