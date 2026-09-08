#!/usr/bin/env python3
"""Regression checks for privileged rootless Quadlet policy."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BROKER_PATH = ROOT / "runtime-generator/podman-ops/p0-host-broker.py"
SPEC = importlib.util.spec_from_file_location("p0_host_broker", BROKER_PATH)
assert SPEC and SPEC.loader
BROKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BROKER)


def fixture(root: Path, relative: str, quadlet: str, owner: str = "webservices-communications") -> Path:
    files = {
        "bundle.json": {"backend": "podman"},
        "stack.ir.json": {},
        "podman-domains.json": {"domains": [{"name": "communications", "user": owner}]},
        "podman-loopback-endpoints.json": {},
    }
    for name, value in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))
    for name in ("ops/platform-zero.nft", "ops/install-podman-bundle.sh"):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("table inet platform_zero {\n policy accept\n}\n")
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(quadlet)
    return root


def rejected(root: Path) -> None:
    try:
        BROKER.validate_bundle(root)
    except BROKER.RequestError:
        return
    raise AssertionError("unsafe rootless Quadlet was accepted")


with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    allowed = base / "allowed"
    BROKER.validate_bundle(
        fixture(
            allowed,
            "quadlet/rootless-communications/webservices-livekit.container",
            "[Container]\nNetwork=host\n",
        )
    )
    rejected(
        fixture(
            base / "wrong-service",
            "quadlet/rootless-communications/webservices-element.container",
            "[Container]\nNetwork=host\n",
        )
    )
    rejected(
        fixture(
            base / "wrong-owner",
            "quadlet/rootless-communications/webservices-livekit.container",
            "[Container]\nNetwork=host\n",
            owner="webservices-media",
        )
    )
    rejected(
        fixture(
            base / "privileged",
            "quadlet/rootless-communications/webservices-livekit.container",
            "[Container]\nNetwork=host\nPrivileged=true\n",
        )
    )

print("[test-p0-host-broker] ok")
