#!/usr/bin/env python3
"""Start only manifest-declared containers bearing Worklane identity labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tomllib


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"worklane autostart: {message}")


def podman(*args: str) -> str:
    result = subprocess.run(("podman", *args), check=False, text=True, stdout=subprocess.PIPE)
    if result.returncode:
        fail(f"podman {' '.join(args)} failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path.home() / ".config/platform-zero/workspaces.json")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    if manifest.get("schemaVersion") != 1:
        fail("unsupported workspace manifest")
    root = Path(manifest["root"]).resolve()
    for workspace in manifest["workspaces"]:
        if not workspace.get("startAtBoot", False):
            continue
        project = Path(workspace.get("projectPath", root / workspace["name"])).resolve()
        if project != root and root not in project.parents:
            fail(f"workspace path escapes declared root: {project}")
        lane_manifest = project / ".worklane/lane.toml"
        if not lane_manifest.is_file():
            fail(f"missing lane manifest: {lane_manifest}")
        lane = tomllib.loads(lane_manifest.read_text())
        container = str(lane.get("container_name", ""))
        lane_id = str(lane.get("id", ""))
        lane_name = str(lane.get("session_name", lane.get("name", "")))
        if not container or not lane_id or not lane_name:
            fail(f"incomplete lane identity: {lane_manifest}")
        labels = podman("inspect", "--format", "{{json .Config.Labels}}", container)
        identity = json.loads(labels)
        if identity.get("io.worklane.id") != lane_id or identity.get("io.worklane.name") != lane_name:
            fail(f"container is not owned by lane {workspace['name']}: {container}")
        state = podman("inspect", "--format", "{{.State.Status}}", container)
        if state != "running":
            podman("start", container)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
