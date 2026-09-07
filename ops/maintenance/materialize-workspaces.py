#!/usr/bin/env python3
"""Plan or materialize Platform Zero's stack_lab Worklane workspaces."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"workspace materializer: {message}")


def run(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    if result.returncode:
        fail(f"command failed ({result.returncode}): {' '.join(args)}")
    return (result.stdout or "").strip()


def repo_path(workspace: Path, repo: dict[str, object]) -> Path:
    name = str(repo["name"])
    if not name or "/" in name or name in {".", ".."}:
        fail(f"unsafe repository name: {name!r}")
    return workspace / name


def inspect_repo(path: Path, repo: dict[str, object]) -> dict[str, object]:
    if not path.exists():
        return {"state": "missing"}
    if not (path / ".git").is_dir():
        return {"state": "collision", "reason": "destination is not a Git checkout"}
    dirty = bool(run("git", "status", "--porcelain", cwd=path, capture=True))
    remote = run("git", "remote", "get-url", "origin", cwd=path, capture=True)
    commit = run("git", "rev-parse", "HEAD", cwd=path, capture=True)
    expected_remote = str(repo["remote"])
    expected_commit = str(repo["commit"])
    if dirty:
        return {"state": "dirty", "commit": commit, "remote": remote}
    if remote != expected_remote:
        return {"state": "remote-drift", "commit": commit, "remote": remote}
    if commit != expected_commit:
        return {"state": "commit-drift", "commit": commit, "remote": remote}
    return {"state": "current", "commit": commit, "remote": remote}


def agents_text(workspace: dict[str, object]) -> str:
    name = str(workspace["name"])
    role = str(workspace["role"])
    service_account = workspace.get("serviceAccount")
    writable = [
        str(repo["name"])
        for repo in workspace.get("repositories", [])
        if repo.get("writable", False)
    ]
    services = [str(service) for service in workspace.get("services", [])]
    lines = [
        f"# Platform Zero maintenance lane: {name}",
        "",
        f"Role: `{role}`.",
    ]
    if service_account:
        lines += [f"Runtime account: `{service_account}`."]
    if services:
        lines += [f"Owned services: {', '.join(f'`{item}`' for item in services)}."]
    lines += [
        "",
        "## Boundaries",
        "",
        "- This lane has no sudo and must not make host-level changes.",
        "- Do not read, change, deploy, restart, or inspect sibling domains.",
        "- Keep secrets encrypted; never commit private keys or rendered environment files.",
        "- Use the domain dispatcher for remote status, logs, verification, restart, and deployment.",
        "- Coordinate repository edits through the Worklane agent claim directory.",
    ]
    if role == "control":
        lines += [
            "- This lane owns global domain configuration and repository pins.",
            "- It validates the full composition but intentionally has no domain deployment keys.",
        ]
    elif role == "host":
        lines += [
            "- This is the only lane permitted to prepare rootful and host-policy changes.",
            "- Gerald sudo remains temporary; use only the documented hash-gated host plan.",
        ]
    else:
        lines += [
            "- Build and deploy only this lane's named domain.",
            "- Global site-config changes flow through the control lane.",
        ]
    lines += [
        "",
        "## Writable repositories",
        "",
        *(f"- `{item}`" for item in writable),
        "",
        "Run each repository's CI-equivalent checks before pushing. A deployment must use the",
        "accepted site-config pin and the checksum emitted by Platform Zero.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    if manifest.get("schemaVersion") != 1:
        fail("unsupported maintenance workspace manifest")
    declared_root = Path(manifest["root"])
    root = (args.root or declared_root).resolve()
    if not root.is_absolute() or root == Path("/"):
        fail(f"unsafe workspace root: {root}")

    actions: list[dict[str, object]] = []
    blockers: list[dict[str, object]] = []
    for workspace in manifest["workspaces"]:
        name = str(workspace["name"])
        destination = root / name
        for repo in workspace.get("repositories", []):
            path = repo_path(destination, repo)
            state = inspect_repo(path, repo)
            row = {"workspace": name, "repository": repo["name"], "path": str(path), **state}
            actions.append(row)
            if state["state"] not in {"missing", "current"}:
                blockers.append(row)

    result = {"root": str(root), "apply": args.apply, "actions": actions, "blockers": blockers}
    print(json.dumps(result, indent=2))
    if blockers:
        fail("workspace drift must be resolved before materialization")
    if not args.apply:
        return 0
    if shutil.which("git") is None or shutil.which("worklane") is None:
        fail("git and worklane are required for --apply")

    root.mkdir(parents=True, exist_ok=True)
    for workspace in manifest["workspaces"]:
        destination = root / str(workspace["name"])
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        for repo in workspace.get("repositories", []):
            path = repo_path(destination, repo)
            if path.exists():
                continue
            run("git", "clone", "--no-checkout", str(repo["remote"]), str(path))
            run("git", "checkout", "--detach", str(repo["commit"]), cwd=path)
        agents = destination / "AGENTS.md"
        expected = agents_text(workspace)
        if agents.exists() and agents.read_text() != expected:
            fail(f"refusing to replace locally changed {agents}")
        agents.write_text(expected)
        os.chmod(agents, 0o600)
        if not (destination / ".worklane" / "lane.toml").exists():
            run("worklane", "lane", "create", str(workspace["name"]), "--project", str(destination), "--profile", "default")
    return 0


if __name__ == "__main__":
    sys.exit(main())
