#!/usr/bin/env python3
"""Plan or safely materialize Platform Zero Worklane workspaces."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


PROFILES = """[profiles.p0-stack]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[[profiles.p0-stack.mounts]]
source = "/run/platform-zero/host-broker.sock"
target = "/run/platform-zero/host-broker.sock"
read_only = true

[profiles.software-gpu]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true
devices = ["nvidia.com/gpu=all"]
"""
PREVIOUS_PROFILES = """[profiles.p0-control]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[profiles.p0-host]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[profiles.p0-domain]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = false

[profiles.software-gpu]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true
devices = ["nvidia.com/gpu=all"]
"""
INTERMEDIATE_PROFILES = PROFILES.replace(
    'target = "/home/dev/.local/bin/p0-hostctl"',
    'target = "/usr/local/bin/p0-hostctl"',
)
LEGACY_PROFILES = PREVIOUS_PROFILES.split("\n[profiles.software-gpu]", 1)[0].rstrip() + "\n"
TRANSITIONAL_PROFILES = """[profiles.p0-control]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[[profiles.p0-control.mounts]]
source = "/usr/local/bin/p0-hostctl"
target = "/home/dev/.local/bin/p0-hostctl"
read_only = true

[[profiles.p0-control.mounts]]
source = "/run/platform-zero"
target = "/run/platform-zero"
read_only = true

[[profiles.p0-control.mounts]]
source = "/home/stack_lab/.config/platform-zero"
target = "/home/dev/.config/platform-zero"
read_only = true

[profiles.p0-host]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[[profiles.p0-host.mounts]]
source = "/usr/local/bin/p0-hostctl"
target = "/home/dev/.local/bin/p0-hostctl"
read_only = true

[[profiles.p0-host.mounts]]
source = "/run/platform-zero"
target = "/run/platform-zero"
read_only = true

[[profiles.p0-host.mounts]]
source = "/home/stack_lab/.config/platform-zero"
target = "/home/dev/.config/platform-zero"
read_only = true

[profiles.p0-domain]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = false

[profiles.software-gpu]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true
devices = ["nvidia.com/gpu=all"]
"""
PREVIOUS_STACK_PROFILES = """[profiles.p0-stack]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[[profiles.p0-stack.mounts]]
source = "/usr/local/bin/p0-hostctl"
target = "/home/dev/.local/bin/p0-hostctl"
read_only = true

[[profiles.p0-stack.mounts]]
source = "/run/platform-zero"
target = "/run/platform-zero"
read_only = true

[[profiles.p0-stack.mounts]]
source = "/home/stack_lab/.config/platform-zero"
target = "/home/dev/.config/platform-zero"
read_only = true

[profiles.software-gpu]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true
devices = ["nvidia.com/gpu=all"]
"""
OBSOLETE_STACK_PROFILES = """[profiles.p0-stack]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true

[[profiles.p0-stack.mounts]]
source = "/run/platform-zero"
target = "/run/platform-zero"
read_only = true

[profiles.software-gpu]
image = "worklane:latest"
network = "outbound"
mount_codex_credentials = true
mount_gh_credentials = true
devices = ["nvidia.com/gpu=all"]
"""

HOST_ACCESS_MOUNTS = [
    {
        "source": "/run/platform-zero/host-broker.sock",
        "target": "/run/platform-zero/host-broker.sock",
        "read_only": True,
    },
]
PREVIOUS_HOST_ACCESS_MOUNTS = [
    {"source": "/usr/local/bin/p0-hostctl", "target": "/home/dev/.local/bin/p0-hostctl", "read_only": True},
    {"source": "/run/platform-zero", "target": "/run/platform-zero", "read_only": True},
    {"source": "/home/stack_lab/.config/platform-zero", "target": "/home/dev/.config/platform-zero", "read_only": True},
]


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


def safe_destination(root: Path, declared_root: Path, workspace: dict[str, object]) -> Path:
    raw = workspace.get("projectPath")
    if raw:
        declared_destination = Path(str(raw)).resolve()
        if declared_destination != declared_root and declared_root not in declared_destination.parents:
            fail(f"workspace path escapes declared root: {declared_destination}")
        destination = root / declared_destination.relative_to(declared_root)
    else:
        destination = root / str(workspace["name"])
    destination = destination.resolve()
    if destination != root and root not in destination.parents:
        fail(f"workspace path escapes declared root: {destination}")
    return destination


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
    authorities = list(workspace.get("authorities", []))
    writable = [
        str(repo["name"])
        for repo in workspace.get("repositories", [])
        if repo.get("writable", False)
    ]
    services = [str(service) for service in workspace.get("services", [])]
    heading = "software lane" if role == "software" else "stack engineering lane"
    lines = [
        f"# Platform Zero {heading}: {name}",
        "",
        f"You are operating inside the `{name}` Worklane. This is the `{role}` workspace.",
        f"Role: `{role}`.",
    ]
    if authorities:
        lines += [
            "Runtime authorities: "
            + ", ".join(
                f"`{authority['name']}` (`{authority['serviceAccount']}`)"
                for authority in authorities
            )
            + "."
        ]
    if services:
        lines += [f"Owned services: {', '.join(f'`{item}`' for item in services)}."]
    lines += [
        "",
        "## Boundaries",
        "",
        "- This lane has no sudo and must not make host-level changes.",
        "- Do not read, change, deploy, restart, or inspect sibling domains.",
        "- Keep secrets encrypted; never commit private keys or rendered environment files.",
        "- Coordinate repository edits through the Worklane agent claim directory.",
    ]
    if role == "stack":
        lines += [
            "- This lane owns the complete stack source, encrypted SOPS inputs, repository pins, and test infrastructure.",
            "- A human enters this environment as `stack_lab@192.168.0.11`; you are already inside",
            "  its `stack` Worklane at `/mnt/lab_debian/stack_lab/stack_work`.",
            "- Runtime remains split across the named rootless `webservices-*` Linux-user authorities",
            "  and the separate rootful host authority. Workspace consolidation does not change ownership.",
            "- Treat `software_lab` and `/mnt/lab_debian/software_lab` as a separate authority. Never",
            "  restart, replace, or inspect its active Worklanes during stack maintenance.",
            "- Software Worklanes require the RTX 3060 through CDI as `nvidia.com/gpu=all`; preserve",
            "  that contract in generated profiles and host configuration.",
            "- Gerald passwordless sudo is intentionally retained; routine changes use the typed broker.",
            "- Protected databases, volumes, media, service homes, rendered environments, raw logs, and",
            "  service sockets are not mounted here; only the typed host-broker socket is exposed.",
        ]
    elif role == "software":
        lines += [
            "- This lane is owned by `software_lab`; do not inspect Platform Zero service-domain state.",
            "- The RTX 3060 is exposed through CDI as `nvidia.com/gpu=all`.",
            "- Account-level Codex, GitHub, and SSH credentials are mounted; never copy them into the project.",
            "- Recreate dependencies from project lockfiles and the commands declared in `software-workspaces.json`.",
        ]
    if role == "stack":
        lines += [
            "",
            "## Maintenance workflow",
            "",
            "- Query the live authority map with `python3 sso-stack-generator/runtime-generator/podman-ops/p0-hostctl.py diagnostics`.",
            "- Use that repository's `p0-hostctl.py` for broker operations; do not copy a release ID from this document.",
            "- Build and validate an immutable candidate bundle, then use `p0-hostctl.py plan` and",
            "  `p0-hostctl apply` with the returned plan ID. Poll `operation-status` after disconnects.",
            "- Scope is derived from changed authorities and the dependency graph; never request a",
            "  broader service restart than the candidate requires.",
            "- Review `/mnt/stack/podman/test-runners/state/test-runner/results/all-summary.txt` after",
            "  the mandatory Kotlin, TypeScript, isolated end-to-end, and MatrixRTC/LiveKit gates.",
            "- Destructive actions, secret operations, account/storage changes, irreversible migrations,",
            "  and host-security changes require Gerald's separate approval.",
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


def reconcile_host_access_profile(destination: Path, workspace: dict[str, object]) -> bool:
    if workspace.get("role") != "stack":
        return False
    manifest = destination / ".worklane/lane.toml"
    if not manifest.exists():
        return False
    text = manifest.read_text()
    current = tomllib.loads(text).get("profile", {}).get("mounts", [])
    if current == HOST_ACCESS_MOUNTS:
        return False
    obsolete_client_config_mounts = [
        {"source": "/usr/local/bin/p0-hostctl", "target": "/usr/local/bin/p0-hostctl", "read_only": True},
        {"source": "/run/platform-zero", "target": "/run/platform-zero", "read_only": True},
        {"source": "/home/stack_lab/.config/platform-zero", "target": "/etc/platform-zero", "read_only": True},
    ]
    previous_directory_mount = [
        {"source": "/run/platform-zero", "target": "/run/platform-zero", "read_only": True},
    ]
    if current and current not in (
        PREVIOUS_HOST_ACCESS_MOUNTS, obsolete_client_config_mounts, previous_directory_mount,
    ):
        fail(f"refusing to replace locally changed profile mounts in {manifest}")
    marker = "\n[[profile.mounts]]"
    first_mount = text.find(marker)
    if current and first_mount < 0:
        fail(f"cannot safely update managed profile mounts in {manifest}")
    prefix = text[:first_mount] if first_mount >= 0 else text.rstrip()
    rendered = "".join(
        f'\n[[profile.mounts]]\nsource = "{mount["source"]}"\ntarget = "{mount["target"]}"\nread_only = true\n'
        for mount in HOST_ACCESS_MOUNTS
    )
    manifest.write_text(prefix.rstrip() + rendered + "\n")
    return True


def legacy_agents_texts(workspace: dict[str, object]) -> set[str]:
    current = agents_text(workspace)
    name = str(workspace["name"])
    role = str(workspace["role"])
    prior = current.replace(
        f"You are operating inside the `{name}` Worklane. This is the `{role}` workspace.\n",
        "",
    )
    prior = prior.replace(
        "- A human enters this environment as `stack_lab@192.168.0.11`; you are already inside\n"
        "  its `control` Worklane at `/mnt/lab_debian/stack_lab/stack_work/control`.\n",
        "- Enter this maintenance environment as `stack_lab@192.168.0.11`; its workspace root is\n"
        "  `/mnt/lab_debian/stack_lab/stack_work`.\n",
    )
    if role == "software":
        return {prior}
    previous = prior
    if role == "stack":
        previous = current.replace(
            "- Query the live authority map with `python3 sso-stack-generator/runtime-generator/podman-ops/p0-hostctl.py diagnostics`.\n"
            "- Use that repository's `p0-hostctl.py` for broker operations; do not copy a release ID from this document.\n"
            "- Build and validate an immutable candidate bundle, then use `p0-hostctl.py plan` and",
            "- Read `~/.config/platform-zero/workspaces.json` for current repository pins and domains.\n"
            "- Query live state with `p0-hostctl status`; do not copy a release ID from this document.\n"
            "- Build and validate an immutable candidate bundle, then use `p0-hostctl plan` and",
        )
        previous = previous.replace("p0-hostctl.py", "p0-hostctl")
    previous_etc = previous.replace(
        "~/.config/platform-zero/workspaces.json",
        "/etc/platform-zero/workspaces.json",
    )
    old_boundary = (
        "- Protected databases, volumes, media, service homes, rendered environments, raw logs, and\n"
        "  service sockets are not mounted here. Use broker status, diagnostics, and scrubbed evidence."
    )
    previous_old_boundary = previous.replace(
        "- Protected databases, volumes, media, service homes, rendered environments, raw logs, and\n"
        "  service sockets are not mounted here; only the typed host-broker socket is exposed.",
        old_boundary,
    )
    previous_etc_old_boundary = previous_etc.replace(
        "- Protected databases, volumes, media, service homes, rendered environments, raw logs, and\n"
        "  service sockets are not mounted here; only the typed host-broker socket is exposed.",
        old_boundary,
    )
    current_old_boundary = current.replace(
        "- Protected databases, volumes, media, service homes, rendered environments, raw logs, and\n"
        "  service sockets are not mounted here; only the typed host-broker socket is exposed.",
        old_boundary,
    )
    if workspace.get("role") == "control":
        previous = previous.replace(
            "- Enter this maintenance environment as `stack_lab@192.168.0.11`; its workspace root is\n"
            "  `/mnt/lab_debian/stack_lab/stack_work`.\n"
            "- The service stack is split across 7 rootless `webservices-*` Linux-user authorities\n"
            "  plus a separate rootful host authority. Use each role lane for authority-owned changes.\n"
            "- Treat `software_lab` and `/mnt/lab_debian/software_lab` as a separate authority. Never\n"
            "  restart, replace, or inspect its active Worklanes during stack maintenance.\n"
            "- Software Worklanes require the RTX 3060 through CDI as `nvidia.com/gpu=all`; preserve\n"
            "  that contract in generated profiles and host configuration.\n"
            "- Gerald passwordless sudo is intentionally retained, but routine deployments must use\n"
            "  the checksum-gated Platform Zero broker rather than an unrestricted sudo shell.\n",
            "",
        )
        previous = previous.replace(
            "\n## Maintenance workflow\n\n"
            "- Read `~/.config/platform-zero/workspaces.json` for current repository pins and domains.\n"
            "- Query live state with `p0-hostctl status`; do not copy a release ID from this document.\n"
            "- Build and validate the complete composition before requesting any host-side change.\n"
            "- Deploy only a reviewed immutable bundle through `p0-hostctl` using its full SHA-256:\n"
            "  stage, preflight, snapshot, activate, then verify with that same digest.\n"
            "- Review `/mnt/stack/podman/test-runners/state/test-runner/results/all-summary.txt` after\n"
            "  the mandatory Kotlin, TypeScript, isolated end-to-end, and MatrixRTC/LiveKit gates.\n"
            "- Stop on dirty repositories, manifest drift, a failed authority, or a changed software\n"
            "  Worklane container ID. Do not reset or overwrite user-owned changes.\n",
            "",
        )
    legacy = previous.replace(
        "- Gerald passwordless sudo is intentionally retained; use only the documented hash-gated host plan.",
        "- Gerald sudo remains temporary; use only the documented hash-gated host plan.",
    )
    if workspace.get("role") == "domain":
        legacy = legacy.replace("- Use the domain dispatcher for remote status, logs, verification, restart, and deployment.\n", "")
    marker = "- Keep secrets encrypted; never commit private keys or rendered environment files.\n"
    legacy = legacy.replace(marker, marker + "- Use the domain dispatcher for remote status, logs, verification, restart, and deployment.\n")
    return {
        prior, previous, previous_etc, previous_old_boundary, previous_etc_old_boundary,
        current_old_boundary, legacy,
    }


def managed_agents_texts(workspace: dict[str, object]) -> set[str]:
    return {agents_text(workspace), *legacy_agents_texts(workspace)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--update",
        action="store_true",
        help="update clean, correctly configured checkouts to their manifest commit",
    )
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
    owner = str(manifest.get("owner", "stack_lab"))
    if not owner or "/" in owner:
        fail(f"unsafe workspace owner: {owner!r}")
    names: set[str] = set()
    if owner == "stack_lab" and (len(manifest["workspaces"]) != 1 or manifest["workspaces"][0].get("name") != "stack" or manifest["workspaces"][0].get("role") != "stack"):
        fail("maintenance manifest must contain exactly one unified stack workspace")
    for workspace in manifest["workspaces"]:
        name = str(workspace["name"])
        if not name or "/" in name or name in {".", ".."} or name in names:
            fail(f"unsafe or duplicate workspace name: {name!r}")
        names.add(name)
        destination = safe_destination(root, declared_root.resolve(), workspace)
        for repo in workspace.get("repositories", []):
            path = repo_path(destination, repo)
            state = inspect_repo(path, repo)
            row = {"workspace": name, "repository": repo["name"], "path": str(path), **state}
            actions.append(row)
            if state["state"] not in {"missing", "current"} and not (
                args.update and state["state"] == "commit-drift"
            ):
                blockers.append(row)

    result = {
        "root": str(root),
        "apply": args.apply,
        "update": args.update,
        "actions": actions,
        "blockers": blockers,
    }
    print(json.dumps(result, indent=2))
    if blockers:
        fail("workspace drift must be resolved before materialization")
    if not args.apply:
        return 0
    import pwd
    if pwd.getpwuid(os.getuid()).pw_name != owner:
        fail(f"--apply must run as declared owner {owner}")
    if shutil.which("git") is None or shutil.which("worklane") is None:
        fail("git and worklane are required for --apply")

    root.mkdir(parents=True, exist_ok=True)
    profiles = Path.home() / ".config" / "worklane" / "profiles.toml"
    profiles.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if profiles.exists() and profiles.read_text() not in {
        PROFILES, INTERMEDIATE_PROFILES, PREVIOUS_PROFILES, LEGACY_PROFILES,
        TRANSITIONAL_PROFILES, PREVIOUS_STACK_PROFILES, OBSOLETE_STACK_PROFILES,
    }:
        fail(f"refusing to replace locally changed {profiles}")
    profiles.write_text(PROFILES)
    os.chmod(profiles, 0o600)
    for workspace in manifest["workspaces"]:
        destination = safe_destination(root, declared_root.resolve(), workspace)
        if destination.exists() and destination.stat().st_uid != os.getuid():
            fail(f"workspace is not owned by {owner}: {destination}")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        for repo in workspace.get("repositories", []):
            path = repo_path(destination, repo)
            if path.exists():
                state = inspect_repo(path, repo)
                if args.update and state["state"] == "commit-drift":
                    run("git", "fetch", "--no-tags", "origin", str(repo["commit"]), cwd=path)
                    run("git", "checkout", "--detach", str(repo["commit"]), cwd=path)
                continue
            run("git", "clone", "--no-checkout", str(repo["remote"]), str(path))
            run("git", "checkout", "--detach", str(repo["commit"]), cwd=path)
        agents = destination / (".platform-zero/AGENTS.md" if workspace.get("role") == "software" else "AGENTS.md")
        agents.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        expected = agents_text(workspace)
        if agents.exists() and agents.read_text() not in managed_agents_texts(workspace):
            fail(f"refusing to replace locally changed {agents}")
        agents.write_text(expected)
        os.chmod(agents, 0o600)
        if not (destination / ".worklane" / "lane.toml").exists():
            profile = "p0-stack" if workspace.get("role") == "stack" else str(workspace.get("profile", "software-gpu"))
            if profile is None:
                fail(f"unknown workspace role: {workspace['role']}")
            run("worklane", "lane", "create", str(workspace["name"]), "--project", str(destination), "--profile", profile)
        elif reconcile_host_access_profile(destination, workspace):
            run("worklane", "lane", "reconcile", str(workspace["name"]), "--apply")
    platform_config = Path.home() / ".config" / "platform-zero"
    platform_config.mkdir(mode=0o700, parents=True, exist_ok=True)
    installed_manifest = platform_config / "workspaces.json"
    rendered_manifest = json.dumps(manifest, indent=2) + "\n"
    if installed_manifest.exists():
        try:
            installed = json.loads(installed_manifest.read_text())
        except json.JSONDecodeError:
            fail(f"refusing to replace invalid {installed_manifest}")
        if installed != manifest:
            fail(f"refusing to replace locally changed {installed_manifest}")
    installed_manifest.write_text(rendered_manifest)
    os.chmod(installed_manifest, 0o600)
    return 0


if __name__ == "__main__":
    sys.exit(main())
