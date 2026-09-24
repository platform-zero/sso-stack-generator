#!/usr/bin/env python3
"""Socket-activated, allowlisted Platform Zero host operations."""

from __future__ import annotations

import hashlib
import json
import os
import fcntl
import base64
from pathlib import Path
import pwd
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


SOCKET_FD = 3
MAX_REQUEST = 64 * 1024
INCOMING = Path(os.environ.get("P0_INCOMING", "/var/lib/platform-zero/incoming"))
SNAPSHOTS = Path(os.environ.get("P0_SNAPSHOTS", "/mnt/stack/platform-zero-snapshots"))
STACK_ROOT = Path(os.environ.get("P0_STACK_ROOT", "/mnt/lab_debian/stack_lab"))
LEGACY_USER = os.environ.get("P0_LEGACY_USER", "webservices")
DOMAINS_MANIFEST = Path(os.environ.get("P0_DOMAINS_MANIFEST", "/etc/platform-zero/podman-domains.json"))
SUDOERS = Path(os.environ.get("P0_SUDOERS", "/etc/sudoers"))
GERALD_DROPIN = Path(os.environ.get("P0_GERALD_DROPIN", "/etc/sudoers.d/gerald-webservices"))
ACTIVE_RELEASE = Path(os.environ.get("P0_ACTIVE_RELEASE", "/var/lib/platform-zero/active.json"))
ROOTFUL_RELEASES = Path(os.environ.get("P0_ROOTFUL_RELEASES", "/var/lib/webservices/releases"))
SNAPSHOT_RETENTION = 5
RELEASE_RETENTION = 3
INCOMING_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
ROOTLESS_HOST_NETWORK_ALLOWLIST = {
    "quadlet/rootless-apps/webservices-livekit.container": (
        "apps",
        "webservices-apps",
    ),
}
OPERATIONS = Path(os.environ.get("P0_OPERATIONS", "/var/lib/platform-zero/operations"))
BREAK_GLASS = Path(os.environ.get("P0_BREAK_GLASS", "/var/lib/platform-zero/break-glass"))
GERALD_APPROVAL = Path(os.environ.get("P0_GERALD_APPROVAL", "/run/platform-zero/gerald-approval.token"))
TEST_RUNNER_CURRENT = Path(os.environ.get(
    "P0_TEST_RUNNER_CURRENT", "/mnt/stack/podman/test-runners/state/current"
))
TEST_RUNNER_RESULTS = Path(os.environ.get(
    "P0_TEST_RUNNER_RESULTS", "/mnt/stack/podman/test-runners/state/test-runner/results"
))
SAFE_TEST_SUITES = {
    "ts-unit", "ts-sso", "ts-mobile-smoke", "ts-mobile-auth", "ts-e2e-visual",
    "ts-e2e-huly", "ts-e2e-jupyterhub",
}
TEST_SUITE_TIMEOUT_SECONDS = {
    "ts-unit": 600, "ts-sso": 900, "ts-mobile-smoke": 900,
    "ts-mobile-auth": 900, "ts-e2e-visual": 1200,
    "ts-e2e-huly": 240, "ts-e2e-jupyterhub": 900,
}
TEST_RUNNER_USER = "webservices-test-runners"


class RequestError(Exception):
    pass


def require_gerald_approval(request: dict[str, object], operation: str) -> None:
    token = str(request.get("approval_token", ""))
    if not token or not GERALD_APPROVAL.is_file():
        raise RequestError(f"{operation} requires Gerald's separate approval")
    expected = GERALD_APPROVAL.read_text().strip()
    if not expected or token != expected:
        raise RequestError(f"{operation} approval token is invalid")
    GERALD_APPROVAL.unlink(missing_ok=True)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("HOME", "/root")
    env.setdefault("XDG_CONFIG_HOME", "/root/.config")
    result = subprocess.run(args, text=True, capture_output=True, check=False, env=env)
    if check and result.returncode:
        raise RequestError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stderr[-4000:]}")
    return result


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise RequestError(f"bundle contains a symlink: {relative}")
        if path.is_file():
            digest.update(relative.encode() + b"\0")
            digest.update(str(path.stat().st_mode & 0o777).encode() + b"\0")
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def validate_bundle(bundle: Path) -> None:
    required = [
        "bundle.json",
        "stack.ir.json",
        "podman-domains.json",
        "podman-loopback-endpoints.json",
        "ops/platform-zero.nft",
        "ops/install-podman-bundle.sh",
    ]
    for relative in required:
        if not (bundle / relative).is_file():
            raise RequestError(f"bundle is missing {relative}")
    metadata = json.loads((bundle / "bundle.json").read_text())
    if metadata.get("backend") != "podman":
        raise RequestError("bundle backend is not podman")
    domains = json.loads((bundle / "podman-domains.json").read_text()).get("domains", [])
    if not domains or len({item["user"] for item in domains}) != len(domains):
        raise RequestError("invalid or duplicate Podman domains")
    domain_users = {item["name"]: item["user"] for item in domains}
    domain_capabilities = {item["name"]: set(item.get("hostCapabilities", [])) for item in domains}
    for path in (bundle / "quadlet").glob("rootless-*/*.container"):
        text = path.read_text()
        relative = path.relative_to(bundle).as_posix()
        domain = path.parent.name.removeprefix("rootless-")
        if "Privileged=true" in text:
            raise RequestError(f"unsafe rootless Quadlet: {path.relative_to(bundle)}")
        if "Network=host" in text:
            expected_owner = ROOTLESS_HOST_NETWORK_ALLOWLIST.get(relative)
            if expected_owner is None or domain_users.get(expected_owner[0]) != expected_owner[1]:
                raise RequestError(f"unsafe rootless Quadlet: {path.relative_to(bundle)}")
        device_lines = [line for line in text.splitlines() if line.startswith("AddDevice=")]
        if device_lines:
            if device_lines != ["AddDevice=/dev/kvm:/dev/kvm"] or "kvm" not in domain_capabilities.get(domain, set()):
                raise RequestError(f"unauthorized rootless device: {path.relative_to(bundle)}")
            if "GroupAdd=keep-groups" not in text:
                raise RequestError(f"rootless KVM Quadlet lacks keep-groups: {path.relative_to(bundle)}")
    nft = (bundle / "ops/platform-zero.nft").read_text()
    if not nft.startswith("table inet platform_zero {") or "policy accept" not in nft:
        raise RequestError("unexpected nftables policy")


def stage(request: dict[str, object]) -> dict[str, object]:
    source = Path(str(request.get("bundle", ""))).resolve()
    if not source.is_dir() or not source.is_relative_to(STACK_ROOT):
        raise RequestError(f"bundle must be a directory below {STACK_ROOT}")
    validate_bundle(source)
    INCOMING.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=INCOMING))
    try:
        shutil.copytree(source, temporary / "bundle", symlinks=False, dirs_exist_ok=True)
        copied = temporary / "bundle"
        validate_bundle(copied)
        digest = tree_sha256(copied)
        expected = str(request.get("sha256", ""))
        if expected and digest != expected:
            raise RequestError(f"bundle digest mismatch: expected {expected}, got {digest}")
        destination = INCOMING / digest
        if destination.exists():
            if tree_sha256(destination) == digest:
                shutil.rmtree(temporary)
                return {"release": digest, "path": str(destination)}
            shutil.rmtree(destination)
        os.replace(copied, destination)
        temporary.rmdir()
        return {"release": digest, "path": str(destination)}
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def release_path(request: dict[str, object]) -> Path:
    release = str(request.get("release", ""))
    if len(release) != 64 or any(char not in "0123456789abcdef" for char in release):
        raise RequestError("release must be a SHA-256 digest")
    path = INCOMING / release
    if not path.is_dir() or tree_sha256(path) != release:
        raise RequestError("release is missing or has changed")
    validate_bundle(path)
    return path


def scrub(text: str) -> str:
    """Remove common credentials and multiline payloads from broker evidence."""
    import re
    text = re.sub(r"(?im)^([^=\n]*(?:password|secret|token|cookie|authorization|private[_ -]?key)[^=\n]*)=[^\n]*$", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+|basic\s+)[A-Za-z0-9+/=._-]+", r"\1[REDACTED]", text)
    return text[-16000:]


def write_record(record: dict[str, object]) -> None:
    OPERATIONS.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = OPERATIONS / f"{record['id']}.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(record, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def locked_record(identifier: str):
    """Serialize state transitions for one durable operation or plan."""
    if not identifier or "/" in identifier or ".." in identifier:
        raise RequestError("invalid operation or plan identifier")
    OPERATIONS.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = OPERATIONS / f".{identifier}.lock"
    lock = lock_path.open("a+")
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
    return lock


def read_record(identifier: str) -> dict[str, object]:
    if not identifier or "/" in identifier or ".." in identifier:
        raise RequestError("invalid operation or plan identifier")
    path = OPERATIONS / f"{identifier}.json"
    if not path.is_file():
        raise RequestError("operation or plan not found")
    record = json.loads(path.read_text())
    if record.get("id") != identifier:
        raise RequestError("operation record identity mismatch")
    return record


def candidate_scope(bundle: Path) -> dict[str, object]:
    current = None
    if ACTIVE_RELEASE.is_file():
        try:
            current = release_path({"release": json.loads(ACTIVE_RELEASE.read_text()).get("release")})
        except (RequestError, TypeError, ValueError):
            current = None
    candidate_ir = json.loads((bundle / "stack.ir.json").read_text())
    previous_ir = json.loads((current / "stack.ir.json").read_text()) if current and (current / "stack.ir.json").is_file() else {}
    candidate_services = candidate_ir.get("services", {})
    previous_services = previous_ir.get("services", {})
    changed_services = {name for name in set(candidate_services) | set(previous_services)
                        if candidate_services.get(name) != previous_services.get(name)}
    candidate_domains = json.loads((bundle / "podman-domains.json").read_text()).get("domains", [])
    previous_domains = json.loads((current / "podman-domains.json").read_text()).get("domains", []) if current and (current / "podman-domains.json").is_file() else []
    authorities = {item["name"] for item in candidate_domains} | {item["name"] for item in previous_domains} | {"rootful"}

    def service_authority(name: str, service: object) -> str:
        if not isinstance(service, dict):
            return "rootful"
        if service.get("placement") == "rootless":
            return str(service.get("rootlessDomain", "rootful"))
        return "rootful"

    affected = {service_authority(name, candidate_services.get(name, previous_services.get(name)))
                for name in changed_services}
    shared = not current

    def file_map(root: Path) -> dict[str, str]:
        return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.rglob("*") if path.is_file() and not path.is_symlink()}

    old_files = file_map(current) if current else {}
    new_files = file_map(bundle)
    changed_files = {name for name in set(old_files) | set(new_files) if old_files.get(name) != new_files.get(name)}
    config_owners: dict[str, set[str]] = {}
    for services in (previous_services, candidate_services):
        for service_name, service in services.items():
            owner = service_authority(service_name, service)
            for mount in service.get("volumes", []) if isinstance(service, dict) else []:
                source = mount.split(":", 1)[0] if isinstance(mount, str) else mount.get("source", "")
                if source.startswith("./configs/"):
                    config_owners.setdefault(source.removeprefix("./"), set()).add(owner)

    for relative in changed_files:
        if relative in {"stack.ir.json", "bundle.json", "podman-domains.json", "podman-domain-dependencies.json"}:
            continue
        if relative.startswith("quadlet/rootless-"):
            domain = relative.split("/", 2)[1].removeprefix("rootless-")
            affected.add(domain)
        elif relative.startswith("quadlet/rootful/") or relative.startswith("quadlet/"):
            affected.add("rootful")
        elif relative.startswith("runtime-env/"):
            service = Path(relative).name.removesuffix(".env.template").removesuffix(".env")
            if service in candidate_services or service in previous_services:
                affected.add(service_authority(service, candidate_services.get(service, previous_services.get(service))))
            else:
                shared = True
        elif relative.startswith("runtime/configs/"):
            source = relative.removeprefix("runtime/")
            owners = {owner for path, values in config_owners.items()
                      if source == path or source.startswith(path.rstrip("/") + "/") for owner in values}
            if owners:
                affected.update(owners)
            else:
                shared = True
        elif relative.startswith(("site/", "repos/", "docs/")) or relative in {
            "runtime-model.yml", "compose.yml", "README.md", "maintenance-workspaces.json", "software-workspaces.json",
        }:
            continue
        elif relative.startswith(("scripts/test-", "scripts/tests/", "scripts/deploy/__pycache__/", "scripts/__pycache__/")):
            continue
        elif relative.startswith("scripts/"):
            shared = True
        elif relative.startswith("build/stack.containers/"):
            image_name = relative.removeprefix("build/stack.containers/").split("/", 1)[0]
            service = image_name.removesuffix("-managed")
            if service in candidate_services or service in previous_services:
                affected.add(service_authority(service, candidate_services.get(service, previous_services.get(service))))
            else:
                shared = True
        elif relative.startswith("build/stack.config/"):
            config_name = relative.removeprefix("build/stack.config/").split("/", 1)[0]
            if config_name in candidate_services or config_name in previous_services:
                affected.add(service_authority(
                    config_name, candidate_services.get(config_name, previous_services.get(config_name))
                ))
            else:
                # Global/shared configuration cannot be safely attributed to one
                # authority from its path alone.
                shared = True
        elif relative.startswith("ops/") and relative in {
            "ops/p0-host-broker.py", "ops/p0-hostctl.py", "ops/p0-domain-dispatch",
            "ops/install-platform-zero-control-plane.sh", "ops/install-podman-bundle.sh",
            "ops/materialize-workspaces.py", "ops/start-worklane-containers.py",
            "ops/reap-idle-worklanes.py",
        }:
            continue
        elif relative.startswith("ops/__pycache__/"):
            continue
        else:
            # Runtime behavior not attributable to one authority is shared.
            shared = True

    if candidate_domains != previous_domains and current:
        shared = True
    if current and (candidate_ir.get("networks") != previous_ir.get("networks") or
                    candidate_ir.get("volumes") != previous_ir.get("volumes")):
        shared = True
    # The broker's active-release record can outlive a failed/partial runtime
    # activation. Treat release-marker drift as a full reconciliation request
    # even when the staged bundle itself is byte-identical to that record.
    if current and diagnostics({}).get("drift", {}).get("state") != "clean":
        shared = True
    if changed_services and not affected:
        shared = True
    if shared:
        affected = set(authorities)

    edges_path = bundle / "podman-domain-dependencies.json"
    old_edges_path = current / "podman-domain-dependencies.json" if current else None
    edges = json.loads(edges_path.read_text()).get("dependencies", []) if edges_path.is_file() else []
    old_edges = json.loads(old_edges_path.read_text()).get("dependencies", []) if old_edges_path and old_edges_path.is_file() else []
    if edges != old_edges:
        shared = True
        affected = set(authorities)
    expanded = set(affected)
    changed_again = True
    while changed_again:
        changed_again = False
        for edge in edges:
            if edge.get("providerDomain") in expanded and edge.get("consumerDomain") not in expanded:
                expanded.add(edge["consumerDomain"])
                changed_again = True
    return {"changedServices": sorted(changed_services), "changedFiles": sorted(changed_files),
            "affectedAuthorities": sorted(expanded), "sharedChange": shared,
            "previousRelease": current.name if current else None}


def plan(request: dict[str, object]) -> dict[str, object]:
    source = Path(str(request.get("bundle", ""))).resolve()
    if not source.is_dir() or not source.is_relative_to(STACK_ROOT):
        raise RequestError(f"bundle must be a directory below {STACK_ROOT}")
    validate_bundle(source)
    staged = stage(request)
    candidate = INCOMING / staged["release"]
    scope = candidate_scope(candidate)
    identifier = hashlib.sha256(f"{staged['release']}:{time.time_ns()}".encode()).hexdigest()[:32]
    record = {"id": identifier, "kind": "plan", "state": "planned", "release": staged["release"],
              "createdAt": int(time.time()), "scope": scope, "evidence": {"bundle": staged["release"]}}
    write_record(record)
    return record


def enqueue_operation(operation: dict[str, object]) -> dict[str, object]:
    operation_id = str(operation["id"])
    write_record(operation)
    try:
        unit = f"platform-zero-operation-{operation_id}"
        run("systemd-run", "--quiet", "--collect", "--no-block", "--unit", unit,
            "/usr/local/libexec/p0-host-broker", "--worker", operation_id)
    except Exception as error:
        with locked_record(operation_id):
            operation = read_record(operation_id)
            operation.update({"state": "failed", "phase": "enqueue", "finishedAt": int(time.time()),
                              "error": scrub(str(error))})
            write_record(operation)
        raise RequestError("could not queue durable deployment operation")
    return operation


def apply_plan(request: dict[str, object]) -> dict[str, object]:
    plan_id = str(request.get("plan_id", ""))
    with locked_record(plan_id):
        plan_record = read_record(plan_id)
        if plan_record.get("kind") != "plan" or plan_record.get("state") != "planned":
            raise RequestError("plan is not available for application")
        authorities = plan_record.get("scope", {}).get("affectedAuthorities", [])
        if not authorities:
            plan_record.update({"state": "applied", "appliedAt": int(time.time()), "noOp": True})
            write_record(plan_record)
            return {"id": plan_id, "kind": "operation", "state": "succeeded", "phase": "no-op",
                    "result": {"release": plan_record["release"], "scope": []}}
        operation_id = hashlib.sha256(f"{plan_id}:{time.time_ns()}".encode()).hexdigest()[:32]
        operation = {"id": operation_id, "kind": "operation", "state": "queued", "phase": "queued",
                     "planId": plan_id, "release": plan_record["release"], "scope": plan_record["scope"],
                     "createdAt": int(time.time()), "applicationDataRollback": False}
        write_record(operation)
        plan_record["state"] = "applying"
        plan_record["operationId"] = operation_id
        write_record(plan_record)
    try:
        return enqueue_operation(operation)
    except Exception:
        with locked_record(plan_id):
            plan_record = read_record(plan_id)
            plan_record.update({"state": "planned"})
            plan_record.pop("operationId", None)
            write_record(plan_record)
        raise


def run_operation(operation_id: str) -> dict[str, object]:
    with locked_record(operation_id):
        operation = read_record(operation_id)
        if operation.get("kind") != "operation" or operation.get("state") != "queued":
            raise RequestError("operation is not queued")
        operation.update({"state": "running", "phase": "preflight", "startedAt": int(time.time())})
        write_record(operation)
    plan_id = str(operation["planId"])
    plan_record = read_record(plan_id)
    previous = plan_record.get("scope", {}).get("previousRelease")
    try:
        operation.update({"phase": "activation", "updatedAt": int(time.time())})
        write_record(operation)
        result = activate({"release": str(operation["release"]),
                           "authorities": operation.get("scope", {}).get("affectedAuthorities", [])})
        operation.update({"state": "succeeded", "phase": "complete", "finishedAt": int(time.time()),
                          "result": {"release": result["release"], "scope": operation["scope"]}})
        with locked_record(plan_id):
            plan_record = read_record(plan_id)
            plan_record["state"] = "applied"
            write_record(plan_record)
    except Exception as error:
        operation.update({"state": "rolling-back", "phase": "rollback", "error": scrub(str(error))})
        write_record(operation)
        if previous:
            try:
                activate({"release": str(previous),
                          "authorities": operation.get("scope", {}).get("affectedAuthorities", []),
                          "installer_release": str(operation["release"])})
                operation["rollback"] = {"state": "succeeded", "release": previous,
                                          "applicationDataRestored": False}
            except Exception as rollback_error:
                operation["rollback"] = {"state": "failed", "error": scrub(str(rollback_error))}
        else:
            operation["rollback"] = {"state": "unavailable", "reason": "no previous release"}
        operation.update({"state": "failed", "phase": "complete", "finishedAt": int(time.time())})
    write_record(operation)
    return operation


def operation_status(request: dict[str, object]) -> dict[str, object]:
    identifier = str(request.get("operation_id", request.get("plan_id", "")))
    record = read_record(identifier)
    if record.get("kind") == "test" and record.get("state") == "running":
        worker = run("systemctl", "is-active", "--quiet",
                     f"platform-zero-operation-{identifier}.service", check=False)
        if worker.returncode:
            with locked_record(identifier):
                current = read_record(identifier)
                if current.get("state") == "running":
                    current.update({"state": "failed", "phase": "complete",
                                    "finishedAt": int(time.time()), "exitCode": 125,
                                    "failureStage": {"kind": "worker-interrupted"}})
                    write_record(current)
                record = current
    if record.get("kind") == "test" and record.get("suite") in {"ts-e2e-visual", "ts-e2e-jupyterhub"}:
        record["jupyterHubReadiness"] = jupyterhub_readiness()
    return record


def jupyterhub_readiness() -> dict[str, object]:
    """Expose aggregate JupyterHub user-server state without container metadata."""
    try:
        domains = json.loads(DOMAINS_MANIFEST.read_text()).get("domains", [])
        authority = next((item for item in domains if item.get("name") == "workloads"), None)
        if not isinstance(authority, dict):
            return {"state": "unavailable", "reason": "workloads-authority-missing"}
        user = str(authority.get("user", ""))
        account = pwd.getpwnam(user)
        runtime = f"/run/user/{account.pw_uid}"
        result = run(
            "podman", "--remote", "--url", f"unix://{runtime}/podman/podman.sock",
            "ps", "--all", "--format", "json", check=False,
        )
        if result.returncode:
            error_text = str(getattr(result, "stderr", "")).lower()
            if "permission denied" in error_text:
                reason = "runtime-permission-denied"
            elif "connection refused" in error_text or "cannot connect" in error_text:
                reason = "runtime-socket-unavailable"
            elif "not found" in error_text or "no such file" in error_text:
                reason = "runtime-command-unavailable"
            else:
                reason = "runtime-query-failed"
            return {"state": "unavailable", "reason": reason,
                    "exitCode": result.returncode}
        try:
            containers = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return {"state": "unavailable", "reason": "runtime-response-invalid"}
        if not isinstance(containers, list) or any(not isinstance(item, dict) for item in containers):
            return {"state": "unavailable", "reason": "runtime-response-invalid"}
        counts = {"running": 0, "created": 0, "exited": 0, "paused": 0, "other": 0}
        for container in containers:
            names = container.get("Names", [])
            if isinstance(names, str):
                names = [names]
            if not isinstance(names, list) or not any(
                isinstance(name, str) and name.startswith("jupyter-") for name in names
            ):
                continue
            state = str(container.get("State", "")).lower()
            counts[state if state in counts and state != "other" else "other"] += 1
        images = run(
            "podman", "--remote", "--url", f"unix://{runtime}/podman/podman.sock",
            "images", "--format", "json", check=False,
        )
        image_state = "unavailable"
        if images.returncode == 0:
            try:
                image_records = json.loads(images.stdout or "[]")
                expected_image = "localhost/webservices/jupyter-notebook-build:bundle"
                present = False
                if isinstance(image_records, list) and all(isinstance(item, dict) for item in image_records):
                    for image in image_records:
                        tags = image.get("Names", image.get("RepoTags", []))
                        if isinstance(tags, str):
                            tags = [tags]
                        if isinstance(tags, list) and expected_image in tags:
                            present = True
                        repository, tag = image.get("Repository"), image.get("Tag")
                        if repository and tag and f"{repository}:{tag}" == expected_image:
                            present = True
                else:
                    return {"state": "unavailable", "reason": "runtime-response-invalid"}
                image_state = "present" if present else "missing"
            except json.JSONDecodeError:
                return {"state": "unavailable", "reason": "runtime-response-invalid"}
        networks = run(
            "podman", "--remote", "--url", f"unix://{runtime}/podman/podman.sock",
            "network", "ls", "--format", "json", check=False,
        )
        network_state = "unavailable"
        if networks.returncode == 0:
            try:
                network_records = json.loads(networks.stdout or "[]")
                if not isinstance(network_records, list) or any(
                    not isinstance(item, dict) for item in network_records
                ):
                    return {"state": "unavailable", "reason": "runtime-response-invalid"}
                network_state = "present" if any(
                    item.get("name", item.get("Name")) == "webservices_workloads_ai"
                    for item in network_records
                ) else "missing"
            except json.JSONDecodeError:
                return {"state": "unavailable", "reason": "runtime-response-invalid"}
        log_outputs = []
        for selector in (
            f"_UID={account.pw_uid}", "CONTAINER_NAME=jupyterhub",
        ), (
            f"_UID={account.pw_uid}", "_SYSTEMD_USER_UNIT=webservices-jupyterhub.service",
        ):
            journal = run("journalctl", "--no-pager", "-n", "300", *selector, check=False)
            if journal.returncode == 0 and journal.stdout:
                log_outputs.append(journal.stdout)
        app_logs = run(
            "podman", "--remote", "--url", f"unix://{runtime}/podman/podman.sock",
            "logs", "--tail", "300", "jupyterhub", check=False,
        )
        app_log_state = "unavailable" if app_logs.returncode else (
            "available" if (app_logs.stdout or app_logs.stderr).strip() else "empty"
        )
        if app_logs.returncode == 0:
            log_outputs.extend((app_logs.stdout or "", app_logs.stderr or ""))
        signals = jupyterhub_log_signals("\n".join(log_outputs))
        return {"state": "reported", "authorityContainers": len(containers),
                "userServers": counts,
                "notebookImage": image_state, "notebookNetwork": network_state,
                "applicationLogState": app_log_state,
                "runtimeSignals": signals}
    except (OSError, KeyError, TypeError, ValueError):
        return {"state": "unavailable", "reason": "broker-query-error"}


def jupyterhub_log_signals(log_text: str) -> list[str]:
    """Classify selected runtime errors; never return journal text or identifiers."""
    normalized = log_text.lower()
    markers = {
        "spawner-error": ("error spawning", "spawn failed", "failed to start server"),
        "runtime-socket-error": ("podman socket", "docker socket", "connection refused"),
        "image-availability-error": ("image not found", "manifest unknown", "pull access denied"),
        "volume-permission-error": ("permission denied", "operation not permitted"),
        "spawn-timeout": ("timed out", "timeout while"),
    }
    return sorted(label for label, phrases in markers.items()
                  if any(phrase in normalized for phrase in phrases))


def test_suite(request: dict[str, object]) -> dict[str, object]:
    suite = str(request.get("suite", ""))
    if suite not in SAFE_TEST_SUITES:
        raise RequestError("suite is not in the synthetic-data test allowlist")
    script = TEST_RUNNER_CURRENT / "build/stack.containers/test-runner/run-tests.sh"
    if not script.is_file():
        raise RequestError("deployed test runner is unavailable")
    identifier = hashlib.sha256(f"test:{suite}:{time.time_ns()}".encode()).hexdigest()[:32]
    operation = {"id": identifier, "kind": "test", "state": "queued", "phase": "queued",
                 "suite": suite, "createdAt": int(time.time()), "evidencePolicy": "status-only"}
    write_record(operation)
    try:
        unit = f"platform-zero-operation-{identifier}"
        run("systemd-run", "--quiet", "--collect", "--no-block", "--unit", unit,
            "/usr/local/libexec/p0-host-broker", "--test-worker", identifier)
    except Exception as error:
        operation.update({"state": "failed", "phase": "enqueue", "finishedAt": int(time.time()),
                          "error": scrub(str(error))})
        write_record(operation)
        raise RequestError("could not queue durable test operation")
    return operation


def test_runner_account() -> tuple[str, str, int]:
    domains = json.loads(DOMAINS_MANIFEST.read_text()).get("domains", [])
    item = next((entry for entry in domains if entry.get("name") == "test-runners"), None)
    if not item or item.get("user") != TEST_RUNNER_USER:
        raise RequestError("test-runner authority mapping is invalid")
    account = pwd.getpwnam(TEST_RUNNER_USER)
    return TEST_RUNNER_USER, account.pw_dir, account.pw_uid


def summarize_test_output(output: str) -> dict[str, object] | None:
    """Project Playwright output onto counts and source locations only."""
    import re

    plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    counters: dict[str, int] = {}
    for field in ("passed", "failed", "skipped", "timed out"):
        matches = re.findall(rf"\b(\d+)\s+{re.escape(field)}\b", plain, flags=re.IGNORECASE)
        if matches:
            counters[field.replace(" ", "") if field == "timed out" else field] = int(matches[-1])
    failures = []
    failure_pattern = re.compile(
        r"(?m)^\s*\d+\)\s+\[[^\]\r\n]+\]\s+›\s+"
        r"(tests/[A-Za-z0-9_./-]+\.spec\.ts)(?::(\d+))?(?::\d+)?"
        r"(?:\s+›\s+[^\r\n›]{1,180})*\s+›\s+([A-Za-z0-9][A-Za-z0-9 ._-]{0,119})\s*$"
    )
    for match in failure_pattern.finditer(plain):
        failures.append({
            "spec": match.group(1),
            "line": int(match.group(2)) if match.group(2) else None,
            "testName": match.group(3).strip(),
        })
    failures = sorted({(item["spec"], item["line"], item["testName"]) for item in failures})
    # Reduce each Playwright failure block to a fixed route and diagnostic label.
    # The block itself is never returned: it can contain credentials or page data.
    failure_diagnostics = []
    headings = list(failure_pattern.finditer(plain))
    for index, heading in enumerate(headings):
        block_end = headings[index + 1].start() if index + 1 < len(headings) else len(plain)
        block = plain[heading.end():block_end].lower()
        spec = heading.group(1).lower()
        test_name = heading.group(3).lower()
        route = "jupyterhub" if "jupyterhub" in spec or "jupyterhub" in test_name else (
            "huly" if "huly" in spec or "huly" in test_name else None
        )
        category = None
        if "navigation timeout" in block or "goto: timeout" in block:
            category = "navigation-timeout"
        elif "waiting for locator" in block or "waiting for selector" in block:
            category = "selector-timeout"
        elif "waiting for expect(" in block:
            category = "assertion-timeout"
        elif "timeout" in block:
            category = "playwright-timeout"
        elif "net::err_" in block or "requestfailed" in block:
            category = "browser-request-error"
        if route and category:
            failure_diagnostics.append({"route": route, "category": category})
    failure_diagnostics = sorted({(item["route"], item["category"])
                                  for item in failure_diagnostics})
    failure_kinds = []
    for marker, kind in (
        ("authenticated page did not satisfy smoke contract", "smoke-contract"),
        ("visual anchor must finish painting", "visual-anchor"),
        ("screenshot failed its pixel contract", "screenshot-pixel-contract"),
        ("screenshot capture did not produce image data", "screenshot-capture"),
        ("Timeout", "playwright-timeout"),
    ):
        if marker.casefold() in plain.casefold():
            failure_kinds.append(kind)
    if failures and not failure_kinds:
        failure_kinds.append("assertion")
    readiness_matches = re.findall(
        r"\[p0-test-evidence\]\s+smoke-readiness=(empty-page|start-required|spawn-pending|"
        r"service-unavailable|authorization|disallowed-url|disallowed-content|"
        r"expected-content-missing|selector-missing|unclassified)"
        r"(?:\s+route=([a-z0-9-]{1,64}))?",
        plain,
    )
    readiness_states = sorted({state for state, _route in readiness_matches})
    readiness_by_route = {
        route: sorted({state for state, matched_route in readiness_matches if matched_route == route})
        for route in sorted({route for _state, route in readiness_matches if route})
    }
    stage_matches = re.findall(
        r"\[p0-test-evidence\]\s+jupyterhub-prepare=(prepare-started|"
        r"redirect-(?:spawn-pending|user-server|hub-home|hub-login|other)|redirect-failed|"
        r"start-button-visible|start-button-absent|start-click-succeeded|start-click-failed|"
        r"start-transition-(?:spawn-pending|user-server)|start-transition-timeout|"
        r"home-server-link-click-succeeded|home-server-link-click-failed|home-server-link-absent|"
        r"home-redirect-(?:spawn-pending|user-server|hub-home|hub-login|other)|home-redirect-failed|"
        r"user-server-ready|user-server-timeout-(?:spawn-pending|user-server|hub-home|hub-login|other))"
        r"\s+route=jupyterhub\b",
        plain,
    )
    huly_stage_matches = re.findall(
        r"\[p0-test-evidence\]\s+huly-prepare=(prepare-started|"
        r"initial-(?:workspace-visible|service-error|signup-shell|login-shell|empty-shell|other-shell|"
        r"ui-(?:error|loading|auth-copy|workspace-copy|product-shell|other|empty)|"
        r"fields-(?:credentials|email|password|other|none))|"
        r"password-input-(?:visible|absent)|login-button-(?:visible|absent)|login-clicked|"
        r"login-form-(?:ready|timeout)|login-credentials-filled|login-submit-(?:started|clicked)|"
        r"signup-button-(?:visible|absent)|signup-clicked|signup-form-ready|"
        r"signup-credentials-filled|signup-submit-(?:started|clicked)|"
        r"keycloak-password-absent|accounts-providers-(?:network-error|5xx|4xx|2xx|other)|"
        r"openid-provider-(?:present|absent|unavailable)|"
        r"openid-callback-http-(?:unobserved|5xx|4xx|3xx|2xx|other)|"
        r"openid-start-http-(?:unobserved|5xx|4xx|3xx|2xx|other)|"
        r"post-auth-location-(?:keycloak|auth-gateway|account-callback|account-auth|account-api|app-login|app-root|huly-front|other)|"
        r"openid-flow-(?:entry-missing|redirect-missing|timeout|other)|"
        r"post-submit-ui-(?:invalid-credentials|email-verification|workspace-selection|"
        r"verification-challenge|service-error|loading|auth-required|other|empty)|"
        r"workspace-(?:ready|timeout))\s+route=huly\b",
        plain,
    )
    readiness_stages_by_route = {}
    if stage_matches:
        readiness_stages_by_route["jupyterhub"] = sorted(set(stage_matches))
    if huly_stage_matches:
        readiness_stages_by_route["huly"] = sorted(set(huly_stage_matches))
    if not counters and not failures and not failure_kinds and not readiness_states and not stage_matches and not huly_stage_matches:
        return None
    return {
        "counts": counters,
        "failures": [
            {"spec": spec, "line": line, "testName": test_name}
            for spec, line, test_name in failures[:20]
        ],
        "failureKinds": failure_kinds,
        "failureDiagnostics": [
            {"route": route, "category": category}
            for route, category in failure_diagnostics[:20]
        ],
        "readinessStates": readiness_states,
        "readinessByRoute": readiness_by_route,
        "readinessStagesByRoute": readiness_stages_by_route,
    }


def classify_test_failure(output: str) -> dict[str, object]:
    """Return only fixed test-runner failure labels and source line numbers."""
    import re

    failure = re.search(r"\[test-runner\] command failed at line=(\d+) status=(\d+)", output)
    if failure is None:
        return {"kind": "suite-exit"}
    normalized = output.lower()
    for phrases, kind in (
        (("managed podman socket is unavailable", "launch podman socket is unavailable"), "runner-runtime-unavailable"),
        (("permission denied", "operation not permitted"), "runner-permission-denied"),
        (("manifest unknown", "pull access denied", "image not known", "no such image"), "runner-image-unavailable"),
        (("no generated rootless podman networks", "network not found", "network does not exist"), "runner-network-unavailable"),
        (("connection refused", "cannot connect", "failed to connect"), "runner-runtime-connection-failed"),
        (("no such file or directory", "command not found"), "runner-dependency-unavailable"),
    ):
        if any(phrase in normalized for phrase in phrases):
            return {"kind": kind, "line": int(failure.group(1))}
    return {"kind": "runner-command", "line": int(failure.group(1))}


def run_test_operation(operation_id: str) -> dict[str, object]:
    with locked_record(operation_id):
        operation = read_record(operation_id)
        if operation.get("kind") != "test" or operation.get("state") != "queued":
            raise RequestError("test operation is not queued")
        suite = str(operation.get("suite", ""))
        if suite not in SAFE_TEST_SUITES:
            raise RequestError("recorded suite is not allowed")
        operation.update({"state": "running", "phase": "execution", "startedAt": int(time.time())})
        write_record(operation)
    script = TEST_RUNNER_CURRENT / "build/stack.containers/test-runner/run-tests.sh"
    try:
        user, home, uid = test_runner_account()
    except (RequestError, ValueError, OSError, KeyError):
        operation.update({"state": "failed", "phase": "complete", "exitCode": 126,
                          "finishedAt": int(time.time()),
                          "failureStage": {"kind": "authority-mapping"}})
        write_record(operation)
        return operation
    runtime = f"/run/user/{uid}"
    runner_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": home,
        "XDG_CONFIG_HOME": f"{home}/.config",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
        "WEBSERVICES_ROOTLESS_USER": user,
        "WEBSERVICES_ROOTLESS_STATE_ROOT": "/mnt/stack/podman/test-runners/state",
        "TEST_RUNNER_STATE_ROOT": "/mnt/stack/podman/test-runners/state/test-runner",
        "TEST_RUNNER_NETWORK_MODE": "isolated",
    }
    command = ["/usr/sbin/runuser", "-u", user, "--", "env"]
    command.extend(f"{key}={value}" for key, value in runner_env.items())
    focused_route = {
        "ts-e2e-huly": "Huly snapshot",
        "ts-e2e-jupyterhub": "JupyterHub snapshot",
    }.get(suite)
    command.extend((str(script), "ts-e2e-name", focused_route) if focused_route else (str(script), suite))
    worker_env = {"PATH": runner_env["PATH"], "HOME": "/root", "XDG_CONFIG_HOME": "/root/.config"}
    try:
        completed = subprocess.run(command, cwd=str(TEST_RUNNER_CURRENT), env=worker_env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, check=False,
                                   timeout=TEST_SUITE_TIMEOUT_SECONDS.get(suite, 900))
        operation.update({"state": "succeeded" if completed.returncode == 0 else "failed",
                          "phase": "complete", "exitCode": completed.returncode,
                          "finishedAt": int(time.time())})
        test_summary = summarize_test_output(completed.stdout or "")
        if test_summary is not None:
            operation["testSummary"] = test_summary
        if completed.returncode:
            output = completed.stdout or ""
            if "could not locate the repository root" in output:
                operation["failureStage"] = {"kind": "repository-root"}
            else:
                operation["failureStage"] = classify_test_failure(output)
    except subprocess.TimeoutExpired as error:
        partial_output = error.stdout or error.output or ""
        if isinstance(partial_output, bytes):
            partial_output = partial_output.decode("utf-8", errors="replace")
        operation.update({"state": "failed", "phase": "complete", "exitCode": 124,
                          "finishedAt": int(time.time()),
                          "failureStage": {"kind": "execution-timeout"}})
        test_summary = summarize_test_output(str(partial_output))
        if test_summary is not None:
            operation["testSummary"] = test_summary
    except OSError:
        operation.update({"state": "failed", "phase": "complete", "exitCode": 127,
                          "finishedAt": int(time.time()), "error": "test runner could not start"})
    write_record(operation)
    return operation


def diagnostics(request: dict[str, object]) -> dict[str, object]:
    result = status({})
    active_record = json.loads(ACTIVE_RELEASE.read_text()) if ACTIVE_RELEASE.is_file() else {}
    active = active_record.get("release")
    result["activeRelease"] = active
    result["operations"] = sorted((path.name.removesuffix(".json") for path in OPERATIONS.glob("*.json")), reverse=True)[:20] if OPERATIONS.is_dir() else []
    result["evidencePolicy"] = {"secrets": "redacted", "applicationPayloads": "withheld", "logs": "scrubbed"}
    podman = run("podman", "--version", check=False)
    systemd = run("systemctl", "--version", check=False)
    result["versions"] = {
        "podman": podman.stdout.splitlines()[0] if podman.stdout else "unavailable",
        "systemd": systemd.stdout.splitlines()[0] if systemd.stdout else "unavailable",
        "kernel": os.uname().release,
    }
    disks = {}
    for name, path in (("root", Path("/")), ("stackStorage", Path("/mnt/stack")), ("stackWorkspace", STACK_ROOT)):
        try:
            usage = shutil.disk_usage(path)
            disks[name] = {"totalBytes": usage.total, "freeBytes": usage.free, "usedPercent": round((usage.used / usage.total) * 100, 1)}
        except OSError:
            disks[name] = {"state": "unavailable"}
    try:
        memory = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, raw = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                memory[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        memory = {}
    result["resources"] = {"disks": disks, "memoryBytes": memory}
    drift = []
    expected_releases = active_record.get("authorities", {})
    if active and not expected_releases:
        expected_releases = {"rootful": active}
        if DOMAINS_MANIFEST.is_file():
            expected_releases.update({item["name"]: active for item in json.loads(DOMAINS_MANIFEST.read_text()).get("domains", [])})
    checks = [("rootful", ROOTFUL_RELEASES.parent / "current")]
    if DOMAINS_MANIFEST.is_file():
        for item in json.loads(DOMAINS_MANIFEST.read_text()).get("domains", []):
            checks.append((item["name"], Path(item["stateRoot"]) / "current"))
    for authority, current in checks:
        marker = current.resolve() / ".platform-zero-release" if current.is_symlink() else None
        deployed = marker.read_text().strip() if marker and marker.is_file() else None
        expected = expected_releases.get(authority)
        if expected is None or deployed != expected:
            drift.append({"authority": authority, "expectedRelease": expected, "deployedRelease": deployed})
    result["drift"] = {"state": "clean" if not drift else "drifted", "authorities": drift}
    result["migrationStatus"] = {"state": "not-reported", "pending": []}
    result["testResults"] = {"state": "reported-by-test-runner", "authority": "test-runners"}
    return result


def rollback(request: dict[str, object]) -> dict[str, object]:
    record = read_record(str(request.get("operation_id", request.get("plan_id", ""))))
    release = record.get("scope", {}).get("previousRelease")
    if not release:
        raise RequestError("no previous configuration release is recorded")
    authorities = record.get("scope", {}).get("affectedAuthorities", [])
    if not authorities:
        raise RequestError("the recorded operation has no deployment scope")
    active = json.loads(ACTIVE_RELEASE.read_text()).get("release") if ACTIVE_RELEASE.is_file() else None
    operation_id = hashlib.sha256(f"rollback:{record['id']}:{time.time_ns()}".encode()).hexdigest()[:32]
    operation = {"id": operation_id, "kind": "operation", "state": "queued", "phase": "queued",
                 "planId": record.get("planId", record.get("id")), "release": release,
                 "scope": {**record.get("scope", {}), "previousRelease": active},
                 "rollbackOf": record["id"], "createdAt": int(time.time()),
                 "applicationDataRollback": False}
    return enqueue_operation(operation)


def break_glass_request(request: dict[str, object]) -> dict[str, object]:
    service = str(request.get("service", ""))
    reason = str(request.get("reason", ""))
    ttl = int(request.get("ttl_seconds", 900) or 900)
    if not service or not reason or ttl < 60 or ttl > 3600:
        raise RequestError("break-glass requires service, reason, and a TTL between 60 and 3600 seconds")
    identifier = hashlib.sha256(f"{service}:{reason}:{time.time_ns()}".encode()).hexdigest()[:32]
    record = {"id": identifier, "kind": "break-glass", "state": "pending-gerald-approval", "service": service,
              "reason": scrub(reason), "requestedAt": int(time.time()), "expiresAt": int(time.time()) + ttl,
              "access": "read-only", "approvedBy": None}
    BREAK_GLASS.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = BREAK_GLASS / f"{identifier}.json"
    path.write_text(json.dumps(record, sort_keys=True) + "\n")
    path.chmod(0o600)
    return record


def approve_break_glass(request: dict[str, object], peer_uid: int) -> dict[str, object]:
    gerald_uid = pwd.getpwnam("gerald").pw_uid
    if peer_uid != gerald_uid:
        raise RequestError("break-glass approval must be submitted directly by Gerald")
    identifier = str(request.get("request_id", ""))
    if not identifier or "/" in identifier or ".." in identifier:
        raise RequestError("invalid break-glass request ID")
    path = BREAK_GLASS / f"{identifier}.json"
    if not path.is_file():
        raise RequestError("break-glass request not found")
    record = json.loads(path.read_text())
    if record.get("state") != "pending-gerald-approval":
        raise RequestError("break-glass request is not pending")
    if int(record.get("expiresAt", 0)) <= int(time.time()):
        record["state"] = "expired"
        path.write_text(json.dumps(record, sort_keys=True) + "\n")
        raise RequestError("break-glass request has expired")
    record.update({"state": "approved", "approvedBy": "gerald", "approvedAt": int(time.time())})
    path.write_text(json.dumps(record, sort_keys=True) + "\n")
    return record


def service_volume_roots(bundle: Path, service_name: str) -> list[Path]:
    ir = json.loads((bundle / "stack.ir.json").read_text())
    service = ir.get("services", {}).get(service_name)
    if not isinstance(service, dict):
        raise RequestError("unknown service in active release")
    domains = {item["name"]: item for item in json.loads((bundle / "podman-domains.json").read_text()).get("domains", [])}
    domain = str(service.get("rootlessDomain", "")) if service.get("placement") == "rootless" else ""
    roots: set[Path] = set()
    for mount in service.get("volumes", []):
        name = mount.split(":", 1)[0] if isinstance(mount, str) else str(mount.get("source", ""))
        if not name or name.startswith("./"):
            continue
        volume = ir.get("volumes", {}).get(name)
        if not isinstance(volume, dict):
            continue
        host_path = str(volume.get("hostPath", ""))
        if domain:
            domain_record = domains.get(domain)
            if not domain_record:
                raise RequestError("service authority is absent from the active domain manifest")
            root = (Path(host_path) if volume.get("rootlessStrategy") == "shared" and host_path
                    else Path(str(domain_record["volumeRoot"])) / name)
        elif host_path:
            root = Path(host_path)
        else:
            continue
        if root.is_absolute():
            roots.add(root)
    if service_name == "test-runner-managed":
        try:
            results_mode = TEST_RUNNER_RESULTS.lstat().st_mode
        except FileNotFoundError:
            results_mode = 0
        if stat.S_ISDIR(results_mode):
            roots.add(TEST_RUNNER_RESULTS)
    return sorted(roots)


def read_break_glass(request: dict[str, object], peer_uid: int) -> dict[str, object]:
    identifier = str(request.get("request_id", ""))
    relative = str(request.get("path", ""))
    if not identifier or "/" in identifier or ".." in identifier:
        raise RequestError("invalid break-glass request ID")
    relative_path = Path(relative)
    if not relative or relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
        raise RequestError("break-glass read requires a normalized path relative to a service volume")
    record_path = BREAK_GLASS / f"{identifier}.json"
    if not record_path.is_file():
        raise RequestError("break-glass request not found")
    record = json.loads(record_path.read_text())
    now = int(time.time())
    if record.get("state") != "approved" or int(record.get("expiresAt", 0)) <= now:
        raise RequestError("break-glass grant is not approved or has expired")
    if ACTIVE_RELEASE.is_file():
        try:
            bundle = release_path({"release": json.loads(ACTIVE_RELEASE.read_text()).get("release")})
        except (RequestError, TypeError, ValueError):
            bundle = None
    else:
        bundle = None
    if bundle is None:
        raise RequestError("active release is unavailable")

    components = list(relative_path.parts)
    data = None
    opened: list[int] = []
    selected_path = None
    try:
        for root in service_volume_roots(bundle, str(record.get("service", ""))):
            descriptor = os.open(root.resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened.append(descriptor)
            try:
                for component in components[:-1]:
                    descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    opened.append(descriptor)
                file_descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                opened.append(file_descriptor)
                metadata = os.fstat(file_descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise RequestError("break-glass reads are limited to regular files")
                if metadata.st_size > 256 * 1024:
                    raise RequestError("break-glass read exceeds the 256 KiB limit")
                with os.fdopen(os.dup(file_descriptor), "rb") as stream:
                    data = stream.read(256 * 1024 + 1)
                if len(data) > 256 * 1024:
                    raise RequestError("break-glass read exceeds the 256 KiB limit")
                selected_path = str(root / relative_path)
                break
            except FileNotFoundError:
                continue
        if data is None or selected_path is None:
            raise RequestError("path is not present in a volume owned by the approved service")
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass

    BREAK_GLASS.mkdir(mode=0o700, parents=True, exist_ok=True)
    audit_path = BREAK_GLASS / "audit.jsonl"
    audit_fd = os.open(audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchmod(audit_fd, 0o600)
    with os.fdopen(audit_fd, "a", encoding="utf-8") as audit:
        audit.write(json.dumps({"at": now, "requestId": identifier, "service": record["service"],
                                "relativePath": relative, "bytes": len(data),
                                "sha256": hashlib.sha256(data).hexdigest(), "peerUid": peer_uid}) + "\n")
    return {"requestId": identifier, "service": record["service"], "path": relative,
            "bytes": len(data), "encoding": "base64", "content": base64.b64encode(data).decode("ascii"),
            "expiresAt": record["expiresAt"]}


def user_systemctl(user: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    record = pwd.getpwnam(user)
    return run(
        "/usr/sbin/runuser", "-u", user, "--", "env",
        f"HOME={record.pw_dir}", f"XDG_RUNTIME_DIR=/run/user/{record.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{record.pw_uid}/bus",
        "systemctl", "--user", *args, check=check,
    )


def stop_legacy_runtime() -> None:
    try:
        user_systemctl(LEGACY_USER, "stop", "webservices.target", check=False)
    except KeyError:
        # The legacy account is intentionally absent after modular cutover.
        return


def preflight(request: dict[str, object]) -> dict[str, object]:
    path = release_path(request)
    run("nft", "-c", "-f", str(path / "ops/platform-zero.nft"))
    with tempfile.TemporaryDirectory(prefix="p0-preflight-") as temporary:
        working = Path(temporary) / "bundle"
        shutil.copytree(path, working)
        installer_release = str(request.get("installer_release", path.name))
        installer_bundle = release_path({"release": installer_release})
        installer = installer_bundle / "ops/install-podman-bundle.sh"
        if not installer.is_file():
            raise RequestError("compatible deployment installer is unavailable")
        shutil.copy2(installer, working / "ops/install-podman-bundle.sh")
        args = [str(working / "ops/install-podman-bundle.sh"), "--bundle", str(working)]
        authorities = request.get("authorities")
        if isinstance(authorities, list) and authorities:
            args.extend(("--authorities", ",".join(str(item) for item in authorities)))
        result = run(*args)
    return {"release": path.name, "output": result.stdout[-8000:]}


def apply_platform_zero_nftables(rules: Path) -> None:
    """Atomically replace the managed table instead of appending to it."""
    existing = run("nft", "list", "table", "inet", "platform_zero", check=False)
    if existing.returncode:
        run("nft", "-f", str(rules))
        return
    with tempfile.NamedTemporaryFile("w", prefix="p0-nft-", suffix=".nft", delete=False) as stream:
        stream.write("delete table inet platform_zero\n")
        stream.write(rules.read_text())
        candidate = Path(stream.name)
    try:
        run("nft", "-f", str(candidate))
    finally:
        candidate.unlink(missing_ok=True)


def snapshot(_: dict[str, object]) -> dict[str, object]:
    require_gerald_approval(_, "snapshot")
    snapshot_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    destination = SNAPSHOTS / snapshot_id
    if destination.exists():
        raise RequestError("snapshot identifier collision")
    destination.mkdir(mode=0o700, parents=True)
    previous = next((path for path in sorted(SNAPSHOTS.iterdir(), reverse=True) if path.is_dir() and path != destination), None)
    sources = (
        Path("/mnt/stack/rootless"),
        Path("/mnt/stack/volumes"),
        Path("/mnt/stack/vector-dbs"),
        Path("/mnt/stack/pg-ssd"),
        Path("/var/lib/webservices"),
        Path("/etc/containers/systemd"),
    )
    for source in sources:
        if source.exists():
            target = destination / source.relative_to("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            args = ["rsync", "-aHAX", "--numeric-ids"]
            if previous is not None and (previous / source.relative_to("/")).is_dir():
                args.append(f"--link-dest={previous / source.relative_to('/')}" )
            run(*args, f"{source}/", f"{target}/")
    ruleset = run("nft", "list", "ruleset", check=False)
    if ruleset.returncode == 0 and ruleset.stdout:
        (destination / "nftables.conf").write_text(ruleset.stdout)
    return {"snapshot": snapshot_id, "path": str(destination)}


def snapshot_path(request: dict[str, object]) -> Path:
    snapshot_id = str(request.get("snapshot", ""))
    if len(snapshot_id) != 16 or not snapshot_id.endswith("Z") or not snapshot_id[:-1].replace("T", "").isdigit():
        raise RequestError("invalid snapshot identifier")
    path = SNAPSHOTS / snapshot_id
    if not path.is_dir() or path.parent != SNAPSHOTS:
        raise RequestError("snapshot does not exist")
    return path


def restore(request: dict[str, object]) -> dict[str, object]:
    require_gerald_approval(request, "restore")
    if request.get("confirm") != "RESTORE_PLATFORM_ZERO":
        raise RequestError("restore requires --confirm RESTORE_PLATFORM_ZERO")
    source = snapshot_path(request)
    run("systemctl", "stop", "webservices.target", check=False)
    if DOMAINS_MANIFEST.is_file():
        for item in json.loads(DOMAINS_MANIFEST.read_text()).get("domains", []):
            user_systemctl(item["user"], "stop", "webservices.target", check=False)
    for destination in (
        Path("/mnt/stack/rootless"),
        Path("/mnt/stack/volumes"),
        Path("/mnt/stack/vector-dbs"),
        Path("/mnt/stack/pg-ssd"),
        Path("/var/lib/webservices"),
        Path("/etc/containers/systemd"),
    ):
        saved = source / destination.relative_to("/")
        if saved.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            run("rsync", "-aHAX", "--numeric-ids", "--delete", f"{saved}/", f"{destination}/")
    if (source / "nftables.conf").is_file():
        run("nft", "-f", str(source / "nftables.conf"))
    run("systemctl", "daemon-reload")
    return {"snapshot": source.name, "restored": True}


def finalize_access(request: dict[str, object]) -> dict[str, object]:
    require_gerald_approval(request, "finalize-access")
    if request.get("confirm") != "REMOVE_GERALD_NOPASSWD":
        raise RequestError("access finalization requires --confirm REMOVE_GERALD_NOPASSWD")
    changed = []
    if GERALD_DROPIN.exists():
        GERALD_DROPIN.unlink()
        changed.append(str(GERALD_DROPIN))
    if SUDOERS.is_file():
        original = SUDOERS.read_text()
        filtered = "\n".join(
            line for line in original.splitlines()
            if not ("gerald" in line and "NOPASSWD" in line)
        ) + "\n"
        if filtered != original:
            with tempfile.NamedTemporaryFile("w", dir=SUDOERS.parent, delete=False) as stream:
                stream.write(filtered)
                candidate = Path(stream.name)
            candidate.chmod(0o440)
            try:
                run("visudo", "-cf", str(candidate))
                os.replace(candidate, SUDOERS)
            finally:
                candidate.unlink(missing_ok=True)
            changed.append(str(SUDOERS))
    run("visudo", "-cf", str(SUDOERS))
    return {"changed": changed, "geraldNopasswdRemoved": True}


def activate(request: dict[str, object]) -> dict[str, object]:
    path = release_path(request)
    installer_release = str(request.get("installer_release", path.name))
    installer_bundle = release_path({"release": installer_release})
    installer_source = installer_bundle / "ops/install-podman-bundle.sh"
    if not installer_source.is_file():
        raise RequestError("compatible deployment installer is unavailable")
    preflight({**request, "installer_release": installer_release})
    scope = request.get("authorities")
    authorities = [str(item) for item in scope] if isinstance(scope, list) else []
    if not authorities:
        raise RequestError("activation requires a non-empty authority scope")
    current_release = None
    if ACTIVE_RELEASE.is_file():
        try:
            current_release = release_path({"release": json.loads(ACTIVE_RELEASE.read_text()).get("release")})
        except (RequestError, TypeError, ValueError):
            current_release = None
    nft_changed = current_release is None or (current_release / "ops/platform-zero.nft").read_bytes() != (path / "ops/platform-zero.nft").read_bytes()
    if nft_changed:
        apply_platform_zero_nftables(path / "ops/platform-zero.nft")
    stop_legacy_runtime()
    env = os.environ.copy()
    env.setdefault("HOME", "/root")
    env.setdefault("XDG_CONFIG_HOME", "/root/.config")
    # The durable operation worker owns rollback. Avoid a second full restart
    # from the installer's legacy in-process rollback handler.
    env["WEBSERVICES_ACTIVATION_ROLLBACK"] = "0"
    with tempfile.TemporaryDirectory(prefix="p0-activate-") as temporary:
        working = Path(temporary) / "bundle"
        shutil.copytree(path, working)
        shutil.copy2(installer_source, working / "ops/install-podman-bundle.sh")
        command = [str(working / "ops/install-podman-bundle.sh"), "--bundle", str(working),
                   "--authorities", ",".join(authorities), "--candidate-release", path.name, "--activate"]
        result = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
    if result.returncode:
        if nft_changed and current_release is not None:
            try:
                apply_platform_zero_nftables(current_release / "ops/platform-zero.nft")
            except Exception as nft_error:
                raise RequestError("activation failed and nftables rollback failed: " + scrub(str(nft_error)))
        details = scrub(result.stdout + "\n" + result.stderr)
        raise RequestError(f"activation failed ({result.returncode}); durable broker rollback will be attempted\n{details}")
    active_record = {}
    if ACTIVE_RELEASE.is_file():
        try:
            active_record = json.loads(ACTIVE_RELEASE.read_text())
        except (ValueError, OSError):
            active_record = {}
    authority_releases = dict(active_record.get("authorities", {}))
    for authority in authorities:
        authority_releases[authority] = path.name
    ACTIVE_RELEASE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = ACTIVE_RELEASE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"release": path.name, "authorities": authority_releases,
                                     "activatedAt": int(time.time())}) + "\n")
    temporary.chmod(0o600)
    os.replace(temporary, ACTIVE_RELEASE)
    return {"release": path.name, "output": scrub(result.stdout[-8000:])}


def scope_health(user: str | None, expected: list[str] | None = None) -> dict[str, object]:
    ctl = ((lambda *args, check=True: user_systemctl(user, *args, check=check)) if user else
           (lambda *args, check=True: run("systemctl", *args, check=check)))
    target_state = ctl("is-active", "webservices.target", check=False).stdout.strip()
    dependencies = ctl("list-dependencies", "--plain", "--all", "webservices.target", check=False)
    units = sorted({line.strip().lstrip("●○ ") for line in dependencies.stdout.splitlines()
                    if line.strip().lstrip("●○ ").startswith("webservices-")
                    and line.strip().lstrip("●○ ").endswith(".service")})
    offenders = []
    restart_counts = {}
    for unit in units:
        details = ctl("show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "Type", "-p", "Result", "-p", "Job", "-p", "NRestarts", check=False)
        values = dict(line.split("=", 1) for line in details.stdout.splitlines() if "=" in line)
        completed_oneshot = (values.get("Type") == "oneshot" and values.get("ActiveState") == "inactive"
                             and values.get("Result") == "success" and not values.get("Job"))
        if not completed_oneshot and (values.get("ActiveState") != "active" or values.get("Result") not in {"", "success"} or values.get("Job")):
            offenders.append({"unit": unit, **values})
        if int(values.get("NRestarts", "0") or "0"):
            restart_counts[unit] = int(values["NRestarts"])
    for service in expected or []:
        unit = f"webservices-{service}.service"
        if unit not in units:
            offenders.append({"unit": unit, "reason": "missing-persistent-unit"})
    state = target_state if target_state != "active" or not offenders else "degraded"
    return {"state": state, "targetState": target_state, "offenders": offenders, "restartCounts": restart_counts}


def status(_: dict[str, object]) -> dict[str, object]:
    rootful = scope_health(None)
    result: dict[str, object] = {"rootful": rootful["state"], "rootfulHealth": rootful}
    domains_file = DOMAINS_MANIFEST if DOMAINS_MANIFEST.is_file() else None
    if domains_file is None and INCOMING.exists():
        domains_file = next((path / "podman-domains.json" for path in sorted(INCOMING.iterdir(), reverse=True) if len(path.name) == 64 and path.is_dir()), None)
    domains = []
    if domains_file and domains_file.is_file():
        for item in json.loads(domains_file.read_text()).get("domains", []):
            health = scope_health(item["user"], item.get("persistentServices", []))
            domains.append({"name": item["name"], "user": item["user"], **health})
    result["domains"] = domains
    return result


def verify(request: dict[str, object]) -> dict[str, object]:
    path = release_path(request)
    preflight(request)
    current = status({})
    inactive = [item["name"] for item in current["domains"] if item["state"] != "active"]
    if current["rootful"] != "active" or inactive:
        raise RequestError(f"inactive Platform Zero targets: rootful={current['rootful']} domains={inactive}")
    release_drift = diagnostics({})["drift"]
    if release_drift["state"] != "clean":
        raise RequestError("runtime authority release drift: " + json.dumps(release_drift["authorities"], sort_keys=True))
    return current


def garbage_collect(request: dict[str, object]) -> dict[str, object]:
    dry_run = bool(request.get("dry_run", False))
    active = None
    if ACTIVE_RELEASE.is_file():
        active = json.loads(ACTIVE_RELEASE.read_text()).get("release")
    removals: list[str] = []

    def prune_directories(root: Path, keep: int, protected: set[Path] | None = None) -> None:
        protected = protected or set()
        if not root.is_dir():
            return
        directories = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
        retained = set(directories[:keep]) | protected
        for path in directories:
            if path not in retained:
                removals.append(str(path))
                if not dry_run:
                    shutil.rmtree(path)

    prune_directories(SNAPSHOTS, SNAPSHOT_RETENTION)
    release_roots = [ROOTFUL_RELEASES]
    if DOMAINS_MANIFEST.is_file():
        for item in json.loads(DOMAINS_MANIFEST.read_text()).get("domains", []):
            release_roots.append(Path(item["stateRoot"]) / "releases")
    for root in release_roots:
        protected = set()
        current = root.parent / "current"
        if current.is_symlink():
            protected.add(current.resolve())
        prune_directories(root, RELEASE_RETENTION, protected)
    if INCOMING.is_dir():
        now = time.time()
        for path in INCOMING.iterdir():
            if path.is_dir() and path.name != active and not path.name.startswith(".stage-") and now - path.stat().st_mtime > INCOMING_MAX_AGE_SECONDS:
                removals.append(str(path))
                if not dry_run:
                    shutil.rmtree(path)
    return {"dryRun": dry_run, "removed": removals, "activeRelease": active}


def logs(request: dict[str, object]) -> dict[str, object]:
    unit = str(request.get("unit", ""))
    if not unit.startswith("webservices-") or not unit.endswith(".service") or "/" in unit:
        raise RequestError("logs requires a webservices-*.service unit")
    domain = str(request.get("domain", "rootful"))
    if domain == "rootful":
        result = run("journalctl", "-u", unit, "-n", "200", "--no-pager", check=False)
    else:
        path = release_path(request)
        entries = json.loads((path / "podman-domains.json").read_text()).get("domains", [])
        item = next((entry for entry in entries if entry["name"] == domain), None)
        if item is None:
            raise RequestError("unknown domain")
        result = user_systemctl(item["user"], "status", unit, "--no-pager", "-l", check=False)
        # Rootless Quadlet container output is recorded by journald under the
        # container name, not necessarily attached to the user unit's journal
        # stream. Read only this user's matching container records; the common
        # scrubber still gates everything returned to the caller.
        container = unit.removeprefix("webservices-").removesuffix(".service")
        uid = pwd.getpwnam(str(item["user"])).pw_uid
        journal = run(
            "journalctl", "--no-pager", "-n", "200",
            f"_UID={uid}", f"CONTAINER_NAME={container}", check=False,
        )
        if journal.stdout.strip():
            result.stdout += "\n" + journal.stdout
            result.stderr += journal.stderr
    return safe_log_evidence(result.stdout + result.stderr)


def safe_log_evidence(value: str) -> dict[str, object]:
    """Return only log lines with no apparent payload or credential material."""
    import re
    allowed = []
    suspicious = re.compile(
        r"(?i)(password|secret|token|cookie|authorization|private[_ -]?key|bearer\s|basic\s|"
        r"set-cookie|request body|response body|payload|@[^ ]+\.[a-z]{2,}|\{.*\}|\[.*\])"
    )
    for line in value.splitlines():
        if len(line) > 1200 or suspicious.search(line):
            continue
        allowed.append(line)
    if value and not allowed:
        return {"output": "", "scrubbed": True, "withheld": True}
    return {"output": "\n".join(allowed)[-8000:], "scrubbed": True, "withheld": False}


ACTIONS = {
    "plan": plan, "apply": apply_plan, "operation-status": operation_status,
    "diagnostics": diagnostics, "rollback": rollback, "break-glass-request": break_glass_request,
    "status": status, "verify": verify, "logs": logs,
    "test": test_suite,
}


def authorized_uid_ranges(user: str, subuid_file: Path = Path("/etc/subuid")) -> tuple[int, list[tuple[int, int]]]:
    direct = pwd.getpwnam(user).pw_uid
    ranges: list[tuple[int, int]] = []
    if subuid_file.exists():
        for raw in subuid_file.read_text().splitlines():
            fields = raw.split(":")
            if len(fields) == 3 and fields[0] == user:
                start, count = int(fields[1]), int(fields[2])
                ranges.append((start, start + count))
    return direct, ranges


def authorized_peer(uid: int, direct: int, subordinate: list[tuple[int, int]]) -> bool:
    return uid == direct or any(start <= uid < end for start, end in subordinate)


def handle(raw: bytes, peer_uid: int | None = None) -> dict[str, object]:
    try:
        request = json.loads(raw)
        if not isinstance(request, dict) or request.get("version") != 1:
            raise RequestError("request version must be 1")
        action = str(request.get("action", ""))
        if action == "break-glass-approve":
            if peer_uid is None:
                raise RequestError("break-glass approval requires an authenticated peer")
            return {"ok": True, "result": approve_break_glass(request, peer_uid)}
        if action == "break-glass-read":
            if peer_uid is None:
                raise RequestError("break-glass read requires an authenticated peer")
            return {"ok": True, "result": read_break_glass(request, peer_uid)}
        if action not in ACTIONS:
            raise RequestError(f"unsupported action: {action}")
        return {"ok": True, "result": ACTIONS[action](request)}
    except (RequestError, ValueError, OSError, KeyError) as error:
        return {"ok": False, "error": scrub(str(error))}


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        try:
            record = run_operation(sys.argv[2])
            sys.exit(0 if record["state"] == "succeeded" else 1)
        except Exception as error:
            print("p0-host-broker worker failed: " + scrub(str(error)), file=sys.stderr)
            sys.exit(1)
    if len(sys.argv) == 3 and sys.argv[1] == "--test-worker":
        try:
            record = run_test_operation(sys.argv[2])
            sys.exit(0 if record["state"] == "succeeded" else 1)
        except Exception as error:
            print("p0-host-broker test worker failed: " + scrub(str(error)), file=sys.stderr)
            sys.exit(1)
    expected_uid, subordinate_uids = authorized_uid_ranges("stack_lab")
    gerald_uid = pwd.getpwnam("gerald").pw_uid
    listener = socket.socket(fileno=SOCKET_FD)
    while True:
        connection, _ = listener.accept()
        with connection:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            raw = b""
            while b"\n" not in raw and len(raw) <= MAX_REQUEST:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                raw += chunk
            request_bytes = raw.split(b"\n", 1)[0]
            try:
                action = json.loads(request_bytes).get("action")
            except (ValueError, AttributeError):
                action = None
            authorized = authorized_peer(uid, expected_uid, subordinate_uids)
            if action == "break-glass-approve":
                authorized = uid == gerald_uid
            if not authorized:
                connection.sendall(json.dumps({"ok": False, "error": "unauthorized peer"}).encode() + b"\n")
                continue
            response = handle(request_bytes, uid) if len(raw) <= MAX_REQUEST else {"ok": False, "error": "request too large"}
            connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


if __name__ == "__main__":
    main()
