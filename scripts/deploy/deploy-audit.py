#!/usr/bin/env python3
"""Deployment validation and reporting helpers for webservices bundles."""

import argparse
import base64
import binascii
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


REQUIRED_SECRET_KEYS = [
    "BOOKSTACK_APP_KEY",
    "KOPIA_PASSWORD",
    "KOPIA_PROXY_AUTHORIZATION",
    "MASTODON_SECRET_KEY_BASE",
    "MASTODON_OTP_SECRET",
    "MASTODON_VAPID_PRIVATE_KEY",
    "MASTODON_VAPID_PUBLIC_KEY",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY",
    "OAUTH2_PROXY_CLIENT_SECRET",
    "OAUTH2_PROXY_COOKIE_SECRET",
    "TEST_RUNNER_OAUTH_SECRET",
    "MODEL_CONTEXT_PROXY_AUTH_SECRET",
    "INFERENCE_CONTROLLER_API_TOKEN",
    "GPU_ARBITER_API_TOKEN",
]

ALLOWED_HOST_BINDS = {
    "/",
    "/dev/disk",
    "/dev/disk/",
    "/etc/localtime",
    "/etc/timezone",
    "/proc",
    "/sys",
    "/var/log/webservices/caddy",
}

DEFAULT_OPTIONAL_VM_SERVICES = [
    "forgejo-runner",
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    content = path.read_text(encoding="utf-8")
    stripped = content.lstrip()
    if stripped.startswith("{"):
        raise ValueError(
            f"{path} looks like JSON/SOPS input; deploy audit requires the rendered runtime env file"
        )
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.replace("$$", "$")
    return values


def runtime_contract_config(bundle_root: Path, env_file: Path, project_name: str) -> dict:
    env = os.environ.copy()
    env["COMPOSE_PROJECT_NAME"] = project_name
    output = subprocess.check_output(
        [
            "podman",
            "compose",
            "--project-directory",
            str(bundle_root.parent),
            "--env-file",
            str(env_file),
            "-f",
            str(bundle_root / "runtime-contract.yml"),
            "config",
            "--format",
            "json",
        ],
        env=env,
        text=True,
    )
    return json.loads(output)


def podman_ps_all() -> Dict[str, str]:
    output = subprocess.check_output(
        ["podman", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
        text=True,
    )
    result: Dict[str, str] = {}
    for line in output.splitlines():
        if "\t" not in line:
            continue
        name, status = line.split("\t", 1)
        result[name] = status
    return result


def podman_container_exists(name: str) -> bool:
    return subprocess.run(
        ["podman", "container", "inspect", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    ).returncode == 0


def optional_services(bundle_root: Path) -> List[str]:
    metadata_path = bundle_root / "scripts" / "lib" / "optional-capabilities.json"
    if not metadata_path.exists():
        return DEFAULT_OPTIONAL_VM_SERVICES
    metadata = load_json(metadata_path)
    services: List[str] = []
    for capability in (metadata.get("capabilities") or {}).values():
        services.extend(capability.get("services") or [])
    return sorted(set(services))


def optional_runtime_configured(env_values: Dict[str, str]) -> bool:
    runner_ssh_dir = env_values.get("FORGEJO_RUNNER_SSH_DIR")
    return bool(runner_ssh_dir and (Path(runner_ssh_dir) / "id_ed25519").is_file())


def completion_job_services(runtime_config: dict) -> List[str]:
    jobs = set()
    services = runtime_config.get("services") or {}
    for name, config in services.items():
        if config.get("restart") == "no":
            jobs.add(name)
    for config in services.values():
        for dep_name, dep_config in (config.get("depends_on") or {}).items():
            if (dep_config or {}).get("condition") == "service_completed_successfully":
                jobs.add(dep_name)
    return sorted(jobs)


def container_name_for(service: str, config: dict) -> str:
    return ((config.get("services") or {}).get(service) or {}).get("container_name") or service


def runtime_service_names(bundle_root: Path, env_file: Path, project_name: str) -> List[str]:
    config = runtime_contract_config(bundle_root, env_file, project_name)
    return sorted((config.get("services") or {}).keys())


def validate_secrets(env_file: Path) -> int:
    try:
        values = load_env_file(env_file)
    except ValueError as exc:
        print(f"[webservices-audit] {exc}", file=sys.stderr)
        return 1
    missing = [key for key in REQUIRED_SECRET_KEYS if not values.get(key)]
    invalid = []
    app_key = values.get("BOOKSTACK_APP_KEY", "")
    if app_key and not app_key.startswith("base64:"):
        invalid.append("BOOKSTACK_APP_KEY must use Laravel base64 format")
    kopia_auth = values.get("KOPIA_PROXY_AUTHORIZATION", "")
    if kopia_auth and not kopia_auth.startswith("Basic "):
        invalid.append("KOPIA_PROXY_AUTHORIZATION must be a Basic authorization header")
    vapid_private = values.get("MASTODON_VAPID_PRIVATE_KEY", "")
    vapid_public = values.get("MASTODON_VAPID_PUBLIC_KEY", "")
    if vapid_private and not valid_base64url_bytes(vapid_private, 32):
        invalid.append("MASTODON_VAPID_PRIVATE_KEY must be a 32-byte base64url P-256 private key")
    if vapid_public and not valid_vapid_public_key(vapid_public):
        invalid.append("MASTODON_VAPID_PUBLIC_KEY must be a 65-byte base64url uncompressed P-256 public key")
    if missing or invalid:
        for key in missing:
            print(f"[webservices-audit] missing required runtime value: {key}", file=sys.stderr)
        for message in invalid:
            print(f"[webservices-audit] invalid runtime value: {message}", file=sys.stderr)
        return 1
    print(f"[webservices-audit] secret inventory validated ({len(REQUIRED_SECRET_KEYS)} required values present)", file=sys.stderr)
    return 0


def decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def valid_base64url_bytes(value: str, expected_length: int) -> bool:
    try:
        return len(decode_base64url(value)) == expected_length
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return False


def valid_vapid_public_key(value: str) -> bool:
    try:
        decoded = decode_base64url(value)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        return False
    return len(decoded) == 65 and decoded.startswith(b"\x04")


def expand_env_path(value: str, env_values: Dict[str, str]) -> str:
    result = value
    for key, env_value in env_values.items():
        result = result.replace("${" + key + "}", env_value)
    return result


def path_is_or_under(path: str, root: str) -> bool:
    root = root.rstrip("/") if root != "/" else root
    path = path.rstrip("/") if path != "/" else path
    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(f"{root}/")


def classify_bind(source: str, deploy_root: Path, env_values: Dict[str, str]) -> str:
    source = source.rstrip("/") if source != "/" else source
    deploy_root_str = deploy_root.as_posix()
    if path_is_or_under(source, f"{deploy_root_str}/runtime"):
        return "runtime-config"
    if path_is_or_under(source, f"{deploy_root_str}/build"):
        return "bundle"
    if path_is_or_under(source, f"{deploy_root_str}/reports") or path_is_or_under(source, f"{deploy_root_str}/repos"):
        return "deploy-root-data"
    if source.startswith("/mnt/media/"):
        return "media"
    if source.startswith("/mnt/stack/"):
        return "legacy-host-storage"
    if source in ALLOWED_HOST_BINDS:
        return "host-system"
    runner_ssh_dir = env_values.get("FORGEJO_RUNNER_SSH_DIR")
    if runner_ssh_dir and source == runner_ssh_dir.rstrip("/"):
        return "optional-identity"
    return "other-bind"


def storage_report(bundle_root: Path, env_file: Path, output: Path, project_name: str) -> int:
    env_values = load_env_file(env_file)
    deploy_root = bundle_root.parent.resolve()
    config = runtime_contract_config(bundle_root, env_file, project_name)
    volume_infra = load_json(bundle_root / "systemd-user" / "infra" / "volumes.json")
    binds = []
    findings = []
    for service, service_config in sorted((config.get("services") or {}).items()):
        for mount in service_config.get("volumes") or []:
            if not isinstance(mount, dict) or mount.get("type") != "bind":
                continue
            source = str(mount.get("source") or "")
            item = {
                "service": service,
                "source": source,
                "target": mount.get("target"),
                "classification": classify_bind(source, deploy_root, env_values),
            }
            binds.append(item)
            if item["classification"] in {"legacy-host-storage", "other-bind"} and service != "volume-init":
                findings.append(item)
    volumes = []
    for volume in volume_infra:
        driver_opts = volume.get("driver_opts") or {}
        device = expand_env_path(str(driver_opts.get("device") or ""), env_values)
        classification = "named-volume"
        if device.startswith("/mnt/media/"):
            classification = "named-volume-media-bind"
        elif device.startswith("/mnt/stack/"):
            classification = "named-volume-stack-bind"
        elif device:
            classification = "named-volume-bind"
        volumes.append({
            "key": volume.get("key"),
            "name": volume.get("name"),
            "driver": volume.get("driver"),
            "device": device,
            "classification": classification,
        })
    report = {
        "summary": {
            "bindMounts": len(binds),
            "containerVolumes": len(volumes),
            "findings": len(findings),
        },
        "bindMounts": binds,
        "containerVolumes": volumes,
        "findings": findings,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if findings:
        print(f"[webservices-audit] storage audit found {len(findings)} unexpected host bind(s); see {output}", file=sys.stderr)
        return 1
    print(f"[webservices-audit] storage audit ok; report written to {output}", file=sys.stderr)
    return 0


def module_report(bundle_root: Path, env_file: Path, output: Path, project_name: str, strict: bool) -> int:
    env_values = load_env_file(env_file)
    config = runtime_contract_config(bundle_root, env_file, project_name)
    graph = load_json(bundle_root / "stack.systemd" / "graph.json")
    excluded = set(graph.get("excludedServices") or [])
    on_demand = set(graph.get("onDemandServices") or [])
    optional = set(optional_services(bundle_root))
    optional_disabled = not optional_runtime_configured(env_values)
    jobs = set(completion_job_services(config))
    statuses = podman_ps_all()
    services = []
    problems = []
    for service, service_config in sorted((config.get("services") or {}).items()):
        container_name = container_name_for(service, config)
        status = statuses.get(container_name)
        classification = "runtime"
        ok = True
        if service in excluded:
            classification = "excluded"
            ok = status is None
        elif service in on_demand:
            classification = "on-demand"
            ok = status is None or not any(token in status.lower() for token in ("unhealthy", "restarting", "dead", "created"))
        elif optional_disabled and service in optional:
            classification = "skipped-optional"
            ok = status is None or status.startswith("Exited")
        elif service in jobs:
            classification = "job"
            ok = bool(status and status.startswith("Exited (0)"))
        else:
            ok = bool(status) and not any(token in status.lower() for token in ("unhealthy", "restarting", "exited", "dead", "created"))
        item = {
            "service": service,
            "container": container_name,
            "classification": classification,
            "status": status or "absent",
            "ok": ok,
        }
        services.append(item)
        if not ok:
            problems.append(item)
    summary = {
        "services": len(services),
        "runtime": sum(1 for item in services if item["classification"] == "runtime"),
        "jobs": sum(1 for item in services if item["classification"] == "job"),
        "onDemand": sum(1 for item in services if item["classification"] == "on-demand"),
        "skippedOptional": sum(1 for item in services if item["classification"] == "skipped-optional"),
        "excluded": sum(1 for item in services if item["classification"] == "excluded"),
        "problems": len(problems),
    }
    report = {"summary": summary, "services": services, "problems": problems}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[webservices-audit] module deployment report written to {output}: {summary}", file=sys.stderr)
    return 1 if strict and problems else 0


def cleanup_optional_orphans(bundle_root: Path, env_file: Path, project_name: str) -> int:
    env_values = load_env_file(env_file)
    if optional_runtime_configured(env_values):
        print("[webservices-audit] optional runtime identity configured; no optional orphan cleanup needed", file=sys.stderr)
        return 0
    config = runtime_contract_config(bundle_root, env_file, project_name)
    removed = []
    for service in optional_services(bundle_root):
        container_name = container_name_for(service, config)
        if podman_container_exists(container_name):
            subprocess.run(["podman", "rm", "-f", container_name], check=False)
            removed.append(container_name)
    if removed:
        print(f"[webservices-audit] removed skipped optional container state: {' '.join(removed)}", file=sys.stderr)
    else:
        print("[webservices-audit] no skipped optional container state found", file=sys.stderr)
    return 0


def podman_container_ip(name: str) -> str:
    output = subprocess.check_output(
        ["podman", "inspect", name, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
        text=True,
    ).strip()
    return output


def qdrant_get(base_url: str, path: str, api_key: str) -> dict:
    request = urllib.request.Request(f"{base_url}{path}")
    if api_key:
        request.add_header("api-key", api_key)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def vector_size_from_collection(payload: dict) -> int:
    vectors = (((payload.get("result") or {}).get("config") or {}).get("params") or {}).get("vectors")
    if isinstance(vectors, dict):
        if isinstance(vectors.get("size"), int):
            return int(vectors["size"])
        for value in vectors.values():
            if isinstance(value, dict) and isinstance(value.get("size"), int):
                return int(value["size"])
    return 0


def validate_qdrant_schema(bundle_root: Path, env_file: Path, project_name: str) -> int:
    if "qdrant" not in runtime_service_names(bundle_root, env_file, project_name):
        print("[webservices-audit] qdrant is not selected in this bundle; skipping vector schema audit", file=sys.stderr)
        return 0
    env_values = load_env_file(env_file)
    expected = int(env_values.get("VECTOR_EMBED_SIZE") or "0")
    if expected <= 0:
        print("[webservices-audit] VECTOR_EMBED_SIZE is missing or invalid", file=sys.stderr)
        return 1
    if not podman_container_exists("qdrant"):
        print("[webservices-audit] qdrant container is not present; skipping vector schema audit", file=sys.stderr)
        return 0
    try:
        ip_address = podman_container_ip("qdrant")
        if not ip_address:
            print("[webservices-audit] qdrant container has no IP address yet; skipping vector schema audit", file=sys.stderr)
            return 0
        base_url = f"http://{ip_address}:6333"
        api_key = env_values.get("QDRANT_ADMIN_API_KEY", "")
        collections = qdrant_get(base_url, "/collections", api_key)
        names = [item.get("name") for item in (collections.get("result") or {}).get("collections") or [] if item.get("name")]
        mismatches = []
        checked = 0
        for name in names:
            payload = qdrant_get(base_url, f"/collections/{name}", api_key)
            size = vector_size_from_collection(payload)
            if not size:
                continue
            checked += 1
            if size != expected:
                mismatches.append((name, size))
        if mismatches:
            for name, size in mismatches:
                print(f"[webservices-audit] qdrant collection dimension mismatch: {name} has {size}, expected {expected}", file=sys.stderr)
            return 1
        print(f"[webservices-audit] qdrant vector schema ok ({checked} collection(s), dimension={expected})", file=sys.stderr)
        return 0
    except (OSError, urllib.error.URLError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"[webservices-audit] qdrant schema audit could not run yet: {exc}", file=sys.stderr)
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-secrets", "storage-report", "module-report", "cleanup-optional-orphans", "qdrant-schema"):
        command = sub.add_parser(name)
        command.add_argument("--env-file", required=True, type=Path)
        command.add_argument("--bundle-root", required=True, type=Path)
        command.add_argument("--project-name", default="webservices")
        if name in {"storage-report", "module-report"}:
            command.add_argument("--output", required=True, type=Path)
        if name == "module-report":
            command.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    if args.command == "validate-secrets":
        return validate_secrets(args.env_file)
    if args.command == "storage-report":
        return storage_report(args.bundle_root, args.env_file, args.output, args.project_name)
    if args.command == "module-report":
        return module_report(args.bundle_root, args.env_file, args.output, args.project_name, args.strict)
    if args.command == "cleanup-optional-orphans":
        return cleanup_optional_orphans(args.bundle_root, args.env_file, args.project_name)
    if args.command == "qdrant-schema":
        return validate_qdrant_schema(args.bundle_root, args.env_file, args.project_name)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
