#!/usr/bin/env python3
"""Render a Docker-in-Docker friendly Runtime contract file for disposable testdev."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


EXCLUDED_SERVICES = {
    # GPU / hardware-bound.
    "embedding-gpu",
    "gpu-bootstrap-arbiter",
    "gpu-workload-monitor",
    "inference-controller",
    "inference-gateway",
    # User-excluded ingestion/publication pipeline.
    "airflow-init",
    "airflow-webserver",
    "airflow-scheduler",
    "ingestion-runner",
    "nats",
}

DOCKER_VM_REPLACEMENTS: dict[str, str] = {}

CACHE_IMAGE_REPLACEMENTS = {
    "alpine:testdev-cache": "alpine:3.21",
    "fviolence/docker-health-exporter:testdev-cache": "fviolence/docker-health-exporter@sha256:14116e61c73c868a6c244a6729dd0e1e556988d99d1b2c1475aaa968fcddaed7",
    "grafana/alloy:testdev-cache": "grafana/alloy@sha256:8f5666aebb871ba43ee2d65159c5d1c26c903720efafaf2d9ed4e237afc3bc88",
    "timescale/timescaledb:testdev-cache": "timescale/timescaledb@sha256:0af03ecf697825f6ddae76fd275d16bf46007bed6d00eb3d754779cb7db96fa6",
    "vaultwarden/server:testdev-cache": "vaultwarden/server@sha256:9a8eec71f4a52411cc43edc7a50f33e9b6f62b5baca0dd95f0c6e7fd60f1a341",
    "zenika/kotlin:testdev-cache": "zenika/kotlin@sha256:6aa73e11c07b361e4cf068dce3745a4bc9f8b0b7d8d0b8cbbcc385539184d46a",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-contract-file", required=True)
    parser.add_argument("--output-file", required=True)
    return parser.parse_args()


def compose_as_json(compose_file: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "config",
            "--format",
            "json",
            "--no-interpolate",
            "--no-path-resolution",
            "--no-env-resolution",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def replace_strings(value: Any) -> Any:
    if isinstance(value, str):
        for old, new in DOCKER_VM_REPLACEMENTS.items():
            value = value.replace(old, new)
        value = CACHE_IMAGE_REPLACEMENTS.get(value, value)
        return value
    if isinstance(value, list):
        return [replace_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: replace_strings(item) for key, item in value.items()}
    return value


def strip_missing_dependencies(service: dict[str, Any], excluded: set[str], existing: set[str]) -> None:
    depends_on = service.get("depends_on")
    if isinstance(depends_on, dict):
        filtered = {
            name: condition
            for name, condition in depends_on.items()
            if name not in excluded and name in existing
        }
        if filtered:
            service["depends_on"] = filtered
        else:
            service.pop("depends_on", None)
    elif isinstance(depends_on, list):
        filtered = [name for name in depends_on if name not in excluded and name in existing]
        if filtered:
            service["depends_on"] = filtered
        else:
            service.pop("depends_on", None)


def add_dependency(service: dict[str, Any], name: str) -> None:
    depends_on = service.setdefault("depends_on", {})
    if isinstance(depends_on, dict):
        depends_on.setdefault(name, {"condition": "service_started"})


def normalize_deploy_limits(service: dict[str, Any]) -> None:
    cpus = (
        service.get("deploy", {})
        .get("resources", {})
        .get("limits", {})
        .get("cpus")
    )
    if cpus is None:
        return
    try:
        if float(str(cpus)) > 1.0:
            service["deploy"]["resources"]["limits"]["cpus"] = "1.0"
    except ValueError:
        return


def disable_volume_init(service: dict[str, Any]) -> None:
    service["command"] = ["echo 'testdev: host bind volume initialization skipped'"]
    service.pop("volumes", None)


def normalize_volumes(compose: dict[str, Any]) -> None:
    volumes = compose.get("volumes")
    if not isinstance(volumes, dict):
        return
    for config in volumes.values():
        if not isinstance(config, dict):
            continue
        opts = config.get("driver_opts")
        if isinstance(opts, dict) and opts.get("type") == "bind":
            config.pop("driver_opts", None)
            if config.get("driver") == "local":
                config.pop("driver", None)
        config.pop("name", None)


def testdev_volume_name(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:10]
    return f"testdev_bind_{digest}"


def should_normalize_storage_source(source: str, volume_type: str) -> bool:
    if volume_type == "volume":
        return "/" in source or "${" in source
    if volume_type != "bind":
        return False
    if source.startswith("./") or source.startswith("../"):
        return False
    if source in {"/", "/proc", "/sys", "/dev/disk", "/etc/timezone", "/var/run/docker.sock", "/var/lib/docker"}:
        return False
    return source.startswith("${")


def normalize_service_volumes(compose: dict[str, Any], service_name: str, service: dict[str, Any]) -> None:
    service_volumes = service.get("volumes")
    if not isinstance(service_volumes, list):
        return

    service["volumes"] = [
        volume for volume in service_volumes
        if not is_localtime_bind(volume)
        and not is_seafile_nested_storage_volume(service_name, volume)
    ]
    service_volumes = service["volumes"]

    top_level_volumes = compose.setdefault("volumes", {})
    for volume in service_volumes:
        if not isinstance(volume, dict):
            continue
        source = volume.get("source")
        volume_type = volume.get("type")
        if not isinstance(source, str) or not source:
            continue
        if not should_normalize_storage_source(source, volume_type):
            continue

        replacement = testdev_volume_name(source)
        volume["source"] = replacement
        volume.pop("bind", None)
        volume["type"] = "volume"
        volume.setdefault("volume", {})
        top_level_volumes.setdefault(replacement, {})


def is_localtime_bind(volume: Any) -> bool:
    if isinstance(volume, str):
        parts = volume.split(":")
        return len(parts) >= 2 and parts[0] == "/etc/localtime" and parts[1] == "/etc/localtime"

    if not isinstance(volume, dict):
        return False

    return (
        volume.get("type") == "bind"
        and volume.get("source") == "/etc/localtime"
        and volume.get("target") == "/etc/localtime"
    )


def is_seafile_nested_storage_volume(service_name: str, volume: Any) -> bool:
    if service_name != "seafile" or not isinstance(volume, dict):
        return False
    return volume.get("target") == "/shared/seafile/seafile-data/storage"


def normalize_networks(compose: dict[str, Any]) -> None:
    networks = compose.get("networks")
    if not isinstance(networks, dict):
        return
    for config in networks.values():
        if isinstance(config, dict):
            config.pop("name", None)


def write_json_as_yaml_compatible(output_file: Path, compose: dict[str, Any]) -> None:
    output_file.write_text(
        json.dumps(compose, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    compose_file = Path(args.compose_file)
    output_file = Path(args.output_file)
    compose = compose_as_json(compose_file)

    services = compose.get("services")
    if not isinstance(services, dict):
        raise SystemExit("runtime contract file has no services map")

    excluded = {name for name in EXCLUDED_SERVICES if name in services}
    for name in excluded:
        services.pop(name, None)

    existing = set(services)
    for name, service in list(services.items()):
        if not isinstance(service, dict):
            continue
        service.pop("container_name", None)
        strip_missing_dependencies(service, excluded, existing)
        normalize_deploy_limits(service)
        normalize_service_volumes(compose, name, service)
        normalized = replace_strings(service)
        service.clear()
        service.update(normalized)

        if name == "forgejo-runner" and "docker-socket-controller-proxy" in existing:
            add_dependency(service, "docker-socket-controller-proxy")
        if name == "jupyterhub":
            env = service.setdefault("environment", {})
            if isinstance(env, dict):
                env["DOCKER_NETWORK_NAME"] = "${COMPOSE_PROJECT_NAME}_ai"
        if name == "volume-init":
            disable_volume_init(service)

    normalize_volumes(compose)
    normalize_networks(compose)
    write_json_as_yaml_compatible(output_file, compose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
