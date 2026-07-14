#!/usr/bin/env python3
"""Render systemd user units and runtime-contract shards for a built webservices bundle.

Inputs:
- a merged compatibility runtime contract config
- stack.systemd/graph.json
- the local deploy root and bundle root paths selected by the build

Outputs:
- systemd user service/target units
- per-lifecycle-domain runtime-contract JSON shards
- shared container network/volume metadata for deploy-time reconciliation

The graph separates platform services into installable targets and lifecycle
domains. A lifecycle domain is the smallest Compose shard that systemd starts
or waits on as one unit. Services not assigned to an explicit lifecycle domain
are rendered as their own domain unless excluded or marked on-demand.

Security model:
- unit names, service names, target references, and generated file names are
  validated before use
- generated files are written only under the selected output directories
- build-only Compose fields are stripped from deploy-time shards
"""

import argparse
import copy
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class Domain:
    name: str
    services: List[str]
    is_job: bool
    on_demand: bool


@dataclass
class Target:
    name: str
    description: str
    install: bool
    include_units_from_non_on_demand_domains: bool
    wants_targets: List[str]
    after_targets: List[str]
    conflicts: List[str]
    part_of_targets: List[str]
    services: Set[str]
    domains: Set[str]


@dataclass(frozen=True)
class PathContract:
    path: str
    kind: str


VM_IDENTITY_DEPENDENT_DOMAINS: Set[str] = set()
VM_IDENTITY_DEPENDENT_SERVICES: Set[str] = set()
OPTIONAL_CAPABILITIES_PATH = Path("scripts/lib/optional-capabilities.json")

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SAFE_TARGET_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.target$")
SAFE_UNIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(?:service|target)$")


def shell_join(parts: List[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_text_within(root: Path, file_name: str, content: str) -> None:
    ensure_no_control_chars(file_name, "output file name")
    if "/" in file_name or "\\" in file_name:
        raise ValueError(f"output file name must not contain path separators: {file_name!r}")
    path = (root / file_name).resolve(strict=False)
    root_resolved = root.resolve(strict=True)
    try:
        path.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"output path escapes output directory: {file_name!r}") from exc
    write_text(path, content)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_vm_identity_dependent_sets(local_bundle_root: Path) -> Tuple[Set[str], Set[str]]:
    metadata_path = local_bundle_root / OPTIONAL_CAPABILITIES_PATH
    if not metadata_path.exists():
        return set(VM_IDENTITY_DEPENDENT_DOMAINS), set(VM_IDENTITY_DEPENDENT_SERVICES)
    metadata = load_json(metadata_path)
    capability = (metadata.get("capabilities") or {}).get("isolatedDockerVm") or {}
    domains = set(capability.get("domains") or [])
    services = set(capability.get("services") or [])
    if not domains and not services:
        return set(VM_IDENTITY_DEPENDENT_DOMAINS), set(VM_IDENTITY_DEPENDENT_SERVICES)
    return domains, services


def ensure_no_control_chars(value: str, label: str) -> None:
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"{label} contains control characters")


def validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    ensure_no_control_chars(value, label)
    if not SAFE_IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{label} must match {SAFE_IDENTIFIER_RE.pattern}: {value!r}")


def validate_target_unit_name(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    ensure_no_control_chars(value, label)
    if "/" in value or "\\" in value:
        raise ValueError(f"{label} must not contain path separators: {value!r}")
    if not SAFE_TARGET_UNIT_RE.fullmatch(value):
        raise ValueError(f"{label} must match {SAFE_TARGET_UNIT_RE.pattern}: {value!r}")


def validate_unit_reference(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    ensure_no_control_chars(value, label)
    if "/" in value or "\\" in value:
        raise ValueError(f"{label} must not contain path separators: {value!r}")
    if not SAFE_UNIT_REF_RE.fullmatch(value):
        raise ValueError(f"{label} must match {SAFE_UNIT_REF_RE.pattern}: {value!r}")


def validate_target_definition(raw_target: dict, label: str) -> None:
    validate_target_unit_name(raw_target["name"], f"{label}.name")
    description = raw_target.get("description")
    if not isinstance(description, str) or not description:
        raise ValueError(f"{label}.description must be a non-empty string")
    ensure_no_control_chars(description, f"{label}.description")

    for field in ("wantsTargets", "afterTargets", "conflicts", "partOfTargets"):
        for index, entry in enumerate(raw_target.get(field, [])):
            validate_unit_reference(entry, f"{label}.{field}[{index}]")
    for index, service_name in enumerate(raw_target.get("services", [])):
        validate_identifier(service_name, f"{label}.services[{index}]")
    for index, domain_name in enumerate(raw_target.get("domains", [])):
        validate_identifier(domain_name, f"{label}.domains[{index}]")


def validate_graph_identifiers(graph: dict, compose_services: dict) -> None:
    validate_identifier(graph["unitPrefix"], "graph.unitPrefix")
    for service_name in compose_services.keys():
        validate_identifier(service_name, f"compose.services[{service_name}]")

    validate_target_definition(graph["defaultTarget"], "graph.defaultTarget")
    for index, raw_target in enumerate(graph.get("auxiliaryTargets", [])):
        validate_target_definition(raw_target, f"graph.auxiliaryTargets[{index}]")

    for index, raw_domain in enumerate(graph.get("lifecycleDomains", [])):
        validate_identifier(raw_domain["name"], f"graph.lifecycleDomains[{index}].name")
        for service_index, service_name in enumerate(raw_domain.get("services", [])):
            validate_identifier(service_name, f"graph.lifecycleDomains[{index}].services[{service_index}]")

    for index, service_name in enumerate(graph.get("excludedServices", [])):
        validate_identifier(service_name, f"graph.excludedServices[{index}]")
    for index, service_name in enumerate(graph.get("onDemandServices", [])):
        validate_identifier(service_name, f"graph.onDemandServices[{index}]")
    for index, domain_name in enumerate(graph.get("onDemandDomains", [])):
        validate_identifier(domain_name, f"graph.onDemandDomains[{index}]")


def stable_resource_name(prefix: str, resource_name: str, resource_config: dict) -> str:
    explicit_name = resource_config.get("name")
    if explicit_name:
        return explicit_name
    return f"{prefix}_{resource_name}"


def labels_as_list(value):
    if isinstance(value, dict):
        return [f"{key}={val}" for key, val in value.items()]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def merge_label_lists(*label_groups):
    merged = []
    seen = set()
    for group in label_groups:
        for label in group:
            if label in seen:
                continue
            seen.add(label)
            merged.append(label)
    return merged


def is_job(service_name: str, service_config: dict, services: dict) -> bool:
    if service_config.get("restart") == "no":
        return True
    for other_config in services.values():
        depends_on = other_config.get("depends_on") or {}
        if service_name in depends_on:
            condition = (depends_on[service_name] or {}).get("condition", "service_started")
            if condition == "service_completed_successfully":
                return True
    return False


def service_unit_name(unit_prefix: str, domain_name: str) -> str:
    return f"{unit_prefix}-{domain_name}.service"


def healthy_unit_name(unit_prefix: str, domain_name: str) -> str:
    return f"{unit_prefix}-{domain_name}-healthy.service"


def infra_unit_name(unit_prefix: str, suffix: str) -> str:
    return f"{unit_prefix}-{suffix}.service"


def has_healthcheck(service_config: dict) -> bool:
    return service_config.get("healthcheck") is not None


def build_domains(graph: dict, services: dict, excluded_services: Set[str]) -> List[Domain]:
    lifecycle_domains = graph.get("lifecycleDomains", [])
    on_demand_services = set(graph.get("onDemandServices", []))
    on_demand_domains = set(graph.get("onDemandDomains", []))
    assigned: Dict[str, str] = {}
    domains: List[Domain] = []

    for raw_domain in lifecycle_domains:
        domain_name = raw_domain["name"]
        domain_services = []
        for service_name in raw_domain["services"]:
            if service_name in excluded_services:
                raise ValueError(f"lifecycle domain {domain_name} references excluded service {service_name}")
            if service_name not in services:
                continue
            if service_name in assigned:
                raise ValueError(f"service {service_name} is assigned to multiple lifecycle domains")
            assigned[service_name] = domain_name
            domain_services.append(service_name)
        if not domain_services:
            continue
        domains.append(Domain(
            name=domain_name,
            services=domain_services,
            is_job=False,
            on_demand=(domain_name in on_demand_domains or set(domain_services).issubset(on_demand_services)),
        ))

    for service_name in sorted(services.keys()):
        if service_name in excluded_services or service_name in assigned:
            continue
        domains.append(Domain(
            name=service_name,
            services=[service_name],
            is_job=False,
            on_demand=(service_name in on_demand_domains or service_name in on_demand_services),
        ))

    resolved_domains: List[Domain] = []
    for domain in domains:
        job_flags = [is_job(service_name, services[service_name], services) for service_name in domain.services]
        if any(job_flags) and not all(job_flags):
            raise ValueError(f"lifecycle domain {domain.name} mixes job and long-running services")
        if all(job_flags) and len(domain.services) != 1:
            raise ValueError(f"job lifecycle domain {domain.name} must contain exactly one service")
        resolved_domains.append(Domain(
            name=domain.name,
            services=domain.services,
            is_job=all(job_flags),
            on_demand=domain.on_demand,
        ))

    return sorted(resolved_domains, key=lambda item: item.name)


def strongest_condition(existing: Optional[str], candidate: str) -> str:
    rank = {
        "service_started": 1,
        "service_healthy": 2,
        "service_completed_successfully": 3,
    }
    if existing is None:
        return candidate
    return candidate if rank.get(candidate, 1) > rank.get(existing, 1) else existing


def domain_dependencies(domain: Domain, compose_services: dict, service_to_domain: dict, excluded_services: Set[str]) -> Dict[str, str]:
    dependencies: Dict[str, str] = {}
    for service_name in domain.services:
        depends_on = compose_services[service_name].get("depends_on") or {}
        for dependency_name, dependency_config in depends_on.items():
            if dependency_name in excluded_services:
                continue
            dependency_domain = service_to_domain.get(dependency_name)
            if dependency_domain is None or dependency_domain == domain.name:
                continue
            condition = (dependency_config or {}).get("condition", "service_started")
            dependencies[dependency_domain] = strongest_condition(dependencies.get(dependency_domain), condition)
    return dependencies


def topo_sort_domains(domains: List[Domain], dependency_map: Dict[str, Dict[str, str]]) -> List[Domain]:
    domain_index = {domain.name: index for index, domain in enumerate(domains)}
    incoming_counts: Dict[str, int] = {domain.name: 0 for domain in domains}
    outgoing: Dict[str, Set[str]] = {domain.name: set() for domain in domains}

    for domain in domains:
        dependencies = dependency_map.get(domain.name, {})
        for dependency_domain in dependencies.keys():
            incoming_counts[domain.name] += 1
            outgoing.setdefault(dependency_domain, set()).add(domain.name)

    ready = [domain.name for domain in domains if incoming_counts[domain.name] == 0]
    ready.sort(key=lambda name: domain_index[name])

    ordered_names: List[str] = []
    while ready:
        domain_name = ready.pop(0)
        ordered_names.append(domain_name)
        for dependent_name in sorted(outgoing.get(domain_name, set()), key=lambda name: domain_index[name]):
            incoming_counts[dependent_name] -= 1
            if incoming_counts[dependent_name] == 0:
                ready.append(dependent_name)
                ready.sort(key=lambda name: domain_index[name])

    if len(ordered_names) != len(domains):
        unresolved = sorted(set(domain_index.keys()) - set(ordered_names))
        raise ValueError(f"cycle detected in systemd domain dependency graph: {unresolved}")

    ordered_lookup = {domain.name: domain for domain in domains}
    return [ordered_lookup[name] for name in ordered_names]


def build_target(raw_target: dict, *, install_default: bool, include_units_default: bool) -> Target:
    return Target(
        name=raw_target["name"],
        description=raw_target["description"],
        install=bool(raw_target.get("install", install_default)),
        include_units_from_non_on_demand_domains=bool(raw_target.get("includeUnitsFromNonOnDemandDomains", include_units_default)),
        wants_targets=sorted(dict.fromkeys(raw_target.get("wantsTargets", []))),
        after_targets=sorted(dict.fromkeys(raw_target.get("afterTargets", []))),
        conflicts=sorted(dict.fromkeys(raw_target.get("conflicts", []))),
        part_of_targets=sorted(dict.fromkeys(raw_target.get("partOfTargets", []))),
        services=set(raw_target.get("services", [])),
        domains=set(raw_target.get("domains", [])),
    )


def member_target_names(domain: Domain, default_target: Target, auxiliary_targets: List[Target]) -> List[str]:
    target_names: List[str] = []
    if not domain.on_demand and default_target.include_units_from_non_on_demand_domains:
        target_names.append(default_target.name)
    for target in auxiliary_targets:
        if domain.name in target.domains or target.services.intersection(domain.services):
            target_names.append(target.name)
    return sorted(dict.fromkeys(target_names))


def project_relative_source(source: str, local_deploy_root: Path) -> Optional[str]:
    try:
        source_path = Path(source).resolve()
    except OSError:
        return None
    try:
        relative = source_path.relative_to(local_deploy_root)
    except ValueError:
        return None
    return f"./{relative.as_posix()}"


def strip_deploy_root_from_template_path(source: str, local_deploy_root: Path) -> str:
    deploy_root_prefix = f"{local_deploy_root.as_posix()}/"
    if "$" in source and source.startswith(deploy_root_prefix):
        return source[len(deploy_root_prefix):]
    return source


def infer_path_kind(source_path: Path, local_deploy_root: Path, local_bundle_root: Path) -> str:
    if source_path.exists():
        if source_path.is_dir():
            return "dir"
        if source_path.is_file():
            return "file"
        return "exists"

    try:
        relative = source_path.relative_to(local_deploy_root).as_posix()
    except ValueError:
        return "exists"

    if relative.startswith("runtime/configs/"):
        config_relative = relative[len("runtime/configs/"):]
        source_candidate = local_bundle_root / "stack.config" / config_relative
        template_candidate = local_bundle_root / "stack.config" / f"{config_relative}.template"
        if source_candidate.exists():
            if source_candidate.is_dir():
                return "dir"
            if source_candidate.is_file():
                return "file"
        if template_candidate.exists():
            return "file"
    return "exists"


def collect_path_contracts(domain: Domain, compose_config: dict, local_deploy_root: Path, local_bundle_root: Path, deploy_root_template: str, vm_identity_domains: Set[str], vm_identity_services: Set[str]) -> List[PathContract]:
    contracts: Dict[str, PathContract] = {}
    for service_name in domain.services:
        for mount in compose_config["services"][service_name].get("volumes") or []:
            if not isinstance(mount, dict) or mount.get("type") != "bind":
                continue
            source = mount.get("source")
            if not source:
                continue
            if "$" in source:
                contract_source = strip_deploy_root_from_template_path(source, local_deploy_root)
                existing = contracts.get(contract_source)
                if existing is None or existing.kind == "exists":
                    contracts[contract_source] = PathContract(path=contract_source, kind="exists")
                continue
            project_relative = project_relative_source(source, local_deploy_root)
            if project_relative is None:
                continue
            host_path = f"{deploy_root_template}/{project_relative[2:]}"
            kind = infer_path_kind(Path(source), local_deploy_root, local_bundle_root)
            existing = contracts.get(host_path)
            if existing is None or existing.kind == "exists":
                contracts[host_path] = PathContract(path=host_path, kind=kind)
    return sorted(contracts.values(), key=lambda item: item.path)


def looks_like_host_path(source: str) -> bool:
    return "/" in source or source.startswith(".") or source.startswith("~")


def normalize_service_mounts(service_config: dict, local_deploy_root: Path, declared_volume_names: Set[str]) -> dict:
    service_copy = copy.deepcopy(service_config)
    normalized_volumes = []
    for mount in service_copy.get("volumes") or []:
        if isinstance(mount, dict) and mount.get("source"):
            mount = dict(mount)
            mount_type = mount.get("type")
            source = str(mount["source"])
            if mount_type == "volume" and (looks_like_host_path(source) or source not in declared_volume_names):
                mount["type"] = "bind"
                mount["bind"] = dict(mount.get("bind") or {})
                mount["bind"].setdefault("create_host_path", True)
                mount.pop("volume", None)
                mount_type = "bind"
            if mount_type == "bind" and "$" in source:
                mount["source"] = strip_deploy_root_from_template_path(source, local_deploy_root)
            elif mount_type == "bind":
                project_relative = project_relative_source(source, local_deploy_root)
                if project_relative is not None:
                    mount["source"] = project_relative
        normalized_volumes.append(mount)
    if normalized_volumes:
        service_copy["volumes"] = normalized_volumes
    return service_copy


def normalize_service_env_files(service_config: dict, local_deploy_root: Path) -> dict:
    service_copy = copy.deepcopy(service_config)
    env_files = service_copy.get("env_file")
    if not env_files:
        return service_copy

    normalized_env_files = []
    for entry in env_files:
        if isinstance(entry, dict):
            entry_copy = dict(entry)
            path = entry_copy.get("path")
            if isinstance(path, str) and "$" in path:
                entry_copy["path"] = strip_deploy_root_from_template_path(path, local_deploy_root)
            elif isinstance(path, str):
                project_relative = project_relative_source(path, local_deploy_root)
                if project_relative is not None:
                    entry_copy["path"] = project_relative
            normalized_env_files.append(entry_copy)
            continue

        if isinstance(entry, str) and "$" in entry:
            normalized_env_files.append(strip_deploy_root_from_template_path(entry, local_deploy_root))
            continue

        if isinstance(entry, str):
            project_relative = project_relative_source(entry, local_deploy_root)
            normalized_env_files.append(project_relative if project_relative is not None else entry)
            continue

        normalized_env_files.append(entry)

    service_copy["env_file"] = normalized_env_files
    return service_copy


def extract_network_names(service_config: dict) -> Set[str]:
    referenced_networks = service_config.get("networks") or {}
    if isinstance(referenced_networks, list):
        return set(referenced_networks)
    return set(referenced_networks.keys())


def extract_volume_names(service_config: dict) -> Set[str]:
    referenced_volumes: Set[str] = set()
    for mount in service_config.get("volumes") or []:
        if isinstance(mount, dict) and mount.get("type") == "volume" and mount.get("source"):
            referenced_volumes.add(mount["source"])
    return referenced_volumes


def normalize_volume_driver_opts(volume_config: dict, local_deploy_root: Path) -> dict:
    normalized = dict(volume_config or {})
    driver_opts = dict(normalized.get("driver_opts") or {})
    device = driver_opts.get("device")
    if isinstance(device, str):
        deploy_root = local_deploy_root.as_posix()
        deploy_prefix = f"{deploy_root}/"
        if device.startswith(deploy_prefix):
            candidate = device[len(deploy_prefix):]
            if "${" in candidate:
                driver_opts["device"] = candidate
    if driver_opts:
        normalized["driver_opts"] = driver_opts
    return normalized


def compose_shard(domain: Domain, compose_config: dict, service_to_domain: dict, excluded_services: Set[str], unit_prefix: str, local_deploy_root: Path):
    top_level = {"services": {}}
    referenced_networks: Set[str] = set()
    referenced_volumes: Set[str] = set()
    declared_volume_names = set((compose_config.get("volumes") or {}).keys())

    for service_name in domain.services:
        service_config = compose_config["services"][service_name]
        service_copy = {key: value for key, value in service_config.items() if key not in {"build", "profiles", "pull_policy"}}
        service_copy = normalize_service_mounts(service_copy, local_deploy_root, declared_volume_names)
        service_copy = normalize_service_env_files(service_copy, local_deploy_root)
        depends_on = service_copy.get("depends_on") or {}
        if depends_on:
            filtered_depends_on = {}
            for dependency_name, dependency_config in depends_on.items():
                if dependency_name in excluded_services:
                    continue
                if service_to_domain.get(dependency_name) == domain.name:
                    filtered_depends_on[dependency_name] = dependency_config
            if filtered_depends_on:
                service_copy["depends_on"] = filtered_depends_on
            else:
                service_copy.pop("depends_on", None)

        referenced_networks.update(extract_network_names(service_copy))
        referenced_volumes.update(extract_volume_names(service_copy))
        top_level["services"][service_name] = service_copy

    if referenced_networks:
        top_level["networks"] = {}
        for network_name in sorted(referenced_networks):
            network_config = dict((compose_config.get("networks") or {}).get(network_name, {}))
            top_level["networks"][network_name] = {
                "external": True,
                "name": stable_resource_name(unit_prefix, network_name, network_config),
            }

    if referenced_volumes:
        top_level["volumes"] = {}
        for volume_name in sorted(referenced_volumes):
            volume_config = dict((compose_config.get("volumes") or {}).get(volume_name, {}))
            top_level["volumes"][volume_name] = {
                "external": True,
                "name": stable_resource_name(unit_prefix, volume_name, volume_config),
            }

    return top_level


def render_target(target: Target, wanted_units: List[str], stop_propagates_to: Optional[List[str]] = None) -> str:
    lines = ["[Unit]", f"Description={target.description}"]
    for unit in wanted_units:
        lines.append(f"Wants={unit}")
    for target_name in target.wants_targets:
        lines.append(f"Wants={target_name}")
    for target_name in target.after_targets:
        lines.append(f"After={target_name}")
    for target_name in target.conflicts:
        lines.append(f"Conflicts={target_name}")
    for target_name in target.part_of_targets:
        lines.append(f"PartOf={target_name}")
    for target_name in sorted(dict.fromkeys(stop_propagates_to or [])):
        lines.append(f"PropagatesStopTo={target_name}")
    lines.extend(["", "[Install]"])
    if target.install:
        lines.append("WantedBy=default.target")
    return "\n".join(lines) + "\n"


def render_infra_unit(description: str, exec_start: str, part_of_targets: List[str], wanted_by: Optional[str], on_failure_unit: str) -> str:
    lines = ["[Unit]", f"Description={description}", f"OnFailure={on_failure_unit}"]
    for target_name in part_of_targets:
        lines.append(f"PartOf={target_name}")
    lines.extend([
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        "RemainAfterExit=yes",
        f"ExecStart={exec_start}",
        "",
        "[Install]",
    ])
    if wanted_by:
        lines.append(f"WantedBy={wanted_by}")
    return "\n".join(lines) + "\n"


def render_path_contract_condition(contract: PathContract, runtime_env_file: str) -> str:
    test_flag = {
        "file": "-f",
        "dir": "-d",
    }.get(contract.kind, "-e")
    if "$" in contract.path:
        if "$(" in contract.path or "`" in contract.path:
            raise ValueError(f"path contract contains disallowed shell substitution: {contract.path}")
        quoted_path = contract.path.replace("\\", "\\\\").replace('"', '\\"')
        return f"ExecCondition=/bin/sh -c {shlex.quote(f'. {runtime_env_file}; test {test_flag} \"{quoted_path}\"')}"
    return f"ExecCondition=/usr/bin/test {test_flag} {contract.path}"


def render_preflight_lines(runtime_env_file: str, compose_file: str, project_directory: str, path_contracts: List[PathContract]) -> Tuple[List[str], List[str]]:
    unit_lines = [
        f"ConditionPathExists={runtime_env_file}",
        f"ConditionPathExists={compose_file}",
        f"ConditionPathExists={project_directory}",
        f"RequiresMountsFor={project_directory} {project_directory}/build {project_directory}/runtime",
    ]
    service_lines: List[str] = []
    for contract in path_contracts:
        service_lines.append(render_path_contract_condition(contract, runtime_env_file))
    return unit_lines, service_lines


def service_systemd_timeout_start_sec(service_config: dict, default: int) -> int:
    value = None
    extension = service_config.get("x-webservices-systemd")
    if isinstance(extension, dict):
        value = extension.get("timeoutStartSec")
    labels = labels_as_list(service_config.get("labels") or [])
    for label in labels:
        key, separator, raw_value = label.partition("=")
        if separator and key == "org.webservices.systemd.timeout-start-sec":
            value = raw_value
    if value is None:
        return default
    try:
        timeout = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"systemd timeoutStartSec must be an integer: {value!r}") from exc
    if timeout < 1 or timeout > 86400:
        raise ValueError(f"systemd timeoutStartSec must be between 1 and 86400 seconds: {timeout}")
    return timeout


def render_job_unit(description: str, exec_start: str, exec_stop: str, requires: List[str], after: List[str], part_of_targets: List[str], unit_preflight_lines: List[str], service_preflight_lines: List[str], on_failure_unit: str, timeout_start_sec: int = 1800) -> str:
    lines = ["[Unit]", f"Description={description}", f"OnFailure={on_failure_unit}"]
    for line in unit_preflight_lines:
        lines.append(line)
    for unit in requires:
        lines.append(f"Requires={unit}")
    for unit in after:
        lines.append(f"After={unit}")
    for target_name in part_of_targets:
        lines.append(f"PartOf={target_name}")
    lines.extend([
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        "RemainAfterExit=yes",
        f"TimeoutStartSec={timeout_start_sec}",
    ])
    for line in service_preflight_lines:
        lines.append(line)
    lines.extend([
        f"ExecStart={exec_start}",
        f"ExecStop={exec_stop}",
    ])
    return "\n".join(lines) + "\n"


def render_service_unit(description: str, exec_start: str, exec_stop: str, exec_reload: str, requires: List[str], after: List[str], part_of_targets: List[str], unit_preflight_lines: List[str], service_preflight_lines: List[str], on_failure_unit: str) -> str:
    lines = ["[Unit]", f"Description={description}", f"OnFailure={on_failure_unit}"]
    lines.extend([
        "StartLimitIntervalSec=300",
        "StartLimitBurst=3",
    ])
    for line in unit_preflight_lines:
        lines.append(line)
    for unit in requires:
        lines.append(f"Requires={unit}")
    for unit in after:
        lines.append(f"After={unit}")
    for target_name in part_of_targets:
        lines.append(f"PartOf={target_name}")
    lines.extend([
        "",
        "[Service]",
        "Type=notify",
        "NotifyAccess=all",
        "NoNewPrivileges=yes",
        "KillMode=control-group",
        "Restart=on-failure",
        "RestartSec=5s",
        "TimeoutStartSec=900",
        "TimeoutStopSec=120",
    ])
    for line in service_preflight_lines:
        lines.append(line)
    lines.extend([
        f"ExecStart={exec_start}",
        f"ExecStop={exec_stop}",
        f"ExecReload={exec_reload}",
    ])
    return "\n".join(lines) + "\n"


def render_healthy_unit(description: str, exec_start: str, primary_unit: str, runtime_env_file: str, compose_file: str, project_directory: str, service_preflight_lines: List[str], on_failure_unit: str) -> str:
    lines = [
        "[Unit]",
        f"Description={description}",
        f"OnFailure={on_failure_unit}",
        f"ConditionPathExists={runtime_env_file}",
        f"ConditionPathExists={compose_file}",
        f"ConditionPathExists={project_directory}",
        f"RequiresMountsFor={project_directory} {project_directory}/build {project_directory}/runtime",
        f"Requires={primary_unit}",
        f"After={primary_unit}",
        f"PartOf={primary_unit}",
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        "RemainAfterExit=yes",
        "TimeoutStartSec=900",
    ]
    for line in service_preflight_lines:
        lines.append(line)
    lines.extend([
        f"ExecStart={exec_start}",
        "ExecStop=/bin/true",
    ])
    return "\n".join(lines) + "\n"


def render_diagnostics_unit(diagnostics_helper: str) -> str:
    lines = [
        "[Unit]",
        "Description=Web Services diagnostics for %I",
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        f"ExecStart={shell_join([diagnostics_helper, '%I'])}",
    ]
    return "\n".join(lines) + "\n"


def render_host_autoheal_unit(host_autoheal_helper: str) -> str:
    lines = [
        "[Unit]",
        "Description=Web Services host-side autoheal",
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        f"ExecStart={shell_join([host_autoheal_helper])}",
    ]
    return "\n".join(lines) + "\n"


def render_host_autoheal_timer() -> str:
    lines = [
        "[Unit]",
        "Description=Run Web Services host-side autoheal every minute",
        "",
        "[Timer]",
        "OnBootSec=1min",
        "OnUnitActiveSec=1min",
        "AccuracySec=15s",
        "Unit=webservices-host-autoheal.service",
        "",
        "[Install]",
        "WantedBy=timers.target",
    ]
    return "\n".join(lines) + "\n"


def render_update_deploy_unit(update_deploy_helper: str) -> str:
    lines = [
        "[Unit]",
        "Description=Web Services stable GitHub update deploy",
        "",
        "[Service]",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        "TimeoutStartSec=7200",
        f"ExecStart={shell_join([update_deploy_helper])}",
    ]
    return "\n".join(lines) + "\n"


def render_update_deploy_timer() -> str:
    lines = [
        "[Unit]",
        "Description=Run Web Services stable GitHub update deploy daily",
        "",
        "[Timer]",
        "OnCalendar=04:00",
        "RandomizedDelaySec=30min",
        "Persistent=true",
        "Unit=webservices-update-deploy.service",
        "",
        "[Install]",
        "WantedBy=timers.target",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-bundle-root", required=True)
    parser.add_argument("--local-deploy-root", required=True)
    parser.add_argument("--deploy-root-template", required=True)
    parser.add_argument("--unit-root-template", required=True)
    parser.add_argument("--runtime-env-file-template", required=True)
    parser.add_argument("--compose-config-json", required=True)
    parser.add_argument("--graph-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--compose-project-name", required=True)
    parser.add_argument("--systemd-notify-bin", required=True)
    parser.add_argument("--runtime-helper", required=True)
    parser.add_argument("--infra-helper", required=True)
    parser.add_argument("--diagnostics-helper", required=True)
    parser.add_argument("--host-autoheal-helper", required=True)
    parser.add_argument("--update-deploy-helper", required=True)
    parser.add_argument("--base-networks-json", required=True)
    args = parser.parse_args()

    local_bundle_root = Path(args.local_bundle_root).resolve()
    local_deploy_root = Path(args.local_deploy_root).resolve()
    output_dir = Path(args.output_dir)
    compose_dir = output_dir / "compose"
    infra_dir = output_dir / "infra"

    compose_config = load_json(Path(args.compose_config_json))
    graph = load_json(Path(args.graph_path))
    base_networks = load_json(Path(args.base_networks_json))
    vm_identity_domains, vm_identity_services = load_vm_identity_dependent_sets(local_bundle_root)
    compose_services = compose_config["services"]
    validate_graph_identifiers(graph, compose_services)

    output_dir.mkdir(parents=True, exist_ok=True)
    if compose_dir.exists():
        for path in compose_dir.glob("*.compose.json"):
            path.unlink()
    else:
        compose_dir.mkdir(parents=True, exist_ok=True)
    if infra_dir.exists():
        for path in infra_dir.glob("*.json"):
            path.unlink()
    else:
        infra_dir.mkdir(parents=True, exist_ok=True)

    for path in output_dir.glob("webservices*.service"):
        path.unlink()
    for path in output_dir.glob("webservices*.target"):
        path.unlink()
    for path in output_dir.glob("webservices*.timer"):
        path.unlink()

    unit_prefix = graph["unitPrefix"]
    excluded_services = set(graph.get("excludedServices", []))
    default_target = build_target(graph["defaultTarget"], install_default=True, include_units_default=True)
    auxiliary_targets = [build_target(raw_target, install_default=False, include_units_default=False) for raw_target in graph.get("auxiliaryTargets", [])]

    domains = build_domains(graph, compose_services, excluded_services)
    service_to_domain = {}
    for domain in domains:
        for service_name in domain.services:
            service_to_domain[service_name] = domain.name
    dependency_map = {
        domain.name: domain_dependencies(domain, compose_services, service_to_domain, excluded_services)
        for domain in domains
    }
    ordered_domains = topo_sort_domains(domains, dependency_map)
    vm_identity_domains, vm_identity_services = load_vm_identity_dependent_sets(local_bundle_root)

    base_network_configs = (base_networks.get("networks") or {})
    shared_networks = []
    for network_name, network_config in sorted((compose_config.get("networks") or {}).items()):
        merged = dict(network_config or {})
        if network_name in base_network_configs:
            merged = dict(base_network_configs[network_name])
            merged.update({key: value for key, value in (network_config or {}).items() if key in {"name", "external"}})
        shared_networks.append({
            "key": network_name,
            "name": stable_resource_name(unit_prefix, network_name, merged),
            "driver": merged.get("driver", "bridge"),
            "internal": bool(merged.get("internal", False)),
            "attachable": bool(merged.get("attachable", False)),
            "enable_ipv6": bool(merged.get("enable_ipv6", False)),
            "labels": merge_label_lists(
                labels_as_list(merged.get("labels")),
                [
                    f"org.platform-zero.runtime.project={args.compose_project_name}",
                    f"org.platform-zero.runtime.network={network_name}",
                ],
            ),
        })

    shared_volumes = []
    for volume_name, volume_config in sorted((compose_config.get("volumes") or {}).items()):
        volume_config = normalize_volume_driver_opts(dict(volume_config or {}), local_deploy_root)
        shared_volumes.append({
            "key": volume_name,
            "name": stable_resource_name(unit_prefix, volume_name, volume_config),
            "driver": volume_config.get("driver", "local"),
            "driver_opts": volume_config.get("driver_opts") or {},
            "labels": merge_label_lists(
                labels_as_list(volume_config.get("labels")),
                [
                    f"org.platform-zero.runtime.project={args.compose_project_name}",
                    f"org.platform-zero.runtime.volume={volume_name}",
                ],
            ),
        })

    write_text(infra_dir / "networks.json", json.dumps(shared_networks, indent=2, sort_keys=True) + "\n")
    write_text(infra_dir / "volumes.json", json.dumps(shared_volumes, indent=2, sort_keys=True) + "\n")

    default_target_name = default_target.name
    diagnostics_unit = f"{unit_prefix}-diagnostics@.service"
    host_autoheal_unit = f"{unit_prefix}-host-autoheal.service"
    host_autoheal_timer = f"{unit_prefix}-host-autoheal.timer"
    update_deploy_unit = f"{unit_prefix}-update-deploy.service"
    update_deploy_timer = f"{unit_prefix}-update-deploy.timer"
    networks_unit = infra_unit_name(unit_prefix, "networks")
    volumes_unit = infra_unit_name(unit_prefix, "volumes")
    infra_units = [networks_unit, volumes_unit]
    write_text_within(output_dir, diagnostics_unit, render_diagnostics_unit(args.diagnostics_helper))
    write_text_within(output_dir, host_autoheal_unit, render_host_autoheal_unit(args.host_autoheal_helper))
    write_text_within(output_dir, host_autoheal_timer, render_host_autoheal_timer())
    write_text_within(output_dir, update_deploy_unit, render_update_deploy_unit(args.update_deploy_helper))
    write_text_within(output_dir, update_deploy_timer, render_update_deploy_timer())
    write_text_within(output_dir, networks_unit, render_infra_unit(
        "Web Services container networks",
        shell_join([
            args.infra_helper,
            "ensure-networks",
            "--config-file",
            f"{args.unit_root_template}/infra/networks.json",
            "--env-file",
            args.runtime_env_file_template,
        ]),
        [default_target_name],
        default_target_name,
        diagnostics_unit.replace("@.service", "@%n.service"),
    ))
    write_text_within(output_dir, volumes_unit, render_infra_unit(
        "Web Services container volumes",
        shell_join([
            args.infra_helper,
            "ensure-volumes",
            "--config-file",
            f"{args.unit_root_template}/infra/volumes.json",
            "--env-file",
            args.runtime_env_file_template,
        ]),
        [default_target_name],
        default_target_name,
        diagnostics_unit.replace("@.service", "@%n.service"),
    ))

    target_units: Dict[str, List[str]] = {default_target.name: list(infra_units)}
    for target in auxiliary_targets:
        target_units[target.name] = []

    if not default_target.include_units_from_non_on_demand_domains:
        uncovered_domains = []
        for domain in domains:
            if domain.on_demand:
                continue
            if not any(domain.name in target.domains or target.services.intersection(domain.services) for target in auxiliary_targets):
                uncovered_domains.append(domain.name)
        if uncovered_domains:
            raise ValueError(
                "default target direct unit membership is disabled, but these non-on-demand domains are not assigned to any target: "
                + ", ".join(sorted(uncovered_domains))
            )

    for domain in domains:
        shard = compose_shard(domain, compose_config, service_to_domain, excluded_services, unit_prefix, local_deploy_root)
        write_text_within(compose_dir, f"{domain.name}.compose.json", json.dumps(shard, indent=2, sort_keys=True) + "\n")

        runtime_compose_path = f"{args.unit_root_template}/compose/{domain.name}.compose.json"
        path_contracts = collect_path_contracts(
            domain,
            compose_config,
            local_deploy_root,
            local_bundle_root,
            args.deploy_root_template,
            vm_identity_domains,
            vm_identity_services,
        )
        unit_preflight_lines, service_preflight_lines = render_preflight_lines(
            args.runtime_env_file_template,
            runtime_compose_path,
            args.deploy_root_template,
            path_contracts,
        )

        dependency_conditions = dependency_map[domain.name]
        requires = list(infra_units)
        after = list(infra_units)
        for dependency_domain_name, dependency_condition in sorted(dependency_conditions.items()):
            dependency_domain = next(item for item in domains if item.name == dependency_domain_name)
            if dependency_condition == "service_healthy" and not dependency_domain.is_job:
                dep_unit = healthy_unit_name(unit_prefix, dependency_domain_name)
            else:
                dep_unit = service_unit_name(unit_prefix, dependency_domain_name)
            requires.append(dep_unit)
            after.append(dep_unit)
        requires = sorted(dict.fromkeys(requires))
        after = sorted(dict.fromkeys(after))

        primary_unit = service_unit_name(unit_prefix, domain.name)
        target_names = member_target_names(domain, default_target, auxiliary_targets)
        has_domain_healthcheck = any(has_healthcheck(compose_services[service_name]) for service_name in domain.services)

        if not domain.on_demand and default_target.include_units_from_non_on_demand_domains:
            target_units[default_target.name].append(primary_unit)
            if not domain.is_job and has_domain_healthcheck:
                target_units[default_target.name].append(healthy_unit_name(unit_prefix, domain.name))

        for target in auxiliary_targets:
            if domain.name in target.domains or target.services.intersection(domain.services):
                target_units[target.name].append(primary_unit)
                if not domain.is_job and has_domain_healthcheck:
                    target_units[target.name].append(healthy_unit_name(unit_prefix, domain.name))

        project = args.compose_project_name
        diagnostics_on_failure = diagnostics_unit.replace("@.service", "@%n.service")
        common_args = [
            "--runtime-contract-file",
            runtime_compose_path,
            "--env-file",
            args.runtime_env_file_template,
            "--project-directory",
            args.deploy_root_template,
            "--project-name",
            project,
            "--unit-name",
            domain.name,
        ]

        if domain.is_job:
            service_name = domain.services[0]
            timeout_start_sec = service_systemd_timeout_start_sec(compose_services[service_name], 1800)
            unit_text = render_job_unit(
                f"Web Services job domain ({domain.name})",
                shell_join([
                    args.runtime_helper,
                    "job-run",
                    "--runtime-contract-file",
                    runtime_compose_path,
                    "--env-file",
                    args.runtime_env_file_template,
                    "--project-directory",
                    args.deploy_root_template,
                    "--service-name",
                    service_name,
                    "--project-name",
                    project,
                ]),
                shell_join([
                    args.runtime_helper,
                    "service-stop",
                    *common_args,
                ]),
                requires,
                after,
                target_names,
                unit_preflight_lines,
                service_preflight_lines,
                diagnostics_on_failure,
                timeout_start_sec,
            )
            write_text_within(output_dir, primary_unit, unit_text)
            continue

        unit_text = render_service_unit(
            f"Web Services lifecycle domain ({domain.name})",
            shell_join([
                args.runtime_helper,
                "service-start",
                *common_args,
                "--notify-bin",
                args.systemd_notify_bin,
            ]),
            shell_join([
                args.runtime_helper,
                "service-stop",
                *common_args,
            ]),
            shell_join([
                args.runtime_helper,
                "service-reload",
                *common_args,
            ]),
            requires,
            after,
            target_names,
            unit_preflight_lines,
            service_preflight_lines,
            diagnostics_on_failure,
        )
        write_text_within(output_dir, primary_unit, unit_text)

        healthy_text = render_healthy_unit(
            f"Web Services healthy gate ({domain.name})",
            shell_join([
                args.runtime_helper,
                "service-wait-healthy",
                *common_args,
            ]),
            primary_unit,
            args.runtime_env_file_template,
            runtime_compose_path,
            args.deploy_root_template,
            service_preflight_lines,
            diagnostics_on_failure,
        )
        write_text_within(output_dir, healthy_unit_name(unit_prefix, domain.name), healthy_text)

    write_text_within(output_dir, default_target.name, render_target(
        default_target,
        sorted(dict.fromkeys(target_units[default_target.name])),
        [target.name for target in auxiliary_targets if target.name in default_target.wants_targets],
    ))

    for target in auxiliary_targets:
        write_text_within(output_dir, target.name, render_target(
            target,
            sorted(dict.fromkeys(target_units[target.name])),
        ))

    print(f"[webservices-build] rendered {len(list(output_dir.glob('webservices*.service')))} units into {output_dir}", file=sys.stderr)
    print(f"[webservices-build] rendered compose shards into {compose_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
