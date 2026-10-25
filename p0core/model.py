"""Strict, secret-free catalog contract and deterministic dependency resolution."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """Invalid or unsafe declarative input; callers must not log input values."""


ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
IMAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}\Z")
KINDS = frozenset({"provision", "order", "ready", "integration"})


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ContractError("manifest exceeds size limit")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("invalid JSON document") from error


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value) or len(value) > 80:
        raise ContractError("invalid identifier")
    return value


def fields(value: Any, required: set, optional: set = frozenset()) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ContractError("unknown or missing contract fields")
    return value


def text(value: Any) -> str:
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ContractError("invalid single-line text")
    return value


@dataclass(frozen=True)
class Edge:
    service: str
    kind: str


@dataclass(frozen=True)
class Service:
    id: str
    module: str
    runtime: str
    image: str | None
    requires: tuple[Edge, ...]
    declaration: dict


class Catalog:
    def __init__(self, manifests: list[dict]):
        self.services: dict[str, Service] = {}
        self.modules: dict[str, dict] = {}
        for original in manifests:
            # Snapshot inputs so callers cannot mutate an already validated graph.
            manifest = json.loads(canonical(original))
            fields(manifest, {"schemaVersion", "id", "services"}, {"description"})
            if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1:
                raise ContractError("unsupported manifest version")
            module = identifier(manifest["id"])
            if module in self.modules:
                raise ContractError("duplicate module")
            declarations = manifest["services"]
            if not isinstance(declarations, list):
                raise ContractError("services must be an array")
            self.modules[module] = manifest
            for item in declarations:
                fields(item, {"id", "runtime", "requires"}, {"image", "mounts", "endpoints",
                       "probes", "resources", "command", "description", "environment",
                       "networks", "lifecycle", "entrypoint"})
                name = identifier(item["id"])
                if name in self.services:
                    raise ContractError("duplicate service owner")
                runtime = item["runtime"]
                if runtime not in ("rootless", "rootful", "test"):
                    raise ContractError("invalid runtime")
                image = item.get("image")
                if image is not None and (not isinstance(image, str) or not IMAGE.fullmatch(image)):
                    raise ContractError("image must use immutable sha256 digest")
                edges = []
                requirements = item.get("requires", [])
                if not isinstance(requirements, list):
                    raise ContractError("requires must be an array")
                for edge in requirements:
                    fields(edge, {"service", "kind"})
                    target = identifier(edge["service"])
                    if edge["kind"] not in KINDS or target == name:
                        raise ContractError("invalid dependency")
                    parsed = Edge(target, edge["kind"])
                    if parsed in edges:
                        raise ContractError("duplicate dependency")
                    edges.append(parsed)
                self.services[name] = Service(name, module, runtime, image,
                                              tuple(sorted(edges, key=lambda e: (e.service, e.kind))), item)
        for service in self.services.values():
            for edge in service.requires:
                if edge.service not in self.services:
                    raise ContractError("missing dependency provider")
        # Validate the entire catalog, not just the next target's reachable graph.
        self._order(set(self.services))

    @classmethod
    def read(cls, directory: Path) -> Catalog:
        root = directory.resolve(strict=True)
        if not root.is_dir():
            raise ContractError("catalog must be a directory")
        paths = sorted(root.glob("modules/*/module.json"))
        if not paths:
            raise ContractError("catalog contains no module manifests")
        for path in paths:
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ContractError("manifest escapes catalog")
        return cls([load_json(path) for path in paths])

    def _order(self, selected: set[str]) -> list[str]:
        visiting, visited, ordered = set(), set(), []

        def visit(name):
            if name in visiting:
                raise ContractError("startup dependency cycle")
            if name in visited:
                return
            visiting.add(name)
            for edge in self.services[name].requires:
                if edge.kind != "integration" and edge.service in selected:
                    visit(edge.service)
            visiting.remove(name)
            visited.add(name)
            ordered.append(name)

        for name in sorted(selected):
            visit(name)
        return ordered

    def plan(self, targets: list[str]) -> dict:
        if not targets:
            raise ContractError("at least one explicit target required")
        selected: set[str] = set()

        def select(name):
            if name not in self.services:
                raise ContractError("unknown service target")
            if name in selected:
                return
            selected.add(name)
            for edge in self.services[name].requires:
                if edge.kind != "integration":
                    select(edge.service)

        for name in targets:
            select(identifier(name))
        ordered = self._order(selected)
        inputs = [{"module": self.services[name].module,
                   "declaration": self.services[name].declaration} for name in ordered]
        modules = sorted({self.services[name].module for name in ordered})
        # Unrelated module edits do not invalidate a target's input identity.
        return {"schemaVersion": 1, "targets": sorted(set(targets)), "services": ordered,
                "modules": modules, "inputSha256": digest(inputs),
                "readinessEdges": [{"service": name, "requires": edge.service}
                                   for name in ordered for edge in self.services[name].requires
                                   if edge.kind == "ready"],
                "integrations": [{"service": name, "with": edge.service}
                                 for name in ordered for edge in self.services[name].requires
                                 if edge.kind == "integration" and edge.service in selected]}
