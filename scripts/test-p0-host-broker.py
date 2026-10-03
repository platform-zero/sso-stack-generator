#!/usr/bin/env python3
"""Regression checks for privileged rootless Quadlet policy."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BROKER_PATH = ROOT / "runtime-generator/podman-ops/p0-host-broker.py"
SPEC = importlib.util.spec_from_file_location("p0_host_broker", BROKER_PATH)
assert SPEC and SPEC.loader
BROKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BROKER)


with tempfile.TemporaryDirectory() as temporary:
    subuids = Path(temporary) / "subuid"
    subuids.write_text("stack_lab:2000000:65536\nother:3000000:65536\n")
    with patch.object(BROKER.pwd, "getpwnam", return_value=type("Record", (), {"pw_uid": 1002})()):
        direct, subordinate = BROKER.authorized_uid_ranges("stack_lab", subuids)
    assert BROKER.authorized_peer(1002, direct, subordinate)
    assert BROKER.authorized_peer(2000999, direct, subordinate)
    assert not BROKER.authorized_peer(3000999, direct, subordinate)


def fixture(root: Path, relative: str, quadlet: str, owner: str = "webservices-apps", capabilities=None) -> Path:
    files = {
        "bundle.json": {"backend": "podman"},
        "stack.ir.json": {},
        "podman-domains.json": {"domains": [{"name": "apps", "user": owner, "hostCapabilities": capabilities or []}]},
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
            "quadlet/rootless-apps/webservices-livekit.container",
            "[Container]\nNetwork=host\n",
        )
    )
    rejected(
        fixture(
            base / "wrong-service",
            "quadlet/rootless-apps/webservices-element.container",
            "[Container]\nNetwork=host\n",
        )
    )
    rejected(
        fixture(
            base / "wrong-owner",
            "quadlet/rootless-apps/webservices-livekit.container",
            "[Container]\nNetwork=host\n",
            owner="webservices-platform",
        )
    )
    rejected(
        fixture(
            base / "privileged",
            "quadlet/rootless-apps/webservices-livekit.container",
            "[Container]\nNetwork=host\nPrivileged=true\n",
        )
    )
    BROKER.validate_bundle(
        fixture(
            base / "kvm",
            "quadlet/rootless-apps/webservices-android.container",
            "[Container]\nAddDevice=/dev/kvm:/dev/kvm\nGroupAdd=keep-groups\n",
            capabilities=["kvm"],
        )
    )
    rejected(
        fixture(
            base / "kvm-without-capability",
            "quadlet/rootless-apps/webservices-android.container",
            "[Container]\nAddDevice=/dev/kvm:/dev/kvm\nGroupAdd=keep-groups\n",
        )
    )

print("[test-p0-host-broker] ok")


class Result:
    def __init__(self, stdout: str):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


calls = []
original_run = BROKER.run
try:
    def fake_run(*args: str, check: bool = True) -> Result:
        calls.append(args)
        if args[1] == "is-active":
            return Result("active\n")
        if args[1] == "list-dependencies":
            return Result("webservices.target\nwebservices-caddy.service\n")
        return Result("ActiveState=active\nSubState=running\nType=notify\nResult=success\nJob=\n")

    BROKER.run = fake_run
    health = BROKER.scope_health(None)
    assert health["state"] == "active" and not health["offenders"]
    assert all(call[0] == "systemctl" for call in calls)
finally:
    BROKER.run = original_run

print("[test-p0-host-broker-status] ok")

calls = []
try:
    def fake_oneshot(*args: str, check: bool = True) -> Result:
        calls.append(args)
        if args[1] == "is-active":
            return Result("active\n")
        if args[1] == "list-dependencies":
            return Result("webservices.target\nwebservices-bootstrap.service\n")
        return Result("ActiveState=inactive\nSubState=dead\nType=oneshot\nResult=success\nJob=\n")

    BROKER.run = fake_oneshot
    health = BROKER.scope_health(None)
    assert health["state"] == "active" and not health["offenders"]
finally:
    BROKER.run = original_run

print("[test-p0-host-broker-oneshot] ok")

original_user_systemctl = BROKER.user_systemctl
try:
    def missing_legacy_user(*args: str, **kwargs: object) -> Result:
        raise KeyError("legacy account absent")

    BROKER.user_systemctl = missing_legacy_user
    BROKER.stop_legacy_runtime()
finally:
    BROKER.user_systemctl = original_user_systemctl

print("[test-p0-host-broker-retired-legacy] ok")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    incoming = root / "incoming"
    snapshots = root / "snapshots"
    releases = root / "releases"
    domains = root / "podman-domains.json"
    active = root / "active.json"
    for parent, count in ((snapshots, 7), (releases, 5)):
        parent.mkdir()
        for index in range(count):
            path = parent / f"release-{index}"
            path.mkdir()
            path.touch()
            BROKER.os.utime(path, (index + 1, index + 1))
    incoming.mkdir()
    old = incoming / ("a" * 64)
    current = incoming / ("b" * 64)
    old.mkdir()
    current.mkdir()
    BROKER.os.utime(old, (1, 1))
    BROKER.os.utime(current, (1, 1))
    active.write_text(json.dumps({"release": current.name}))
    domains.write_text(json.dumps({"domains": []}))
    with patch.multiple(
        BROKER,
        INCOMING=incoming,
        SNAPSHOTS=snapshots,
        DOMAINS_MANIFEST=domains,
        ACTIVE_RELEASE=active,
        ROOTFUL_RELEASES=releases,
    ):
        preview = BROKER.garbage_collect({"dry_run": True})
        assert preview["dryRun"] and str(old) in preview["removed"]
        assert old.exists() and len(list(snapshots.iterdir())) == 7
        result = BROKER.garbage_collect({})
        assert not result["dryRun"] and not old.exists() and current.exists()
        assert len(list(snapshots.iterdir())) == BROKER.SNAPSHOT_RETENTION

print("[test-p0-host-broker-gc] ok")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    old = root / "old"
    candidate = root / "candidate"
    active_release = root / "active.json"

    def scope_tree(path: Path, config_value: str) -> None:
        (path / "runtime/configs/apps").mkdir(parents=True)
        (path / "runtime/configs/apps/app.yml").write_text(config_value)
        (path / "bundle.json").write_text('{"backend":"podman"}\n')
        (path / "stack.ir.json").write_text(json.dumps({"services": {
            "app": {"placement": "rootless", "rootlessDomain": "apps",
                    "volumes": ["./configs/apps/app.yml:/etc/app.yml"]}
        }, "networks": {}, "volumes": {}}))
        (path / "podman-domains.json").write_text(json.dumps({"domains": [
            {"name": "apps", "user": "webservices-apps"},
            {"name": "other", "user": "webservices-other"}
        ]}))
        (path / "podman-domain-dependencies.json").write_text(json.dumps({"dependencies": [
            {"providerDomain": "apps", "consumerDomain": "other"}
        ]}))

    scope_tree(old, "before\n")
    scope_tree(candidate, "after\n")
    active_release.write_text(json.dumps({"release": "old-release"}))
    with patch.object(BROKER, "ACTIVE_RELEASE", active_release), \
         patch.object(BROKER, "release_path", return_value=old), \
         patch.object(BROKER, "diagnostics", return_value={"drift": {"state": "clean"}}):
        scope = BROKER.candidate_scope(candidate)
    assert scope["affectedAuthorities"] == ["apps", "other"]
    assert scope["sharedChange"] is False

    (candidate / "ops").mkdir()
    (candidate / "ops/p0-host-broker.py").write_text("control plane change\n")
    (candidate / "scripts").mkdir()
    (candidate / "scripts/test-broker.sh").write_text("test-only change\n")
    with patch.object(BROKER, "ACTIVE_RELEASE", active_release), \
         patch.object(BROKER, "release_path", return_value=old), \
         patch.object(BROKER, "diagnostics", return_value={"drift": {"state": "clean"}}):
        scope = BROKER.candidate_scope(candidate)
    assert scope["sharedChange"] is False
    assert scope["affectedAuthorities"] == ["apps", "other"]

    (candidate / "ops/shared-runtime.conf").write_text("changed\n")
    with patch.object(BROKER, "ACTIVE_RELEASE", active_release), \
         patch.object(BROKER, "release_path", return_value=old), \
         patch.object(BROKER, "diagnostics", return_value={"drift": {"state": "clean"}}):
        scope = BROKER.candidate_scope(candidate)
    assert scope["sharedChange"] is True
    assert scope["affectedAuthorities"] == ["apps", "other", "rootful"]

print("[test-p0-host-broker-scope] ok")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    release = root / "release"
    volume = root / "volumes" / "apps-data"
    volume.mkdir(parents=True)
    (release / "runtime").mkdir(parents=True)
    (release / "stack.ir.json").write_text(json.dumps({
        "services": {"app": {"placement": "rootless", "rootlessDomain": "apps", "volumes": ["apps-data:/data"]}},
        "volumes": {"apps-data": {"rootlessStrategy": "copy"}}
    }))
    (release / "podman-domains.json").write_text(json.dumps({"domains": [
        {"name": "apps", "user": "webservices-apps", "volumeRoot": str(root / "volumes")}
    ]}))
    (volume / "health.txt").write_text("synthetic-health\n")
    (volume / "escape").symlink_to("/etc/passwd")
    active = root / "active.json"
    active.write_text('{"release":"fixture"}\n')
    grants = root / "break-glass"
    grants.mkdir()
    grant = {"id": "grant-1", "state": "approved", "service": "app", "expiresAt": 9999999999}
    (grants / "grant-1.json").write_text(json.dumps(grant))
    with patch.object(BROKER, "ACTIVE_RELEASE", active), \
         patch.object(BROKER, "BREAK_GLASS", grants), \
         patch.object(BROKER, "release_path", return_value=release):
        result = BROKER.read_break_glass({"request_id": "grant-1", "path": "health.txt"}, 1001)
        assert result["content"] == "c3ludGhldGljLWhlYWx0aAo="
        audit = (grants / "audit.jsonl").read_text()
        assert "synthetic-health" not in audit and '"peerUid": 1001' in audit
        try:
            BROKER.read_break_glass({"request_id": "grant-1", "path": "escape"}, 1001)
        except OSError:
            pass
        else:
            raise AssertionError("break-glass read followed a symlink")
        try:
            BROKER.read_break_glass({"request_id": "grant-1", "path": "../health.txt"}, 1001)
        except BROKER.RequestError:
            pass
        else:
            raise AssertionError("break-glass read accepted traversal")

print("[test-p0-host-broker-break-glass] ok")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    rootful_releases = root / "rootful" / "releases"
    rootful_current = root / "rootful" / "current"
    domain_state = root / "domain"
    (rootful_releases / "one").mkdir(parents=True)
    (domain_state / "releases" / "one").mkdir(parents=True)
    (rootful_releases / "one" / ".platform-zero-release").write_text("a" * 64 + "\n")
    (domain_state / "releases" / "one" / ".platform-zero-release").write_text("a" * 64 + "\n")
    rootful_current.symlink_to(rootful_releases / "one")
    (domain_state / "current").symlink_to(domain_state / "releases" / "one")
    domains_manifest = root / "domains.json"
    domains_manifest.write_text(json.dumps({"domains": [{"name": "apps", "stateRoot": str(domain_state)}]}))
    active = root / "active.json"
    active.write_text(json.dumps({"release": "a" * 64, "authorities": {"rootful": "a" * 64, "apps": "a" * 64}}))

    def version_result(*args: str, check: bool = True) -> Result:
        return Result("podman version 5.4.2\n" if args[0] == "podman" else "systemd 257\n")

    with patch.object(BROKER, "status", return_value={"rootful": "active", "domains": []}), \
         patch.object(BROKER, "run", side_effect=version_result), \
         patch.object(BROKER, "ACTIVE_RELEASE", active), \
         patch.object(BROKER, "ROOTFUL_RELEASES", rootful_releases), \
         patch.object(BROKER, "DOMAINS_MANIFEST", domains_manifest), \
         patch.object(BROKER, "OPERATIONS", root / "operations"), \
         patch.object(BROKER, "STACK_ROOT", root):
        report = BROKER.diagnostics({})
        assert report["drift"]["state"] == "clean"
        assert report["versions"]["podman"] == "podman version 5.4.2"
        assert "disks" in report["resources"]
        (domain_state / "releases" / "one" / ".platform-zero-release").write_text("b" * 64 + "\n")
        report = BROKER.diagnostics({})
        assert report["drift"]["state"] == "drifted"

print("[test-p0-host-broker-diagnostics] ok")
