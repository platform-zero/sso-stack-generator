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

with tempfile.TemporaryDirectory() as temporary:
    original_operations = BROKER.OPERATIONS
    try:
        BROKER.OPERATIONS = Path(temporary)
        interrupted_id = "a" * 32
        BROKER.write_record({"id": interrupted_id, "kind": "test", "suite": "ts-unit",
                             "state": "running", "phase": "execution"})
        with patch.object(BROKER, "run", return_value=type(
            "Inactive", (), {"returncode": 3, "stdout": "", "stderr": ""}
        )()):
            recovered = BROKER.operation_status({"operation_id": interrupted_id})
        assert recovered["state"] == "failed"
        assert recovered["failureStage"] == {"kind": "worker-interrupted"}
        assert "stderr" not in recovered
    finally:
        BROKER.OPERATIONS = original_operations

print("[test-p0-host-broker-test-worker-recovery] ok")

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

    with patch.object(BROKER, "ACTIVE_RELEASE", active_release), \
         patch.object(BROKER, "release_path", return_value=old), \
         patch.object(BROKER, "diagnostics", return_value={"drift": {"state": "drifted"}}):
        scope = BROKER.candidate_scope(candidate)
    assert scope["sharedChange"] is True
    assert scope["affectedAuthorities"] == ["apps", "other", "rootful"]

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    old = root / "old"
    candidate = root / "candidate"
    active_release = root / "active.json"

    def config_scope_tree(path: Path, config_value: str) -> None:
        (path / "build/stack.config/jupyterhub").mkdir(parents=True)
        (path / "build/stack.config/jupyterhub/jupyterhub_config.py").write_text(config_value)
        (path / "bundle.json").write_text('{"backend":"podman"}\n')
        (path / "stack.ir.json").write_text(json.dumps({"services": {
            "jupyterhub": {"placement": "rootless", "rootlessDomain": "workloads", "volumes": []}
        }, "networks": {}, "volumes": {}}))
        (path / "podman-domains.json").write_text(json.dumps({"domains": [
            {"name": "workloads", "user": "webservices-workloads"},
            {"name": "apps", "user": "webservices-apps"}
        ]}))
        (path / "podman-domain-dependencies.json").write_text(json.dumps({"dependencies": []}))

    config_scope_tree(old, "before\n")
    config_scope_tree(candidate, "after\n")
    active_release.write_text(json.dumps({"release": "old-release"}))
    with patch.object(BROKER, "ACTIVE_RELEASE", active_release), \
         patch.object(BROKER, "release_path", return_value=old), \
         patch.object(BROKER, "diagnostics", return_value={"drift": {"state": "clean"}}):
        scope = BROKER.candidate_scope(candidate)
    assert scope["affectedAuthorities"] == ["workloads"]
    assert scope["changedServices"] == []
    assert scope["sharedChange"] is False

print("[test-p0-host-broker-scope] ok")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    release = root / "release"
    volume = root / "volumes" / "apps-data"
    test_results = root / "test-runner-results"
    volume.mkdir(parents=True)
    test_results.mkdir()
    (release / "runtime").mkdir(parents=True)
    (release / "stack.ir.json").write_text(json.dumps({
        "services": {
            "app": {"placement": "rootless", "rootlessDomain": "apps", "volumes": ["apps-data:/data"]},
            "test-runner-managed": {"placement": "rootless", "rootlessDomain": "test-runners", "volumes": []},
        },
        "volumes": {"apps-data": {"rootlessStrategy": "copy"}}
    }))
    (release / "podman-domains.json").write_text(json.dumps({"domains": [
        {"name": "apps", "user": "webservices-apps", "volumeRoot": str(root / "volumes")},
        {"name": "test-runners", "user": "webservices-test-runners", "volumeRoot": str(root / "test-runner-volumes")},
    ]}))
    (volume / "health.txt").write_text("synthetic-health\n")
    (volume / "escape").symlink_to("/etc/passwd")
    (test_results / "summary.txt").write_text("synthetic-test-summary\n")
    (test_results / "escape").symlink_to("/etc/passwd")
    active = root / "active.json"
    active.write_text('{"release":"fixture"}\n')
    grants = root / "break-glass"
    grants.mkdir()
    grant = {"id": "grant-1", "state": "approved", "service": "app", "expiresAt": 9999999999}
    (grants / "grant-1.json").write_text(json.dumps(grant))
    runner_grant = {"id": "grant-2", "state": "approved", "service": "test-runner-managed", "expiresAt": 9999999999}
    (grants / "grant-2.json").write_text(json.dumps(runner_grant))
    with patch.object(BROKER, "ACTIVE_RELEASE", active), \
         patch.object(BROKER, "BREAK_GLASS", grants), \
         patch.object(BROKER, "TEST_RUNNER_RESULTS", test_results), \
         patch.object(BROKER, "release_path", return_value=release):
        result = BROKER.read_break_glass({"request_id": "grant-1", "path": "health.txt"}, 1001)
        assert result["content"] == "c3ludGhldGljLWhlYWx0aAo="
        assert BROKER.service_volume_roots(release, "test-runner-managed") == [test_results]
        assert test_results not in BROKER.service_volume_roots(release, "app")
        summary = BROKER.read_break_glass({"request_id": "grant-2", "path": "summary.txt"}, 1001)
        assert summary["content"] == "c3ludGhldGljLXRlc3Qtc3VtbWFyeQo="
        audit = (grants / "audit.jsonl").read_text()
        assert "synthetic-health" not in audit and '"peerUid": 1001' in audit
        try:
            BROKER.read_break_glass({"request_id": "grant-1", "path": "escape"}, 1001)
        except OSError:
            pass
        else:
            raise AssertionError("break-glass read followed a symlink")
        try:
            BROKER.read_break_glass({"request_id": "grant-2", "path": "escape"}, 1001)
        except OSError:
            pass
        else:
            raise AssertionError("test-runner break-glass read followed a symlink")
        try:
            BROKER.read_break_glass({"request_id": "grant-1", "path": "../health.txt"}, 1001)
        except BROKER.RequestError:
            pass
        else:
            raise AssertionError("break-glass read accepted traversal")

print("[test-p0-host-broker-break-glass] ok")

with tempfile.TemporaryDirectory() as temporary:
    release = Path(temporary)
    (release / "podman-domains.json").write_text(json.dumps({
        "domains": [{"name": "platform", "user": "webservices-platform"}],
    }))
    original_release_path = BROKER.release_path
    original_user_systemctl = BROKER.user_systemctl
    original_run = BROKER.run
    try:
        BROKER.release_path = lambda _request: release
        BROKER.user_systemctl = lambda *_args, **_kwargs: Result("unit status\n")
        with patch.object(BROKER.pwd, "getpwnam", return_value=type("Record", (), {"pw_uid": 992})()):
            BROKER.run = lambda *args, **_kwargs: Result(
                "FATAL invalid issuer configuration\nresponse body contains-private-value\n"
            ) if args[0] == "journalctl" else Result("")
            evidence = BROKER.logs({
                "unit": "webservices-keycloak-auth-gateway.service",
                "domain": "platform",
                "release": "a" * 64,
            })
        assert evidence["scrubbed"] is True
        assert "FATAL invalid issuer configuration" in evidence["output"]
        assert "contains-private-value" not in evidence["output"]
    finally:
        BROKER.release_path = original_release_path
        BROKER.user_systemctl = original_user_systemctl
        BROKER.run = original_run

print("[test-p0-host-broker-logs] ok")

summary = BROKER.summarize_test_output(
    """1 failed, 12 passed (4m)
       1) [chromium] › tests/visual/mastodon.spec.ts:87:4 › Visual Smoke › Authenticated snapshots › Mastodon snapshot
       Error: JupyterHub authenticated page did not satisfy smoke contract; Request body: user@example.test secret-value
       [p0-test-evidence] smoke-readiness=spawn-pending route=jupyterhub
    """
)
assert summary == {
    "counts": {"passed": 12, "failed": 1},
    "failures": [{
        "spec": "tests/visual/mastodon.spec.ts",
        "line": 87,
        "testName": "Mastodon snapshot",
    }],
    "failureKinds": ["smoke-contract"],
    "failureDiagnostics": [],
    "readinessStates": ["spawn-pending"],
    "readinessByRoute": {"jupyterhub": ["spawn-pending"]},
    "readinessStagesByRoute": {},
}
assert "Visual Smoke" not in json.dumps(summary)
assert "Mastodon snapshot" in json.dumps(summary)
assert BROKER.summarize_test_output("private app payload with no test totals") is None
diagnostic = BROKER.summarize_test_output(
    """1 failed
       1) [chromium] › tests/visual/jupyterhub.spec.ts:42:2 › JupyterHub snapshot
       Error: page.goto: Navigation timeout of 30000ms exceeded
       [p0-test-evidence] jupyterhub-prepare=start-button-visible route=jupyterhub
       [p0-test-evidence] jupyterhub-prepare=start-transition-timeout route=jupyterhub
       [p0-test-evidence] huly-prepare=login-submit-started route=huly
       [p0-test-evidence] huly-prepare=workspace-timeout route=huly
       [p0-test-evidence] huly-prepare=initial-other-shell route=huly
       [p0-test-evidence] huly-prepare=initial-ui-other route=huly
       [p0-test-evidence] huly-prepare=initial-fields-none route=huly
       Request body: user@example.test secret-value
       https://private.invalid/path
    """
)
assert diagnostic["failureDiagnostics"] == [
    {"route": "jupyterhub", "category": "navigation-timeout"},
]
assert diagnostic["readinessStagesByRoute"] == {
    "huly": ["initial-fields-none", "initial-other-shell", "initial-ui-other",
             "login-submit-started", "workspace-timeout"],
    "jupyterhub": ["start-button-visible", "start-transition-timeout"],
}
assert "user@example.test" not in json.dumps(diagnostic)
assert "secret-value" not in json.dumps(diagnostic)
assert "private.invalid" not in json.dumps(diagnostic)
classified = BROKER.classify_test_failure(
    "[test-runner] command failed at line=1021 status=1\nError: network does not exist "
    "private-network-name user=synthetic-user token=private-secret\n"
)
assert classified == {"kind": "runner-network-unavailable", "line": 1021}
assert "private-network-name" not in json.dumps(classified)
assert "private-secret" not in json.dumps(classified)
print("[test-p0-host-broker-test-summary] ok")

with tempfile.TemporaryDirectory() as temporary:
    manifest = Path(temporary) / "domains.json"
    manifest.write_text(json.dumps({"domains": [{"name": "workloads", "user": "webservices-workloads"}]}))
    podman_output = json.dumps([
        {"Names": ["jupyter-synth-a"], "State": "running", "Mounts": ["must-not-escape"]},
        {"Names": "jupyter-synth-b", "State": "exited", "Labels": {"user": "must-not-escape"}},
        {"Names": ["unrelated-service"], "State": "running"},
    ])
    fake_account = type("Account", (), {"pw_uid": 1200, "pw_dir": "/home/webservices-workloads"})()
    def fake_jupyter_runtime(*args: str, check: bool = True) -> Result:
        if args[0] == "podman" and "ps" in args:
            return Result(podman_output)
        if args[0] == "podman" and "images" in args:
            return Result(json.dumps([{"Names": ["private-tag"]}, {
                "Names": ["localhost/webservices/jupyter-notebook-build:bundle"],
            }]))
        if args[0] == "podman" and "network" in args:
            return Result(json.dumps([{"name": "private-network"}, {
                "name": "webservices_workloads_ai",
            }]))
        if args[0] == "podman" and "logs" in args:
            return Result("Spawner error: permission denied; password=private-secret\n")
        return Result("")

    with patch.object(BROKER, "DOMAINS_MANIFEST", manifest), \
         patch.object(BROKER.pwd, "getpwnam", return_value=fake_account), \
         patch.object(BROKER, "run", side_effect=fake_jupyter_runtime) as podman:
        readiness = BROKER.jupyterhub_readiness()
        assert readiness == {"state": "reported", "authorityContainers": 3, "userServers": {
            "running": 1, "created": 0, "exited": 1, "paused": 0, "other": 0,
        }, "notebookImage": "present", "notebookNetwork": "present",
            "applicationLogState": "available",
            "runtimeSignals": ["volume-permission-error"]}
        assert "must-not-escape" not in json.dumps(readiness)
        assert "private-secret" not in json.dumps(readiness)
        assert "private-tag" not in json.dumps(readiness)
        assert "private-network" not in json.dumps(readiness)
        assert podman.call_args_list[0].args == (
            "podman", "--remote", "--url", "unix:///run/user/1200/podman/podman.sock",
            "ps", "--all", "--format", "json",
        )
        with patch.object(BROKER, "read_record", return_value={
            "id": "visual-test", "kind": "test", "suite": "ts-e2e-visual", "state": "running",
        }):
            status = BROKER.operation_status({"operation_id": "visual-test"})
        assert status["jupyterHubReadiness"] == readiness
        assert "Names" not in json.dumps(status) and "Labels" not in json.dumps(status)
        assert BROKER.jupyterhub_log_signals(
            "Spawn failed for synthetic-user; token=secret and private content"
        ) == ["spawner-error"]
        assert "secret" not in json.dumps(BROKER.jupyterhub_log_signals("token=secret"))
    with patch.object(BROKER, "DOMAINS_MANIFEST", manifest), \
         patch.object(BROKER.pwd, "getpwnam", return_value=fake_account), \
         patch.object(BROKER, "run", return_value=type("Failure", (), {"returncode": 1, "stdout": "secret"})()):
        assert BROKER.jupyterhub_readiness() == {
            "state": "unavailable", "reason": "runtime-query-failed", "exitCode": 1,
        }

print("[test-p0-host-broker-jupyterhub-readiness] ok")

try:
    BROKER.test_suite({"suite": "kt-live-ingestion"})
except BROKER.RequestError:
    pass
else:
    raise AssertionError("live-data suite escaped the synthetic test allowlist")

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    current = root / "current"
    runner = current / "build/stack.containers/test-runner/run-tests.sh"
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\nexit 0\n")
    runner.chmod(0o755)
    with patch.object(BROKER, "TEST_RUNNER_CURRENT", current), \
         patch.object(BROKER, "OPERATIONS", root / "operations"), \
         patch.object(BROKER, "run") as queue:
        queued = BROKER.test_suite({"suite": "ts-sso"})
        assert queued["kind"] == "test" and queued["state"] == "queued"
        focused = BROKER.test_suite({"suite": "ts-e2e-jupyterhub"})
        assert focused["kind"] == "test" and focused["suite"] == "ts-e2e-jupyterhub"
        assert queue.call_count == 2
        with patch.object(BROKER, "test_runner_account", return_value=("webservices-test-runners", "/home/webservices-test-runners", 997)), \
             patch.object(BROKER.subprocess, "run", return_value=Result("safe test output")) as run_suite:
            completed = BROKER.run_test_operation(queued["id"])
            command = run_suite.call_args.args[0]
            assert command[:4] == ["/usr/sbin/runuser", "-u", "webservices-test-runners", "--"]
            assert "TEST_RUNNER_NETWORK_MODE=isolated" in command
        assert completed["state"] == "succeeded" and completed["exitCode"] == 0
        assert "stdout" not in completed and "stderr" not in completed
        with patch.object(BROKER, "test_runner_account", return_value=("webservices-test-runners", "/home/webservices-test-runners", 997)), \
             patch.object(BROKER.subprocess, "run", return_value=Result("safe focused output")) as focused_run:
            focused_completed = BROKER.run_test_operation(focused["id"])
            focused_command = focused_run.call_args.args[0]
        assert focused_completed["state"] == "succeeded"
        assert focused_command[-2:] == ["ts-e2e-name", "JupyterHub snapshot"]
        failed_id = "f" * 32
        BROKER.write_record({"id": failed_id, "kind": "test", "state": "queued", "suite": "ts-unit"})

        class FailedRunner:
            returncode = 1
            stdout = "private output\n[test-runner] command failed at line=42 status=1\n"

        with patch.object(BROKER, "test_runner_account", return_value=("webservices-test-runners", "/home/webservices-test-runners", 997)), \
             patch.object(BROKER.subprocess, "run", return_value=FailedRunner()):
            failed = BROKER.run_test_operation(failed_id)
        assert failed["failureStage"] == {"kind": "runner-command", "line": 42}
        assert "private output" not in json.dumps(failed)
        timeout_id = "e" * 32
        BROKER.write_record({"id": timeout_id, "kind": "test", "state": "queued",
                             "suite": "ts-e2e-jupyterhub"})
        timeout_output = "1 failed\n1) [chromium] › tests/visual/jupyterhub.spec.ts:42:2 › JupyterHub snapshot\nNavigation timeout private-secret\n".encode()
        with patch.object(BROKER, "test_runner_account", return_value=("webservices-test-runners", "/home/webservices-test-runners", 997)), \
             patch.object(BROKER.subprocess, "run", side_effect=BROKER.subprocess.TimeoutExpired(
                 "runner", 900, output=timeout_output)):
            timed_out = BROKER.run_test_operation(timeout_id)
        assert timed_out["state"] == "failed" and timed_out["exitCode"] == 124
        assert timed_out["failureStage"] == {"kind": "execution-timeout"}
        assert "private-secret" not in json.dumps(timed_out)
        assert timed_out["testSummary"]["failureDiagnostics"] == [
            {"route": "jupyterhub", "category": "navigation-timeout"},
        ]

print("[test-p0-host-broker-synthetic-tests] ok")

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
