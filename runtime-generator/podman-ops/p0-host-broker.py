#!/usr/bin/env python3
"""Socket-activated, allowlisted Platform Zero host operations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
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


class RequestError(Exception):
    pass


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
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
    for path in (bundle / "quadlet").glob("rootless-*/*.container"):
        text = path.read_text()
        if "Network=host" in text or "Privileged=true" in text:
            raise RequestError(f"unsafe rootless Quadlet: {path.relative_to(bundle)}")
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


def user_systemctl(user: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    record = pwd.getpwnam(user)
    return run(
        "/usr/sbin/runuser", "-u", user, "--", "env",
        f"HOME={record.pw_dir}", f"XDG_RUNTIME_DIR=/run/user/{record.pw_uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{record.pw_uid}/bus",
        "systemctl", "--user", *args, check=check,
    )


def preflight(request: dict[str, object]) -> dict[str, object]:
    path = release_path(request)
    run("nft", "-c", "-f", str(path / "ops/platform-zero.nft"))
    with tempfile.TemporaryDirectory(prefix="p0-preflight-") as temporary:
        working = Path(temporary) / "bundle"
        shutil.copytree(path, working)
        result = run(str(working / "ops/install-podman-bundle.sh"), "--bundle", str(working))
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
    preflight(request)
    user_systemctl(LEGACY_USER, "stop", "webservices.target", check=False)
    apply_platform_zero_nftables(path / "ops/platform-zero.nft")
    env = os.environ.copy()
    env["WEBSERVICES_ACTIVATION_ROLLBACK"] = "0"
    with tempfile.TemporaryDirectory(prefix="p0-activate-") as temporary:
        working = Path(temporary) / "bundle"
        shutil.copytree(path, working)
        result = subprocess.run(
            [str(working / "ops/install-podman-bundle.sh"), "--bundle", str(working), "--activate"],
            text=True, capture_output=True, check=False, env=env,
        )
    if result.returncode:
        details = (result.stdout + "\n" + result.stderr)[-16000:]
        raise RequestError(f"activation failed ({result.returncode}); fix-forward required\n{details}")
    return {"release": path.name, "output": result.stdout[-8000:]}


def status(_: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {"rootful": run("systemctl", "is-active", "webservices.target", check=False).stdout.strip()}
    domains_file = DOMAINS_MANIFEST if DOMAINS_MANIFEST.is_file() else None
    if domains_file is None and INCOMING.exists():
        domains_file = next((path / "podman-domains.json" for path in sorted(INCOMING.iterdir(), reverse=True) if len(path.name) == 64 and path.is_dir()), None)
    domains = []
    if domains_file and domains_file.is_file():
        for item in json.loads(domains_file.read_text()).get("domains", []):
            state = user_systemctl(item["user"], "is-active", "webservices.target", check=False).stdout.strip()
            domains.append({"name": item["name"], "user": item["user"], "state": state})
    result["domains"] = domains
    return result


def verify(request: dict[str, object]) -> dict[str, object]:
    path = release_path(request)
    preflight(request)
    current = status({})
    inactive = [item["name"] for item in current["domains"] if item["state"] != "active"]
    if current["rootful"] != "active" or inactive:
        raise RequestError(f"inactive Platform Zero targets: rootful={current['rootful']} domains={inactive}")
    return current


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
    return {"output": (result.stdout + result.stderr)[-16000:]}


ACTIONS = {"stage": stage, "preflight": preflight, "snapshot": snapshot, "activate": activate, "status": status, "verify": verify, "logs": logs, "restore": restore, "finalize-access": finalize_access}


def handle(raw: bytes) -> dict[str, object]:
    try:
        request = json.loads(raw)
        if not isinstance(request, dict) or request.get("version") != 1:
            raise RequestError("request version must be 1")
        action = str(request.get("action", ""))
        if action not in ACTIONS:
            raise RequestError(f"unsupported action: {action}")
        return {"ok": True, "result": ACTIONS[action](request)}
    except (RequestError, ValueError, OSError, KeyError) as error:
        return {"ok": False, "error": str(error)}


def main() -> None:
    expected_uid = pwd.getpwnam("stack_lab").pw_uid
    listener = socket.socket(fileno=SOCKET_FD)
    while True:
        connection, _ = listener.accept()
        with connection:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != expected_uid:
                connection.sendall(json.dumps({"ok": False, "error": "unauthorized peer"}).encode() + b"\n")
                continue
            raw = b""
            while b"\n" not in raw and len(raw) <= MAX_REQUEST:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                raw += chunk
            response = handle(raw.split(b"\n", 1)[0]) if len(raw) <= MAX_REQUEST else {"ok": False, "error": "request too large"}
            connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


if __name__ == "__main__":
    main()
