"""Immutable, secret-free build publication and exact file-set verification."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath

from .model import Catalog, ContractError, canonical, load_json
from .render import render


def build(catalog: Catalog, targets: list[str], destination: Path) -> dict:
    plan, rendered = render(catalog, targets)
    if destination.exists() or destination.is_symlink():
        raise ContractError("build destination must not exist")
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir() or destination.name in (".", "..", ""):
        raise ContractError("invalid build destination")
    temporary = Path(tempfile.mkdtemp(prefix=".p0-build-", dir=parent))
    try:
        files = {}
        for name, content in sorted(rendered.items()):
            encoded = content.encode()
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            path.chmod(0o444)
            files[name] = hashlib.sha256(encoded).hexdigest()
        lock = {"schemaVersion": 1, "kind": "p0-quadlet-bundle", "plan": plan,
                "images": {name: catalog.services[name].image for name in plan["services"]},
                "serviceSpecs": {name: catalog.services[name].declaration for name in plan["services"]},
                "files": files, "installationCertified": False}
        with (temporary / "bundle.json").open("xb") as output:
            output.write(canonical(lock) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        (temporary / "bundle.json").chmod(0o444)
        # Fail closed if a competing publication has appeared, even if empty.
        # link the directory with renameat2(RENAME_NOREPLACE) on Linux; never
        # replace an existing empty directory with ordinary rename.
        import ctypes
        import errno
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise ContractError("atomic no-replace publication unavailable")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        target = parent / destination.name
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(target), 1) != 0:
            raise ContractError("build destination publication refused")
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return lock
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def verify(directory: Path) -> dict:
    if directory.is_symlink():
        raise ContractError("bundle root must not be a symlink")
    root = directory.resolve(strict=True)
    paths = list(root.rglob("*"))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in paths):
        raise ContractError("bundle contains unsupported filesystem object")
    lock = load_json(root / "bundle.json")
    from .model import fields
    fields(lock, {"schemaVersion", "kind", "plan", "images", "serviceSpecs", "files", "installationCertified"})
    if (type(lock["schemaVersion"]) is not int or lock["schemaVersion"] != 1
            or lock["kind"] != "p0-quadlet-bundle" or lock["installationCertified"] is not False
            or not isinstance(lock["files"], dict)):
        raise ContractError("invalid bundle contract")
    expected = {"bundle.json"}
    for name, checksum in lock["files"].items():
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or str(path) != name
                or name == "bundle.json" or not path.parts):
            raise ContractError("unsafe bundle member")
        import re
        if not isinstance(checksum, str) or not re.fullmatch("[0-9a-f]{64}", checksum):
            raise ContractError("invalid bundle checksum")
        candidate = root / name
        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != checksum:
            raise ContractError("bundle content mismatch")
        expected.add(name)
    actual = {path.relative_to(root).as_posix() for path in paths if path.is_file()}
    if actual != expected:
        raise ContractError("bundle file set mismatch")
    return lock
