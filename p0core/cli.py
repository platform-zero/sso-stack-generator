"""Explicit-input CLI. No discovery of site configuration or secrets."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .bundle import build, verify
from .journal import Journal
from .model import Catalog, ContractError, canonical
from .lifecycle import Lifecycle, OperationError
from .readiness import ReadinessError


def parser():
    result = argparse.ArgumentParser(prog="p0", description="P0 v2 service graph and Quadlet tooling")
    result.add_argument("--version", action="version", version=__version__)
    sub = result.add_subparsers(dest="command", required=True)
    for command in ("validate", "plan", "build"):
        child = sub.add_parser(command)
        child.add_argument("--catalog", type=Path, required=True)
        if command != "validate":
            child.add_argument("--target", action="append", required=True)
        if command == "build":
            child.add_argument("--output", type=Path, required=True)
    child = sub.add_parser("verify-bundle", help="verify bytes, not installed workflows")
    child.add_argument("--bundle", type=Path, required=True)
    child = sub.add_parser("status", help="read-only operation-journal observation")
    child.add_argument("--state-dir", type=Path, required=True)
    for command in ("install", "start", "stop", "runtime-status", "secret-generate"):
        child = sub.add_parser(command, help="owned rootless runtime only")
        child.add_argument("--state-dir", type=Path, required=True)
        child.add_argument("--quadlet-dir", type=Path, required=True)
        if command == "install":
            child.add_argument("--bundle", type=Path, required=True)
            child.add_argument("--expected-sha256", required=True)
            child.add_argument("--pull", action="store_true")
            child.add_argument("--resume-stopped", action="store_true", help="same owned release only; no unit overwrite")
        elif command == "secret-generate":
            child.add_argument("--name", required=True)
        elif command in ("start", "stop"):
            child.add_argument("--target", action="append", required=True)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in ("install", "start", "stop", "runtime-status", "secret-generate"):
            runtime = Lifecycle(args.state_dir, args.quadlet_dir)
            if args.command == "install":
                output = runtime.install(args.bundle, args.expected_sha256, pull=args.pull,
                                         resume_stopped=args.resume_stopped)
            elif args.command == "secret-generate":
                output = runtime.generate_service_secret(args.name)
            elif args.command == "runtime-status":
                output = runtime.status()
            else:
                output = runtime.change(args.command, args.target)
        elif args.command == "status":
            output = Journal.status(args.state_dir / "operations.sqlite3")
        elif args.command == "verify-bundle":
            lock = verify(args.bundle)
            output = {"schemaVersion": 1, "verified": "bundle-bytes-only",
                      "inputSha256": lock["plan"]["inputSha256"], "installationCertified": False}
        else:
            catalog = Catalog.read(args.catalog)
            if args.command == "validate":
                output = {"schemaVersion": 1, "valid": True, "scope": "graph-contract-only",
                          "modules": len(catalog.modules), "services": len(catalog.services),
                          "installationCertified": False}
            elif args.command == "plan":
                output = catalog.plan(args.target)
            else:
                output = build(catalog, args.target, args.output)
        print(canonical(output).decode())
        return 0
    except (ContractError, OperationError, ReadinessError, OSError, sqlite3.Error, RecursionError) as error:
        # Never print values from arbitrary input, raw paths, exception locals,
        # subprocess output or rendered configuration.
        message = str(error) if isinstance(error, (ContractError, OperationError, ReadinessError)) else "input or state unavailable"
        print(json.dumps({"schemaVersion": 1, "error": message, "installationCertified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
