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
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "status":
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
    except (ContractError, OSError, sqlite3.Error, RecursionError) as error:
        # Never print values from arbitrary input, raw paths, exception locals,
        # subprocess output or rendered configuration.
        message = str(error) if isinstance(error, ContractError) else "input or state unavailable"
        print(json.dumps({"schemaVersion": 1, "error": message, "installationCertified": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
