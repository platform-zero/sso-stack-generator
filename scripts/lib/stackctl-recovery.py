#!/usr/bin/env python3
"""Public native STOPPED backup/restore through the canonical journal owner.

--plan is read-only, not an operation permit. Execution requires all four exact
native selection pins, retains the canonical lock OFD at FD9, publishes source
custody through the journal, and consumes one process-local operation lease.
No caller proof JSON, alternate age path, manager start, stop, or auto-recovery.
"""
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
# Reviewed frozen public native lifecycle source, not a live self-approved hash.
OPERATIONS_SHA256 = '13a3056fa239ef99e4681f0e334419bb41e730e1e686488e05b27f74d2ba19e3'


def operations():
    source = Path(__file__).with_name('stackctl-operations.py')
    spec = importlib.util.spec_from_file_location('stackctl_recovery_operations', source)
    module = importlib.util.module_from_spec(spec)
    body = source.read_bytes()
    if hashlib.sha256(body).hexdigest() != OPERATIONS_SHA256:
        raise ValueError('Reviewed native public operations source changed')
    exec(compile(body, str(source), 'exec'), module.__dict__)
    module._recovery_compiled_source_sha256 = OPERATIONS_SHA256
    return module


def operate(action, root, expected=None, operation=None, plan=False, ops=None):
    if action not in ('backup', 'restore'): raise ValueError('Exact native recovery action required')
    ops = ops or operations()
    journal = ops.journal_module()
    with ops.installer_lock(root) as locked, ops.canonical_lock_fd(locked[2]):
        release, intent, proof, plans, observed = ops.snapshot(root, journal)
        if plan:
            source = ops.runtime_api(release).verify_prepared_units(root, release, intent)
            return dict(schemaVersion=1, operation=action, **proof,
                        selectionSourceSha256=source['selectionSourceSha256'],
                        nativeStopped=ops.stopped(plans, observed), operationAuthorized=False,
                        installedAcceptance=False, restart=False)
        ops.check_expected(proof, expected or {})
        # Only the selected release's complete liveOps closure may supply the
        # canonical mutation owner, not a newer/stale public-tree journal.
        selected_journal = ops.runtime_api(release).o.journal
        if not callable(getattr(selected_journal, 'native_recovery', None)):
            raise ValueError('Selected release lacks native recovery owner; no historical adoption')
        if not isinstance(operation, dict) or (operation.get('kind') != action
                and not (action == 'restore' and operation.get('kind') == 'recover-originals')):
            raise ValueError('Typed exact backup/restore operation required')
        return selected_journal.native_recovery(root, proof['intentSha256'], operation, ops)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('backup', 'restore'))
    parser.add_argument('--state-root', required=True, type=Path)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--expected-release')
    parser.add_argument('--expected-intent-sha256')
    parser.add_argument('--expected-receipt-sha256')
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--recipient')
    parser.add_argument('--archive-sha256')
    parser.add_argument('--identity-file', type=Path)
    parser.add_argument('--recover-originals', action='store_true')
    parser.add_argument('--recovery-journal-sha256')
    args = parser.parse_args(argv)
    expected = dict(selectedRelease=args.expected_release, intentSha256=args.expected_intent_sha256,
                    receiptSha256=args.expected_receipt_sha256, planSha256=args.expected_plan_sha256)
    if args.plan:
        if any((args.archive, args.recipient, args.archive_sha256, args.identity_file, args.recover_originals, args.recovery_journal_sha256)):
            parser.error('--plan does not take archive/key/recipient options')
        operation = None
    else:
        if not all(expected.values()):
            parser.error('Execution requires all four exact selection pins')
        if args.recover_originals:
            if args.command != 'restore' or not args.recovery_journal_sha256 or any((args.archive, args.recipient, args.archive_sha256, args.identity_file)):
                parser.error('restore --recover-originals takes only --recovery-journal-sha256 plus exact native pins')
            operation = dict(kind='recover-originals', recoveryJournalSha256=args.recovery_journal_sha256)
        elif args.recovery_journal_sha256 or args.archive is None:
            parser.error('Normal backup/restore requires --archive and no recovery journal option')
        elif args.command == 'backup':
            if not args.recipient or args.archive_sha256 or args.identity_file:
                parser.error('backup requires only --archive and --recipient')
            operation = dict(kind='backup', archive=str(args.archive), recipient=args.recipient)
        else:
            if not args.archive_sha256 or args.identity_file is None or args.recipient:
                parser.error('restore requires --archive, --archive-sha256 and --identity-file')
            operation = dict(kind='restore', archive=str(args.archive), archiveSha256=args.archive_sha256,
                             identityFile=str(args.identity_file))
    try:
        result = operate(args.command, args.state_root, expected, operation, args.plan)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print('stackctl: stopped recovery refused; preserve protected journal/originals and inspect exact source/lease', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__': raise SystemExit(main())
