#!/usr/bin/env python3
"""Explicit native upgrade / data rollback coordinator (no standalone authority).

CURRENT CALLABLE INTEGRATION: NativeCoordinator(binding, journal, recovery)
provides plan(), settle_failed(operation_id, authorize), restore_checkpoint(
archive, archive_sha256, identity_file, operation_id, authorize) and
recover_interrupted(expected_recovery_sha256, authorize). It uses the existing
canonical journal lock, failed/quarantine boundary and actual recovery.Backend
API. Controller retains its existing typed-operation lease/admission. There is
no standalone mutation CLI or activation fallback. NATIVE_BINDING_KEYS defines
its exact source/selection/marker/CAS input. --plan-native --request FILE
--request-sha256 SHA exposes its read-only plan from a root 0600 binding file.
The operator/group 2770 storage scope is canonical ownership, not foreign data;
only metadata, release sources and authority files require root sealing here.
The real recovery owner supports receipted recoveryCustody plus the existing
stopped lease for operator-writable parents, but NOT cross-release checkpoints.
This coordinator passes that lease without manufacturing custody or admission;
plan does not claim recovery/upgrade acceptance. Source rollback is NOT data compatibility.

OPTIONAL FUTURE CROSS-RELEASE DISPATCH (still fail closed without owner hooks):
Dispatch: python3 host-upgrade.py --request /ROOT/REQUEST.json --request-sha256 SHA
The request is root-owned mode 0600, immutable for the dispatch, and contains the
exact REQUEST_KEYS below. No environment options, alternate installer, automatic
retry, daemon, old-release restart, cache pruning, or data deletion are provided.

REQUIRED INTEGRATION (deliberately fail closed on today's unextended installer):
* The canonical sibling install-journal.py must export HOST_UPGRADE_API = 1 and
  host_upgrade_transaction(binding), a context manager holding the CANONICAL
  installer lock for its entire lifetime. __enter__ MUST atomically recheck the
  binding's intent CAS, marker, receipts, source tree, checkpoint and admission,
  without changing the bound inputs. admit() then consumes existing installer
  admission and durably journals operationId. A rejected admit() must not touch
  workloads/data; a partially consumed intent stays pending for explicit review.
  It must not stop/start/migrate before the coordinator calls quiesce(). Never
  manufacture an approval from a request, release signature or this interface.
* The session exports admit(), quiesce(), verify_stopped(), install(start=bool),
  finish(disposition), fail_stopped(). install MUST use the canonical installer,
  not replay commands or call an alternate deployment path, and MUST force
  WEBSERVICES_ACTIVATION_ROLLBACK=0. The selected scope is the only authority.
  fail_stopped MUST journal failure, disable only selected boot/update triggers,
  stop only selected jobs/services, verify them stopped and never restart old
  production. If killed, the journal remains pending; only explicit reviewed
  exact-CAS rollback is allowed, never automatic resume/start. __exit__ releases
  the lock even on BaseException and must not restart anything.
* The sibling host-recovery.py must export HOST_UPGRADE_API = 1,
  verify_upgrade_checkpoint(binding) and restore_upgrade_checkpoint(binding).
  Verify is read-only and proves actual checkpoint content/integrity, compatible
  forward AND backward data formats, exact scope/marker/receipts, safe paths,
  data recovery and physical reserves; it returns exactly recovery_proof().
  Restore is called ONLY for explicit rollback, after verified quiescence, under
  the same native transaction lock. It performs scoped CAS restore and returns
  exactly restore_proof(). It may neither start services nor change other data.

These hooks are integration dependencies, NOT implemented support in the current
installer. The current host-recovery.Backend API (plan/backup/restore/recover)
is cold, same-release, same-machine SYNTHETIC only and takes .install.lock itself.
It must NOT be aliased to these hooks: cross-release/production compatibility,
checkpoint verification before admission and shared-lock composition are absent.
No legacy --activate fallback is safe: it lacks an atomic active-CAS handoff and
cannot reinstall a predecessor stopped. Source-only fake-session checks exercise
this coordinator, not installed/real-host acceptance. Pending recovery here is
limited to an already-sealed, current-selected candidate; interruption before
that point remains a canonical-installer recovery dependency, not an auto-resume.

Canonical journal/receipt extensions expected from finish(): hostTransaction =
{operationId, kind, disposition, checkpointSha256, sourceSha256, startAllowed}.
Upgrade finishes at phase active/disposition upgraded/startAllowed true. Explicit
rollback installs the checkpoint's predecessor as a NEW release, leaves phase
failed/disposition rolled-back-stopped/startAllowed false. This retains existing
journal PHASES without claiming an intentionally stopped release is active.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

# Dynamic canonical-owner imports must not create caches in protected sources.
sys.dont_write_bytecode = True
ROOT_UID = 0
MAX_JSON = 1024 * 1024
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_TREE_ENTRIES = 50000
REQUEST_KEYS = frozenset((
    'schemaVersion', 'kind', 'operationId', 'root', 'scope', 'markerSha256',
    'expectedIntentSha256', 'selectedRelease', 'selectedReceiptSha256',
    'source', 'sourceSha256', 'sourceReceiptSha256', 'checkpoint',
    'checkpointSha256', 'admission', 'admissionSha256'))
CHECKPOINT_KEYS = frozenset((
    'schemaVersion', 'kind', 'root', 'scope', 'markerSha256', 'previousRelease',
    'previousReceiptSha256', 'previousInputs', 'candidateInputs',
    'candidateSourceSha256'))
IDENTITY_KEYS = ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')


class Refused(ValueError):
    """No acceptance, retry, restart or broader authority is implied."""


class FailedStopped(Refused):
    """Native authority proved a failed operation remains stopped."""


class StopUnproved(Refused):
    """A native stop/terminal-journal proof failed; operator recovery required."""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_value(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def hex_digest(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value):
        raise Refused('Exact lowercase SHA256 required')
    return value


def canonical(value):
    if (not isinstance(value, str) or not re.fullmatch('/[A-Za-z0-9_./-]+', value)
            or value == '/' or value.startswith('//')
            or str(Path(value)) != value or '..' in Path(value).parts):
        raise Refused('Canonical absolute path required')
    return Path(value)


def directory(path):
    """No symlinks in ANY ancestor, including the selected root's parents."""
    canonical(str(path))
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_mode & 0o022):
            raise Refused('Directory is not root-controlled')


def read_bytes(path, *, private=False, maximum=MAX_JSON):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    return read_fd(fd, private=private, maximum=maximum)


def read_fd(fd, *, private=False, maximum=MAX_JSON):
    """Consume and close an already pinned authority descriptor."""
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or info.st_nlink != 1 or info.st_mode & 0o022
                or (private and stat.S_IMODE(info.st_mode) != 0o600)
                or info.st_size > maximum):
            raise Refused('Unsafe root authority file')
        parts, size = [], 0
        while True:
            raw = os.read(fd, min(65536, maximum + 1 - size))
            if not raw:
                break
            parts.append(raw)
            size += len(raw)
            if size > maximum:
                raise Refused('Oversized authority file')
        after = os.fstat(fd)
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise Refused('Authority changed during read')
        return b''.join(parts)
    finally:
        os.close(fd)


def strict(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise Refused('Duplicate authority key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refused('Nonfinite JSON')))
    if not isinstance(value, dict):
        raise Refused('Authority object required')
    return value


def exact_json(path, expected, *, private=True):
    raw = read_bytes(path, private=private)
    if sha(raw) != hex_digest(expected):
        raise Refused('Authority hash/CAS changed')
    return strict(raw)


def tree_sha256(root):
    """Deterministic framed tree hash; all entries root owned, no links/devices.

    Includes directories (including empty ones) and file modes/bytes. This is
    intentionally NOT the historical broker's digest. Dispatch must use this
    function, not reinterpret another tree digest as an upgrade source proof.
    """
    directory(root)
    root_dev = root.lstat().st_dev
    result = hashlib.sha256()
    entries, total = 0, 0
    def visit(path):
        nonlocal entries, total
        for child in sorted(path.iterdir(), key=lambda p: p.name):
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise Refused('Oversized source tree')
            info = child.lstat()
            name = child.relative_to(root).as_posix()
            if (info.st_uid != ROOT_UID or info.st_mode & 0o7022
                    or info.st_dev != root_dev):
                raise Refused('Unsealed, privileged or cross-filesystem source entry')
            if stat.S_ISDIR(info.st_mode):
                row = ['directory', name, stat.S_IMODE(info.st_mode)]
                result.update((json.dumps(row, separators=(',', ':')) + '\n').encode())
                visit(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                raw = read_bytes(child, maximum=MAX_TREE_BYTES - total)
                total += len(raw)
                row = ['file', name, stat.S_IMODE(info.st_mode), len(raw), sha(raw)]
                result.update((json.dumps(row, separators=(',', ':')) + '\n').encode())
            else:
                raise Refused('Linked or special source entry')
    visit(root)
    return result.hexdigest()


def inputs(bundle, journal):
    # Validate paths/ownership/hardlinks before using canonical pin semantics.
    for name in journal.CORE_INPUTS + journal.PINNED_INPUTS:
        path = bundle / name
        if path.exists() or path.is_symlink():
            read_bytes(path, maximum=MAX_TREE_BYTES)
    return journal.fingerprint(bundle)


def release_path(value, root):
    path = canonical(value)
    if path.parent != root / 'releases':
        raise Refused('Release escaped the selected native root')
    directory(path)
    return path


def selection(root, selected):
    # Sole link exception: canonical installer-owned current pointer. Never
    # follow it. Compare its literal absolute target to a validated release.
    directory(root)
    pointer = root / 'current'
    info = pointer.lstat()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != ROOT_UID
            or info.st_nlink != 1 or os.readlink(pointer) != str(selected)):
        raise Refused('Current selection differs from exact native release')


def marker_binding(bundle, root, scope):
    metadata = strict(read_bytes(bundle / 'podman-domains.json'))
    manifest = strict(read_bytes(bundle / 'site/manifest.json'))
    config = manifest.get('storageScope')
    if (metadata.get('deploymentMode') != 'standalone'
            or manifest.get('deploymentMode') != 'standalone' or 'venue' in metadata
            or config != metadata.get('storageScope') or not isinstance(config, dict)
            or set(config) != {'root', 'dataClass'} or config.get('root') != str(scope)
            or config.get('dataClass') not in ('production', 'synthetic')
            or metadata.get('installerStateRoot') != str(root)
            or manifest.get('installerStateRoot') != str(root)):
        raise Refused('Exact standalone host scope required; no legacy/venue adoption')
    domains = metadata.get('domains')
    if not isinstance(domains, list) or not domains:
        raise Refused('Missing selected domain authority')
    rows = []
    for domain in domains:
        row = {key: domain[key] for key in IDENTITY_KEYS}
        if (not isinstance(row['name'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}', row['name'])
                or not isinstance(row['user'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,31}', row['user'])
                or type(row['uid']) is not int or row['uid'] <= 0):
            raise Refused('Invalid selected domain identity')
        for key in IDENTITY_KEYS[3:]:
            path = canonical(row[key])
            if path == scope or not path.is_relative_to(scope):
                raise Refused('Domain data escaped selected scope')
            # Recovery/native owner verifies live data paths and ACLs. Do not
            # walk data trees or read a user's data here.
        rows.append(row)
    if any(len({row[key] for row in rows}) != len(rows) for key in ('name', 'user', 'uid')):
        raise Refused('Duplicate selected domain identity')
    roots = [row[key] for row in rows for key in IDENTITY_KEYS[3:]]
    for index, a in enumerate(roots):
        for b in roots[index + 1:]:
            if Path(a).is_relative_to(b) or Path(b).is_relative_to(a):
                raise Refused('Overlapping selected domain storage')
    return {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': manifest['site'],
            'scope': config, 'domains': sorted(rows, key=lambda row: row['name']),
            'roots': sorted(roots)}


def storage_marker(bundle, root, scope, journal):
    """Use existing standalone authority, not a root-owned-data assumption.

    Only the marker is read. Canonical authority owns operator/group/ACL and
    actor identity checks; this coordinator never adopts or walks actor data.
    Pin every directory component without following links, then open the root
    0600 marker relative to that descriptor (the scope may be operator 2770).
    """
    expected = marker_binding(bundle, root, scope)
    if sha_value(journal.standalone_binding(bundle)) != sha_value(expected):
        raise Refused('Canonical standalone ownership differs')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in scope.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        marker_fd = os.open('.stack-installation.json', os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        raw = read_fd(marker_fd, private=True)
        if sha_value(strict(raw)) != sha_value(expected):
            raise Refused('Pinned standalone storage marker differs')
        # Revalidate the path-based canonical ACL/identity evidence after read.
        if sha_value(journal.standalone_binding(bundle)) != sha_value(expected):
            raise Refused('Standalone storage authority changed during read')
        return raw
    finally:
        os.close(fd)


def preflight(request, expected, journal):
    raw = read_bytes(request, private=True)
    if sha(raw) != hex_digest(expected):
        raise Refused('Dispatch request CAS changed')
    row = strict(raw)
    if (set(row) != REQUEST_KEYS or type(row['schemaVersion']) is not int
            or row['schemaVersion'] != 1 or row['kind'] not in ('upgrade', 'rollback')
            or not isinstance(row['operationId'], str)
            or not re.fullmatch('[a-f0-9]{32}', row['operationId'])):
        raise Refused('Unsupported explicit host transaction request')
    for key in ('markerSha256', 'expectedIntentSha256', 'selectedReceiptSha256',
                'sourceSha256', 'checkpointSha256', 'admissionSha256'):
        hex_digest(row[key])
    root, scope, source = (canonical(row[key]) for key in ('root', 'scope', 'source'))
    directory(root)
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        raise Refused('Dedicated private native metadata root required')
    directory(source)
    if root.is_relative_to(scope) or scope.is_relative_to(root):
        raise Refused('Native metadata and selected data overlap')
    # Never hash data as source, nor accept a source containing selected data.
    if source.is_relative_to(scope) or scope.is_relative_to(source):
        raise Refused('Source and data scope overlap')
    selected = release_path(row['selectedRelease'], root)
    if source == selected:
        raise Refused('Target must differ from current selection')
    selection(root, selected)
    intent = exact_json(root / '.install-intent.json', row['expectedIntentSha256'])
    receipt = exact_json(selected / 'installation-receipt.json', row['selectedReceiptSha256'])
    if (sha_value(intent) != sha_value(receipt) or type(intent.get('schemaVersion')) is not int
            or intent.get('schemaVersion') != 1
            or intent.get('release') != str(selected)
            or intent.get('inputs') != inputs(selected, journal)):
        raise Refused('Selected canonical journal/receipt/input binding changed')
    allowed = ('active',) if row['kind'] == 'upgrade' else (
        'active', 'preparing', 'units-selected', 'building', 'starting', 'failed')
    if intent.get('phase') not in allowed:
        raise Refused('Upgrade requires active; recovery requires exact pending/failed selection')
    marker_raw = storage_marker(selected, root, scope, journal)
    if sha(marker_raw) != row['markerSha256']:
        raise Refused('Storage marker CAS changed')
    marker = strict(marker_raw)
    if (sha_value(marker) != sha_value(marker_binding(selected, root, scope))
            or sha_value(marker) != sha_value(marker_binding(source, root, scope))):
        raise Refused('Source/selected scope ownership marker differs')
    if tree_sha256(source) != row['sourceSha256']:
        raise Refused('Exact source tree changed')
    source_inputs = inputs(source, journal)
    checkpoint = exact_json(canonical(row['checkpoint']), row['checkpointSha256'])
    if (set(checkpoint) != CHECKPOINT_KEYS or type(checkpoint['schemaVersion']) is not int
            or checkpoint['schemaVersion'] != 1 or checkpoint['kind'] != 'host-upgrade-checkpoint'
            or any(checkpoint[key] != row[key] for key in ('root', 'scope', 'markerSha256'))):
        raise Refused('Recovery checkpoint is not bound to the selected installation')
    previous = release_path(checkpoint['previousRelease'], root)
    previous_receipt = exact_json(previous / 'installation-receipt.json',
                                  checkpoint['previousReceiptSha256'])
    if (previous_receipt.get('phase') != 'active' or previous_receipt.get('release') != str(previous)
            or previous_receipt.get('inputs') != checkpoint['previousInputs']
            or inputs(previous, journal) != checkpoint['previousInputs']):
        raise Refused('Checkpoint predecessor receipt/input binding changed')
    if row['kind'] == 'upgrade':
        if (row['sourceReceiptSha256'] is not None or previous != selected
                or checkpoint['previousReceiptSha256'] != row['selectedReceiptSha256']
                or checkpoint['candidateSourceSha256'] != row['sourceSha256']
                or checkpoint['candidateInputs'] != source_inputs):
            raise Refused('Upgrade source/checkpoint does not match exact predecessor')
    else:
        if (source != previous or row['sourceReceiptSha256'] != checkpoint['previousReceiptSha256']
                or source_inputs != checkpoint['previousInputs']
                or intent.get('inputs') != checkpoint['candidateInputs']
                or intent.get('previousRelease') != str(previous)):
            raise Refused('Rollback must name the exact checkpoint predecessor, never arbitrary data')
        transaction = intent.get('hostTransaction')
        if (not isinstance(transaction, dict) or transaction.get('kind') != 'upgrade'
                or transaction.get('sourceSha256') != checkpoint['candidateSourceSha256']
                or transaction.get('checkpointSha256') != row['checkpointSha256']):
            raise Refused('Rollback candidate lacks original canonical source/checkpoint proof')
    hex_digest(checkpoint['candidateSourceSha256'])
    # Opaque existing-installer admission, not a new approval schema. Its actual
    # policy, expiry, machine binding and one-use consumption belong to native.
    admission_raw = read_bytes(canonical(row['admission']), private=True)
    if sha(admission_raw) != row['admissionSha256']:
        raise Refused('Installer admission changed')
    return dict(row, request=str(request), requestSha256=expected,
                selectedInputs=intent['inputs'], sourceInputs=source_inputs,
                checkpointDescriptor=checkpoint)


def recovery_proof(binding):
    return {'schemaVersion': 1, 'checkpointSha256': binding['checkpointSha256'],
            'markerSha256': binding['markerSha256'], 'scope': binding['scope'],
            'selectedReceiptSha256': binding['selectedReceiptSha256'],
            'sourceSha256': binding['sourceSha256'],
            'forwardCompatible': True, 'backwardCompatible': True, 'verified': True}


def restore_proof(binding):
    return dict(recovery_proof(binding), restored=True, stopped=True)


def transaction_stamp(binding, disposition):
    return {'operationId': binding['operationId'], 'kind': binding['kind'],
            'disposition': disposition, 'checkpointSha256': binding['checkpointSha256'],
            'sourceSha256': binding['sourceSha256'], 'startAllowed': disposition == 'upgraded'}


def verify_result(binding, journal, disposition):
    root = Path(binding['root'])
    raw = read_bytes(root / '.install-intent.json', private=True)
    intent = strict(raw)
    selected = release_path(intent['release'], root)
    selection(root, selected)
    receipt_raw = read_bytes(selected / 'installation-receipt.json', private=True)
    if (raw != receipt_raw or selected in (Path(binding['selectedRelease']), Path(binding['source']))
            or intent.get('phase') != ('active' if disposition == 'upgraded' else 'failed')
            or intent.get('inputs') != binding['sourceInputs']
            or inputs(selected, journal) != binding['sourceInputs']
            or intent.get('previousRelease') != binding['selectedRelease']
            or sha_value(intent.get('hostTransaction')) != sha_value(transaction_stamp(binding, disposition))):
        raise Refused('Canonical installer completion proof differs from exact transaction')
    return {'schemaVersion': 1, 'operationId': binding['operationId'], 'state': disposition,
            'journalSha256': sha(raw), 'applicationAcceptance': False,
            'previousReleaseRestarted': False, 'startAllowed': disposition == 'upgraded'}


def verify_failure(binding, journal):
    """Do not advertise a stopped transaction without durable exact owner proof."""
    root = Path(binding['root'])
    raw = read_bytes(root / '.install-intent.json', private=True)
    intent = strict(raw)
    selected = release_path(intent['release'], root)
    selection(root, selected)
    if (raw != read_bytes(selected / 'installation-receipt.json', private=True)
            or intent.get('phase') != 'failed'
            or intent.get('inputs') not in (binding['selectedInputs'], binding['sourceInputs'])
            or inputs(selected, journal) != intent.get('inputs')
            or sha_value(intent.get('hostTransaction')) != sha_value(transaction_stamp(binding, 'failed-stopped'))):
        raise Refused('Exact canonical stopped-failure journal/receipt/input proof missing')


def execute(request, expected, journal, recovery):
    """Injection is for source tests; production loads ONLY fixed canonical owners.

    No filesystem writes are made here. Native owns locking, admission, durable
    intent and installer invocation. Recovery owns checkpoint/restore mutations.
    Every error after native admission attempts scoped stop and failure journaling
    even for KeyboardInterrupt/SystemExit. SIGKILL requires an explicit new
    rollback request against the preserved canonical pending intent.
    """
    if os.geteuid() != ROOT_UID:
        raise Refused('Root dispatch required')
    if (getattr(journal, 'HOST_UPGRADE_API', None) != 1
            or not callable(getattr(journal, 'host_upgrade_transaction', None))
            or getattr(recovery, 'HOST_UPGRADE_API', None) != 1
            or any(not callable(getattr(recovery, key, None)) for key in (
                'verify_upgrade_checkpoint', 'restore_upgrade_checkpoint'))):
        raise Refused('Canonical installer/recovery transaction integration unavailable')
    binding = preflight(request, expected, journal)
    if sha_value(recovery.verify_upgrade_checkpoint(binding)) != sha_value(recovery_proof(binding)):
        raise Refused('Compatible verified recovery checkpoint required before admission')
    with journal.host_upgrade_transaction(binding) as native:
        # No stop, cleanup or restore is authorized on failed admission. Native
        # lock/admission owns the last CAS, including one-use policy/expiry.
        if preflight(request, expected, journal) != binding:
            raise Refused('Transaction inputs changed at admission')
        if sha_value(recovery.verify_upgrade_checkpoint(binding)) != sha_value(recovery_proof(binding)):
            raise Refused('Checkpoint changed at admission')
        native.admit()
        try:
            native.quiesce()
            native.verify_stopped()
            if sha_value(recovery.verify_upgrade_checkpoint(binding)) != sha_value(recovery_proof(binding)):
                raise Refused('Checkpoint not valid at stopped migration boundary')
            if binding['kind'] == 'rollback':
                if sha_value(recovery.restore_upgrade_checkpoint(binding)) != sha_value(restore_proof(binding)):
                    raise Refused('Exact scoped stopped checkpoint restore unproved')
                native.verify_stopped()
            native.install(start=binding['kind'] == 'upgrade')
            disposition = 'upgraded' if binding['kind'] == 'upgrade' else 'rolled-back-stopped'
            if binding['kind'] == 'rollback':
                native.verify_stopped()
            native.finish(disposition)
            result = verify_result(binding, journal, disposition)
            # Sealed source, marker and recovery authority must survive install.
            if (tree_sha256(Path(binding['source'])) != binding['sourceSha256']
                    or sha(storage_marker(Path(binding['source']), Path(binding['root']),
                                          Path(binding['scope']), journal)) != binding['markerSha256']):
                raise Refused('Source or marker changed during native install')
            return result
        except BaseException as failure:
            try:
                native.fail_stopped()
                native.verify_stopped()
                verify_failure(binding, journal)
            except BaseException as stop_failure:
                raise StopUnproved('Selected stop/failure proof incomplete; no restart permitted') from stop_failure
            raise FailedStopped('Native transaction failed and remains stopped; explicit CAS recovery required') from failure
    raise Refused('Native authority suppressed a failed transaction')


# Existing-owner API. Unlike the optional cross-release hooks above, these
# functions compose APIs that are present in the canonical owners today.
NATIVE_BINDING_KEYS = frozenset(('schemaVersion', 'root', 'scope',
    'expectedIntentSha256', 'selectedReceiptSha256', 'markerSha256',
    'source', 'sourceSha256'))


def inspect_native(binding, journal):
    """Read-only exact selection/candidate proof; no workload or data inspection.

    The source digest includes ALL candidate files, not just journal input pins.
    A retired failure is a supported stopped selection, never an active upgrade.
    Unselected initial preparation still belongs to native seal/retire-unselected.
    """
    if (set(binding) != NATIVE_BINDING_KEYS or type(binding['schemaVersion']) is not int
            or binding['schemaVersion'] != 1):
        raise Refused('Exact native candidate binding required')
    for key in ('expectedIntentSha256', 'selectedReceiptSha256', 'markerSha256', 'sourceSha256'):
        hex_digest(binding[key])
    root, scope, source = (canonical(binding[key]) for key in ('root', 'scope', 'source'))
    directory(root)
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        raise Refused('Dedicated private native metadata root required')
    if (root.is_relative_to(scope) or scope.is_relative_to(root)
            or source.is_relative_to(scope) or scope.is_relative_to(source)):
        raise Refused('Metadata/source and selected data overlap')
    intent = exact_json(root / '.install-intent.json', binding['expectedIntentSha256'])
    selected = release_path(intent['release'], root)
    selection(root, selected)
    receipt = exact_json(selected / 'installation-receipt.json', binding['selectedReceiptSha256'])
    if (sha_value(receipt) != sha_value(intent) or intent.get('phase') not in journal.PHASES
            or intent.get('schemaVersion') != 1 or type(intent.get('schemaVersion')) is not int
            or intent.get('inputs') != inputs(selected, journal)):
        raise Refused('Exact expanded native receipt/input proof required')
    marker = storage_marker(selected, root, scope, journal)
    if sha(marker) != binding['markerSha256']:
        raise Refused('Selected storage marker CAS changed')
    if (source == selected or tree_sha256(source) != binding['sourceSha256']
            or sha_value(marker_binding(source, root, scope)) != sha_value(strict(marker))):
        raise Refused('Candidate source/scope binding changed')
    # Both source and selection must satisfy the SAME canonical authority.
    if sha(storage_marker(source, root, scope, journal)) != binding['markerSha256']:
        raise Refused('Candidate standalone ownership changed')
    return dict(binding, selectedRelease=str(selected), phase=intent['phase'],
                selectedInputs=intent['inputs'], sourceInputs=inputs(source, journal))


def native_command(root, action, *, expected=None, bundle=None, env_dir=None, image_inputs=None):
    """Exact existing shell flags, for the owning controller's command display.

    This does NOT execute or approve a command. --activate is intentionally not
    offered: today's installer has no atomic active-CAS handoff or stopped
    installation mode. --resume-intent cannot authorize changed candidate pins.
    No invented --root/--start/--expected-intent flags reach the shell installer.
    'validate' is the installer's PREACTIVATION path, NOT a read-only check: it
    may render configs/SOPS and run native helpers. Only a command reference is
    returned, never authorization; plan() deliberately does not recommend it.
    """
    root = canonical(str(root))
    installer = Path(__file__).absolute().with_name('install-podman-bundle.sh')
    args = ['/bin/bash', str(installer)]
    if action == 'inspect':
        if any(value is not None for value in (expected, bundle, env_dir, image_inputs)):
            raise Refused('Inspect takes no installation options')
        args += ['--inspect']
    elif action in ('quarantine-failed', 'retire-failed'):
        if any(value is not None for value in (bundle, env_dir, image_inputs)):
            raise Refused('Settlement cannot install a bundle')
        args += ['--' + action + '-intent', hex_digest(expected), '--reviewed-data-state']
    elif action == 'validate':
        if expected is not None or bundle is None:
            raise Refused('Validation is not resume or activation')
        args += ['--bundle', str(canonical(str(bundle)))]
        for flag, value in (('--env-dir', env_dir), ('--image-inputs', image_inputs)):
            if value is not None:
                args += [flag, str(canonical(str(value)))]
    else:
        raise Refused('Unsupported native command; activation requires owner integration')
    return {'argv': args, 'environment': {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
            'WEBSERVICES_STATE_ROOT': str(root), 'WEBSERVICES_ACTIVATION_ROLLBACK': '0'},
            'authorized': False, 'executed': False}


class NativeCoordinator:
    """Usable trusted-controller API to today's canonical owners.

    Construct with NATIVE_BINDING_KEYS, canonical journal/recovery modules and
    call plan(), settle_failed(operation_id, authorize), recovery_plan(),
    restore_checkpoint(...) or recover_interrupted(...). Pass lease=the existing
    stopped lease for receipted operator/actor recovery custody.
    The controller MUST hold its existing typed
    operation lease; authorize must consume/revalidate and return the EXACT
    request. No callback/approval can be supplied via JSON or a new CLI flag.
    No native subprocess is launched here. Settlement calls canonical journal
    functions under the existing lock; recovery owns that lock itself, so it
    must NEVER be nested under ours. No data-format compatibility is inferred
    from a predecessor receipt, a retired failure or a successful cold restore.
    """
    def __init__(self, binding, journal, recovery, *, lease=None):
        self.binding = dict(binding)
        self.journal, self.recovery = journal, recovery
        self.lease = lease

    def inspect(self):
        if os.geteuid() != ROOT_UID:
            raise Refused('Root controller required')
        return inspect_native(self.binding, self.journal)

    def plan(self):
        selected = self.inspect()
        return {'schemaVersion': 1, 'selection': selected, 'restart': False,
                'installedAcceptance': False, 'applicationAcceptance': False,
                'settlementAvailable': selected['phase'] not in ('active', 'retired-failed'),
                'retiredFailure': selected['phase'] == 'retired-failed', 'stoppedProof': False,
                'upgradeAvailable': False, 'crossReleaseRestoreAvailable': False,
                'dependencies': ['native atomic active-CAS installation handoff',
                                 'native stopped release materialization',
                                 'cross-release data checkpoint compatibility and shared-lock recovery'],
                'nativePreactivationCheckIsReadOnly': False,
                'commands': {'inspect': native_command(selected['root'], 'inspect')}}

    @contextlib.contextmanager
    def locked(self):
        root = canonical(self.binding['root'])
        directory(root)
        fd = os.open(root / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise Refused('Unsafe canonical installation lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    @staticmethod
    def admit(authorize, request):
        if not callable(authorize):
            raise Refused('Existing typed-operation admission required')
        approved = authorize(strict(json.dumps(request, sort_keys=True).encode()))
        if sha_value(approved) != sha_value(request):
            raise Refused('Exact consumed typed-operation admission differs')

    def settle_failed(self, operation_id, authorize):
        """Explicit interrupted/failed -> failed + stopped. NEVER retire/start.

        A pending CURRENT sealed release is first terminally journaled failed;
        this gives quarantine_failed its required canonical failure boundary.
        Any failure leaves that boundary intact, never an automatic old restart.
        A retired-failed selection is verified read-only; not reactivated.
        """
        if not isinstance(operation_id, str) or not re.fullmatch('[a-f0-9]{32}', operation_id):
            raise Refused('Exact settlement operation ID required')
        original = self.inspect()
        if original['phase'] == 'active':
            raise Refused('Active release is not failed settlement authority')
        with self.locked():
            if self.inspect() != original:
                raise Refused('Selection changed under native lock')
            release, root = Path(original['selectedRelease']), Path(original['root'])
            if original['phase'] == 'retired-failed':
                self.journal.verify_quarantined(release)
                return {'state': 'retired-failed-stopped', 'restart': False,
                        'intentSha256': original['expectedIntentSha256'], 'installedAcceptance': False}
            request = {'schemaVersion': 1, 'kind': 'settle-failed-stopped', 'operationId': operation_id,
                       'selection': original, 'restart': False, 'retire': False}
            self.admit(authorize, request)
            if self.inspect() != original:
                raise Refused('Selection changed while consuming settlement admission')
            if original['phase'] != 'failed':
                self.journal.update(root, release, release, 'failed')
            expected = sha(read_bytes(root / '.install-intent.json', private=True))
            failed = dict(self.binding, expectedIntentSha256=expected,
                          selectedReceiptSha256=sha(read_bytes(release / 'installation-receipt.json', private=True)))
            if inspect_native(failed, self.journal)['phase'] != 'failed':
                raise Refused('Canonical failure boundary not proved')
            self.journal.quarantine_failed(root, expected, True)
            self.journal.verify_quarantined(release)
            if inspect_native(failed, self.journal)['phase'] != 'failed':
                raise Refused('Stopped failure selection changed')
            return {'state': 'failed-stopped', 'intentSha256': expected, 'restart': False,
                    'intentRetired': False, 'dataCompatibilityProved': False, 'installedAcceptance': False}

    def recovery_backend(self):
        selected = self.inspect()
        if selected['phase'] not in ('active', 'retired-failed'):
            raise Refused('Recovery requires canonical terminal active/retired-failed selection; no phase bypass')
        # Real Backend verifies scope, quarantine, reserves, archive, key and
        # same-release input pins under its OWN native lock. Never alias the
        # missing cross-release hooks to this cold same-release primitive.
        return self.recovery.Backend(Path(selected['root']), selected['expectedIntentSha256'], lease=self.lease)

    def recovery_plan(self):
        """Real cold-recovery inventory under native lock/custody; no approval."""
        return self.recovery_backend().plan()

    def recovery_authorize(self, authorize):
        def consume(request):
            self.inspect()
            self.admit(authorize, request)
            self.inspect()
            return request
        return consume

    def restore_checkpoint(self, archive, archive_sha256, identity_file, operation_id, authorize):
        """Same-release checkpoint only; Backend refuses different input pins.

        No predecessor source selection, intent retirement or install follows.
        Operator-writable recovery parents need root-receipted recoveryCustody
        AND the existing stopped lease. Do not manufacture that proof or
        chmod/chown/seal/adopt parents here to make this call succeed.
        """
        if not isinstance(operation_id, str) or not re.fullmatch('[a-f0-9]{32}', operation_id):
            raise Refused('Exact recovery operation ID required')
        backend = self.recovery_backend()
        return backend.restore(canonical(str(archive)), hex_digest(archive_sha256),
                               canonical(str(identity_file)), operation_id, self.recovery_authorize(authorize))

    def recover_interrupted(self, expected_recovery_sha256, authorize):
        """Exact existing recovery journal CAS -> originals restored, stopped.

        This is recover(), NOT replaying restore() and not restarting a release.
        """
        return self.recovery_backend().recover(hex_digest(expected_recovery_sha256),
                                               self.recovery_authorize(authorize))


def load_owner(name):
    path = Path(__file__).absolute().with_name(name)
    # Owner code is trusted only through root-owned nonlinked source/ancestors.
    read_bytes(path, maximum=MAX_TREE_BYTES)
    spec = importlib.util.spec_from_file_location('host_upgrade_' + name.replace('-', '_'), path)
    if spec is None or spec.loader is None:
        raise Refused('Canonical owner source missing')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--plan-native', action='store_true',
                        help='Read-only current-owner candidate plan; no approval or activation')
    args = parser.parse_args()
    try:
        if os.geteuid() != ROOT_UID:
            raise Refused('Root dispatch required')
        canonical(str(args.request))
        journal, recovery = load_owner('install-journal.py'), load_owner('host-recovery.py')
        if args.plan_native:
            binding = exact_json(args.request, args.request_sha256)
            result = NativeCoordinator(binding, journal, recovery).plan()
        else:
            result = execute(args.request, args.request_sha256, journal, recovery)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        # Never echo paths, request contents, native exceptions or credentials.
        raise SystemExit('Host transaction refused or failed; inspect canonical journal; no automatic restart') from None


if __name__ == '__main__':
    main()
