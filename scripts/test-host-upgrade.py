#!/usr/bin/env python3
"""Isolated coordinator/real-journal tests; no installer, services, network or JVM.

The native transaction and recovery adapters below are synthetic owner fixtures,
NOT an installer admission bypass or installed-host proof. They use the tracked
canonical journal in a temporary root. Root UID/ancestor checks are substituted
only inside this process; there is no runtime test/root-override CLI flag.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[1]


def load(name):
    path = ROOT / 'runtime-generator/podman-ops' / name
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upgrade = load('host-upgrade.py')
journal = load('install-journal.py')


def write(path, value):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
        parent.chmod(0o700)  # explicit isolated-fixture modes, independent of umask
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    path.chmod(0o600)


class ReadinessFixture:
    """Explicit dependency callbacks for the transaction model, NOT RootFS proof.

    The real journal still owns phase ordering, immutable inputs and dual-record
    publication. Only its readiness_owner() dependency is substituted inside
    these isolated tests; production source/RootFilesystem checks stay intact.
    """
    def __init__(self, case):
        self.case = case
        self.calls = []

    def observe(self, callback, phase, root, release, prior):
        case = self.case
        case.assertEqual(root, case.state)
        case.assertEqual(release.parent, root / 'releases')
        case.directory(root)
        case.directory(release)
        case.assertEqual(prior['phase'], phase)
        case.assertEqual(prior['release'], str(release))
        case.assertEqual(journal.read(root / '.install-intent.json'), prior)
        case.assertEqual(journal.read(release / 'installation-receipt.json'), prior)
        case.assertEqual(journal.fingerprint(release), prior['inputs'])
        self.calls.append((callback, str(release), phase))
        return {'schemaVersion': 1, 'kind': 'synthetic-readiness-callback',
                'callback': callback, 'release': str(release), 'inputs': dict(prior['inputs']),
                'fixtureOnly': True, 'installedAcceptance': False, 'activationAuthorized': False}

    def seal_selection(self, root, release, prior):
        return self.observe('seal_selection', 'preparing', root, release, prior)

    def capture_images(self, root, release, prior):
        self.case.assertEqual(prior['readiness']['callback'], 'seal_selection')
        return self.observe('capture_images', 'building', root, release, prior)

    def verify_active_transition(self, root, release, prior):
        self.case.assertEqual(prior['readiness']['callback'], 'capture_images')
        return self.observe('verify_active_transition', 'starting', root, release, prior)


class RecoveryFixture:
    HOST_UPGRADE_API = 1

    def __init__(self, case):
        self.case = case
        self.events = case.events
        self.compatible = True
        self.restore_failure = False
        self.saved = case.data.read_bytes()

    def verify_upgrade_checkpoint(self, binding):
        self.events.append('checkpoint-verify')
        if not self.compatible:
            raise upgrade.Refused('Synthetic incompatible checkpoint')
        if self.case.payload.read_bytes() != self.saved:
            raise upgrade.Refused('Synthetic checkpoint corrupted')
        return upgrade.recovery_proof(binding)

    def restore_upgrade_checkpoint(self, binding):
        self.events.append('restore')
        self.case.assertTrue(self.case.locked)
        self.case.assertFalse(self.case.running)
        self.case.data.write_bytes(self.saved)
        if self.restore_failure:
            raise ValueError('Synthetic partial restore failure')
        return upgrade.restore_proof(binding)


class NativeFixture:
    """Synthetic canonical extension; all writes are inside the fixture root.

    The adapter intentionally uses journal.update/retire_failed, not an alternate
    install journal. admit/hostTransaction are the missing production extension.
    install models migration and immutable selection, not real installation.
    """
    def __init__(self, case, binding):
        self.case, self.binding = case, binding
        self.admitted = False

    def __enter__(self):
        self.case.assertFalse(self.case.locked)
        self.case.events.append('lock')
        self.case.locked = True
        if self.case.race:
            self.case.race()
        return self

    def __exit__(self, *_):
        self.case.events.append('unlock')
        self.case.locked = False

    def admit(self):
        self.case.events.append('admit')
        self.case.assertTrue(self.case.locked)
        if self.case.deny_admission:
            raise upgrade.Refused('Synthetic native admission denied')
        admission = upgrade.exact_json(Path(self.binding['admission']), self.binding['admissionSha256'])
        if admission != {'operationId': self.binding['operationId'], 'kind': self.binding['kind'],
                         'scope': self.binding['scope'], 'approved': True}:
            raise upgrade.Refused('Synthetic wrong admission binding')
        if self.binding['operationId'] in self.case.consumed:
            raise upgrade.Refused('Synthetic admission already consumed')
        self.case.consumed.add(self.binding['operationId'])
        self.admitted = True

    def quiesce(self):
        self.case.events.append('quiesce')
        self.case.assertTrue(self.admitted)
        self.case.running = False
        self.case.boot_enabled = False

    def verify_stopped(self):
        self.case.events.append('verify-stopped')
        if self.case.running or self.case.boot_enabled or self.case.stop_failure:
            raise upgrade.Refused('Synthetic scoped stop unproved')

    def install(self, *, start):
        case, binding = self.case, self.binding
        case.events.append('install-start' if start else 'install-stopped')
        case.assertTrue(self.admitted)
        case.assertFalse(case.running)
        source = Path(binding['source'])
        before = journal.read(case.state / '.install-intent.json')
        if before['phase'] not in ('active', 'retired-failed'):
            if before['phase'] != 'failed':
                journal.update(case.state, Path(before['release']), Path(before['release']), 'failed')
            journal.retire_failed(case.state, journal.digest(case.state / '.install-intent.json'),
                                  True, verifier=lambda _: self.verify_stopped())
        case.counter += 1
        selected = case.state / 'releases' / ('native-%02d' % case.counter)
        # Source copy is synthetic immutable-release materialization, not backup.
        shutil.copytree(source, selected, ignore=shutil.ignore_patterns('installation-receipt.json'))
        value = journal.update(case.state, source, selected, 'preparing')
        # Failed-intent retirement does not infer previousRelease. The proposed
        # canonical extension must pin the explicit reviewed predecessor itself.
        value['previousRelease'] = binding['selectedRelease']
        value['hostTransaction'] = upgrade.transaction_stamp(binding, 'installing')
        journal.write(selected / 'installation-receipt.json', value)
        journal.write(case.state / '.install-intent.json', value)
        case.select(selected)
        for phase in ('units-selected', 'building'):
            journal.update(case.state, source, selected, phase)
        if case.install_failure:
            case.data.write_text('{"schema":"partially-migrated"}\n')
            if case.install_failure == 'interrupt':
                raise KeyboardInterrupt()
            if case.install_failure == 'system-exit':
                raise SystemExit(143)
            raise ValueError('Synthetic migration failed')
        if start:
            journal.update(case.state, source, selected, 'starting')
            case.running = True
            case.boot_enabled = True
            journal.update(case.state, source, selected, 'active')
        else:
            journal.update(case.state, source, selected, 'failed')
        if case.corrupt_completion:
            write(selected / 'bundle.json', {'corrupt': True})

    def finish(self, disposition):
        self.case.events.append('finish-' + disposition)
        path = self.case.state / '.install-intent.json'
        value = journal.read(path)
        value['hostTransaction'] = upgrade.transaction_stamp(self.binding, disposition)
        journal.write(Path(value['release']) / 'installation-receipt.json', value)
        journal.write(path, value)

    def fail_stopped(self):
        case = self.case
        case.events.append('fail-stopped')
        case.assertTrue(self.admitted)
        case.running = False
        case.boot_enabled = False
        path = case.state / '.install-intent.json'
        value = journal.read(path)
        value['phase'] = 'failed'
        if value['steps'][-1] != 'failed':
            value['steps'].append('failed')
        value['hostTransaction'] = upgrade.transaction_stamp(self.binding, 'failed-stopped')
        journal.write(Path(value['release']) / 'installation-receipt.json', value)
        journal.write(path, value)
        if case.cleanup_failure:
            raise upgrade.Refused('Synthetic failure journal or stop not proved')


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='host-upgrade-test-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(upgrade, 'ROOT_UID', os.geteuid()))
        # Production checks every ancestor. Only fixture-owned ancestors are
        # checked in tests: /tmp is intentionally not production root authority.
        self.stack.enter_context(patch.object(upgrade, 'directory', self.directory))
        self.stack.enter_context(patch.object(journal, 'directory', self.directory))
        self.stack.enter_context(patch.object(journal, 'read', self.journal_read))
        self.stack.enter_context(patch.object(journal, 'standalone_binding', self.standalone_binding))
        self.readiness = ReadinessFixture(self)
        self.stack.enter_context(patch.object(journal, 'readiness_owner', return_value=self.readiness))
        self.stack.enter_context(patch.object(journal, 'HOST_UPGRADE_API', 1, create=True))
        self.stack.enter_context(patch.object(journal, 'host_upgrade_transaction',
                                             lambda binding: NativeFixture(self, binding), create=True))
        self.state = self.base / 'native'
        self.scope = self.base / 'data'
        self.previous = self.state / 'releases' / 'previous'
        self.source = self.base / 'candidate'
        for path in (self.state, self.scope, self.state / 'releases', self.previous, self.source):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        self.data = self.scope / 'service' / 'rows.json'
        write(self.data, {'schema': 'v1', 'rows': ['synthetic-record']})
        self.payload = self.base / 'recovery' / 'payload.json'
        self.payload.parent.mkdir(mode=0o700)
        self.payload.write_bytes(self.data.read_bytes())
        self.payload.chmod(0o600)
        self.make_bundle(self.previous, 'previous')
        self.make_bundle(self.source, 'candidate')
        for phase in journal.PHASES[:5]:
            journal.update(self.state, self.previous, self.previous, phase)
        self.select(self.previous)
        self.marker = self.scope / '.stack-installation.json'
        write(self.marker, upgrade.marker_binding(self.previous, self.state, self.scope))
        self.checkpoint = self.base / 'recovery' / 'checkpoint.json'
        write(self.checkpoint, {
            'schemaVersion': 1, 'kind': 'host-upgrade-checkpoint',
            'root': str(self.state), 'scope': str(self.scope),
            'markerSha256': upgrade.sha(self.marker.read_bytes()),
            'previousRelease': str(self.previous),
            'previousReceiptSha256': upgrade.sha((self.previous / 'installation-receipt.json').read_bytes()),
            'previousInputs': journal.fingerprint(self.previous),
            'candidateInputs': journal.fingerprint(self.source),
            'candidateSourceSha256': upgrade.tree_sha256(self.source)})
        self.events = []
        self.recovery = RecoveryFixture(self)
        self.locked = False
        self.running = True
        self.boot_enabled = True
        self.deny_admission = self.stop_failure = self.cleanup_failure = False
        self.corrupt_completion = False
        self.install_failure = None
        self.race = None
        self.counter = 0
        self.consumed = set()
        self.unrelated = self.base / 'unrelated' / 'sentinel.json'
        write(self.unrelated, {'untouched': True})
        self.unrelated_bytes = self.unrelated.read_bytes()
        self.request = self.make_request()

    def tearDown(self):
        self.assertEqual(self.unrelated.read_bytes(), self.unrelated_bytes)
        self.assertFalse(self.locked)

    def directory(self, path):
        # Test-only authority anchor. Do not weaken production ancestor checks.
        path = Path(path)
        if not path.is_relative_to(self.base):
            raise upgrade.Refused('Test escaped isolated root')
        chain = [self.base]
        relative = path.relative_to(self.base)
        for index in range(1, len(relative.parts) + 1):
            chain.append(self.base.joinpath(*relative.parts[:index]))
        for entry in chain:
            info = entry.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022):
                raise upgrade.Refused('Unsafe synthetic ancestor')

    def standalone_binding(self, bundle):
        # Synthetic canonical ownership fixture: real scope data is never read.
        expected = upgrade.marker_binding(bundle, self.state, self.scope)
        info = self.marker.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()
                or upgrade.strict(self.marker.read_bytes()) != expected):
            raise upgrade.Refused('Synthetic canonical storage authority changed')
        return expected

    def journal_read(self, path):
        if not path.exists() and not path.is_symlink():
            return None
        value = upgrade.strict(upgrade.read_bytes(path, private=True))
        if value.get('schemaVersion') != 1 or value.get('phase') not in journal.PHASES:
            raise upgrade.Refused('Bad canonical test receipt')
        return value

    def select(self, release):
        (self.state / 'current').unlink(missing_ok=True)
        (self.state / 'current').symlink_to(release)

    def make_bundle(self, path, label):
        config = {'root': str(self.scope), 'dataClass': 'synthetic'}
        domains = [{'name': 'content', 'user': 'synthetic-content', 'uid': 24001,
                    'stateRoot': str(self.scope / 'state-content'),
                    'graphRoot': str(self.scope / 'graph-content'),
                    'volumeRoot': str(self.scope / 'volume-content')}]
        write(path / 'bundle.json', {'backend': 'podman', 'release': label})
        write(path / 'stack.ir.json', {'services': {}, 'volumes': {}, 'release': label})
        write(path / 'source-provenance.json', {'release': label})
        write(path / 'podman-domains.json', {'schemaVersion': 1, 'deploymentMode': 'standalone',
            'storageScope': config, 'installerStateRoot': str(self.state), 'domains': domains})
        write(path / 'site/manifest.json', {'site': 'synthetic', 'deploymentMode': 'standalone',
                                           'installerStateRoot': str(self.state), 'storageScope': config})

    def make_request(self, kind='upgrade'):
        selected = journal.read(self.state / '.install-intent.json')['release']
        source = self.source if kind == 'upgrade' else self.previous
        op = ('a' if kind == 'upgrade' else 'b') * 32
        admission = self.base / 'authority' / (op + '.json')
        write(admission, {'operationId': op, 'kind': kind, 'scope': str(self.scope), 'approved': True})
        request = self.base / 'requests' / (op + '.json')
        write(request, {'schemaVersion': 1, 'kind': kind, 'operationId': op,
            'root': str(self.state), 'scope': str(self.scope),
            'markerSha256': upgrade.sha(self.marker.read_bytes()),
            'expectedIntentSha256': upgrade.sha((self.state / '.install-intent.json').read_bytes()),
            'selectedRelease': selected,
            'selectedReceiptSha256': upgrade.sha((Path(selected) / 'installation-receipt.json').read_bytes()),
            'source': str(source), 'sourceSha256': upgrade.tree_sha256(source),
            'sourceReceiptSha256': None if kind == 'upgrade' else upgrade.sha(
                (source / 'installation-receipt.json').read_bytes()),
            'checkpoint': str(self.checkpoint), 'checkpointSha256': upgrade.sha(self.checkpoint.read_bytes()),
            'admission': str(admission), 'admissionSha256': upgrade.sha(admission.read_bytes())})
        return request

    def dispatch(self, request=None, expected=None):
        request = request or self.request
        return upgrade.execute(request, expected or upgrade.sha(request.read_bytes()), journal, self.recovery)

    def change_request(self, **changes):
        value = json.loads(self.request.read_text())
        value.update(changes)
        write(self.request, value)

    def test_upgrade_exact_native_journal_and_no_predecessor_restart(self):
        prior = (self.previous / 'installation-receipt.json').read_bytes()
        result = self.dispatch()
        self.assertEqual(result['state'], 'upgraded')
        self.assertFalse(result['applicationAcceptance'])
        self.assertFalse(result['previousReleaseRestarted'])
        self.assertTrue(result['startAllowed'])
        self.assertEqual((self.previous / 'installation-receipt.json').read_bytes(), prior)
        self.assertLess(self.events.index('admit'), self.events.index('quiesce'))
        self.assertLess(self.events.index('quiesce'), self.events.index('install-start'))
        self.assertNotIn('restore', self.events)
        self.assertEqual([call[0] for call in self.readiness.calls],
                         ['seal_selection', 'capture_images', 'verify_active_transition'] * 2)
        selected = journal.read(self.state / '.install-intent.json')
        self.assertTrue(selected['nativeReadiness']['fixtureOnly'])
        self.assertFalse(selected['nativeReadiness']['installedAcceptance'])
        self.assertFalse(selected['nativeReadiness']['activationAuthorized'])

    def test_explicit_rollback_restores_checkpoint_but_never_starts(self):
        self.dispatch()
        self.data.write_text('{"schema":"v2"}\n')
        request = self.make_request('rollback')
        self.events.clear()
        result = self.dispatch(request)
        self.assertEqual(result['state'], 'rolled-back-stopped')
        self.assertFalse(result['startAllowed'])
        self.assertFalse(self.running or self.boot_enabled)
        self.assertEqual(self.data.read_bytes(), self.payload.read_bytes())
        self.assertLess(self.events.index('verify-stopped'), self.events.index('restore'))
        self.assertLess(self.events.index('restore'), self.events.index('install-stopped'))
        self.assertNotIn('install-start', self.events)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'failed')

    def test_migration_failure_requires_explicit_rollback_and_keeps_stopped(self):
        self.install_failure = 'migration'
        with self.assertRaises(upgrade.FailedStopped):
            self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)
        self.assertNotIn('restore', self.events)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'failed')
        self.assertNotEqual(self.data.read_bytes(), self.payload.read_bytes())
        self.install_failure = None
        self.events.clear()
        result = self.dispatch(self.make_request('rollback'))
        self.assertEqual(result['state'], 'rolled-back-stopped')
        self.assertEqual(self.data.read_bytes(), self.payload.read_bytes())
        self.assertNotIn('install-start', self.events)

    def test_interruption_preserves_failure_and_allows_explicit_stopped_rollback(self):
        self.install_failure = 'interrupt'
        with self.assertRaises(upgrade.FailedStopped):
            self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)
        self.install_failure = None
        result = self.dispatch(self.make_request('rollback'))
        self.assertEqual(result['state'], 'rolled-back-stopped')

    def test_system_exit_is_also_quarantined(self):
        self.install_failure = 'system-exit'
        with self.assertRaises(upgrade.FailedStopped):
            self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)
        self.assertIn('fail-stopped', self.events)

    def test_pending_selected_intent_after_untrappable_interruption(self):
        self.dispatch()
        # Simulate SIGKILL after a sealed selection, before terminal commit.
        path = self.state / '.install-intent.json'
        value = journal.read(path)
        value.update(phase='building', steps=['preparing', 'units-selected', 'building'])
        value['hostTransaction']['disposition'] = 'installing'
        value['hostTransaction']['startAllowed'] = False
        journal.write(Path(value['release']) / 'installation-receipt.json', value)
        journal.write(path, value)
        self.data.write_text('{"schema":"partial-migration"}\n')
        self.events.clear()
        result = self.dispatch(self.make_request('rollback'))
        self.assertEqual(result['state'], 'rolled-back-stopped')
        self.assertFalse(self.running or self.boot_enabled)
        self.assertEqual(self.data.read_bytes(), self.payload.read_bytes())

    def test_rollback_rejects_candidate_without_original_source_checkpoint_proof(self):
        self.dispatch()
        path = self.state / '.install-intent.json'
        value = journal.read(path)
        value['hostTransaction']['sourceSha256'] = '0' * 64
        journal.write(Path(value['release']) / 'installation-receipt.json', value)
        journal.write(path, value)
        self.events.clear()
        with self.assertRaises(upgrade.Refused):
            self.dispatch(self.make_request('rollback'))
        self.assertNotIn('admit', self.events)
        self.assertNotIn('restore', self.events)

    def test_boolean_compatibility_proofs_must_not_be_integer_aliases(self):
        real_verify = self.recovery.verify_upgrade_checkpoint
        def incorrect(binding):
            proof = real_verify(binding)
            proof['forwardCompatible'] = 1
            return proof
        with patch.object(self.recovery, 'verify_upgrade_checkpoint', incorrect):
            with self.assertRaises(upgrade.Refused):
                self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_restore_failure_cannot_start_or_claim_rollback(self):
        self.dispatch()
        self.recovery.restore_failure = True
        self.events.clear()
        with self.assertRaises(upgrade.FailedStopped):
            self.dispatch(self.make_request('rollback'))
        self.assertNotIn('install-start', self.events)
        self.assertNotIn('install-stopped', self.events)
        self.assertFalse(self.running or self.boot_enabled)

    def test_stop_or_failure_journal_unproved_is_not_stopped_acceptance(self):
        self.stop_failure = True
        with self.assertRaises(upgrade.StopUnproved):
            self.dispatch()
        self.assertNotIn('install-start', self.events)

    def test_stopped_callback_without_durable_failure_receipt_is_not_proof(self):
        self.install_failure = 'migration'
        with patch.object(NativeFixture, 'fail_stopped', lambda _: None):
            with self.assertRaises(upgrade.StopUnproved):
                self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'building')

    def test_cleanup_failure_is_not_success(self):
        self.install_failure = 'migration'
        self.cleanup_failure = True
        with self.assertRaises(upgrade.StopUnproved):
            self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)

    def test_corrupt_native_completion_is_stopped_but_exact_failure_unproved(self):
        self.corrupt_completion = True
        with self.assertRaises(upgrade.StopUnproved):
            self.dispatch()
        self.assertFalse(self.running or self.boot_enabled)

    def test_admission_denial_does_not_stop_current_workloads(self):
        self.deny_admission = True
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertTrue(self.running and self.boot_enabled)
        self.assertNotIn('quiesce', self.events)
        self.assertNotIn('fail-stopped', self.events)

    def test_checkpoint_compatibility_and_integrity_before_admission(self):
        self.recovery.compatible = False
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)
        self.assertTrue(self.running)

    def test_checkpoint_is_reverified_stopped_before_any_migration(self):
        real_verify = self.recovery.verify_upgrade_checkpoint
        calls = []
        def expires_at_boundary(binding):
            calls.append(binding['operationId'])
            if len(calls) == 3:
                self.assertFalse(self.running or self.boot_enabled)
                raise upgrade.Refused('Synthetic checkpoint expired at stopped boundary')
            return real_verify(binding)
        with patch.object(self.recovery, 'verify_upgrade_checkpoint', expires_at_boundary):
            with self.assertRaises(upgrade.FailedStopped):
                self.dispatch()
        self.assertEqual(len(calls), 3)
        self.assertNotIn('install-start', self.events)
        self.assertIn('fail-stopped', self.events)
        self.assertFalse(self.running or self.boot_enabled)

    def test_checkpoint_payload_corruption_is_not_recovery_proof(self):
        self.payload.write_text('{}\n')
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_missing_native_or_recovery_api_fails_closed(self):
        with patch.object(journal, 'HOST_UPGRADE_API', None):
            with self.assertRaises(upgrade.Refused):
                self.dispatch()
        with patch.object(self.recovery, 'HOST_UPGRADE_API', None):
            with self.assertRaises(upgrade.Refused):
                self.dispatch()
        self.assertFalse(self.events)

    def test_replay_and_stale_intent_cas_are_refused(self):
        self.dispatch()
        self.events.clear()
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_locked_cas_race_cannot_consume_admission_or_stop(self):
        def race():
            value = journal.read(self.state / '.install-intent.json')
            journal.write(self.state / '.install-intent.json', dict(value, changed=True))
        self.race = race
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)
        self.assertNotIn('fail-stopped', self.events)
        self.assertTrue(self.running)

    def test_unknown_request_keys_duplicate_json_and_request_cas(self):
        self.change_request(automaticRestart=True)
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.request.write_text('{"schemaVersion":1,"schemaVersion":1}\n')
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        with self.assertRaises(upgrade.Refused):
            self.dispatch(expected='0' * 64)
        self.assertNotIn('admit', self.events)

    def test_marker_receipt_source_and_checkpoint_hash_mismatches(self):
        for field in ('markerSha256', 'selectedReceiptSha256', 'sourceSha256',
                      'checkpointSha256', 'admissionSha256', 'expectedIntentSha256'):
            with self.subTest(field=field):
                original = self.request.read_bytes()
                self.change_request(**{field: '0' * 64})
                with self.assertRaises(upgrade.Refused):
                    self.dispatch()
                self.request.write_bytes(original)
        self.assertNotIn('admit', self.events)

    def test_source_drift_and_absent_pin_appearance_refused(self):
        write(self.source / 'site/agent-vm.json', {'unexpected': True})
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_authority_modes_and_bounded_tree_policy_are_fail_closed(self):
        self.request.chmod(0o644)
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.request.chmod(0o600)
        with patch.object(upgrade, 'MAX_TREE_ENTRIES', 1):
            with self.assertRaises(upgrade.Refused):
                self.dispatch()
        with patch.object(upgrade, 'MAX_TREE_BYTES', 1):
            with self.assertRaises(upgrade.Refused):
                upgrade.tree_sha256(self.source)
        self.assertNotIn('admit', self.events)

    def test_symlink_or_hardlink_authorities_refused(self):
        linked = self.base / 'linked-request.json'
        linked.symlink_to(self.request)
        with self.assertRaises((upgrade.Refused, OSError)):
            self.dispatch(linked)
        linked.unlink()
        os.link(self.request, linked)
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_source_link_and_special_entry_are_refused(self):
        link = self.source / 'external.json'
        link.symlink_to(self.unrelated)
        with self.assertRaises(upgrade.Refused):
            upgrade.tree_sha256(self.source)
        link.unlink()
        os.link(self.unrelated, link)
        with self.assertRaises(upgrade.Refused):
            upgrade.tree_sha256(self.source)
        link.unlink()
        os.mkfifo(link, 0o600)
        with self.assertRaises(upgrade.Refused):
            upgrade.tree_sha256(self.source)
        # read_bytes is nonblocking and refuses a FIFO before reading it.
        with self.assertRaises(upgrade.Refused):
            upgrade.read_bytes(link)

    def test_symlinked_directory_and_writable_parent_refused(self):
        linked = self.base / 'linked-source'
        linked.symlink_to(self.source, target_is_directory=True)
        self.change_request(source=str(linked))
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.source.chmod(0o777)
        with self.assertRaises(upgrade.Refused):
            upgrade.tree_sha256(self.source)
        self.source.chmod(0o700)

    def test_scope_escape_and_unrelated_release_refused(self):
        self.change_request(scope=str(self.base / 'unrelated'))
        with self.assertRaises((upgrade.Refused, OSError)):
            self.dispatch()
        for value in (str(self.base / 'x/../candidate'), '//tmp/x', '/', 'relative'):
            with self.subTest(value=value):
                with self.assertRaises(upgrade.Refused):
                    upgrade.canonical(value)
        self.assertNotIn('admit', self.events)

    def test_current_pointer_must_be_exact_not_chain_or_relative(self):
        self.select(Path('releases/previous'))
        with self.assertRaises(upgrade.Refused):
            self.dispatch()
        self.assertNotIn('admit', self.events)

    def test_production_ancestor_and_owner_guards_without_fixture_override(self):
        # Inspect only synthetic files by injecting lstat, never host accounts.
        production = load('host-upgrade.py')
        directory_function = production.directory
        fake = type('Info', (), {'st_mode': stat.S_IFDIR | 0o755, 'st_uid': 0})()
        with patch.object(Path, 'lstat', return_value=fake):
            directory_function(Path('/synthetic/root'))
            fake.st_uid = 1000
            with self.assertRaises(production.Refused):
                directory_function(Path('/synthetic/root'))
            fake.st_uid = 0
            fake.st_mode = stat.S_IFLNK | 0o777
            with self.assertRaises(production.Refused):
                directory_function(Path('/synthetic/root'))


class ExistingOwnerTests(unittest.TestCase):
    # Reuse only isolated fixture helpers, not the optional-extension test cases.
    setUp = UpgradeTests.setUp
    tearDown = UpgradeTests.tearDown
    directory = UpgradeTests.directory
    journal_read = UpgradeTests.journal_read
    standalone_binding = UpgradeTests.standalone_binding
    select = UpgradeTests.select
    make_bundle = UpgradeTests.make_bundle
    make_request = UpgradeTests.make_request

    def binding(self):
        return {'schemaVersion': 1, 'root': str(self.state), 'scope': str(self.scope),
                'expectedIntentSha256': upgrade.sha((self.state / '.install-intent.json').read_bytes()),
                'selectedReceiptSha256': upgrade.sha((self.state / 'current' /
                    'installation-receipt.json').read_bytes()),
                'markerSha256': upgrade.sha(self.marker.read_bytes()),
                'source': str(self.source), 'sourceSha256': upgrade.tree_sha256(self.source)}

    def controller(self, binding=None):
        return upgrade.NativeCoordinator(binding or self.binding(), journal, load('host-recovery.py'))

    def phase(self, phase):
        path = self.state / '.install-intent.json'
        value = journal.read(path)
        value['phase'] = phase
        value['steps'] = ['preparing', 'units-selected', 'building', phase]
        journal.write(self.previous / 'installation-receipt.json', value)
        journal.write(path, value)

    def authorize(self, request):
        self.events.append('authorize-' + request['kind'])
        return request

    def quarantine(self, root, expected, reviewed):
        self.events.append('canonical-quarantine')
        self.assertEqual(root, self.state)
        self.assertEqual(expected, upgrade.sha((root / '.install-intent.json').read_bytes()))
        self.assertTrue(reviewed)
        self.assertEqual(journal.read(root / '.install-intent.json')['phase'], 'failed')
        # Assert this is the canonical exclusive lock, not a replacement lease.
        with self.controller().locked():
            self.fail('Canonical lock was not held')

    def mock_quarantine(self):
        def perform(root, expected, reviewed):
            with self.assertRaises(BlockingIOError):
                self.quarantine(root, expected, reviewed)
            self.running = self.boot_enabled = False
            return {'quarantined': True, 'intentRetired': False}
        return patch.object(journal, 'quarantine_failed', side_effect=perform)

    def verify_stopped(self, release):
        self.events.append('canonical-verify-stopped')
        self.assertEqual(release, self.previous)
        if self.running or self.boot_enabled:
            raise upgrade.Refused('Synthetic selected manager/process/trigger remains')

    def test_plan_uses_existing_api_without_future_hooks(self):
        with patch.object(journal, 'HOST_UPGRADE_API', None):
            plan = self.controller().plan()
        self.assertEqual(plan['selection']['phase'], 'active')
        self.assertFalse(plan['upgradeAvailable'])
        self.assertFalse(plan['crossReleaseRestoreAvailable'])
        self.assertFalse(plan['stoppedProof'])
        self.assertFalse(plan['installedAcceptance'])
        self.assertEqual(set(plan['commands']), {'inspect'})
        self.assertFalse(plan['nativePreactivationCheckIsReadOnly'])
        self.assertTrue(self.running)
        self.assertFalse(self.events)

    def test_operator_group_scope_2770_is_not_rejected_as_foreign(self):
        # Synthetic UID anchor still belongs to this process. Exercise the
        # actual mode exemption ONLY for canonical-authority-proved scope.
        self.scope.chmod(0o2770)
        with patch.object(journal, 'HOST_UPGRADE_API', None):
            plan = self.controller().plan()
        self.assertEqual(plan['selection']['scope'], str(self.scope))
        self.assertEqual(stat.S_IMODE(self.scope.stat().st_mode), 0o2770)
        self.scope.chmod(0o700)

    def test_unsafe_metadata_root_is_not_scope_exemption(self):
        self.state.chmod(0o750)
        with self.assertRaises(upgrade.Refused):
            self.controller().plan()
        self.state.chmod(0o700)

    def test_scope_link_and_linked_marker_cannot_use_ownership_exception(self):
        original_scope = self.base / 'scope-original'
        self.scope.rename(original_scope)
        self.scope.symlink_to(original_scope)
        try:
            with self.assertRaises(OSError):
                self.controller().plan()
        finally:
            self.scope.unlink()
            original_scope.rename(self.scope)
        link = self.scope / 'marker-hardlink'
        os.link(self.marker, link)
        with self.assertRaises(upgrade.Refused):
            self.controller().plan()
        link.unlink()
        saved = self.marker.read_bytes()
        self.marker.unlink()
        target = self.base / 'marker-target'
        target.write_bytes(saved)
        target.chmod(0o600)
        self.marker.symlink_to(target)
        with self.assertRaises(upgrade.Refused):
            self.controller().plan()

    def test_canonical_authority_rejection_is_not_bypassed(self):
        with patch.object(journal, 'standalone_binding', side_effect=ValueError('foreign ACL/actor')):
            with self.assertRaises(ValueError):
                self.controller().plan()
        self.assertFalse(self.events)

    def test_changed_candidate_rejected_before_settlement_admission(self):
        self.phase('failed')
        controller = self.controller()
        write(self.source / 'changed-config.json', {'changed': True})
        with self.assertRaises(upgrade.Refused):
            controller.settle_failed('c' * 32, self.authorize)
        self.assertFalse(self.events)
        self.assertTrue(self.running)

    def test_migration_failed_settlement_preserves_restore_checkpoint(self):
        self.phase('failed')
        self.data.write_text('{"schema":"migration-failed"}\n')
        controller = self.controller()
        with self.mock_quarantine(), patch.object(journal, 'verify_quarantined', self.verify_stopped):
            result = controller.settle_failed('c' * 32, self.authorize)
        self.assertEqual(result['state'], 'failed-stopped')
        self.assertFalse(result['intentRetired'])
        self.assertFalse(result['dataCompatibilityProved'])
        self.assertFalse(self.running or self.boot_enabled)
        self.assertNotEqual(self.data.read_bytes(), self.payload.read_bytes())
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'failed')
        self.assertTrue(self.checkpoint.exists())

    def test_interrupted_selected_intent_is_terminal_failed_then_stopped(self):
        self.phase('building')
        with self.mock_quarantine(), patch.object(journal, 'verify_quarantined', self.verify_stopped):
            result = self.controller().settle_failed('d' * 32, self.authorize)
        self.assertEqual(result['state'], 'failed-stopped')
        receipt = journal.read(self.previous / 'installation-receipt.json')
        self.assertEqual(receipt['phase'], 'failed')
        self.assertEqual(receipt['steps'][-1], 'failed')
        self.assertNotIn('retired-failed', receipt['steps'])
        self.assertEqual(result['intentSha256'], upgrade.sha((self.state / '.install-intent.json').read_bytes()))

    def test_active_settlement_and_incorrect_approval_refused(self):
        with self.assertRaises(upgrade.Refused):
            self.controller().settle_failed('d' * 32, self.authorize)
        self.phase('building')
        before = (self.state / '.install-intent.json').read_bytes()
        with self.assertRaises(upgrade.Refused):
            self.controller().settle_failed('d' * 32, lambda request: dict(request, restart=0))
        self.assertEqual((self.state / '.install-intent.json').read_bytes(), before)
        self.assertTrue(self.running)

    def test_admission_source_cas_race_cannot_stop(self):
        self.phase('failed')
        def drift(request):
            write(self.source / 'late.json', {'changed': True})
            return request
        with patch.object(journal, 'quarantine_failed') as quarantine:
            with self.assertRaises(upgrade.Refused):
                self.controller().settle_failed('d' * 32, drift)
            quarantine.assert_not_called()
        self.assertTrue(self.running)

    def test_quarantine_failure_preserves_failed_boundary_not_retirement(self):
        self.phase('starting')
        with patch.object(journal, 'quarantine_failed', side_effect=ValueError('still running')):
            with self.assertRaises(ValueError):
                self.controller().settle_failed('d' * 32, self.authorize)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'failed')
        self.assertTrue(self.running)

    def test_retired_failed_plan_does_not_authorize_new_activation(self):
        self.phase('failed')
        self.running = self.boot_enabled = False
        with patch.object(journal, 'verify_quarantined', self.verify_stopped):
            journal.retire_failed(self.state, self.binding()['expectedIntentSha256'], True,
                                  verifier=self.verify_stopped)
            controller = self.controller()
            result = controller.settle_failed('d' * 32, lambda _: self.fail('Retirement was replayed'))
        self.assertEqual(result['state'], 'retired-failed-stopped')
        self.assertFalse(controller.plan()['upgradeAvailable'])
        backend = controller.recovery_backend()
        self.assertEqual(backend.expected, self.binding()['expectedIntentSha256'])
        self.assertIsNone(backend.lease)

    def test_existing_stopped_lease_is_passed_to_real_backend_without_substitution(self):
        self.phase('retired-failed')
        controller = self.controller()
        lease = object()
        controller.lease = lease
        backend = controller.recovery_backend()
        self.assertIs(backend.lease, lease)
        self.assertEqual(backend.expected, self.binding()['expectedIntentSha256'])
        self.assertEqual(backend.root, self.state)
        self.assertFalse(self.events)

    def test_failed_recovery_cannot_substitute_approval_for_retirement_boundary(self):
        self.phase('failed')
        controller = self.controller()
        with patch.object(controller.recovery.Backend, 'restore') as restore:
            with self.assertRaises(upgrade.Refused):
                controller.restore_checkpoint(self.payload, 'a' * 64, self.checkpoint, 'd' * 32, self.authorize)
            restore.assert_not_called()
        self.assertFalse(self.events)

    def test_actual_recovery_api_receives_exact_restore_flags_and_callback(self):
        self.phase('retired-failed')
        controller = self.controller()
        observed = {}
        def restore(backend, archive, archive_sha256, identity_file, operation_id, authorize):
            observed.update(root=backend.root, expected=backend.expected,
                            archive=archive, sha256=archive_sha256, identity=identity_file, operation=operation_id)
            self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'retired-failed')
            request = {'schemaVersion': 1, 'kind': 'restore', 'operationId': operation_id,
                       'selection': {'nativeIntentSha256': backend.expected}, 'restart': False}
            self.assertEqual(authorize(request), request)
            return {'restored': True, 'restart': False, 'installedAcceptance': False}
        with patch.object(controller.recovery.Backend, 'restore', autospec=True, side_effect=restore):
            result = controller.restore_checkpoint(self.payload, 'e' * 64, self.checkpoint, 'f' * 32,
                                                   self.authorize)
        self.assertEqual(observed, {'root': self.state, 'expected': self.binding()['expectedIntentSha256'],
            'archive': self.payload, 'sha256': 'e' * 64, 'identity': self.checkpoint, 'operation': 'f' * 32})
        self.assertTrue(result['restored'])
        self.assertFalse(result['restart'])
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'retired-failed')

    def test_incorrect_checkpoint_and_approval_never_select_old_source(self):
        self.phase('retired-failed')
        controller = self.controller()
        before = (self.state / '.install-intent.json').read_bytes()
        def restore(backend, archive, archive_sha256, identity_file, operation_id, authorize):
            request = {'kind': 'restore', 'restart': False}
            authorize(request)
            raise ValueError('Foreign same-release checkpoint binding')
        with patch.object(controller.recovery.Backend, 'restore', autospec=True, side_effect=restore):
            with self.assertRaises(upgrade.Refused):
                controller.restore_checkpoint(self.payload, 'e' * 64, self.checkpoint, 'f' * 32,
                                               lambda r: dict(r, restart=0))
            with self.assertRaises(ValueError):
                controller.restore_checkpoint(self.payload, 'e' * 64, self.checkpoint, 'f' * 32,
                                               self.authorize)
        self.assertEqual((self.state / '.install-intent.json').read_bytes(), before)
        self.assertEqual(os.readlink(self.state / 'current'), str(self.previous))

    def test_interrupted_recovery_uses_recover_not_restore_or_install(self):
        self.phase('retired-failed')
        controller = self.controller()
        def recover(backend, expected_recovery_sha256, authorize):
            self.assertEqual(expected_recovery_sha256, 'e' * 64)
            self.assertEqual(backend.expected, self.binding()['expectedIntentSha256'])
            request = {'kind': 'recover-originals', 'recoveryJournalSha256': expected_recovery_sha256,
                       'restart': False}
            authorize(request)
            return {'originalsRestored': True, 'restart': False, 'installedAcceptance': False}
        with patch.object(controller.recovery.Backend, 'recover', autospec=True, side_effect=recover), \
                patch.object(controller.recovery.Backend, 'restore') as restore:
            result = controller.recover_interrupted('e' * 64, self.authorize)
            restore.assert_not_called()
        self.assertTrue(result['originalsRestored'])
        self.assertFalse(result['restart'])

    def actual_recovery_fixture(self):
        """Real Backend parser/renames/CAS with isolated ownership/crypto seams.

        No native command or real key: reuse ONLY tracked FAKE_AGE source as a
        fixture protocol. Not real encryption, operator-scope or host proof.
        """
        ir = {'services': {
            'keycloak': {'placement': 'rootful', 'volumes': []},
            'postgres': {'placement': 'rootful', 'volumes': ['rows:/db']}},
            'volumes': {'rows': {'hostPath': str(self.data.parent)}}}
        for path in (self.previous, self.source):
            write(path / 'stack.ir.json', ir)
        write(self.previous / 'runtime/configs/example.json', {'fixture': True})
        value = journal.read(self.state / '.install-intent.json')
        value['inputs'] = journal.fingerprint(self.previous)
        # Model the explicitly reviewed native retirement boundary; coordinator
        # itself must never promote/retire a failure just to permit recovery.
        value['phase'] = 'retired-failed'
        value['steps'] += ['failed', 'retired-failed']
        journal.write(self.previous / 'installation-receipt.json', value)
        journal.write(self.state / '.install-intent.json', value)
        self.running = self.boot_enabled = False
        controller = self.controller()
        r = controller.recovery
        spec = importlib.util.spec_from_file_location('upgrade_recovery_fixture_source',
                                                      ROOT / 'scripts/test-host-recovery.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        age = self.base / 'fixture-bin/age'
        age.parent.mkdir(mode=0o700)
        age.write_text(fixture.FAKE_AGE)
        age.chmod(0o700)
        expected_marker = self.standalone_binding(self.previous)
        backend_type = r.Backend
        self.stack.enter_context(patch.object(r, 'OWNER', os.geteuid()))
        @contextlib.contextmanager
        def fixture_lock(_):
            # Root privilege alone is substituted, not lock identity/serialization.
            with controller.locked():
                yield
        self.stack.enter_context(patch.object(backend_type, 'locked', fixture_lock))
        self.stack.enter_context(patch.object(r, 'mount_points', return_value=set()))
        self.stack.enter_context(patch.object(r.journal, 'read', self.journal_read))
        self.stack.enter_context(patch.object(r.journal, 'verify_quarantined', self.verify_stopped))
        self.stack.enter_context(patch.object(r.storage, 'authority',
                                             return_value=(self.scope, None, expected_marker)))
        self.stack.enter_context(patch.object(r.storage, 'marker',
                                             side_effect=lambda scope, expected: self.standalone_binding(self.previous)))
        self.stack.enter_context(patch.object(r, 'Backend',
            side_effect=lambda root, expected, lease=None: backend_type(root, expected, age, lease=lease)))
        backend = backend_type(self.state, self.binding()['expectedIntentSha256'], age)
        archives = self.base / 'archives'
        keys = self.base / 'separate-fixture-key'
        archives.mkdir(mode=0o700)
        keys.mkdir(mode=0o700)
        key, archive = keys / 'identity', archives / 'snapshot.age'
        key.write_bytes(b'fixture-key')
        key.chmod(0o600)
        backup = backend.backup(archive, 'age1' + 'q' * 58, '1' * 32, self.authorize)
        return controller, backend, archive, backup['archiveSha256'], key

    def test_actual_backend_failed_data_restore_checkpoint_keeps_stopped(self):
        controller, backend, archive, digest, key = self.actual_recovery_fixture()
        original = self.data.read_bytes()
        before = (self.state / '.install-intent.json').read_bytes()
        self.data.write_text('{"schema":"partial-migration"}\n')
        result = controller.restore_checkpoint(archive, digest, key, '2' * 32, self.authorize)
        self.assertTrue(result['restored'])
        self.assertFalse(result['restart'] or result['installedAcceptance'])
        self.assertEqual(self.data.read_bytes(), original)
        self.assertEqual((self.state / '.install-intent.json').read_bytes(), before)
        self.assertEqual(backend.selection()[0]['nativeIntentSha256'], self.binding()['expectedIntentSha256'])
        self.assertFalse(self.running or self.boot_enabled)

    def test_actual_backend_incorrect_checkpoint_and_approval_fail_closed(self):
        controller, backend, archive, digest, key = self.actual_recovery_fixture()
        original = self.data.read_bytes()
        with self.assertRaises(ValueError):
            controller.restore_checkpoint(archive, '0' * 64, key, '2' * 32, self.authorize)
        with self.assertRaises(upgrade.Refused):
            controller.restore_checkpoint(archive, digest, key, '2' * 32,
                                           lambda request: dict(request, restart=0))
        # Even valid ciphertext/approval must not authorize a different release:
        # tamper only fixture archive's selected receipt binding, then re-HMAC.
        import hashlib
        import hmac
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()[41:]), mode='r:') as tar:
            entries = [(item, tar.extractfile(item).read() if item.isfile() else None) for item in tar]
        manifest = json.loads(entries[0][1])
        manifest['selection']['receiptSha256'] = '0' * 64
        body = controller.recovery.canonical(manifest)
        entries[0][0].size = len(body)
        entries[0] = (entries[0][0], body)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for item, content in entries:
                tar.addfile(item, io.BytesIO(content) if content is not None else None)
        raw = output.getvalue()
        archive.write_bytes(b'MOCK-AGE\n' + hmac.digest(b'fixture-key', raw, 'sha256') + raw)
        with self.assertRaises(ValueError):
            controller.restore_checkpoint(archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                                           key, '2' * 32, self.authorize)
        self.assertEqual(self.data.read_bytes(), original)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'retired-failed')
        self.assertFalse(self.running or self.boot_enabled)

    def test_actual_backend_interrupted_swap_recovers_with_exact_cas_only(self):
        controller, backend, archive, digest, key = self.actual_recovery_fixture()
        self.data.write_text('{"schema":"failed-data-original"}\n')
        original = self.data.read_bytes()
        r = controller.recovery
        rename = r.rename
        def crash(source, destination):
            rename(source, destination)
            if destination.name == 'original':
                raise OSError('Synthetic interruption after original rename')
        # Patch the real class, not the fixture factory Mock.
        with patch.object(r, 'rename', side_effect=crash), \
                patch.object(type(backend), 'rollback', side_effect=OSError('Synthetic process death')):
            with self.assertRaises(OSError):
                controller.restore_checkpoint(archive, digest, key, '2' * 32, self.authorize)
        recovery_cas = r.file_sha(backend.intent)
        with self.assertRaises(ValueError):
            controller.recover_interrupted('0' * 64, self.authorize)
        result = controller.recover_interrupted(recovery_cas, self.authorize)
        self.assertTrue(result['originalsRestored'])
        self.assertFalse(result['restart'] or result['installedAcceptance'])
        self.assertEqual(self.data.read_bytes(), original)
        self.assertEqual(journal.read(self.state / '.install-intent.json')['phase'], 'retired-failed')
        self.assertFalse(self.running or self.boot_enabled)

    def test_command_flag_fidelity_to_tracked_shell_installer(self):
        shell = (ROOT / 'runtime-generator/podman-ops/install-podman-bundle.sh').read_text()
        cases = [upgrade.native_command(self.state, 'inspect'),
                 upgrade.native_command(self.state, 'quarantine-failed', expected='a' * 64),
                 upgrade.native_command(self.state, 'retire-failed', expected='a' * 64),
                 upgrade.native_command(self.state, 'validate', bundle=self.source,
                                        env_dir=self.base / 'rendered', image_inputs=self.base / 'images.json')]
        self.assertEqual(cases[1]['argv'][2:], ['--quarantine-failed-intent', 'a' * 64,
                                               '--reviewed-data-state'])
        self.assertEqual(cases[2]['argv'][2:], ['--retire-failed-intent', 'a' * 64,
                                               '--reviewed-data-state'])
        for command in cases:
            self.assertEqual(command['argv'][:2], ['/bin/bash',
                str(ROOT / 'runtime-generator/podman-ops/install-podman-bundle.sh')])
            for argument in command['argv'][2:]:
                if argument.startswith('--'):
                    self.assertIn(argument + ')', shell)
            self.assertEqual(command['environment']['WEBSERVICES_STATE_ROOT'], str(self.state))
            self.assertEqual(command['environment']['WEBSERVICES_ACTIVATION_ROLLBACK'], '0')
            self.assertFalse(command['authorized'] or command['executed'])
            self.assertNotIn('--activate', command['argv'])
            self.assertNotIn('--resume-intent', command['argv'])
        for action in ('activate', 'install-stopped', 'resume-intent'):
            with self.assertRaises(upgrade.Refused):
                upgrade.native_command(self.state, action)
        with self.assertRaises(upgrade.Refused):
            upgrade.native_command(self.state, 'quarantine-failed', expected='a' * 64, bundle=self.source)


if __name__ == '__main__':
    unittest.main()
