"""Legacy mechanism regressions, NOT custody proof. Never mounts/runs engines.

Critical07: named legacy fixtures explicitly stub require_protected_view to retain
ABI/CAS/state-machine regressions. Separate containment tests DO NOT stub it.
Native10 supersedes the old security premise even when every mechanism passes.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'ops/host-admin' / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


n = load('namespace_fixture', 'provision-p0-v2-namespace.py')
c = load('credential_namespace_fixture', 'provision-p0-machine-credentials.py')


def seal(record):
    fields = {k: v for k, v in record.items() if k != 'integrity'}
    record['integrity'] = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return record


def observations(expected, pinned=True):
    parent = {'id': 100, 'parent': 1, 'device': f"{os.major(expected['device'])}:{os.minor(expected['device'])}",
              'root': '/', 'target': str(n.SHARED), 'options': ['rw', 'relatime'], 'optional': [],
              'fsType': 'ext4', 'source': '/dev/fixture'}
    child = dict(copy.deepcopy(parent), id=101, parent=100, root='/p0-v2', target=str(n.TARGET))
    return {'bootId': '12345678-1234-1234-1234-123456789abc', 'mountNamespace': {'device': 4, 'inode': 1000},
            'mounts': [parent, child] if pinned else [parent]}


def marker_record(expected, obs, state='pinned'):
    own = next((m for m in obs['mounts'] if m['target'] == str(n.TARGET)), None)
    return seal({'version': 2, 'state': state, 'owner': 'a' * 32, 'evidenceSha256': 'b' * 64,
                 'namespace': dict(expected), 'bootId': obs['bootId'], 'mountNamespace': dict(obs['mountNamespace']),
                 'mount': copy.deepcopy(own), 'cloneMountId': own['id'] if own else None})


class MemoryMarker:
    def __init__(self, record=None):
        self.record, self.writes, self.fd, self.opens = record, [], (100 if record is not None else None), []

    def open(self, *args, **kwargs):
        self.fd = 100
        self.opens.append((args, kwargs))

    def load(self):
        return copy.deepcopy(self.record)

    def save(self, record):
        seal(record)
        self.record = copy.deepcopy(record)
        self.writes.append(copy.deepcopy(record))


class FakeNative:
    def __init__(self, expected, obs, marker):
        self.expected, self.obs, self.marker = expected, obs, marker
        self.effects = []
        self.fail_stopped = False
        self.crash_after_bind = False
        self.crash_after_private = False
        self.next_mount_id = 101

    def stopped(self, proof, fd, *, record, observation, repin=None):
        n.require(not self.fail_stopped, 'runtime-unit-not-stopped')

    def pin_namespace(self, fd, expected, *, claim_clone, before_attach, verify_attached):
        assert self.marker.record['state'] == 'claimed'
        self.source_fd = fd
        tree = os.dup(fd)  # Private fixture FD, NOT an actual mount.
        try:
            self.effects.append(('clone', tree))
            claim_clone(self.next_mount_id)
            self.effects.append(('private-detached', tree))
            before_attach()
            assert self.marker.record['cloneMountId'] == self.next_mount_id
            self.effects.append(('attach', tree))
            self.obs['mounts'] = observations(self.expected)['mounts']
            self.obs['mounts'][-1]['id'] = self.next_mount_id
            self.obs['mounts'][-1]['optional'] = ['shared:7']
            verify_attached(self.next_mount_id, require_private=False)
            if self.crash_after_bind:
                self.crash_after_bind = False
                raise RuntimeError('SYNTHETIC_NATIVE_ERROR')
            self.effects.append(('private-attached', tree))
            self.obs['mounts'][-1]['optional'] = []
            verify_attached(self.next_mount_id, require_private=True)
            if self.crash_after_private:
                self.crash_after_private = False
                raise RuntimeError('SYNTHETIC_PRIVATE_EFFECT_CRASH')
        finally:
            os.close(tree)

    def privatize_owned(self, fd, expected, mount_id, *, verify_attached):
        verify_attached(mount_id, require_private=False)
        self.effects.append(('private-repair', fd))
        self.obs['mounts'][-1]['optional'] = []
        verify_attached(mount_id, require_private=True)


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.p0-namespace-fixture-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.fd = os.open(self.temp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        s = os.fstat(self.fd)
        self.expected = dict(n.identity(s), filesystemId=os.fstatvfs(self.fd).f_fsid)
        self.obs = observations(self.expected)
        self.record = marker_record(self.expected, self.obs)
        self.entry = types.SimpleNamespace(pw_uid=1234, pw_gid=1234)
        self.proof = {'version': 1, 'namespace': dict(self.expected), 'units': {'rootless': [], 'rootful': []}}

    def contexts(self, obs):
        real_lstat = Path.lstat
        target_stat = types.SimpleNamespace(st_dev=self.expected['device'], st_ino=self.expected['inode'])
        return [patch.object(n, 'require_protected_view'),
                patch.object(n, 'namespace', side_effect=lambda expected: os.dup(self.fd)),
                patch.object(n, 'kernel', side_effect=lambda: copy.deepcopy(obs)), patch.object(n, 'reserves'),
                patch.object(n, 'preflight_children'), patch.object(n, 'create_children'),
                patch.object(n, 'check_actor_directories'), patch.object(n, 'RepinPermit'),
                patch.object(n.Path, 'lstat', new=lambda p: target_stat if p == n.TARGET else real_lstat(p))]

    def run_pin(self, marker, native, obs, mode='apply'):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for context in self.contexts(obs):
                stack.enter_context(context)
            return n.pin(self.proof, 'b' * 64, marker, native, self.entry, mode)

    def test_marker_contract_agrees_without_cross_helper_imports(self):
        self.assertEqual(n.verify_marker(self.record, self.obs, self.expected),
                         c.validate_namespace_marker(self.record, self.obs, self.expected))
        self.assertEqual(n.mountinfo(b'100 1 0:1 / /mnt/stack rw - ext4 /dev/fixture rw\n'),
                         c.mountinfo(b'100 1 0:1 / /mnt/stack rw - ext4 /dev/fixture rw\n'))

    def invalid_cases(self):
        cases = []
        record = copy.deepcopy(self.record)
        record['cloneMountId'] += 1
        seal(record)
        cases.append(('wrong-preclaimed-clone', record, self.obs))
        record = copy.deepcopy(self.record)
        record['version'] = 1
        record.pop('cloneMountId')
        seal(record)
        cases.append(('legacy-marker-version', record, self.obs))
        record = copy.deepcopy(self.record)
        record['owner'] = 'FORGED'
        cases.append(('forged', record, self.obs))
        record = copy.deepcopy(self.record)
        record['namespace']['inode'] += 1
        seal(record)
        cases.append(('renamed', record, self.obs))
        record = copy.deepcopy(self.record)
        record['namespace']['filesystemId'] += 1
        seal(record)
        cases.append(('filesystem', record, self.obs))
        record = copy.deepcopy(self.record)
        record['bootId'] = '87654321-1234-1234-1234-123456789abc'
        seal(record)
        cases.append(('stale', record, self.obs))
        record = copy.deepcopy(self.record)
        record['state'] = 'claimed'
        seal(record)
        cases.append(('incomplete', record, self.obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'][-1]['source'] = '/dev/foreign'
        cases.append(('foreign', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'][-1]['id'] += 100
        cases.append(('mount-id-replaced', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mountNamespace']['inode'] += 1
        cases.append(('wrong-mount-namespace', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'][-1]['optional'] = ['shared:5']
        cases.append(('shared-not-private', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'] = obs['mounts'][:1]
        cases.append(('unpinned', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'].append(dict(obs['mounts'][-1], id=200, target=str(n.TARGET) + '/rootless/engine/overlay/active'))
        cases.append(('submount', self.record, obs))
        obs = copy.deepcopy(self.obs)
        obs['mounts'].append(dict(obs['mounts'][-1], id=201))
        cases.append(('stacked', self.record, obs))
        return cases

    def test_invalid_boundaries_fail_in_both_independent_verifiers(self):
        for name, record, obs in self.invalid_cases():
            with self.subTest(name=name):
                with self.assertRaises(n.Refused):
                    n.verify_marker(record, obs, self.expected)
                with self.assertRaises(c.Refused):
                    c.validate_namespace_marker(record, obs, self.expected)

    def credential_attempt(self, record, obs):
        class MemoryCustody:
            fd = None
            saved = None
            def load(self):
                return None
            def catalog(self, spec):
                pass
            def save(self, value):
                self.saved = copy.deepcopy(value)
        custody = MemoryCustody()
        native = c.Native(self.entry)
        effects = []
        def call(actor, args, payload=None):
            effects.append(args[:2])
            if args[0] == 'info':
                return 0, json.dumps({'store': {'graphRoot': str(c.ROOTFUL), 'runRoot': str(c.RUNFUL), 'graphDriverName': 'overlay'}}).encode()
            if args[:2] == ['secret', 'exists']:
                return (0 if any(e == ['secret', 'create'] for e in effects) else 1), b''
            if args[:2] == ['secret', 'create']:
                return 0, b'X' * 25
            if args[:2] == ['secret', 'inspect']:
                item = custody.saved['resources']['ordinary']
                return 0, json.dumps([{'ID': 'x' * 25, 'Spec': {'Name': 'p0-ordinary',
                      'Labels': c.labels(custody.saved, item), 'Driver': {'Name': 'file', 'Options': {}}}}]).encode()
            raise AssertionError('unexpected fixed API')
        def gate():
            if record is None:
                raise FileNotFoundError()
            c.validate_namespace_marker(record, obs, self.expected)
        intent = {'version': 1, 'classification': 'ordinary-service', 'resources': [{'name': 'ordinary', 'actors': ['rootful']}]}
        with patch.object(c, 'pinned_namespace', side_effect=gate), patch.object(c, 'directory'), \
             patch.object(c, 'trusted_binary'), patch.object(c, 'reserves'), \
             patch.object(c.Path, 'lstat', return_value=types.SimpleNamespace(st_gid=0, st_uid=0, st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700)), \
             patch.object(native, 'call', side_effect=call):
            try:
                result = c.supply(intent, 'd' * 64, custody, native, 'apply')
            except (c.Refused, FileNotFoundError):
                self.assertFalse(effects)
                self.assertIsNone(custody.saved)
                return False
        self.assertEqual(result['resources'][0]['actors']['rootful']['state'], 'complete')
        self.assertIn(['secret', 'create'], effects)
        return True

    def test_missing_forged_stale_foreign_unpinned_submount_fail_before_secret_effect(self):
        self.assertFalse(self.credential_attempt(None, self.obs))
        for name, record, obs in self.invalid_cases():
            with self.subTest(name=name):
                self.assertFalse(self.credential_attempt(record, obs))
        self.assertTrue(self.credential_attempt(self.record, self.obs))

    def test_fresh_pin_claims_before_bind_reopens_mount_and_creates_only_after_private(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        result = self.run_pin(marker, native, obs)
        self.assertEqual([e[0] for e in native.effects], ['clone', 'private-detached', 'attach', 'private-attached'])
        self.assertNotEqual(native.effects[0][1], native.source_fd)
        self.assertTrue(all(e[1] == native.effects[0][1] for e in native.effects))
        self.assertEqual(marker.writes[1]['cloneMountId'], 101)
        self.assertIsNone(marker.writes[1]['mount'])
        self.assertEqual(marker.writes[0]['state'], 'claimed')
        self.assertIsNone(marker.writes[0]['mount'])
        self.assertEqual(marker.writes[-1]['state'], 'pinned')
        self.assertEqual(result['mountId'], 101)
        n.verify_marker(marker.record, obs, self.expected)

    def test_active_unit_failure_precedes_marker_creation_and_all_effects(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        native.fail_stopped = True
        with self.assertRaisesRegex(n.Refused, '^runtime-unit-not-stopped$'):
            self.run_pin(marker, native, obs)
        self.assertFalse(marker.opens)
        self.assertFalse(marker.writes)
        self.assertFalse(native.effects)
        self.assertFalse(self.credential_attempt(marker.record, obs))

    def test_alien_existing_mount_and_submount_refuse_before_gate_or_effect(self):
        for obs in (self.obs, dict(self.obs, mounts=[self.obs['mounts'][0],
                    dict(self.obs['mounts'][1], target=str(n.TARGET) + '/rootless/engine/overlay/mount')])):
            marker = MemoryMarker()
            native = FakeNative(self.expected, obs, marker)
            with self.assertRaises(n.Refused):
                self.run_pin(marker, native, obs)
            self.assertFalse(native.effects)
            self.assertFalse(marker.writes)

    def test_crash_after_bind_resumes_only_from_exact_claim_without_rebind(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        native.crash_after_bind = True
        with self.assertRaises(RuntimeError):
            self.run_pin(marker, native, obs)
        self.assertEqual(marker.record['state'], 'claimed')
        with self.assertRaises(n.Refused):
            self.run_pin(marker, native, obs, 'apply')
        result = self.run_pin(marker, native, obs, 'resume')
        self.assertEqual([e[0] for e in native.effects], ['clone', 'private-detached', 'attach', 'private-repair'])
        self.assertEqual(result['state'], 'pinned')

    def test_crash_after_private_reconciles_only_same_mount_with_removed_tags(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        native.crash_after_private = True
        with self.assertRaises(RuntimeError):
            self.run_pin(marker, native, obs)
        self.assertEqual(marker.record['state'], 'claimed')
        self.assertIsNone(marker.record['mount'])
        self.assertEqual(marker.record['cloneMountId'], 101)
        self.assertEqual(obs['mounts'][-1]['optional'], [])
        self.run_pin(marker, native, obs, 'resume')
        self.assertEqual(marker.record['state'], 'pinned')
        self.assertEqual([e[0] for e in native.effects], ['clone', 'private-detached', 'attach', 'private-attached'])

    def test_absent_preclaimed_clone_is_not_blindly_reallocated(self):
        obs = observations(self.expected, False)
        record = marker_record(self.expected, obs, 'claimed')
        record['cloneMountId'] = 101
        seal(record)
        marker = MemoryMarker(record)
        native = FakeNative(self.expected, obs, marker)
        with self.assertRaisesRegex(n.Refused, '^preclaimed-clone-absent-review-required$'):
            self.run_pin(marker, native, obs, 'resume')
        self.assertFalse(marker.writes)
        self.assertFalse(native.effects)
        self.assertEqual(marker.record, record)

    def test_no_reserve_prevents_marker_or_mount_effect(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        from contextlib import ExitStack
        with ExitStack() as stack:
            for context in self.contexts(obs):
                stack.enter_context(context)
            stack.enter_context(patch.object(n, 'reserves', side_effect=n.Refused('disk-reserve')))
            with self.assertRaisesRegex(n.Refused, '^disk-reserve$'):
                n.pin(self.proof, 'b' * 64, marker, native, self.entry, 'apply')
        self.assertFalse(marker.opens)
        self.assertFalse(marker.writes)
        self.assertFalse(native.effects)

    def test_boot_recheck_reuses_stable_identity_not_old_mount_or_boot_ids(self):
        obs = observations(self.expected, False)
        obs['bootId'] = '87654321-1234-1234-1234-123456789abc'
        obs['mountNamespace']['inode'] += 100
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, obs, marker)
        native.next_mount_id = 201
        with self.assertRaises(n.Refused):
            self.run_pin(marker, native, obs, 'apply')
        with self.assertRaises(n.Refused):
            self.run_pin(marker, native, obs, 'check')
        self.assertFalse(native.effects)
        self.run_pin(marker, native, obs, 'recheck')
        self.assertEqual(marker.record['namespace'], self.expected)
        self.assertEqual(marker.record['bootId'], obs['bootId'])
        self.assertEqual(marker.record['mountNamespace'], obs['mountNamespace'])
        self.assertEqual(marker.record['mount']['id'], 201)
        self.assertEqual(marker.record['state'], 'pinned')

    def test_only_explicit_boot_recheck_can_refresh_reviewed_unit_evidence(self):
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, self.obs, marker)
        from contextlib import ExitStack
        with ExitStack() as stack:
            for context in self.contexts(self.obs):
                stack.enter_context(context)
            for mode in ('check', 'apply', 'resume', 'recheck'):
                with self.assertRaisesRegex(n.Refused, '^namespace-evidence-changed$'):
                    n.pin(self.proof, 'c' * 64, marker, native, self.entry, mode)
        self.assertFalse(marker.writes)
        obs = observations(self.expected, False)
        obs['bootId'] = '87654321-1234-1234-1234-123456789abc'
        native = FakeNative(self.expected, obs, marker)
        with ExitStack() as stack:
            for context in self.contexts(obs):
                stack.enter_context(context)
            n.pin(self.proof, 'c' * 64, marker, native, self.entry, 'recheck')
        self.assertEqual(marker.record['evidenceSha256'], 'c' * 64)
        self.assertEqual(marker.record['namespace'], self.expected)
        self.assertEqual(marker.record['owner'], self.record['owner'])

    def test_recheck_never_adopts_a_new_boot_foreign_mount(self):
        obs = copy.deepcopy(self.obs)
        obs['bootId'] = '87654321-1234-1234-1234-123456789abc'
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, obs, marker)
        with self.assertRaisesRegex(n.Refused, '^foreign-existing-mount$'):
            self.run_pin(marker, native, obs, 'recheck')
        self.assertFalse(native.effects)
        self.assertFalse(marker.writes)

    def test_status_check_are_observations_not_initialization(self):
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, self.obs, marker)
        for mode in ('status', 'check'):
            self.run_pin(marker, native, self.obs, mode)
        self.assertFalse(marker.opens)
        self.assertFalse(marker.writes)
        self.assertFalse(native.effects)
        missing = MemoryMarker()
        with self.assertRaisesRegex(n.Refused, '^marker-missing$'):
            self.run_pin(missing, native, self.obs, 'status')
        self.assertFalse(missing.opens)

    def test_only_verified_fixed_boundary_can_skip_shared_ancestor(self):
        safe = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        shared = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o2775, st_uid=1000, st_gid=1000)
        alien = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=1000, st_gid=1000)
        def metadata(path):
            if path == c.SHARED:
                return shared
            if path == Path('/var/lib/alien'):
                return alien
            return safe
        with patch.object(c.Path, 'lstat', new=metadata), patch.object(c, 'pinned_namespace') as checked:
            c.directory(c.ROOTFUL)
            checked.assert_called_once()
            with self.assertRaises(c.Refused):
                c.directory('/mnt/stack/unrelated')
            with self.assertRaises(c.Refused):
                c.directory('/var/lib/alien')
        with patch.object(c.Path, 'lstat', new=metadata), \
             patch.object(c, 'pinned_namespace', side_effect=c.Refused('marker-missing')):
            with self.assertRaisesRegex(c.Refused, '^marker-missing$'):
                c.directory(c.ROOTFUL)

    def test_rootful_auxiliary_paths_keep_root_only_ancestor_custody(self):
        s = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)
        with patch.object(n, 'strict_directory') as strict, patch.object(n.Path, 'lstat', return_value=s):
            n.owned_descendant(n.NETWORK, self.entry, 0, 0o700)
        strict.assert_called_once_with(n.NETWORK, (0,))

    def test_namespace_open_checks_exact_uid_gid_mode_and_inode_before_mount(self):
        shared = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o2775, st_uid=1000, st_gid=1000, st_dev=5, st_ino=10)
        target = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o711, st_uid=0, st_gid=0,
                                      st_dev=self.expected['device'], st_ino=self.expected['inode'])
        def lstat(path):
            return shared if path == n.SHARED else target
        with patch.object(n, 'strict_directory'), patch.object(n.Path, 'lstat', new=lstat), \
             patch.object(n.os, 'open', side_effect=[5, 6]) as opened, patch.object(n.os, 'close'), \
             patch.object(n.os, 'fstat', side_effect=lambda fd: shared if fd == 5 else target), \
             patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_fsid=self.expected['filesystemId'])):
            self.assertEqual(n.namespace(self.expected), 6)
            self.assertEqual(opened.call_args_list[1].args[0], 'p0-v2')
            self.assertTrue(opened.call_args_list[1].args[1] & os.O_NOFOLLOW)
        target.st_gid = 1000
        with patch.object(n, 'strict_directory'), patch.object(n.Path, 'lstat', new=lstat), \
             patch.object(n.os, 'open', side_effect=[5, 6]), patch.object(n.os, 'close'), \
             patch.object(n.os, 'fstat', side_effect=lambda fd: shared if fd == 5 else target), \
             patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_fsid=self.expected['filesystemId'])):
            with self.assertRaisesRegex(n.Refused, '^namespace-identity$'):
                n.namespace(self.expected)

    def test_strict_evidence_has_no_caller_paths_commands_or_unknown_units(self):
        self.assertEqual(n.evidence(json.dumps(self.proof).encode()), self.proof)
        for extra in ('path', 'command', 'mount', 'url'):
            proof = dict(self.proof, **{extra: 'forbidden'})
            with self.assertRaises(n.Refused):
                n.evidence(json.dumps(proof).encode())
        proof = copy.deepcopy(self.proof)
        proof['units']['rootless'] = [{'name': '../other.service', 'sourceSha256': 'a' * 64}]
        with self.assertRaises(n.Refused):
            n.evidence(json.dumps(proof).encode())

    def test_mount_native_calls_are_fixed_fd_anchored_not_caller_paths(self):
        native = n.Native(self.entry)
        claim, before, verify = object(), object(), object()
        with patch.object(n, 'modern_private_pin') as pin, patch.object(n, 'modern_privatize_owned') as repair, \
             patch.object(native, 'call') as call:
            native.pin_namespace(7, self.expected, claim_clone=claim, before_attach=before, verify_attached=verify)
            native.privatize_owned(8, self.expected, 101, verify_attached=verify)
        call.assert_not_called()
        pin.assert_called_once_with(7, self.expected, claim_clone=claim, before_attach=before, verify_attached=verify)
        repair.assert_called_once_with(8, self.expected, 101, verify_attached=verify)
        self.assertIn(str(n.ROOTFUL), native.engine('rootful'))
        self.assertIn(str(n.ROOTLESS), native.engine('rootless'))
        self.assertNotIn('/proc/self/fd/', repr(native.engine('rootful')) + repr(native.engine('rootless')))
        self.assertIn(str(n.RUNFUL), native.engine('rootful'))
        self.assertIn(str(n.NETWORK), native.engine('rootful'))

    def test_real_marker_atomic_cas_lock_and_readonly_absence(self):
        real_directory, real_read = n.strict_directory, n.read_exact
        with patch.object(n, 'strict_directory', side_effect=lambda p, owners=(0,), mode=None:
                          real_directory(p, tuple(set((*owners, os.getuid()))), mode)), \
             patch.object(n, 'read_exact', side_effect=lambda p, uid=0, mode=None, limit=n.LIMIT:
                          real_read(p, os.getuid() if uid == 0 else uid, mode, limit)):
            base = Path(self.temp.name) / 'marker'
            marker = n.Marker(base)
            self.addCleanup(marker.close)
            self.assertFalse(marker.open(False))
            self.assertFalse(base.exists())
            marker.open(True)
            marker.save(copy.deepcopy(self.record))
            self.assertEqual(stat.S_IMODE((base / 'active.json').stat().st_mode), 0o400)
            self.assertEqual(marker.load(), self.record)
            other = n.Marker(base)
            try:
                with self.assertRaises(BlockingIOError):
                    other.open(True)
            finally:
                other.close()
            path = base / 'active.json'
            path.unlink()
            path.write_text('{}')
            path.chmod(0o400)
            with self.assertRaisesRegex(n.Refused, '^marker-cas$'):
                marker.save(copy.deepcopy(self.record))

    def test_new_child_acl_normalization_touches_only_fresh_fixed_inodes(self):
        target = Path(self.temp.name) / 'target'
        target.mkdir(mode=0o711)
        target.chmod(0o711)  # This fresh test inode, independent of operator umask.
        run = Path(self.temp.name) / 'runtime'
        var = Path(self.temp.name) / 'private'
        run.mkdir(mode=0o700)
        var.mkdir(mode=0o700)
        with patch.object(n, 'TARGET', target), patch.object(n, 'ROOTFUL', target / 'rootful/engine'), \
             patch.object(n, 'RUNFUL', run / 'p0-v2-rootful/engine'), \
             patch.object(n, 'NETWORK', var / 'p0-v2-rootful/networks'), \
             patch.object(n, 'check_actor_directories'), patch.object(n, 'owned_descendant'), \
             patch.object(n, 'strict_directory'), patch.object(n, 'reserves'), patch.object(n.os, 'fchown') as chown, \
             patch.object(n.os, 'fchmod') as chmod, \
             patch.object(n.os, 'listxattr', return_value=['system.posix_acl_default']), \
             patch.object(n.os, 'removexattr') as remove:
            n.create_children(self.entry)
            self.assertEqual(chown.call_count, 6)
            self.assertEqual(chmod.call_count, 6)
            self.assertEqual(remove.call_count, 6)
            # Rechecking existing children never repairs modes/ACLs/ownership.
            n.create_children(self.entry)
            self.assertEqual(chown.call_count, 6)
            self.assertEqual(chmod.call_count, 6)
            self.assertEqual(remove.call_count, 6)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o711)

    def test_both_sources_are_standalone_stdlib_and_no_teardown_or_adoption(self):
        for filename in ('provision-p0-v2-namespace.py', 'provision-p0-machine-credentials.py'):
            text = (ROOT / 'ops/host-admin' / filename).read_text()
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(v.name.split('.')[0] in sys.stdlib_module_names for v in node.names))
                if isinstance(node, ast.ImportFrom):
                    self.assertIn(node.module.split('.')[0], sys.stdlib_module_names)
            for forbidden in ('shell=True', 'importlib', 'sys.path', "'umount'", "'--rbind'", 'os.system('):
                self.assertNotIn(forbidden, text)


class TypedResourceSourceTests(unittest.TestCase):
    def proof(self, entry):
        return {'version': 1, 'namespace': {'device': 1, 'inode': 2, 'filesystemId': 3},
                'units': {'rootless': [entry], 'rootful': []}}

    def test_closed_resource_kind_and_unit_suffix_binding(self):
        cases = [('container', 'p0-example.service', 'p0-example.container'),
                 ('network', 'p0-network-identity-network.service', 'p0-network-identity.network'),
                 ('volume', 'p0-postgres-data-volume.service', 'p0-postgres-data.volume')]
        for kind, name, source in cases:
            entry = {'name': name, 'kind': kind, 'sourceSha256': 'a' * 64}
            self.assertEqual(n.quadlet_name(entry), source)
            self.assertEqual(n.evidence(json.dumps(self.proof(entry)).encode()), self.proof(entry))
        self.assertEqual(n.quadlet_name({'name': 'p0-example-network.service'}), 'p0-example-network.container')
        for kind, name in [('network', 'p0-example.service'), ('volume', 'p0-example-network.service'),
                           ('host-exec', 'p0-example.service'), ('socket', 'p0-example.socket')]:
            with self.subTest(kind=kind, name=name), self.assertRaises(n.Refused):
                n.evidence(json.dumps(self.proof({'name': name, 'kind': kind, 'sourceSha256': 'a' * 64})).encode())

    def test_rootful_evidence_cannot_claim_protected_legacy_unit_names(self):
        proof = self.proof({'name': 'p0-web.service', 'sourceSha256': 'a' * 64})
        proof['units']['rootful'] = proof['units']['rootless']
        proof['units']['rootless'] = []
        with self.assertRaisesRegex(n.Refused, '^evidence-unit$'):
            n.evidence(json.dumps(proof).encode())
        proof['units']['rootful'][0]['name'] = 'p0-v2-edge.service'
        n.evidence(json.dumps(proof).encode())

    def test_bounded_full_service_and_resource_inventory(self):
        proof = self.proof({'name': 'p0-example.service', 'sourceSha256': 'a' * 64})
        proof['units']['rootless'] = [{'name': f'p0-service-{i}.service', 'sourceSha256': 'a' * 64} for i in range(256)]
        self.assertEqual(len(n.evidence(json.dumps(proof).encode())['units']['rootless']), 256)
        proof['units']['rootless'].append({'name': 'p0-extra.service', 'sourceSha256': 'a' * 64})
        with self.assertRaisesRegex(n.Refused, '^evidence-units$'):
            n.evidence(json.dumps(proof).encode())

    def test_generic_exact_and_dash_prefix_quadlet_dropins_refuse(self):
        with tempfile.TemporaryDirectory(prefix='.p0-source-dropin-fixture-', dir=Path.home()) as directory:
            source = Path(directory) / 'p0-network-identity.network'
            n.no_quadlet_dropins(source)
            for name in ('network.d', 'p0-.network.d', 'p0-network-.network.d', 'p0-network-identity.network.d'):
                target = source.parent / name
                target.mkdir()
                with self.subTest(name=name), self.assertRaisesRegex(n.Refused, '^quadlet-source-dropins$'):
                    n.no_quadlet_dropins(source)
                target.rmdir()
            unrelated = source.parent / 'unrelated.network.d'
            unrelated.mkdir()
            n.no_quadlet_dropins(source)
            with patch.object(n.Path, 'lstat', side_effect=PermissionError('synthetic')):
                with self.assertRaises(PermissionError):
                    n.no_quadlet_dropins(source)


class NativeStoppedTests(unittest.TestCase):
    def setUp(self):
        self.entry = types.SimpleNamespace(pw_uid=1234, pw_gid=1234)
        self.native = n.Native(self.entry)
        self.source = b'SYNTHETIC QUADLET SOURCE'
        self.expected = {'device': os.makedev(8, 1), 'inode': 23, 'filesystemId': 45}
        self.observation = observations(self.expected)
        self.record = marker_record(self.expected, self.observation, 'claimed')
        self.proof = {'namespace': self.expected, 'units': {'rootless': [{'name': 'p0-prototype.service',
                      'sourceSha256': hashlib.sha256(self.source).hexdigest()}], 'rootful': []}}
        self.props = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlGroup': '', 'Job': '',
                      'SourcePath': str(n.HOME / '.config/containers/systemd/p0-prototype.container'),
                      'FragmentPath': '/run/user/1234/systemd/generator/p0-prototype.service',
                      'DropInPaths': '', 'TriggeredBy': ''}
        self.containers = []
        self.trigger = False
        self.unreviewed = False
        self.calls = []

    def call(self, args, actor='rootful', pass_fds=()):
        self.calls.append((args, actor, pass_fds))
        if 'list-units' in args or 'list-unit-files' in args:
            if 'p0-*.service' in args:
                return b'p0-unreviewed.service loaded inactive dead\n' if self.unreviewed else b''
            return b'p0-prototype.timer loaded active waiting\n' if self.trigger else b''
        if 'show' in args:
            return ('\n'.join(k + '=' + v for k, v in self.props.items()) + '\n').encode()
        if 'info' in args:
            run = f'/run/user/{self.entry.pw_uid}/containers' if actor == 'rootless' else str(n.RUNFUL)
            return json.dumps({'store': {'graphRoot': args[2], 'runRoot': run, 'graphDriverName': 'overlay'}}).encode()
        if 'ps' in args:
            return json.dumps(self.containers).encode()
        raise AssertionError('unrecognized fixed API')

    def stopped(self, *, protected=True, fresh_error=None):
        with patch.object(n, 'require_protected_view'), \
             patch.object(self.native, 'call', side_effect=self.call), patch.object(n, 'strict_directory'), \
             patch.object(n, 'no_quadlet_dropins'), patch.object(n, 'read_exact', return_value=(self.source, None)), \
             patch.object(n, 'check_actor_directories'), patch.object(n, 'EngineAnchor'), \
             patch.object(n, 'inventory_authority', return_value=protected), \
             patch.object(n, 'fresh_rootful', side_effect=fresh_error, return_value=('absent', ())):
            self.native.stopped(self.proof, 7, record=self.record if protected else None, observation=self.observation)

    def test_stopped_owned_units_and_empty_anchored_engines_succeed(self):
        self.stopped()
        engine_calls = [call for call in self.calls if call[0][0] == '/usr/bin/podman']
        self.assertEqual(len(engine_calls), 4)
        self.assertTrue(all(call[2] == () for call in engine_calls))
        self.assertEqual({call[0][2] for call in engine_calls}, {str(n.ROOTLESS), str(n.ROOTFUL)})
        self.assertNotIn('/proc/self/fd/', repr(engine_calls))
        self.assertTrue(all('--all' in call[0] and '--external' in call[0] for call in engine_calls if 'ps' in call[0]))

    def test_active_pid_cgroup_job_trigger_and_unknown_unit_refuse(self):
        for key, value in (('ActiveState', 'active'), ('MainPID', '123'), ('ControlGroup', '/own/nonempty'),
                           ('Job', '1/start'), ('TriggeredBy', 'p0-prototype.socket'), ('LoadState', 'not-found'),
                           ('FragmentPath', '/etc/systemd/user/p0-prototype.service'),
                           ('DropInPaths', '/etc/systemd/user/p0-prototype.service.d/override.conf')):
            old = self.props[key]
            self.props[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(n.Refused, '^runtime-unit-not-stopped$'):
                self.stopped()
            self.props[key] = old
        self.trigger = True
        with self.assertRaisesRegex(n.Refused, '^runtime-triggers-remain$'):
            self.stopped()
        self.trigger = False
        self.unreviewed = True
        with self.assertRaisesRegex(n.Refused, '^unreviewed-runtime-unit$'):
            self.stopped()

    def test_explicit_network_and_volume_sources_use_native_generator_names(self):
        for kind, name, source in (
                ('network', 'p0-network-identity-network.service', 'p0-network-identity.network'),
                ('volume', 'p0-postgres-data-volume.service', 'p0-postgres-data.volume')):
            with self.subTest(kind=kind):
                self.proof['units']['rootless'][0].update(kind=kind, name=name)
                self.props['SourcePath'] = str(n.HOME / '.config/containers/systemd' / source)
                self.props['FragmentPath'] = '/run/user/1234/systemd/generator/' + name
                self.stopped()
                self.assertEqual(n.quadlet_name(self.proof['units']['rootless'][0]), source)

    def test_rootful_inventory_is_reserved_scope_not_protected_legacy_services(self):
        self.stopped()
        for args, actor, _ in self.calls:
            if actor == 'rootful' and args[0] == '/usr/bin/systemctl':
                patterns = [arg for arg in args if '*' in arg]
                if 'list-unit-files' in args:
                    self.assertEqual(args[-2:], ['list-unit-files', '--no-legend'])
                else:
                    self.assertTrue(patterns)
                    self.assertTrue(all(pattern.startswith('p0-v2-') for pattern in patterns))
                self.assertNotIn('p0-*.service', args)
        original = self.call
        def unreviewed(args, actor='rootful', pass_fds=()):
            if actor == 'rootful' and 'p0-v2-*.service' in args:
                return b'p0-v2-unreviewed.service generated -\n'
            return original(args, actor, pass_fds)
        with patch.object(self, 'call', side_effect=unreviewed):
            with self.assertRaisesRegex(n.Refused, '^unreviewed-runtime-unit$'):
                self.stopped()

    def test_empty_inventory_never_accepts_filtered_list_files_exit_one(self):
        original = self.call
        def inventory(args, actor='rootful', pass_fds=()):
            if 'list-unit-files' in args:
                self.assertFalse(any('*' in argument for argument in args))
                if actor == 'rootful':
                    return b'p0-web.service enabled enabled\np0-native-historical.service transient -\nsshd.service enabled enabled\n'
                return b'nonowned.service static -\n'
            return original(args, actor, pass_fds)
        with patch.object(self, 'call', side_effect=inventory):
            self.stopped()
        def scoped_trigger(args, actor='rootful', pass_fds=()):
            if actor == 'rootful' and 'list-unit-files' in args:
                return b'p0-v2-undeclared.socket disabled -\n'
            return inventory(args, actor, pass_fds)
        with patch.object(self, 'call', side_effect=scoped_trigger):
            with self.assertRaisesRegex(n.Refused, '^runtime-triggers-remain$'):
                self.stopped()

    def test_native_deadline_cancels_group_before_reaping(self):
        reader, writer = os.pipe()
        self.addCleanup(os.close, writer)
        output = os.fdopen(reader, 'rb')
        process = types.SimpleNamespace(stdout=output, pid=7392)
        events = []
        process.poll = lambda: self.fail('must not reap group leader first')
        process.wait = lambda **kwargs: events.append(('wait', kwargs)) or 0
        with patch.object(n, 'strict_directory'), patch.object(n, 'read_exact'), \
             patch.object(n.os, 'stat', return_value=types.SimpleNamespace(st_mode=0o755)), \
             patch.object(n.subprocess, 'Popen', return_value=process), \
             patch.object(n.os, 'killpg', side_effect=lambda pid, sig: events.append(('killpg', pid, sig))), \
             patch.object(n.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(n.Refused, '^native-timeout$'):
                self.native.call(['/usr/bin/systemctl', 'show', 'p0-prototype.service'])
        self.assertEqual(events, [('killpg', 7392, n.signal.SIGKILL), ('wait', {'timeout': 5})])
        self.assertTrue(output.closed)

    def test_any_stopped_running_or_external_builder_container_refuses(self):
        for status in ('running', 'exited', 'storage'):
            self.containers = [{'Id': 'SYNTHETIC', 'State': status}]
            with self.subTest(status=status), self.assertRaisesRegex(n.Refused, '^engine-containers-remain$'):
                self.stopped()

    def test_native_runner_clean_identity_bounded_public_failure_no_raw_output(self):
        reader, writer = os.pipe()
        os.write(writer, b'SYNTHETIC_NATIVE_SENSITIVE_TEXT')
        os.close(writer)
        output = os.fdopen(reader, 'rb')
        process = types.SimpleNamespace(stdout=output, returncode=2)
        process.poll = lambda: 2
        process.wait = lambda **kwargs: 2
        with patch.object(n, 'strict_directory'), patch.object(n, 'read_exact'), \
             patch.object(n.os, 'stat', return_value=types.SimpleNamespace(st_mode=0o755)), \
             patch.object(n.subprocess, 'Popen', return_value=process) as popen:
            with self.assertRaisesRegex(n.Refused, '^native-operation-uncertain$') as refused:
                self.native.call(['/usr/bin/systemctl', '--user', 'show', 'p0-prototype.service'], 'rootless')
        args = popen.call_args.args[0]
        self.assertEqual(args[0], '/usr/bin/setpriv')
        self.assertIn('/usr/bin/systemctl', args)
        self.assertIn('--clear-groups', args)
        self.assertIn('--inh-caps=-all', args)
        self.assertIn('--ambient-caps=-all', args)
        self.assertEqual(popen.call_args.kwargs['pass_fds'], ())
        self.assertEqual(popen.call_args.kwargs['stderr'], n.subprocess.DEVNULL)
        self.assertEqual(set(popen.call_args.kwargs['env']), {'PATH', 'LC_ALL', 'HOME', 'XDG_RUNTIME_DIR'})
        self.assertNotIn('SYNTHETIC_NATIVE_SENSITIVE_TEXT', str(refused.exception))
        self.assertTrue(output.closed)

    def test_unpinned_only_rootless_canonical_observation_and_fresh_rootful_gate(self):
        self.stopped(protected=False)
        engine_calls = [call for call in self.calls if call[0][0] == '/usr/bin/podman']
        self.assertEqual(len(engine_calls), 2)
        self.assertTrue(all(call[1] == 'rootless' and call[0][2] == str(n.ROOTLESS) and call[2] == () for call in engine_calls))
        self.calls.clear()
        with self.assertRaisesRegex(n.Refused, '^rootful-unpinned-existing-store-unsupported$'):
            self.stopped(protected=False, fresh_error=n.Refused('rootful-unpinned-existing-store-unsupported'))
        self.assertFalse(self.calls)

    def test_no_alias_or_inherited_fd_native_api_even_if_canonical_control_would_work(self):
        with patch.object(n.subprocess, 'Popen') as popen:
            for args, pass_fds in ((['/usr/bin/podman', '--root', '/proc/self/fd/7/rootless/engine', 'info'], ()),
                                   (['/usr/bin/podman', '--root', str(n.ROOTLESS), 'info'], (7,))):
                with self.assertRaisesRegex(n.Refused, '^native-fd-alias-refused$'):
                    self.native.call(args, 'rootless', pass_fds)
            popen.assert_not_called()
        # A canonical-first fake native succeeds; both old FD-number APIs are
        # discriminated, not silently retried under a different identity.
        self.stopped(protected=True)
        self.assertTrue(all('/proc/self/fd/' not in repr(call) for call in self.calls))

    def test_rootful_store_refuses_without_protected_pin_before_any_native(self):
        with patch.object(n, 'inventory_authority', return_value=False), patch.object(self.native, 'call') as call:
            with self.assertRaisesRegex(n.Refused, '^protected-view-v3-integration-required$'):
                self.native.observe_empty_engine('rootful', 7, self.proof, None, self.observation)
            call.assert_not_called()

    def test_future_inactive_native_relay_socket_still_blocks_current_contract(self):
        original = self.call
        def relay_files(args, actor='rootful', pass_fds=()):
            if actor == 'rootful' and 'list-unit-files' in args:
                return b'p0-v2-future-relay.socket disabled\n'
            return original(args, actor, pass_fds)
        self.call = relay_files
        with self.assertRaisesRegex(n.Refused, '^runtime-triggers-remain$'):
            self.stopped()
        self.assertFalse(any(call[0][0] == '/usr/bin/podman' for call in self.calls))

    def test_wrong_unit_source_hash_refuses_before_engine_inspection(self):
        self.proof['units']['rootless'][0]['sourceSha256'] = 'f' * 64
        with self.assertRaisesRegex(n.Refused, '^unit-source-binding$'):
            self.stopped()
        self.assertFalse(any(call[0][0] == '/usr/bin/podman' for call in self.calls))


class ModernMountAndAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.p0-source03-fixture-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o711)  # Only this new private synthetic fixture inode.
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        s = os.fstat(self.fd)
        self.expected = dict(n.identity(s), filesystemId=os.fstatvfs(self.fd).f_fsid)
        self.entry = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.proof = {'version': 1, 'namespace': self.expected, 'units': {'rootless': [], 'rootful': []}}
        self.obs = observations(self.expected, False)
        self.marker = MemoryMarker(marker_record(self.expected, self.obs, 'claimed'))
        self.events, self.mount_ids, self.set_count = [], {self.fd: 100}, 0
        real_owned = n.owned_directory_fd
        self.addCleanup(patch.stopall)
        patch.object(n, 'owned_directory_fd', side_effect=lambda fd, uid, gid, mode=0o700:
                     real_owned(fd, os.getuid() if uid == 0 else uid, os.getgid() if gid == 0 else gid, mode)).start()
        self.actual_mount_api, self.actual_fd_mount_id = n._mount_api, n.fd_mount_id
        patch.object(n, '_mount_api', return_value=self.api).start()
        patch.object(n, '_mount_deadline_start').start()
        patch.object(n, '_mount_deadline_end').start()
        patch.object(n, 'fd_mount_id', side_effect=lambda fd: self.mount_ids[fd]).start()
        self.keep_shared = False
        self.fail_move = False
        self.fail_open = False

    def api(self, number, *args):
        # Pure Python fake. No ctypes syscall/CDLL/native mount is executed.
        if number == n.NR_OPEN_TREE:
            self.events.append('open-tree')
            self.assertEqual(args[0].value, self.fd)
            self.assertEqual(args[1].value, b'')
            self.assertEqual(args[2].value & n.AT_EMPTY_PATH, n.AT_EMPTY_PATH)
            self.assertEqual(args[2].value & os.O_CLOEXEC, os.O_CLOEXEC)
            if self.fail_open:
                return -1
            tree = os.dup(self.fd)
            self.tree = tree
            self.mount_ids[tree] = 101
            return tree
        if number == n.NR_MOUNT_SETATTR:
            self.events.append('set-private')
            self.assertEqual(args[0].value, self.tree)
            self.assertNotEqual(args[0].value, self.fd, 'must never privatize covering/shared ancestor FD')
            self.assertEqual(args[1].value, b'')
            self.assertEqual(args[2].value, n.AT_EMPTY_PATH)
            attrs = n.ctypes.cast(args[3], n.ctypes.POINTER(n.MountAttr)).contents
            self.assertEqual((attrs.attr_set, attrs.attr_clr, attrs.propagation, attrs.userns_fd), (0, 0, n.MS_PRIVATE, 0))
            self.assertEqual(args[4].value, 32)
            self.set_count += 1
            if self.set_count >= 2 and not self.keep_shared:
                self.obs['mounts'][-1]['optional'] = []
            return 0
        if number == n.NR_MOVE_MOUNT:
            self.events.append('move')
            self.assertEqual(self.marker.record['cloneMountId'], 101, 'clone ID not durable before attach')
            self.assertEqual((args[0].value, args[1].value, args[2].value, args[3].value, args[4].value),
                             (self.tree, b'', self.fd, b'', 0x44))
            if self.fail_move:
                return -1
            self.obs['mounts'] = observations(self.expected)['mounts']
            # Discriminate receipt03: shared propagation inherited ON attach.
            self.obs['mounts'][-1]['optional'] = ['shared:7']
            return 0
        raise AssertionError('arbitrary syscall is not allowed')

    def claim(self, mount_id):
        self.events.append('claim-id')
        self.marker.record['cloneMountId'] = mount_id
        self.marker.save(self.marker.record)

    def before(self):
        self.events.append('stopped-recheck')
        n.require(len(self.obs['mounts']) == 1, 'unexpected-mount-before-attach')

    def verify(self, mount_id, *, require_private):
        self.events.append('verify-private' if require_private else 'verify-attached')
        own = n.observed_mount(self.obs, self.expected, pinned=True)
        n.require(own['id'] == mount_id == self.marker.record['cloneMountId'], 'preclaimed-mount-id-changed')
        if require_private:
            n.private_mount(own)

    def pin(self):
        n.modern_private_pin(self.fd, self.expected, claim_clone=self.claim,
                             before_attach=self.before, verify_attached=self.verify)

    def test_unsupported_abi_refuses_before_any_libc_symbol_resolution(self):
        with patch.object(n.os, 'uname', return_value=types.SimpleNamespace(machine='aarch64')), \
             patch.object(n.ctypes, 'CDLL') as library:
            with self.assertRaisesRegex(n.Refused, '^modern-mount-unsupported-abi$'):
                self.actual_mount_api()
            library.assert_not_called()

    def test_mount_id_parser_bounded_exact_nonboolean_positive_id(self):
        with patch.object(n, 'bounded_read', return_value=b'pos:\t0\nmnt_id:\t761\n') as read:
            self.assertEqual(self.actual_fd_mount_id(7), 761)
            read.assert_called_once_with('/proc/self/fdinfo/7', 16384)
        for malformed in (b'', b'mnt_id: 0\n', b'mnt_id: -1\n', b'mnt_id: True\n',
                          b'mnt_id: 1\nmnt_id: 2\n', b'mnt_id: 18446744073709551616\n'):
            with patch.object(n, 'bounded_read', return_value=malformed):
                with self.assertRaisesRegex(n.Refused, '^mount-fdinfo$'):
                    self.actual_fd_mount_id(7)

    def test_exact_fd_syscall_protocol_preclaims_id_and_enforces_private_after_attach(self):
        self.pin()
        self.assertEqual(self.events, ['open-tree', 'claim-id', 'set-private', 'stopped-recheck',
                                      'move', 'verify-attached', 'set-private', 'verify-private'])
        self.assertEqual(self.set_count, 2)
        self.assertEqual(self.marker.record['cloneMountId'], 101)
        self.assertEqual(self.obs['mounts'][-1]['id'], 101)
        self.assertEqual(self.obs['mounts'][-1]['optional'], [])
        with self.assertRaises(OSError):
            os.fstat(self.tree)

    def test_syscall_success_without_private_kernel_result_is_not_accepted(self):
        self.keep_shared = True
        with self.assertRaisesRegex(n.Refused, '^namespace-mount-not-private$'):
            self.pin()
        self.assertEqual(self.marker.record['state'], 'claimed')
        self.assertEqual(self.marker.record['cloneMountId'], 101)
        self.assertEqual(self.obs['mounts'][-1]['optional'], ['shared:7'])
        self.assertEqual(self.set_count, 2)

    def test_failed_move_keeps_durable_claim_no_legacy_or_pathname_retry(self):
        self.fail_move = True
        with patch.object(n.subprocess, 'Popen') as native:
            with self.assertRaisesRegex(n.Refused, '^mount-move-uncertain$'):
                self.pin()
            native.assert_not_called()
        self.assertEqual(self.marker.record['state'], 'claimed')
        self.assertEqual(self.marker.record['cloneMountId'], 101)
        self.assertEqual(len(self.obs['mounts']), 1)
        self.assertEqual(self.events.count('open-tree'), 1)
        self.assertEqual(self.events.count('move'), 1)

    def test_open_tree_failure_never_sets_attributes_moves_or_changes_claim(self):
        self.fail_open = True
        with self.assertRaisesRegex(n.Refused, '^mount-open-tree-refused$'):
            self.pin()
        self.assertEqual(self.events, ['open-tree'])
        self.assertIsNone(self.marker.record['cloneMountId'])
        self.assertFalse(self.marker.writes)

    def test_pre_attach_recheck_failure_discards_detached_clone_no_move(self):
        def stopped_failure():
            raise n.Refused('runtime-unit-not-stopped')
        with self.assertRaisesRegex(n.Refused, '^runtime-unit-not-stopped$'):
            n.modern_private_pin(self.fd, self.expected, claim_clone=self.claim,
                                 before_attach=stopped_failure, verify_attached=self.verify)
        self.assertNotIn('move', self.events)
        self.assertEqual(self.marker.record['cloneMountId'], 101)
        with self.assertRaises(OSError):
            os.fstat(self.tree)

    def test_covering_mount_fd_cannot_be_used_for_attached_private_repair(self):
        with self.assertRaisesRegex(n.Refused, '^covering-mount-fd-refused$'):
            n.modern_privatize_owned(self.fd, self.expected, 101, verify_attached=self.verify)
        self.assertFalse(self.events)

    def test_exact_attached_repair_reopens_without_clone_no_move(self):
        self.mount_ids[self.fd] = 101  # Reopened exact mounted directory, not covering FD.
        self.obs['mounts'] = observations(self.expected)['mounts']
        self.obs['mounts'][-1]['optional'] = ['shared:7']
        self.marker.record['cloneMountId'] = 101
        seal(self.marker.record)
        self.set_count = 1
        api = self.api
        def reopen(number, *args):
            if number == n.NR_OPEN_TREE:
                self.assertFalse(args[2].value & n.OPEN_TREE_CLONE)
            return api(number, *args)
        with patch.object(n, '_mount_api', return_value=reopen):
            n.modern_privatize_owned(self.fd, self.expected, 101, verify_attached=self.verify)
        self.assertEqual(self.events, ['open-tree', 'verify-attached', 'set-private', 'verify-private'])
        self.assertEqual(self.obs['mounts'][-1]['optional'], [])

    def test_fresh_rootful_absent_empty_existing_and_alien_controls(self):
        self.assertEqual(n.fresh_rootful(self.fd, self.proof), ('absent', ()))
        rootful = self.root / 'rootful'
        rootful.mkdir(mode=0o700)
        self.assertEqual(n.fresh_rootful(self.fd, self.proof)[0], 'absent')
        engine = rootful / 'engine'
        engine.mkdir(mode=0o700)
        witness = n.fresh_rootful(self.fd, self.proof)
        self.assertEqual(witness[0], 'empty')
        self.assertEqual(n.fresh_rootful(self.fd, self.proof), witness)
        (engine / 'synthetic-native-metadata').write_text('not a credential')
        with self.assertRaisesRegex(n.Refused, '^rootful-unpinned-existing-store-unsupported$'):
            n.fresh_rootful(self.fd, self.proof)
        proof = copy.deepcopy(self.proof)
        proof['units']['rootful'] = [{'name': 'p0-existing.service', 'sourceSha256': 'b' * 64}]
        with self.assertRaisesRegex(n.Refused, '^rootful-unpinned-units-unsupported$'):
            n.fresh_rootful(self.fd, proof)

    def test_engine_anchor_holds_actual_owned_inode_and_detects_replacement_and_symlink(self):
        actor = self.root / 'rootless'
        actor.mkdir(mode=0o700)
        engine = actor / 'engine'
        engine.mkdir(mode=0o700)
        anchor = n.EngineAnchor(self.fd, 'rootless', self.entry)
        self.addCleanup(anchor.close)
        anchor.verify(self.fd)
        engine.rename(actor / 'previous-owned-fixture')
        engine.mkdir(mode=0o700)
        with self.assertRaisesRegex(n.Refused, '^engine-identity-changed$'):
            anchor.verify(self.fd)
        engine.rmdir()  # Exact new empty fixture only.
        engine.symlink_to(actor / 'previous-owned-fixture', target_is_directory=True)
        with self.assertRaises(OSError):
            anchor.verify(self.fd)

    def test_inventory_requires_current_owned_private_preclaimed_pin_for_rootful_authority(self):
        with patch.object(n, 'namespace', side_effect=lambda expected: os.dup(self.fd)), \
             patch.object(n, 'kernel', side_effect=lambda: copy.deepcopy(self.obs)):
            self.assertFalse(n.inventory_authority(self.fd, self.proof, None, self.obs))
            self.obs['mounts'] = observations(self.expected)['mounts']
            record = marker_record(self.expected, self.obs, 'claimed')
            self.assertTrue(n.inventory_authority(self.fd, self.proof, record, self.obs))
            record['cloneMountId'] += 1
            seal(record)
            with self.assertRaisesRegex(n.Refused, '^preclaimed-mount-id-changed$'):
                n.inventory_authority(self.fd, self.proof, record, self.obs)
            record = marker_record(self.expected, self.obs, 'claimed')
            self.obs['mounts'][-1]['optional'] = ['shared:7']
            record['mount'] = copy.deepcopy(self.obs['mounts'][-1])
            seal(record)
            self.assertFalse(n.inventory_authority(self.fd, self.proof, record, self.obs))

    def test_stale_claimed_rootful_store_is_not_prior_complete_boot_authority(self):
        (self.root / 'rootful').mkdir(mode=0o700)
        engine = self.root / 'rootful/engine'
        engine.mkdir(mode=0o700)
        (engine / 'synthetic-native-metadata').write_text('not a credential')
        old = marker_record(self.expected, observations(self.expected), 'claimed')
        self.obs['bootId'] = '87654321-1234-1234-1234-123456789abc'
        native = n.Native(self.entry)
        marker = MemoryMarker(old)
        real_lstat = Path.lstat
        target_stat = types.SimpleNamespace(st_dev=self.expected['device'], st_ino=self.expected['inode'])
        with patch.object(n, 'namespace', side_effect=lambda expected: os.dup(self.fd)), \
             patch.object(n, 'kernel', side_effect=lambda: copy.deepcopy(self.obs)), \
             patch.object(n, 'require_protected_view'), patch.object(n, 'preflight_children'), patch.object(n, 'reserves'), \
             patch.object(n.Path, 'lstat', new=lambda p: target_stat if p == n.TARGET else real_lstat(p)), \
             patch.object(native, 'call') as call, patch.object(native, 'pin_namespace') as mount:
            with self.assertRaisesRegex(n.Refused, '^prior-complete-pin-required$'):
                n.pin(self.proof, 'b' * 64, marker, native, self.entry, 'recheck')
            call.assert_not_called()
            mount.assert_not_called()
        self.assertFalse(marker.writes)
        self.assertEqual(marker.record, old)


class OwnedBootRecheckTests(unittest.TestCase):
    """Actual permit/anchors and native guards, fake calls/mounts, new user fixtures."""
    def setUp(self):
        from contextlib import ExitStack
        self.stack = self.enterContext(ExitStack())
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix='.p0-source05-owned-', dir=Path.home()))
        self.root = Path(self.temp)
        self.root.chmod(0o711)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.entry = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        for actor in ('rootless', 'rootful'):
            (self.root / actor).mkdir(mode=0o700)
            (self.root / actor / 'engine').mkdir(mode=0o700)
        self.engine = self.root / 'rootful/engine'
        self.data = self.engine / 'synthetic-data'
        self.data.write_bytes(b'new-fixture-only-not-application-data')
        initial_bytes = self.data.read_bytes()
        self.data_before = self.data.stat(), initial_bytes
        self.expected = dict(n.identity(os.fstat(self.fd)), filesystemId=os.fstatvfs(self.fd).f_fsid)
        self.proof = {'version': 1, 'namespace': self.expected, 'units': {'rootless': [], 'rootful': []}}
        self.old = marker_record(self.expected, observations(self.expected))
        self.obs = observations(self.expected, False)
        self.obs['bootId'] = '87654321-1234-1234-1234-123456789abc'
        self.marker = MemoryMarker(copy.deepcopy(self.old))
        self.native = n.Native(self.entry)
        self.mounts = FakeNative(self.expected, self.obs, self.marker)
        self.calls, self.hook, self.containers = [], None, []
        real_owned, real_lstat = n.owned_directory_fd, Path.lstat
        self.stack.enter_context(patch.object(n, 'owned_directory_fd', side_effect=lambda fd, uid, gid, mode=0o700:
            real_owned(fd, os.getuid() if uid == 0 else uid, os.getgid() if gid == 0 else gid, mode)))
        self.stack.enter_context(patch.object(n, 'namespace', side_effect=lambda expected: os.dup(self.fd)))
        self.stack.enter_context(patch.object(n, 'kernel', side_effect=lambda: copy.deepcopy(self.obs)))
        for name in ('require_protected_view', 'reserves', 'preflight_children', 'create_children', 'check_actor_directories'):
            self.stack.enter_context(patch.object(n, name))
        target = types.SimpleNamespace(st_dev=self.expected['device'], st_ino=self.expected['inode'])
        self.stack.enter_context(patch.object(n.Path, 'lstat', new=lambda p: target if p == n.TARGET else real_lstat(p)))
        self.stack.enter_context(patch.object(self.native, 'call', side_effect=self.call))
        self.stack.enter_context(patch.object(self.native, 'pin_namespace', side_effect=self.mounts.pin_namespace))

    def call(self, args, actor='rootful', pass_fds=()):
        self.calls.append((list(args), actor))
        if args[0] == '/usr/bin/systemctl':
            return b''
        self.assertEqual(args[0], '/usr/bin/podman')
        self.assertEqual(pass_fds, ())
        if actor == 'rootful':
            self.assertIn(self.marker.record['state'], ('claimed', 'pinned'))
            self.assertEqual(self.marker.record['mount']['id'], self.marker.record['cloneMountId'])
            self.assertEqual(self.obs['mounts'][-1]['optional'], [])
            self.assertTrue(n.inventory_authority(self.fd, self.proof, self.marker.record, self.obs))
        if self.hook:
            self.hook(args, actor)
        if 'info' in args:
            return json.dumps({'store': {'graphRoot': args[2], 'graphDriverName': 'overlay',
                'runRoot': str(n.RUNFUL) if actor == 'rootful' else f'/run/user/{self.entry.pw_uid}/containers'}}).encode()
        if 'ps' in args:
            return json.dumps(self.containers if actor == 'rootful' else []).encode()
        raise AssertionError('unexpected native API')

    def run_pin(self, mode='recheck'):
        return n.pin(self.proof, 'b' * 64, self.marker, self.native, self.entry, mode)

    def root_calls(self):
        return [a for a, actor in self.calls if actor == 'rootful' and a[0] == '/usr/bin/podman']

    def test_initialized_complete_old_claim_repins_before_any_root_native_and_preserves_data(self):
        result = self.run_pin()
        self.assertFalse(result['existingRootfulRepinSupported'])
        self.assertFalse(result['secureAuthority'])
        self.assertFalse(result['installationCertified'])
        self.assertEqual(len(self.root_calls()), 2)
        self.assertEqual(self.marker.record['owner'], self.old['owner'])
        self.assertEqual(self.marker.record['state'], 'pinned')
        self.assertEqual(self.marker.record['bootId'], self.obs['bootId'])
        self.assertEqual([r['cloneMountId'] for r in self.marker.writes[:2]], [None, 101])
        self.assertTrue(all(r['mount'] is None for r in self.marker.writes[:2]))
        self.assertEqual((self.data.stat(), self.data.read_bytes()), self.data_before)
        self.assertEqual([e[0] for e in self.mounts.effects], ['clone', 'private-detached', 'attach', 'private-attached'])

    def test_same_boot_new_typed_unit_review_runs_real_native_guards_without_repin(self):
        self.run_pin()
        before = copy.deepcopy(self.marker.record)
        writes, effects = len(self.marker.writes), list(self.mounts.effects)
        name = 'p0-v2-new-network.service'
        source = b'NEW SYNTHETIC NETWORK QUADLET'
        self.proof['units']['rootful'] = [{'name': name, 'kind': 'network',
                                         'sourceSha256': hashlib.sha256(source).hexdigest()}]
        original = self.call
        def installed(args, actor='rootful', pass_fds=()):
            if actor == 'rootful' and ('list-unit-files' in args or 'p0-v2-*.service' in args):
                return (name + ' generated -\n').encode()
            if actor == 'rootful' and 'show' in args:
                props = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlGroup': '',
                         'Job': '', 'TriggeredBy': '', 'DropInPaths': '',
                         'SourcePath': '/etc/containers/systemd/p0-v2-new.network',
                         'FragmentPath': '/run/systemd/generator/' + name}
                return ''.join(k + '=' + v + '\n' for k, v in props.items()).encode()
            return original(args, actor, pass_fds)
        self.calls.clear()
        with patch.object(self.native, 'call', side_effect=installed), patch.object(n, 'strict_directory'), \
             patch.object(n, 'no_quadlet_dropins'), patch.object(n, 'read_exact', return_value=(source, None)):
            n.pin(self.proof, 'c' * 64, self.marker, self.native, self.entry, 'review-units', previous_digest='b' * 64)
        self.assertEqual(len(self.root_calls()), 4)
        self.assertEqual(self.mounts.effects, effects)
        self.assertEqual(len(self.marker.writes), writes + 1)
        self.assertEqual({k: v for k, v in self.marker.record.items() if k not in ('evidenceSha256', 'integrity')},
                         {k: v for k, v in before.items() if k not in ('evidenceSha256', 'integrity')})

    def test_host_mount_namespace_change_is_explicit_same_safe_transition(self):
        self.obs['bootId'] = self.old['bootId']
        self.obs['mountNamespace']['inode'] += 1
        self.run_pin()
        self.assertEqual(len(self.root_calls()), 2)

    def test_initial_unclaimed_populated_store_still_refuses_before_all_native(self):
        self.marker = MemoryMarker()
        with self.assertRaisesRegex(n.Refused, '^rootful-unpinned-existing-store-unsupported$'):
            self.run_pin('apply')
        self.assertEqual(self.calls, [])
        self.assertFalse(self.marker.writes)

    def test_incomplete_stale_claim_and_wrong_prior_clone_never_authorize_root(self):
        for change in (lambda r: r.update(state='claimed'), lambda r: r.update(cloneMountId=999),
                       lambda r: r.update(mount=None), lambda r: r['namespace'].update(inode=999),
                       lambda r: r['mount'].update(optional=['shared:7']), lambda r: r.update(version=1)):
            self.marker.record = copy.deepcopy(self.old)
            change(self.marker.record)
            seal(self.marker.record)
            with self.subTest(record=self.marker.record), self.assertRaises(n.Refused):
                self.run_pin()
            self.assertFalse(self.calls)
            self.assertFalse(self.marker.writes)

    def test_wrong_physical_store_owner_refuses_before_native(self):
        real = n.os.fstat
        def foreign(fd):
            observed = real(fd)
            if observed.st_ino == (self.root / 'rootful').stat().st_ino:
                return types.SimpleNamespace(st_mode=observed.st_mode, st_uid=999, st_gid=999)
            return observed
        with patch.object(n.os, 'fstat', side_effect=foreign):
            with self.assertRaisesRegex(n.Refused, '^anchored-engine-custody$'):
                self.run_pin()
        self.assertFalse(self.calls)
        self.assertFalse(self.marker.writes)

    def test_wrong_integrity_and_opaque_owner_are_not_prior_authority(self):
        for key, value in (('integrity', '0' * 64), ('owner', 'bad')):
            self.marker.record = copy.deepcopy(self.old)
            self.marker.record[key] = value
            if key != 'integrity':
                seal(self.marker.record)
            with self.subTest(key=key), self.assertRaises(n.Refused):
                self.run_pin()
            self.assertFalse(self.calls)

    def test_wrong_root_store_mode_or_missing_engine_refuses_before_native(self):
        self.engine.chmod(0o750)
        with self.assertRaisesRegex(n.Refused, '^anchored-engine-custody$'):
            self.run_pin()
        self.engine.chmod(0o700)
        self.engine.rename(self.engine.with_name('held-original-fixture'))
        with self.assertRaises(FileNotFoundError):
            self.run_pin()
        self.assertFalse(self.calls)
        self.assertFalse(self.marker.writes)

    def test_pre_pin_store_replacement_is_detected_after_rootless_call_before_any_root_or_mount(self):
        def replace(args, actor):
            if actor == 'rootless' and 'info' in args:
                self.engine.rename(self.engine.with_name('retained-fixture'))
                self.engine.mkdir(mode=0o700)
        self.hook = replace
        with self.assertRaisesRegex(n.Refused, '^engine-identity-changed$'):
            self.run_pin()
        self.assertFalse(self.root_calls())
        self.assertFalse(self.mounts.effects)
        self.assertFalse(self.marker.writes)

    def test_detached_boot_claim_identity_race_is_retained_and_never_replayed(self):
        def replace(args, actor):
            if actor == 'rootless' and 'info' in args and self.marker.record['state'] == 'claimed':
                self.engine.rename(self.engine.with_name('retained-detached-fixture'))
                self.engine.mkdir(mode=0o700)
        self.hook = replace
        with self.assertRaisesRegex(n.Refused, '^engine-identity-changed$'):
            self.run_pin()
        self.assertEqual([e[0] for e in self.mounts.effects], ['clone', 'private-detached'])
        self.assertEqual(self.marker.record['cloneMountId'], 101)
        self.assertIsNone(self.marker.record['mount'])
        self.assertFalse(self.root_calls())
        retained = copy.deepcopy(self.marker.record)
        self.hook = None
        for mode, reason in (('resume', 'preclaimed-clone-absent-review-required'),
                             ('recheck', 'explicit-namespace-recheck-required')):
            with self.subTest(mode=mode), self.assertRaisesRegex(n.Refused, '^' + reason + '$'):
                self.run_pin(mode)
            self.assertEqual(self.marker.record, retained)
        self.assertFalse(self.root_calls())

    def test_post_pin_authority_loss_is_detected_before_next_root_native(self):
        def lose(args, actor):
            if actor == 'rootful' and 'info' in args:
                self.obs['mounts'][-1]['id'] += 1
        self.hook = lose
        with self.assertRaisesRegex(n.Refused, '^namespace-observation-changed$'):
            self.run_pin()
        self.assertEqual(len(self.root_calls()), 1)
        self.assertEqual(self.marker.record['state'], 'claimed')
        self.assertEqual((self.data.stat(), self.data.read_bytes()), self.data_before)

    def test_stopped_native_objects_are_not_deleted_to_make_recheck_pass(self):
        self.containers = [{'Id': 'synthetic-stopped-object', 'State': 'exited'}]
        with self.assertRaisesRegex(n.Refused, '^engine-containers-remain$'):
            self.run_pin()
        self.assertEqual(self.marker.record['state'], 'claimed')
        self.assertEqual(len(self.root_calls()), 2)
        self.assertFalse(any(x in a for a, _ in self.calls for x in ('rm', 'prune', 'reset')))
        self.assertEqual((self.data.stat(), self.data.read_bytes()), self.data_before)

    def test_foreign_current_submount_blocks_repin_before_any_native(self):
        descendant = copy.deepcopy(observations(self.expected)['mounts'][-1])
        descendant.update(target=str(n.TARGET / 'rootful/engine/unknown-overlay'), id=999)
        self.obs['mounts'].append(descendant)
        with self.assertRaises(n.Refused):
            self.run_pin()
        self.assertFalse(self.calls)
        self.assertFalse(self.mounts.effects)

    def test_unknown_installed_rootful_service_blocks_before_store_and_claim(self):
        original = self.call
        def unreviewed(args, actor='rootful', pass_fds=()):
            if actor == 'rootful' and 'list-unit-files' in args:
                return b'p0-v2-unknown.service disabled disabled\n'
            return original(args, actor, pass_fds)
        with patch.object(self.native, 'call', side_effect=unreviewed):
            with self.assertRaisesRegex(n.Refused, '^unreviewed-runtime-unit$'):
                self.run_pin()
        self.assertFalse(self.root_calls())
        self.assertFalse(self.marker.writes)


class EvidenceAdmissionTests(unittest.TestCase):
    # Reuse synthetic FD/kernel setup only; do not duplicate inherited test counts.
    setUp = NamespaceTests.setUp
    contexts = NamespaceTests.contexts
    def review(self, marker, native, previous='b' * 64, digest='c' * 64):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for context in self.contexts(self.obs):
                stack.enter_context(context)
            return n.pin(self.proof, digest, marker, native, self.entry, 'review-units', previous_digest=previous)

    def test_review_updates_only_digest_and_preserves_independent_credential_marker_contract(self):
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, self.obs, marker)
        result = self.review(marker, native)
        self.assertEqual(result['mode'], 'review-units')
        self.assertEqual(marker.record['evidenceSha256'], 'c' * 64)
        self.assertEqual({k: v for k, v in marker.record.items() if k not in ('integrity', 'evidenceSha256')},
                         {k: v for k, v in self.record.items() if k not in ('integrity', 'evidenceSha256')})
        self.assertEqual(n.verify_marker(marker.record, self.obs, self.expected),
                         c.validate_namespace_marker(marker.record, self.obs, self.expected))
        self.assertEqual(len(marker.writes), 1)
        self.assertFalse(native.effects)

    def test_previous_digest_is_mandatory_exact_and_cannot_change_other_modes(self):
        for previous in (None, 'x' * 64, 'a' * 64):
            marker = MemoryMarker(copy.deepcopy(self.record))
            native = FakeNative(self.expected, self.obs, marker)
            with self.subTest(previous=previous), self.assertRaises(n.Refused):
                self.review(marker, native, previous)
            self.assertFalse(marker.writes)
            self.assertFalse(native.effects)
        from contextlib import ExitStack
        with ExitStack() as stack:
            for context in self.contexts(self.obs):
                stack.enter_context(context)
            with self.assertRaisesRegex(n.Refused, '^previous-evidence-argument$'):
                n.pin(self.proof, 'b' * 64, MemoryMarker(self.record), native, self.entry, 'apply', previous_digest='b' * 64)

    def test_review_refuses_missing_claimed_stale_or_wrong_current_pin_without_effect(self):
        variants = [None, marker_record(self.expected, self.obs, 'claimed'), copy.deepcopy(self.record)]
        variants[-1]['bootId'] = '87654321-1234-1234-1234-123456789abc'
        seal(variants[-1])
        for record in variants:
            marker = MemoryMarker(record)
            native = FakeNative(self.expected, self.obs, marker)
            with self.subTest(record=record), self.assertRaises(n.Refused):
                self.review(marker, native)
            self.assertFalse(marker.writes)
            self.assertFalse(native.effects)

    def test_review_closed_gates_and_second_observation_race_prevent_publication(self):
        for failure in ('first-gate', 'second-gate', 'kernel-race'):
            marker = MemoryMarker(copy.deepcopy(self.record))
            native = FakeNative(self.expected, self.obs, marker)
            calls = []
            def stopped(*args, **kwargs):
                calls.append(1)
                if failure == 'first-gate' or (failure == 'second-gate' and len(calls) == 2):
                    raise n.Refused('runtime-unit-not-stopped')
                if failure == 'kernel-race':
                    self.obs['mounts'][-1]['id'] += 1
            with patch.object(native, 'stopped', side_effect=stopped):
                with self.subTest(failure=failure), self.assertRaises(n.Refused):
                    self.review(marker, native)
            self.obs = observations(self.expected)
            self.assertFalse(marker.writes)
            self.assertEqual(marker.record, self.record)

    def test_review_retains_prior_marker_on_publication_cas_failure(self):
        marker = MemoryMarker(copy.deepcopy(self.record))
        native = FakeNative(self.expected, self.obs, marker)
        with patch.object(marker, 'save', side_effect=n.Refused('marker-cas')):
            with self.assertRaisesRegex(n.Refused, '^marker-cas$'):
                self.review(marker, native)
        self.assertEqual(marker.record, self.record)
        self.assertFalse(native.effects)


class RelayMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.entry = types.SimpleNamespace(pw_uid=1234, pw_gid=1234)
        self.native = n.Native(self.entry)
        self.relay = {'id': 'private-search', 'address': '127.0.0.1', 'port': 18200,
                      'serviceSha256': 'a' * 64, 'socketSha256': 'b' * 64}
        self.sources = n.relay_sources(self.relay)
        service, socket = n.relay_names(self.relay)
        self.relay.update(serviceSha256=hashlib.sha256(self.sources[service]).hexdigest(),
                          socketSha256=hashlib.sha256(self.sources[socket]).hexdigest())
        self.proof = {'version': 2, 'namespace': {'device': 1, 'inode': 2, 'filesystemId': 3},
                      'units': {'rootless': [], 'rootful': []}, 'relays': [self.relay]}
        common = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead', 'ControlPID': '0',
                  'ControlGroup': '', 'Job': '', 'SourcePath': '', 'DropInPaths': '', 'NeedDaemonReload': 'no'}
        self.props = {service: dict(common, MainPID='0', User='p0-runtime', Group='p0-runtime',
                                   FragmentPath=str(n.RELAY_UNITS / service), TriggeredBy=socket),
                      socket: dict(common, FragmentPath=str(n.RELAY_UNITS / socket), TriggeredBy='', Triggers=service)}
        self.extra = None
        self.calls = []

    def call(self, args, actor='rootful', pass_fds=()):
        self.calls.append((args, actor))
        service, socket = n.relay_names(self.relay)
        if actor == 'rootless':
            return b''
        if 'show' in args:
            return ''.join(k + '=' + v + '\n' for k, v in self.props[args[2]].items()).encode()
        if 'list-unit-files' in args:
            names = [service, socket] + ([self.extra] if self.extra else [])
        elif 'p0-v2-*.service' in args:
            names = [service]
        else:
            names = [socket]
        return ''.join(name + ' static -\n' for name in names).encode()

    def stopped(self):
        def source(path, *args, **kwargs):
            return self.sources[path.name], ('synthetic-inode', path.name)
        with patch.object(self.native, 'call', side_effect=self.call), patch.object(n, 'strict_directory'), \
             patch.object(n, 'no_native_dropins'), patch.object(n, 'read_exact', side_effect=source), \
             patch.object(n, 'closed_relay_listener') as listener:
            self.native.stopped_units(self.proof)
            return listener.call_count

    def test_exact_inactive_ordinary_native_pair_is_not_a_quadlet(self):
        self.assertEqual(n.evidence(json.dumps(self.proof).encode()), self.proof)
        self.assertEqual(self.stopped(), 2)
        self.assertTrue(all(actor == 'rootful' for args, actor in self.calls if 'show' in args))

    def test_independent_closed_bytes_match_pure_parent_renderer_without_root_import(self):
        # Import read-only core only in the UNPRIVILEGED source test interpreter.
        sys.path.insert(0, str(ROOT))
        try:
            from p0core import socketrelay
            provider = types.SimpleNamespace(runtime='rootless', declaration={
                'endpoints': [{'port': 8200, 'hostPort': 18200, 'bind': '127.0.0.1'}], 'probes': [{}]})
            for address in ('127.0.0.1', '::1'):
                provider.declaration['endpoints'][0]['bind'] = address
                declaration = {'id': self.relay['id'], 'kind': 'http-socket-relay', 'runtime': 'rootful',
                               'requires': [], 'relay': {'service': 'provider', 'port': 8200},
                               'resources': {'memoryMax': 67108864, 'tasksMax': 32}}
                service = types.SimpleNamespace(id=self.relay['id'], runtime='rootful', image=None,
                    declaration=declaration, requires=[types.SimpleNamespace(service='provider', kind='ready')],
                    unit_name=n.relay_names(self.relay)[0])
                catalog = types.SimpleNamespace(services={'provider': provider})
                relay = dict(self.relay, address=address, resources=declaration['resources'])
                expected = {Path(k).name: v.encode() for k, v in socketrelay.render(catalog, service).items()}
                self.assertEqual(n.relay_sources(relay), expected)
        finally:
            sys.path.remove(str(ROOT))

    def test_closed_schema_rejects_hostnames_commands_paths_unknown_options_and_collisions(self):
        mutations = [dict(address='localhost'), dict(address='0.0.0.0'), dict(address='::1%lo'),
                     dict(port=True), dict(port=65536), dict(id='../escape'), dict(command='/bin/false'),
                     dict(socketPath='/tmp/arbitrary'), dict(user='root'), dict(resources={'cpuQuota': 10}),
                     dict(resources={'tasksMax': True})]
        for mutation in mutations:
            proof = copy.deepcopy(self.proof)
            proof['relays'][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(n.Refused):
                n.evidence(json.dumps(proof).encode())
        for collision in ('duplicate', 'quadlet'):
            proof = copy.deepcopy(self.proof)
            if collision == 'duplicate':
                proof['relays'].append(copy.deepcopy(self.relay))
            else:
                proof['units']['rootful'].append({'name': n.relay_names(self.relay)[0], 'sourceSha256': 'a' * 64})
            with self.subTest(collision=collision), self.assertRaisesRegex(n.Refused, '^evidence-relay-collision$'):
                n.evidence(json.dumps(proof).encode())
        proof = copy.deepcopy(self.proof)
        proof['version'] = 1
        with self.assertRaisesRegex(n.Refused, '^evidence-schema$'):
            n.evidence(json.dumps(proof).encode())

    def test_known_socket_never_allows_unknown_scoped_trigger_service_or_resource(self):
        for extra in ('p0-v2-other.socket', 'p0-v2-other.timer', 'p0-v2-other.path',
                      'p0-v2-other.service', 'p0-v2-other-volume.service'):
            self.extra = extra
            with self.subTest(extra=extra), self.assertRaises(n.Refused):
                self.stopped()

    def test_removed_relay_rows_cannot_launder_installed_native_units(self):
        self.proof['relays'] = []
        with self.assertRaisesRegex(n.Refused, '^unreviewed-runtime-unit$'):
            self.stopped()

    def test_active_service_listener_jobs_pids_cgroups_extra_relations_and_fragment_facts_refuse(self):
        service, socket = n.relay_names(self.relay)
        cases = [(service, 'ActiveState', 'active'), (service, 'MainPID', '123'), (socket, 'ActiveState', 'active'),
                 (socket, 'ControlPID', '3'), (service, 'ControlPID', '3'), (socket, 'Job', '1/start'),
                 (service, 'ControlGroup', '/own/nonempty'), (socket, 'ControlGroup', '/own/socket'),
                 (service, 'TriggeredBy', socket + ' p0-v2-foreign.socket'), (service, 'TriggeredBy', ''),
                 (socket, 'Triggers', 'p0-v2-foreign.service'), (socket, 'TriggeredBy', 'p0-v2-foreign.path'),
                 (service, 'SourcePath', '/etc/containers/systemd/not-a-relay.container'),
                 (socket, 'FragmentPath', '/run/systemd/system/' + socket),
                 (service, 'DropInPaths', '/etc/systemd/system/service.d/extra.conf'),
                 (socket, 'NeedDaemonReload', 'yes'), (service, 'User', 'root'), (service, 'Group', 'root')]
        for name, key, value in cases:
            old = self.props[name][key]
            self.props[name][key] = value
            with self.subTest(name=name, key=key), self.assertRaisesRegex(n.Refused, '^relay-not-stopped$'):
                self.stopped()
            self.props[name][key] = old
        self.props[service]['ActiveState'] = self.props[service]['SubState'] = 'failed'
        self.stopped()  # Failed-but-closed service, socket still strictly inactive.

    def test_changed_bytes_refuse_even_with_approved_hash_for_nonbuiltin(self):
        service, _ = n.relay_names(self.relay)
        self.sources[service] += b'ExecStartPost=/bin/false\n'
        self.relay['serviceSha256'] = hashlib.sha256(self.sources[service]).hexdigest()
        with self.assertRaisesRegex(n.Refused, '^relay-source-binding$'):
            self.stopped()

    def test_source_hash_and_post_observation_identity_are_not_inferred_from_fragment(self):
        self.relay['serviceSha256'] = 'c' * 64
        with self.assertRaisesRegex(n.Refused, '^relay-source-binding$'):
            self.stopped()
        service, _ = n.relay_names(self.relay)
        self.relay['serviceSha256'] = hashlib.sha256(self.sources[service]).hexdigest()
        count = []
        def race(path, *args, **kwargs):
            count.append(1)
            return self.sources[path.name], ('inode', len(count))
        with patch.object(self.native, 'call', side_effect=self.call), patch.object(n, 'strict_directory'), \
             patch.object(n, 'no_native_dropins'), patch.object(n, 'read_exact', side_effect=race), \
             patch.object(n, 'closed_relay_listener'):
            with self.assertRaisesRegex(n.Refused, '^relay-source-changed$'):
                self.native.stopped_units(self.proof)

    def test_generic_exact_dash_prefix_native_dropins_refuse(self):
        with tempfile.TemporaryDirectory(prefix='.p0-source05-dropins-', dir=Path.home()) as directory:
            root = Path(directory)
            with patch.object(n, 'NATIVE_UNIT_ROOTS', (root,)):
                for suffix in ('service', 'socket'):
                    name = 'p0-v2-private-search.' + suffix
                    n.no_native_dropins(name)
                    for prefix in ('', 'p0-.', 'p0-v2-.', 'p0-v2-private-.', 'p0-v2-private-search.'):
                        target = root / (prefix + suffix + '.d')
                        target.mkdir()
                        with self.subTest(path=target), self.assertRaisesRegex(n.Refused, '^native-source-dropins$'):
                            n.no_native_dropins(name)
                        target.rmdir()

    def test_alternate_native_fragment_refuses_even_when_exact_etc_fragment_is_loaded(self):
        service, _ = n.relay_names(self.relay)
        with tempfile.TemporaryDirectory(prefix='.p0-source05-fragment-', dir=Path.home()) as directory:
            root = Path(directory)
            (root / service).write_bytes(b'new-unprivileged-fixture-only')
            with patch.object(n, 'NATIVE_UNIT_ROOTS', (root,)):
                with self.assertRaisesRegex(n.Refused, '^native-alternate-fragment$'):
                    n.no_native_dropins(service)

    def test_bounded_kernel_unix_table_detects_actual_path_even_when_units_inactive(self):
        header = b'Num       RefCount Protocol Flags    Type St Inode Path\n'
        path = str(n.RELAY_BASE / self.relay['id'] / 'http.sock')
        view = types.SimpleNamespace(st_dev=4, st_ino=5)
        with patch.object(n.os, 'stat', return_value=view), patch.object(n.os.path, 'lexists', return_value=False):
            for flags, state in (('00010000', '01'), ('00000000', '03')):
                row = f'0000000000000000: 00000002 00000000 {flags} 0001 {state} 123 {path}\n'.encode()
                with patch.object(n, 'bounded_read', return_value=header + row):
                    with self.assertRaisesRegex(n.Refused, '^relay-kernel-socket-remains$'):
                        n.closed_relay_listener(self.relay, self.entry)
            with patch.object(n, 'bounded_read', return_value=header + b'0: 2 0 0 1 1 123 /unrelated\n') as read:
                n.closed_relay_listener(self.relay, self.entry)
                read.assert_called_once_with('/proc/net/unix', 4 * 1024**2)
            with patch.object(n, 'bounded_read', return_value=b'wrong header\n'):
                with self.assertRaisesRegex(n.Refused, '^unix-table-schema$'):
                    n.closed_relay_listener(self.relay, self.entry)

    def test_wrong_network_namespace_stale_socket_path_and_directory_custody_refuse(self):
        views = [types.SimpleNamespace(st_dev=4, st_ino=i) for i in (5, 6)]
        with patch.object(n.os, 'stat', side_effect=views), patch.object(n, 'bounded_read') as read:
            with self.assertRaisesRegex(n.Refused, '^not-host-network-namespace$'):
                n.closed_relay_listener(self.relay, self.entry)
            read.assert_not_called()
        view = types.SimpleNamespace(st_dev=4, st_ino=5)
        with patch.object(n.os, 'stat', return_value=view), patch.object(n.os.path, 'lexists', return_value=True), \
             patch.object(n, 'strict_directory'), patch.object(n.Path, 'lstat', return_value=types.SimpleNamespace(st_gid=0)):
            with self.assertRaisesRegex(n.Refused, '^relay-socket-path-remains$'):
                n.closed_relay_listener(self.relay, self.entry)
        with patch.object(n.os, 'stat', return_value=view), patch.object(n.os.path, 'lexists', return_value=True), \
             patch.object(n, 'strict_directory'), patch.object(n.Path, 'lstat', return_value=types.SimpleNamespace(st_gid=1234)):
            with self.assertRaisesRegex(n.Refused, '^relay-directory-custody$'):
                n.closed_relay_listener(self.relay, self.entry)


if __name__ == '__main__':
    unittest.main()
