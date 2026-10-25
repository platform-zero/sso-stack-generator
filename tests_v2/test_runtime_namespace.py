"""Source-only namespace contract and fake-native integration. Never mounts/runs engines."""
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
    return seal({'version': 1, 'state': state, 'owner': 'a' * 32, 'evidenceSha256': 'b' * 64,
                 'namespace': dict(expected), 'bootId': obs['bootId'], 'mountNamespace': dict(obs['mountNamespace']),
                 'mount': copy.deepcopy(own)})


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

    def stopped(self, proof, fd):
        n.require(not self.fail_stopped, 'runtime-unit-not-stopped')

    def bind(self, fd):
        assert self.marker.record['state'] == 'claimed'
        self.effects.append(('bind', fd))
        self.obs['mounts'] = observations(self.expected)['mounts']
        self.obs['mounts'][-1]['id'] = self.next_mount_id
        self.obs['mounts'][-1]['optional'] = ['shared:7']
        if self.crash_after_bind:
            self.crash_after_bind = False
            raise RuntimeError('SYNTHETIC_NATIVE_ERROR')

    def make_private(self, fd):
        self.effects.append(('private', fd))
        self.obs['mounts'][-1]['optional'] = []
        if self.crash_after_private:
            self.crash_after_private = False
            raise RuntimeError('SYNTHETIC_PRIVATE_EFFECT_CRASH')


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
        return [patch.object(n, 'namespace', side_effect=lambda expected: os.dup(self.fd)),
                patch.object(n, 'kernel', side_effect=lambda: copy.deepcopy(obs)), patch.object(n, 'reserves'),
                patch.object(n, 'preflight_children'), patch.object(n, 'create_children'),
                patch.object(n, 'check_actor_directories'),
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
             patch.object(c.Path, 'lstat', return_value=types.SimpleNamespace(st_gid=0)), \
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
        self.assertEqual([e[0] for e in native.effects], ['bind', 'private'])
        self.assertNotEqual(native.effects[0][1], native.effects[1][1])
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
        self.assertEqual([e[0] for e in native.effects], ['bind', 'private'])
        self.assertEqual(result['state'], 'pinned')

    def test_crash_after_private_reconciles_only_same_mount_with_removed_tags(self):
        obs = observations(self.expected, False)
        marker = MemoryMarker()
        native = FakeNative(self.expected, obs, marker)
        native.crash_after_private = True
        with self.assertRaises(RuntimeError):
            self.run_pin(marker, native, obs)
        self.assertEqual(marker.record['state'], 'claimed')
        self.assertEqual(marker.record['mount']['optional'], ['shared:7'])
        self.assertEqual(obs['mounts'][-1]['optional'], [])
        self.run_pin(marker, native, obs, 'resume')
        self.assertEqual(marker.record['state'], 'pinned')
        self.assertEqual([e[0] for e in native.effects], ['bind', 'private', 'private'])

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
        with patch.object(native, 'call') as call:
            native.bind(7)
            native.make_private(8)
        self.assertEqual(call.call_args_list[0].args[0], ['/usr/bin/mount', '--no-canonicalize', '--bind',
                                                        '/proc/self/fd/7', '/proc/self/fd/7'])
        self.assertEqual(call.call_args_list[0].kwargs['pass_fds'], (7,))
        self.assertEqual(call.call_args_list[1].args[0], ['/usr/bin/mount', '--no-canonicalize', '--make-private', '/proc/self/fd/8'])
        self.assertIn('/proc/self/fd/7/rootful/engine', native.engine('rootful', 7))
        self.assertIn(str(n.RUNFUL), native.engine('rootful', 7))
        self.assertIn(str(n.NETWORK), native.engine('rootful', 7))

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


class NativeStoppedTests(unittest.TestCase):
    def setUp(self):
        self.entry = types.SimpleNamespace(pw_uid=1234, pw_gid=1234)
        self.native = n.Native(self.entry)
        self.source = b'SYNTHETIC QUADLET SOURCE'
        self.proof = {'units': {'rootless': [{'name': 'p0-prototype.service',
                      'sourceSha256': hashlib.sha256(self.source).hexdigest()}], 'rootful': []}}
        self.props = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlGroup': '', 'Job': '',
                      'SourcePath': str(n.HOME / '.config/containers/systemd/p0-prototype.container'), 'TriggeredBy': ''}
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

    def stopped(self):
        with patch.object(self.native, 'call', side_effect=self.call), patch.object(n, 'strict_directory'), \
             patch.object(n, 'read_exact', return_value=(self.source, None)), \
             patch.object(n, 'check_actor_directories'), patch.object(n, 'anchored_engine', return_value=True):
            self.native.stopped(self.proof, 7)

    def test_stopped_owned_units_and_empty_anchored_engines_succeed(self):
        self.stopped()
        engine_calls = [call for call in self.calls if call[0][0] == '/usr/bin/podman']
        self.assertEqual(len(engine_calls), 4)
        self.assertTrue(all(call[2] == (7,) for call in engine_calls))
        self.assertTrue(all(call[0][2].startswith('/proc/self/fd/7/') for call in engine_calls))
        self.assertTrue(all('--all' in call[0] and '--external' in call[0] for call in engine_calls if 'ps' in call[0]))

    def test_active_pid_cgroup_job_trigger_and_unknown_unit_refuse(self):
        for key, value in (('ActiveState', 'active'), ('MainPID', '123'), ('ControlGroup', '/own/nonempty'),
                           ('Job', '1/start'), ('TriggeredBy', 'p0-prototype.socket'), ('LoadState', 'not-found')):
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
                self.native.call(['/usr/bin/systemctl', '--user', 'show', 'p0-prototype.service'], 'rootless', (7,))
        args = popen.call_args.args[0]
        self.assertEqual(args[0], '/usr/bin/setpriv')
        self.assertIn('/usr/bin/systemctl', args)
        self.assertIn('--clear-groups', args)
        self.assertIn('--inh-caps=-all', args)
        self.assertIn('--ambient-caps=-all', args)
        self.assertEqual(popen.call_args.kwargs['pass_fds'], (7,))
        self.assertEqual(popen.call_args.kwargs['stderr'], n.subprocess.DEVNULL)
        self.assertEqual(set(popen.call_args.kwargs['env']), {'PATH', 'LC_ALL', 'HOME', 'XDG_RUNTIME_DIR'})
        self.assertNotIn('SYNTHETIC_NATIVE_SENSITIVE_TEXT', str(refused.exception))
        self.assertTrue(output.closed)

    def test_wrong_unit_source_hash_refuses_before_engine_inspection(self):
        self.proof['units']['rootless'][0]['sourceSha256'] = 'f' * 64
        with self.assertRaisesRegex(n.Refused, '^unit-source-binding$'):
            self.stopped()
        self.assertFalse(any(call[0][0] == '/usr/bin/podman' for call in self.calls))


if __name__ == '__main__':
    unittest.main()
