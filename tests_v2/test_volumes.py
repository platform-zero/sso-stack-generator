"""Unprivileged fixtures and fake adapters only; no Podman/unshare/Root calls."""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('custody_volumes', Path(__file__).resolve().parents[1] / 'p0core/volumes.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class Crash(BaseException):
    pass


class FakeAdapter:
    def __init__(self, root, records):
        self.root, self.records = root, records
        self.actor_uid, self.actor_gid = os.getuid(), os.getgid()
        self.maps = {'uidMap': [[0, self.actor_uid, 1], [1, self.actor_uid + 100000, 65535]],
                     'gidMap': [[0, self.actor_gid, 1], [1, self.actor_gid + 100000, 65535]]}
        self.rows, self.nodes, self.effects, self.creates = {}, {}, [], 0
        self.fail_create, self.fail_effect = None, None
        self.mounted, self.users, self.not_empty = False, False, False
        self.false_readback, self.hook = False, None

    def mountpoint(self, resource):
        return self.root / 'volumes' / ('p0-' + resource) / '_data'

    def load(self, resource):
        return json.loads((self.records / ('p0-' + resource + '.json')).read_bytes())

    def lookup(self, resource):
        return copy.deepcopy(self.rows.get(resource))

    def create(self, record):
        resource = record['definition']['resource']
        persisted = self.load(resource)
        assert persisted['nonce'] == record['nonce'] and persisted['state'] == 'claimed'
        assert persisted['native'] is None
        self.creates += 1
        if self.fail_create == 'before':
            raise Crash()
        path = self.mountpoint(resource)
        path.mkdir(parents=True, mode=0o755)
        s = path.stat()
        self.nodes[(s.st_dev, s.st_ino)] = {'uid': 0, 'gid': 0, 'mode': '0755'}
        self.rows[resource] = {'Name': 'p0-' + resource, 'Driver': 'local', 'Options': {},
                               'Labels': v.labels(record), 'Mountpoint': str(path),
                               'CreatedAt': '2026-01-02T03:04:05.123456789Z', 'MountCount': 0,
                               'UID': None, 'GID': None}
        if self.fail_create == 'after':
            raise Crash()

    def no_mounts(self, path):
        v.need(not self.mounted, 'volume-mounted')

    def no_users(self, resource):
        v.need(not self.users, 'volume-in-use')

    def node(self, fd):
        s = os.fstat(fd)
        return self.nodes[(s.st_dev, s.st_ino)]

    def host(self, fd):
        node = self.node(fd)
        return dict(v.inode(fd), uid=v.mapping(self.maps['uidMap'], node['uid']),
                    gid=v.mapping(self.maps['gidMap'], node['gid']), mode=node['mode'])

    def probe(self, fd, record, *, fresh, action='probe', before=None):
        resource = record['definition']['resource']
        node = self.node(fd)
        if fresh:
            v.need(not self.not_empty and not any(self.mountpoint(resource).iterdir()), 'volume-not-empty')
        if action != 'probe':
            assert self.load(resource)['state'] == action + '-claimed'
            assert node == before
            self.effects.append(action)
            if self.fail_effect == action + '-before':
                raise Crash()
            if not self.false_readback:
                if action == 'chmod':
                    node['mode'] = record['definition']['custody']['mode']
                else:
                    node.update(record['definition']['custody'])
            if self.hook:
                self.hook(action, resource)
            if self.fail_effect == action + '-after':
                raise Crash()
        return dict(copy.deepcopy(self.maps), stat=dict(v.inode(fd), **node), empty=True if fresh else None)


class VolumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.p0-volume04-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'custody'
        self.state.mkdir(mode=0o700)
        self.adapter = FakeAdapter(self.root / 'engine', self.state)
        self.manager = v.VolumeCustody(self.state, self.adapter)
        self.policy = {'uid': 1000, 'gid': 1000, 'mode': '0700'}
        self.addCleanup(patch.stopall)
        patch.object(v, 'host_stat', side_effect=self.adapter.host).start()

    def ensure(self, **kwargs):
        return self.manager.ensure('consumer-data', self.policy, **kwargs)

    def claim_crash(self):
        self.adapter.fail_create = 'after'
        with self.assertRaises(Crash):
            self.ensure()
        self.adapter.fail_create = None
        return self.adapter.load('consumer-data')

    def write_record(self, record):
        record['integrity'] = v.digest({k: val for k, val in record.items() if k != 'integrity'})
        (self.state / 'p0-consumer-data.json').write_bytes(v.encoded(record))

    def test_prepared_only_missing_or_claimed_never_initializes_or_resumes(self):
        with self.assertRaisesRegex(v.VolumeError, '^volume-preparation-required$'):
            self.ensure(prepared_only=True)
        self.assertEqual(self.adapter.creates, 0)
        self.assertEqual(list(self.state.iterdir()), [])
        self.claim_crash()
        before = (self.state / 'p0-consumer-data.json').read_bytes()
        with self.assertRaisesRegex(v.VolumeError, '^volume-preparation-required$'):
            self.ensure(prepared_only=True, resume=True)
        self.assertEqual(self.adapter.creates, 1)
        self.assertEqual(self.adapter.effects, [])
        self.assertEqual((self.state / 'p0-consumer-data.json').read_bytes(), before)

    def test_prepared_only_populated_admission_has_no_mutation(self):
        result = self.ensure()
        before = (self.state / 'p0-consumer-data.json').read_bytes()
        self.adapter.not_empty = True
        effects = list(self.adapter.effects)
        with patch.object(v.secrets, 'token_hex', side_effect=AssertionError('no entropy during admission')):
            self.assertEqual(self.ensure(prepared_only=True), result)
        self.assertEqual(self.adapter.effects, effects)
        self.assertEqual(self.adapter.creates, 1)
        self.assertEqual((self.state / 'p0-consumer-data.json').read_bytes(), before)

    def test_fresh_claim_before_create_mapping_and_prepared_admission(self):
        result = self.ensure()
        self.assertEqual(self.adapter.effects, ['chmod', 'chown'])
        self.assertEqual(result['state'], 'prepared')
        self.assertFalse(result['installationCertified'])
        record = self.adapter.load('consumer-data')
        self.assertEqual(record['native']['Labels'], result['labels'])
        self.assertEqual(record['definition']['options'], {})
        self.assertNotIn('NativeVolumeID', json.dumps(record))
        self.assertEqual(record['inode'], v.inode(vfd := os.open(self.adapter.mountpoint('consumer-data'), os.O_PATH)))
        os.close(vfd)
        self.assertEqual(stat.S_IMODE((self.state / 'p0-consumer-data.json').stat().st_mode), 0o600)

    def test_foreign_empty_nonempty_native_volume_never_adopted(self):
        for nonempty in (False, True):
            resource = 'foreign-data' if nonempty else 'foreign-empty'
            path = self.adapter.mountpoint(resource)
            path.mkdir(parents=True)
            if nonempty:
                (path / 'retained-data').write_text('synthetic')
            self.adapter.rows[resource] = {'Name': 'p0-' + resource}
            with self.assertRaisesRegex(v.VolumeError, '^volume-foreign-native$'):
                self.manager.ensure(resource, self.policy)
        self.assertEqual(self.adapter.creates, 0)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_partial_path_without_native_row_blocks_first_claim(self):
        self.adapter.mountpoint('consumer-data').parent.mkdir(parents=True)
        with self.assertRaisesRegex(v.VolumeError, '^volume-partial-path$'):
            self.ensure()
        self.assertFalse(list(self.state.iterdir()))

    def test_crash_after_create_before_readback_resume_uses_same_nonce_no_entropy(self):
        old = self.claim_crash()
        with patch.object(v.secrets, 'token_hex', side_effect=AssertionError('resume entropy')):
            result = self.ensure(resume=True)
        self.assertEqual(self.adapter.creates, 1)
        self.assertEqual(result['labels']['io.platform-zero.volume.nonce'], old['nonce'])
        self.assertEqual(result['state'], 'prepared')

    def test_claim_without_native_row_never_recreates_even_without_partial_path(self):
        self.adapter.fail_create = 'before'
        with self.assertRaises(Crash):
            self.ensure()
        for partial in (False, True):
            if partial:
                self.adapter.mountpoint('consumer-data').parent.mkdir(parents=True)
            with self.assertRaisesRegex(v.VolumeError, '^volume-claim-native-absent-indeterminate$'):
                self.ensure(resume=True)
        self.assertEqual(self.adapter.creates, 1)

    def test_partial_requires_explicit_resume(self):
        self.claim_crash()
        with self.assertRaisesRegex(v.VolumeError, '^volume-explicit-resume-required$'):
            self.ensure()

    def test_native_nonce_definition_options_driver_path_timestamp_and_missing_metadata(self):
        self.claim_crash()
        original = copy.deepcopy(self.adapter.rows['consumer-data'])
        mutations = [dict(original, Options={'uid': '1000', 'gid': '1000'}), dict(original, Driver='foreign'),
                     dict(original, Mountpoint='/tmp/wrong'), dict(original, CreatedAt='not-a-time'),
                     dict(original, MountCount=1), dict(original, MountCount=None)]
        for key in ('io.platform-zero.volume.nonce', 'io.platform-zero.volume.intent'):
            row = copy.deepcopy(original)
            row['Labels'][key] = '0' * 32
            mutations.append(row)
        for key in ('CreatedAt', 'Mountpoint', 'Options', 'MountCount'):
            row = copy.deepcopy(original)
            del row[key]
            mutations.append(row)
        for row in mutations:
            self.adapter.rows['consumer-data'] = row
            with self.assertRaises(v.VolumeError):
                self.ensure(resume=True)
        self.assertFalse(self.adapter.effects)

    def test_resume_direct_partial_chmod_and_chown_fault_points(self):
        # Separate independent resources, only newly created fixture directories.
        for phase in ('chmod-before', 'chmod-after', 'chown-before', 'chown-after'):
            resource = 'fault-' + phase
            self.adapter.fail_effect = phase
            with self.assertRaises(Crash):
                self.manager.ensure(resource, self.policy)
            before = list(self.adapter.effects)
            self.adapter.fail_effect = None
            with patch.object(v.secrets, 'token_hex', side_effect=AssertionError('new nonce')):
                result = self.manager.ensure(resource, self.policy, resume=True)
            self.assertEqual(result['state'], 'prepared')
            if phase.endswith('-after'):
                self.assertEqual(self.adapter.effects.count(phase.split('-')[0]), before.count(phase.split('-')[0]))
            self.adapter.effects.clear()

    def test_unexpected_partial_owner_mode_not_a_repair_authorization(self):
        self.adapter.fail_effect = 'chown-before'
        with self.assertRaises(Crash):
            self.ensure()
        node = next(iter(self.adapter.nodes.values()))
        for bad in ({'uid': 1000, 'gid': 0, 'mode': '0700'}, {'uid': 0, 'gid': 0, 'mode': '0777'}):
            node.update(bad)
            with self.assertRaisesRegex(v.VolumeError, '^volume-transition-unknown$'):
                self.ensure(resume=True)
        self.assertEqual(self.adapter.creates, 1)

    def test_syscall_output_success_without_physical_readback_stops(self):
        self.adapter.false_readback = True
        with self.assertRaisesRegex(v.VolumeError, '^volume-effect-readback$'):
            self.ensure()
        self.assertEqual(self.adapter.load('consumer-data')['state'], 'chmod-claimed')
        self.assertEqual(self.adapter.effects, ['chmod'])

    def test_existing_prepared_data_verified_without_empty_scan_or_effect(self):
        self.ensure()
        path = self.adapter.mountpoint('consumer-data')
        (path / 'retained-private-data').write_text('synthetic preserved')
        old_mode, old_inode = path.stat().st_mode, path.stat().st_ino
        before = (self.state / 'p0-consumer-data.json').read_bytes()
        self.adapter.not_empty = True
        self.adapter.users = True
        self.adapter.rows['consumer-data']['MountCount'] = 1
        self.adapter.effects.clear()
        result = self.ensure()
        self.assertEqual(result['state'], 'prepared')
        self.assertEqual(self.adapter.effects, [])
        self.assertEqual((path.stat().st_mode, path.stat().st_ino), (old_mode, old_inode))
        self.assertEqual((path / 'retained-private-data').read_text(), 'synthetic preserved')
        self.assertEqual((self.state / 'p0-consumer-data.json').read_bytes(), before)

    def test_prepared_changed_custody_refuses_without_repair(self):
        self.ensure()
        next(iter(self.adapter.nodes.values()))['mode'] = '0755'
        self.adapter.effects.clear()
        with self.assertRaisesRegex(v.VolumeError, '^volume-prepared-custody-changed$'):
            self.ensure()
        self.assertFalse(self.adapter.effects)

    def test_same_definition_hash_replacement_inode_refuses(self):
        self.ensure()
        path = self.adapter.mountpoint('consumer-data')
        path.rename(path.parent / 'retained-original-fixture')
        path.mkdir()
        with self.assertRaisesRegex(v.VolumeError, '^volume-inode-changed$'):
            self.ensure()

    def test_submount_users_stopped_external_unknown_and_nonempty_fresh_refuse(self):
        self.claim_crash()
        for field, reason in (('mounted', 'volume-mounted'), ('users', 'volume-in-use'), ('not_empty', 'volume-not-empty')):
            setattr(self.adapter, field, True)
            with self.assertRaisesRegex(v.VolumeError, '^' + reason + '$'):
                self.ensure(resume=True)
            setattr(self.adapter, field, False)
        self.assertFalse(self.adapter.effects)

    def test_idmap_unmapped_overlap_actor_change_and_failed_host_readback(self):
        self.claim_crash()
        original = copy.deepcopy(self.adapter.maps)
        for rows in ([[0, os.getuid(), 1]], [[0, os.getuid(), 1], [0, 100000, 65536]],
                     [[0, 0, 65536]], [[0, os.getuid() + 1, 1], [1, 100000, 65535]]):
            self.adapter.maps['uidMap'] = rows
            with self.assertRaises(v.VolumeError):
                self.ensure(resume=True)
        self.adapter.maps = original
        with patch.object(v, 'host_stat', return_value={'uid': 999, 'gid': 999, 'mode': '0755'}):
            with self.assertRaisesRegex(v.VolumeError, '^volume-host-readback$'):
                self.ensure(resume=True)
        self.assertFalse(self.adapter.effects)

    def test_maps_do_not_silently_change_on_resume(self):
        self.adapter.fail_effect = 'chmod-before'
        with self.assertRaises(Crash):
            self.ensure()
        self.adapter.maps['uidMap'][1][1] += 1000
        with self.assertRaisesRegex(v.VolumeError, '^volume-idmap-changed$'):
            self.ensure(resume=True)

    def test_unknown_record_policy_schema_integrity_legacy_and_bool_refuse(self):
        original = self.claim_crash()
        for key, value in (('version', 0), ('version', True), ('nonce', 'bad'), ('state', 'legacy')):
            record = copy.deepcopy(original)
            record[key] = value
            self.write_record(record)
            with self.assertRaises(v.VolumeError):
                self.ensure(resume=True)
        record = copy.deepcopy(original)
        record['extra'] = 1
        self.write_record(record)
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-schema$'):
            self.ensure(resume=True)
        self.write_record(original)
        self.policy['mode'] = '0750'
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-binding$'):
            self.ensure(resume=True)

    def test_data_opath_anchor_needs_no_host_read_permission_and_rejects_symlink(self):
        path = self.root / 'new-empty-unreadable'
        path.mkdir(mode=0o700)
        path.chmod(0o000)  # Exact disposable new fixture only; no mapped chown.
        try:
            fd = v.open_directory(path)
            self.assertEqual(v.inode(fd)['inode'], path.lstat().st_ino)
            os.close(fd)
        finally:
            path.chmod(0o700)
        alias = self.root / 'new-empty-alias'
        alias.symlink_to(path, target_is_directory=True)
        with self.assertRaises(OSError):
            v.open_directory(alias)

    def test_restrictive_closed_policy_and_ids(self):
        for invalid in ({'uid': True, 'gid': 0, 'mode': '0700'}, {'uid': -1, 'gid': 0, 'mode': '0700'},
                        {'uid': 65536, 'gid': 0, 'mode': '0700'}, {'uid': 1, 'gid': 1, 'mode': '700'},
                        {'uid': 1, 'gid': 1, 'mode': '0777'}, {'uid': 1, 'gid': 1, 'mode': '1700'},
                        {'uid': 1, 'gid': 1, 'mode': '0700', 'command': 'false'}):
            with self.assertRaises(v.VolumeError):
                v.definition('consumer-data', invalid)
        self.assertEqual(v.definition('consumer-data', {'uid': 0, 'gid': 65535, 'mode': '0750'})['custody']['gid'], 65535)

    def test_initial_unknown_ownership_or_mode_refuses_even_with_claim_labels(self):
        self.claim_crash()
        node = next(iter(self.adapter.nodes.values()))
        for actual in ({'uid': 1000, 'gid': 1000, 'mode': '0700'}, {'uid': 0, 'gid': 0, 'mode': '0777'}):
            node.update(actual)
            with self.assertRaisesRegex(v.VolumeError, '^volume-initial-custody$'):
                self.ensure(resume=True)
        self.assertFalse(self.adapter.effects)

    def test_prepared_record_rejects_unknown_nested_native_keys(self):
        self.ensure()
        record = self.adapter.load('consumer-data')
        record['native']['inventedNativeVolumeID'] = 'not-an-api-id'
        self.write_record(record)
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-state$'):
            self.ensure()

    def test_record_directory_replacement_rejected_while_lock_is_held(self):
        self.claim_crash()
        with v.Records(self.state) as records:
            records.load('p0-consumer-data.json')
            old = self.root / 'retained-original-state'
            self.state.rename(old)
            self.state.mkdir(mode=0o700)
            with self.assertRaisesRegex(v.VolumeError, '^volume-record-directory-changed$'):
                records.read('p0-consumer-data.json')

    def test_corrupt_record_and_duplicate_json_are_not_repaired(self):
        record = self.claim_crash()
        record['integrity'] = '0' * 64
        (self.state / 'p0-consumer-data.json').write_bytes(v.encoded(record))
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-binding$'):
            self.ensure(resume=True)
        with self.assertRaisesRegex(v.VolumeError, '^volume-json-duplicate$'):
            v.parse(b'{"version":1,"version":1}')

    def test_native_metadata_change_during_effect_preserves_claim(self):
        def changed(action, resource):
            self.adapter.rows[resource]['CreatedAt'] = '2026-01-03T00:00:00Z'
        self.adapter.hook = changed
        with self.assertRaisesRegex(v.VolumeError, '^volume-native-changed$'):
            self.ensure()
        self.assertEqual(self.adapter.load('consumer-data')['state'], 'chmod-claimed')

    def test_record_cas_replacement_during_effect_preserves_indeterminate_evidence(self):
        def change(action, resource):
            path = self.state / ('p0-' + resource + '.json')
            replacement = self.state / 'replacement'
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        self.adapter.hook = change
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-cas$'):
            self.ensure()
        self.assertEqual(self.adapter.load('consumer-data')['state'], 'chmod-claimed')

    def test_record_lock_no_symlink_hardlink_mode_or_unknown_publication(self):
        self.claim_crash()
        with v.Records(self.state):
            with self.assertRaisesRegex(v.VolumeError, '^volume-operation-indeterminate$'):
                self.ensure(resume=True)
        path = self.state / 'p0-consumer-data.json'
        retained = self.root / 'retained-original-record'
        path.rename(retained)
        path.symlink_to(retained)
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-custody$'):
            self.ensure(resume=True)
        path.unlink()  # Exact new fixture symlink, not the retained record.
        retained.rename(path)
        path.chmod(0o644)
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-custody$'):
            self.ensure(resume=True)
        path.chmod(0o600)
        link = self.state / 'p0-second.json'
        os.link(path, link)
        with self.assertRaises(v.VolumeError):
            self.ensure(resume=True)
        link.unlink()
        (self.state / '.publish').write_text('retained failed publication')
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-inventory$'):
            self.ensure(resume=True)

    def test_record_capacity_and_failed_publication_retained(self):
        self.claim_crash()
        with v.Records(self.state) as records:
            record = records.load('p0-consumer-data.json')
            with patch.object(v.os, 'replace', side_effect=OSError('synthetic-private-error')):
                with self.assertRaises(OSError):
                    records.save(record)
        self.assertTrue((self.state / '.publish').exists())
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-inventory$'):
            self.ensure(resume=True)

    def test_other_record_cannot_claim_same_native_name_under_another_filename(self):
        self.claim_crash()
        original = self.state / 'p0-consumer-data.json'
        alias = self.state / 'p0-other-name.json'
        alias.write_bytes(original.read_bytes())
        alias.chmod(0o600)
        with self.assertRaisesRegex(v.VolumeError, '^volume-record-name-collision$'):
            self.ensure(resume=True)
        self.assertFalse(self.adapter.effects)

    def test_record_limit_before_new_claim_and_collision(self):
        with v.Records(self.state) as records:
            records.load('p0-consumer-data.json')
            with patch.object(v.os, 'listdir', return_value=['p0-other.json'] * 512):
                with self.assertRaisesRegex(v.VolumeError, '^volume-record-limit$'):
                    records.save({'synthetic': True})
        self.assertFalse(list(self.state.iterdir()))


class AdapterTests(unittest.TestCase):
    def adapter(self):
        runtime = types.SimpleNamespace()
        runtime.context = {'graphRoot': str(v.GRAPHROOT), 'uid': 1004, 'gid': 1004, 'configSha256': 'a' * 64}
        runtime.verify_volume_context = lambda: runtime.context
        runtime.run = lambda *args, **kwargs: b'[]'
        with patch.object(v.os, 'geteuid', return_value=1004), patch.object(v.os, 'getuid', return_value=1004), \
             patch.object(v.os, 'getgid', return_value=1004), \
             patch.object(v.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='p0-runtime')):
            return v.NativeAdapter(runtime)

    def test_single_executor_canonical_flags_bound_input_fd_fixed_program(self):
        adapter = self.adapter()
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix='.p0-volume04-io-') as temp:
            fd = v.open_directory(Path(temp))
            try:
                record = {'definition': v.definition('sample', {'uid': 1000, 'gid': 1000, 'mode': '0700'}), 'maps': None}
                with patch.object(adapter.runtime, 'run', return_value=b'{}') as runner:
                    adapter.probe(fd, record, fresh=True)
                args = runner.call_args.args[0]
                self.assertEqual(args[0:3], ['/usr/bin/podman', '--root', str(v.GRAPHROOT)])
                self.assertEqual(args[-5:], ['unshare', '/usr/bin/python3', '-I', '-c', v.INODE_PROGRAM])
                self.assertEqual(runner.call_args.kwargs['pass_fds'], (fd,))
                self.assertEqual(runner.call_args.kwargs['timeout'], 30)
                self.assertLess(len(runner.call_args.kwargs['input_bytes']), 4096)
                self.assertNotIn('/proc/self/fd/', ' '.join(args))
                with self.assertRaisesRegex(v.VolumeError, '^volume-fd-command$'):
                    adapter.call(['volume', 'ls'], pass_fds=(fd,))
            finally:
                os.close(fd)

    def test_context_snapshot_not_mutable_alias_and_native_failure_redaction(self):
        adapter = self.adapter()
        adapter.runtime.context['configSha256'] = 'b' * 64
        with self.assertRaisesRegex(v.VolumeError, '^volume-context-changed$'):
            adapter.lookup('sample')
        adapter = self.adapter()
        with patch.object(adapter.runtime, 'run', side_effect=RuntimeError('SYNTHETIC_PRIVATE_NATIVE_DIAGNOSTIC')):
            with self.assertRaisesRegex(v.VolumeError, '^volume-native-indeterminate$'):
                adapter.lookup('sample')

    def test_executor_rechecks_after_success_and_rejects_extra_fds_or_oversize_input(self):
        adapter = self.adapter()
        def changed(*args, **kwargs):
            adapter.runtime.context['configSha256'] = 'c' * 64
            return b'[]'
        adapter.runtime.run = changed
        with self.assertRaisesRegex(v.VolumeError, '^volume-context-changed$'):
            adapter.lookup('sample')
        adapter = self.adapter()
        with patch.object(adapter.runtime, 'run') as runner:
            for fds in ((True,), (3, 4), [3]):
                with self.assertRaisesRegex(v.VolumeError, '^volume-pass-fds$'):
                    adapter.call(['volume', 'ls'], pass_fds=fds)
            with self.assertRaisesRegex(v.VolumeError, '^volume-input-bound$'):
                adapter.call(['volume', 'ls'], input_bytes=b'x' * 4097)
            runner.assert_not_called()

    def test_known_unrelated_container_allowed_target_active_stopped_and_unknown_builder_refused(self):
        adapter = self.adapter()
        row = {'Id': 'a' * 64}
        target = {'Type': 'volume', 'Name': 'p0-sample', 'Source': str(adapter.mountpoint('sample'))}
        for state in ('running', 'exited', 'storage'):
            with patch.object(adapter, 'call', side_effect=[v.encoded([row]),
                    v.encoded([dict(row, State={'Status': state}, Mounts=[target])])]):
                with self.assertRaisesRegex(v.VolumeError, '^volume-in-use$'):
                    adapter.no_users('sample')
        other = {'Type': 'volume', 'Name': 'p0-other', 'Source': str(adapter.mountpoint('other'))}
        other_metadata = {'Name': 'p0-other', 'Driver': 'local', 'Options': {}, 'Mountpoint': other['Source']}
        with patch.object(adapter, 'call', side_effect=[v.encoded([row]), v.encoded([dict(row, Mounts=[other])]),
                                                       v.encoded([other_metadata])]), \
             patch.object(adapter, 'no_mounts') as no_mounts:
            adapter.no_users('sample')
            no_mounts.assert_called_once_with(adapter.mountpoint('other'))
        other_metadata['Options'] = {'type': 'none', 'o': 'bind', 'device': str(adapter.mountpoint('sample'))}
        with patch.object(adapter, 'call', side_effect=[v.encoded([row]), v.encoded([dict(row, Mounts=[other])]),
                                                       v.encoded([other_metadata])]):
            with self.assertRaisesRegex(v.VolumeError, '^volume-users-unknown$'):
                adapter.no_users('sample')
        for unknown in ([{}], [{'Id': 'builder-without-native-id'}]):
            with patch.object(adapter, 'call', return_value=v.encoded(unknown)):
                with self.assertRaisesRegex(v.VolumeError, '^volume-users-unknown$'):
                    adapter.no_users('sample')
        with patch.object(adapter, 'call', side_effect=[v.encoded([row]), v.encoded([row])]):
            with self.assertRaisesRegex(v.VolumeError, '^volume-users-unknown$'):
                adapter.no_users('sample')

    def test_bind_alias_unknown_user_and_submount_refused(self):
        adapter = self.adapter()
        row = {'Id': 'b' * 64}
        for mount in ({'Type': 'bind', 'Source': '/unknown/alias'}, {'Type': 'unknown-plugin'}):
            with patch.object(adapter, 'call', side_effect=[v.encoded([row]), v.encoded([dict(row, Mounts=[mount])])]):
                with self.assertRaisesRegex(v.VolumeError, '^volume-users-unknown$'):
                    adapter.no_users('sample')
        path = adapter.mountpoint('sample')
        from unittest.mock import mock_open
        for target in (path, path / 'nested', path.parent, path.parent.parent):
            raw = f'1 2 8:1 / {target} rw - ext4 /dev/fake rw\n'.encode()
            with patch('builtins.open', mock_open(read_data=raw)):
                with self.assertRaisesRegex(v.VolumeError, '^volume-mounted$'):
                    adapter.no_mounts(path)

    def test_fixed_program_ast_and_no_subprocess_or_recursive_permission_api(self):
        tree = ast.parse(v.INODE_PROGRAM)
        imports = {name.name for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
        self.assertEqual(imports, {'json', 'os', 're', 'stat', 'sys'})
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr in ('fchmod', 'fchown')]
        self.assertEqual(len(functions), 2)
        self.assertTrue(all(isinstance(node.args[0], ast.Name) and node.args[0].id == 'fd' for node in functions))
        self.assertNotIn('subprocess', v.INODE_PROGRAM)
        self.assertNotIn('os.walk', v.INODE_PROGRAM)
        self.assertIn('canonical_identity()', v.INODE_PROGRAM)
        self.assertIn('os.listxattr(fd)', v.INODE_PROGRAM)

    def test_mapping_exact_ranges_and_boolean_rejection(self):
        self.assertEqual(v.mapping([[0, 1004, 1], [1, 362144, 65536]], 1000), 363143)
        for rows in ([[True, 1004, 1]], [[0, 0, 1]], [[0, 1004, 0]],
                     [[0, 1004, 1], [1, 1004, 2]], [[0, 2**32 - 1, 2]]):
            with self.assertRaises(v.VolumeError):
                v.mapping(rows, 0)


if __name__ == '__main__':
    unittest.main()
