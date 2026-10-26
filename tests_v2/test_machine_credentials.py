"""Source-only fixtures. No Root, native stores, services, or actual credentials."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'ops/host-admin/provision-p0-machine-credentials.py'
spec = importlib.util.spec_from_file_location('machine_supply_fixture', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Crash(BaseException):
    pass


class FakeNative:
    def __init__(self):
        self.objects = {}
        self.inputs = []
        self.crash = False
        self.fail = False
        self.bad_store = False
        self.calls = []

    def preflight(self, actors):
        self.calls.append('preflight')
        m.require(not self.bad_store, 'native-store-mismatch')

    def inspect(self, actor, name):
        self.calls.append('inspect')
        return self.objects.get((name, actor))

    def create(self, actor, name, labels, payload):
        self.calls.append('create')
        self.inputs.append((actor, payload))
        if self.fail:
            raise RuntimeError(payload.decode())  # Deliberately hostile native diagnostic.
        self.objects[(name, actor)] = {'id': 'a' * 24 + str(len(self.inputs)), 'labels': dict(labels)}
        if self.crash:
            self.crash = False
            raise Crash()


class MachineCredentialTests(unittest.TestCase):
    def setUp(self):
        # Only private synthetic fixtures. Mapping Root ownership to current uid is
        # test-local; production has no alternate paths/uid/runner CLI switches.
        self.temp = tempfile.TemporaryDirectory(prefix='.p0-machine-fixture-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'custody'
        self.real_directory = m.directory
        self.real_read = m.read_exact
        self.real_reserves = m.reserves
        self.addCleanup(patch.stopall)
        patch.object(m, 'directory', side_effect=lambda path, owners=(0,), mode=None:
                     self.real_directory(path, tuple(set((*owners, os.getuid()))), mode)).start()
        patch.object(m, 'reserves').start()
        self.real_pinned_namespace = m.pinned_namespace
        patch.object(m, 'pinned_namespace').start()
        patch.object(m, 'read_exact', side_effect=lambda path, uid, mode=None, max_bytes=m.LIMIT:
                     self.real_read(path, os.getuid() if uid == 0 else uid, mode, max_bytes)).start()
        self.intent = {'version': 1, 'classification': 'ordinary-service',
                       'resources': [{'name': 'boot-shared', 'actors': ['rootless', 'rootful']}]}
        self.raw = json.dumps(self.intent).encode()
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.native = FakeNative()
        self.c = m.Custody(self.base)
        self.addCleanup(self.c.close)

    def run_supply(self, mode='apply'):
        self.c.open(mode in ('apply', 'resume'), create=mode == 'apply')
        return m.supply(self.intent, self.digest, self.c, self.native, mode)

    def reopen(self):
        self.c.close()
        self.c = m.Custody(self.base)
        self.addCleanup(self.c.close)

    def test_same_random_bytes_both_actors_private_record_no_value_report(self):
        report = self.run_supply()
        self.assertTrue(len(self.native.inputs) == 2)
        self.assertTrue(self.native.inputs[0][1] == self.native.inputs[1][1], 'actor bytes differ')
        self.assertTrue(len(self.native.inputs[0][1]) == 64)
        secret = self.native.inputs[0][1].decode()
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(), json.dumps(report))
        self.assertEqual(stat.S_IMODE(self.base.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.base / 'active.json').stat().st_mode), 0o400)
        record = self.c.load()
        m.validate_record(record, self.intent, self.digest)
        self.assertTrue(all(s['state'] == 'complete' for s in record['resources']['boot-shared']['actors'].values()))
        self.reopen()
        self.run_supply()
        self.assertEqual(len(self.native.inputs), 2)

    def test_crash_after_native_create_before_outcome_explicit_metadata_resume(self):
        self.native.crash = True
        with self.assertRaises(Crash):
            self.run_supply()
        self.assertEqual(self.c.load()['resources']['boot-shared']['actors']['rootless']['state'], 'claimed')
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^explicit-resume-required$'):
            self.run_supply()
        self.reopen()
        result = self.run_supply('resume')
        self.assertEqual(len(self.native.inputs), 2)
        self.assertTrue(self.native.inputs[0][1] == self.native.inputs[1][1], 'resume bytes differ')
        self.assertEqual(result['resources'][0]['actors']['rootful']['state'], 'complete')

    def test_crash_between_actor_creates_keeps_prepared_actor_resumable(self):
        self.c.open(True)
        save = self.c.save
        def interrupted(record):
            save(record)
            states = record['resources']['boot-shared']['actors']
            if states['rootless']['state'] == 'complete' and states['rootful']['state'] == 'prepared':
                raise Crash()
        with patch.object(self.c, 'save', side_effect=interrupted):
            with self.assertRaises(Crash):
                m.supply(self.intent, self.digest, self.c, self.native, 'apply')
        self.reopen()
        self.run_supply('resume')
        self.assertEqual(len(self.native.inputs), 2)
        self.assertTrue(self.native.inputs[0][1] == self.native.inputs[1][1], 'resume bytes differ')

    def test_uncertain_absence_is_never_replayed(self):
        self.native.fail = True
        with self.assertRaisesRegex(m.Refused, '^native-create-uncertain$'):
            self.run_supply()
        self.assertEqual(self.c.load()['resources']['boot-shared']['actors']['rootless']['state'], 'uncertain')
        self.native.fail = False
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^uncertain-absence-no-replay$'):
            self.run_supply('resume')
        self.assertEqual(len(self.native.inputs), 1)

    def test_foreign_name_prevents_any_record_or_native_create(self):
        self.native.objects[('boot-shared', 'rootful')] = {'id': 'x' * 25, 'labels': {}}
        with self.assertRaisesRegex(m.Refused, '^foreign-existing-name$'):
            self.run_supply()
        self.assertFalse((self.base / 'active.json').exists())
        self.assertFalse(self.native.inputs)

    def test_foreign_metadata_after_crash_refuses_every_actor(self):
        self.native.crash = True
        with self.assertRaises(Crash):
            self.run_supply()
        self.native.objects[('boot-shared', 'rootless')]['labels']['p0.machine.owner'] = 'f' * 32
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^foreign-existing-name$'):
            self.run_supply('resume')
        self.assertEqual(len(self.native.inputs), 1)

    def test_native_id_change_even_with_matching_labels_refused(self):
        self.run_supply()
        self.native.objects[('boot-shared', 'rootless')]['id'] = 'z' * 25
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^native-id-changed$'):
            self.run_supply()
        self.assertEqual(len(self.native.inputs), 2)

    def test_offline_status_dry_run_create_nothing_and_no_native_calls(self):
        for mode in ('status', 'dry-run'):
            result = self.run_supply(mode)
            self.assertFalse(self.base.exists())
            self.assertEqual(result['resources'][0]['actors']['rootless']['state'], 'absent')
        self.assertFalse(self.native.calls)

    def test_status_existing_custody_is_read_only(self):
        self.run_supply()
        before = (self.base / 'active.json').read_bytes()
        self.reopen()
        self.native.calls.clear()
        self.run_supply('status')
        self.assertTrue(before == (self.base / 'active.json').read_bytes(), 'status wrote custody')
        self.assertFalse(self.native.calls)

    def test_symlink_and_hardlink_records_refused(self):
        self.run_supply()
        self.c.close()
        path = self.base / 'active.json'
        outside = Path(self.temp.name) / 'outside'
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.c.open(False)
            self.c.load()
        self.c.close()
        path.unlink()
        os.link(outside, path)
        self.c.open(False)
        with self.assertRaisesRegex(m.Refused, '^unsafe-file$'):
            self.c.load()

    def test_symlink_custody_and_writable_ancestor_refused(self):
        target = Path(self.temp.name) / 'target'
        target.mkdir(mode=0o700)
        self.base.symlink_to(target, target_is_directory=True)
        with self.assertRaises(m.Refused):
            self.c.open(True)
        self.base.unlink()
        os.chmod(self.temp.name, 0o777)
        with self.assertRaises(m.Refused):
            self.c.open(True)
        self.assertFalse(self.base.exists())

    def test_cas_external_record_replacement_refused(self):
        self.run_supply()
        record = self.c.load()
        path = self.base / 'active.json'
        path.unlink()
        path.write_text('{}')
        path.chmod(0o400)
        with self.assertRaisesRegex(m.Refused, '^record-cas$'):
            self.c.save(record)

    def test_lock_is_exclusive(self):
        self.c.open(True)
        other = m.Custody(self.base)
        try:
            with self.assertRaises(BlockingIOError):
                other.open(True)
        finally:
            other.close()

    def test_interrupted_publication_is_not_automatically_cleaned(self):
        self.c.open(True)
        (self.base / '.publish-interrupted').write_text('synthetic')
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^unexpected-custody-entry$'):
            self.c.open(True)
        self.assertTrue((self.base / '.publish-interrupted').exists())

    def test_record_tampering_schema_version_and_intent_fail_closed(self):
        self.run_supply()
        record = self.c.load()
        changed = copy.deepcopy(record)
        changed['resources']['boot-shared']['value'] = 'A' * 64
        with self.assertRaisesRegex(m.Refused, '^record-integrity$'):
            m.validate_record(changed, self.intent, self.digest)
        changed = copy.deepcopy(record)
        changed['version'] = 3
        changed['integrity'] = m.record_integrity(changed)
        with self.assertRaisesRegex(m.Refused, '^record-binding$'):
            m.validate_record(changed, self.intent, self.digest)
        with self.assertRaisesRegex(m.Refused, '^record-binding$'):
            m.validate_record(record, self.intent, 'f' * 64)

    def test_intent_closed_schema_duplicate_names_protected_resources(self):
        self.assertEqual(m.intent(self.raw), self.intent)
        for name in ('postgres-admin', 'vault-token', 'keykeeper-boot', 'openbao', 'owner-key', '../bad', 'p0_bad', ''):
            value = copy.deepcopy(self.intent)
            value['resources'][0]['name'] = name
            with self.assertRaises(m.Refused):
                m.intent(json.dumps(value).encode())
        for actors in ([], ['root'], ['rootless', 'rootless'], ['rootful', 'rootless', 'rootful']):
            value = copy.deepcopy(self.intent)
            value['resources'][0]['actors'] = actors
            with self.assertRaises(m.Refused):
                m.intent(json.dumps(value).encode())
        value = copy.deepcopy(self.intent)
        value['resources'] *= 2
        with self.assertRaises(m.Refused):
            m.intent(json.dumps(value).encode())
        for fields in ({'version': True}, {'version': 2}, {'classification': 'vault'}, {'extra': 'forbidden'}):
            value = copy.deepcopy(self.intent)
            value.update(fields)
            with self.assertRaises(m.Refused):
                m.intent(json.dumps(value).encode())
        for raw in (b'{"version":1,"version":1}', b'{"x":NaN}'):
            with self.assertRaises(m.Refused):
                m.intent(raw)

    def test_bad_store_prevents_record_publication_or_native_create(self):
        self.native.bad_store = True
        with self.assertRaisesRegex(m.Refused, '^native-store-mismatch$'):
            self.run_supply()
        self.assertFalse((self.base / 'active.json').exists())
        self.assertFalse(self.native.inputs)

    def test_no_reserve_prevents_main_custody_creation(self):
        source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        with patch.object(m.os, 'geteuid', return_value=0), \
             patch.object(m.resource, 'setrlimit'), patch.object(m.os, 'umask'), \
             patch.object(m.Path, 'is_relative_to', return_value=True), \
             patch.object(m, 'directory'), \
             patch.object(m, 'read_exact', side_effect=[(SOURCE.read_bytes(), None), (self.raw, None)]), \
             patch.object(m, 'actor_identity', return_value=types.SimpleNamespace()), \
             patch.object(m, 'reserves', side_effect=m.Refused('ram-reserve')), \
             patch.object(m.Custody, 'open') as opened:
            with self.assertRaisesRegex(m.Refused, '^ram-reserve$'):
                m.main(['apply', '--intent', '/synthetic/intent.json', '--intent-uid', '1000',
                        '--intent-sha256', self.digest, '--helper-sha256', source_hash])
            opened.assert_not_called()

    def test_main_store_failure_prevents_even_directory_creation(self):
        source = SOURCE.read_bytes()
        with patch.object(m.os, 'geteuid', return_value=0), \
             patch.object(m.resource, 'setrlimit'), patch.object(m.os, 'umask'), \
             patch.object(m.Path, 'is_relative_to', return_value=True), \
             patch.object(m, 'directory'), \
             patch.object(m, 'read_exact', side_effect=[(source, None), (self.raw, None)]), \
             patch.object(m, 'actor_identity', return_value=types.SimpleNamespace()), \
             patch.object(m, 'reserves'), \
             patch.object(m.Native, 'preflight', side_effect=m.Refused('native-store-mismatch')), \
             patch.object(m.Custody, 'open') as opened:
            with self.assertRaisesRegex(m.Refused, '^native-store-mismatch$'):
                m.main(['apply', '--intent', '/synthetic/intent.json', '--intent-uid', '1000',
                        '--intent-sha256', self.digest, '--helper-sha256', hashlib.sha256(source).hexdigest()])
            opened.assert_not_called()

    def test_native_call_requires_preflight_authority_before_process_creation(self):
        native = m.Native(types.SimpleNamespace())
        with patch.object(m.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(m.Refused, '^native-preflight-required$'):
                native.call('rootful', ['info', '--format', 'json'])
            process.assert_not_called()

    def test_marker_mount_or_directory_change_before_native_prevents_all_effects(self):
        native = m.Native(types.SimpleNamespace())
        boundary = {'markerBytes': b'synthetic-marker', 'cloneMountId': 101}
        layout = (('canonical-rootful-engine', (1, 2, 0, 0, 0o700)),)
        native.authorities['rootful'] = (boundary, layout)
        for actual_boundary, actual_layout in ((dict(boundary, cloneMountId=102), layout),
                                                (dict(boundary, markerBytes=b'changed-marker'), layout),
                                                (boundary, (('canonical-rootful-engine', (1, 3, 0, 0, 0o700)),))):
            with patch.object(m, 'pinned_namespace', return_value=actual_boundary), \
                 patch.object(native, 'layout', return_value=actual_layout), patch.object(m.subprocess, 'Popen') as process:
                with self.assertRaisesRegex(m.Refused, '^native-authority-changed$'):
                    native.call('rootful', ['secret', 'exists', 'p0-new'])
                process.assert_not_called()

    def test_native_rechecks_authority_after_successful_canonical_command(self):
        native = m.Native(types.SimpleNamespace())
        boundary, layout = {'cloneMountId': 101}, (('engine-inode', 2),)
        native.authorities['rootful'] = (boundary, layout)
        reader, writer = os.pipe()
        os.close(writer)
        output = os.fdopen(reader, 'rb')
        process = types.SimpleNamespace(stdout=output, stdin=None)
        process.poll = lambda: 0
        process.wait = lambda **kwargs: 0
        with patch.object(m, 'pinned_namespace', side_effect=[boundary, {'cloneMountId': 102}]), \
             patch.object(native, 'layout', return_value=layout), \
             patch.object(m.subprocess, 'Popen', return_value=process) as popen:
            with self.assertRaisesRegex(m.Refused, '^native-authority-changed$'):
                native.call('rootful', ['info', '--format', 'json'])
        args = popen.call_args.args[0]
        self.assertIn(str(m.ROOTFUL), args)
        self.assertNotIn('/proc/self/fd/', repr(args))
        self.assertTrue(output.closed)

    def test_native_commands_explicit_namespaces_and_clean_identity(self):
        native = m.Native(types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
        rootless = native.prefix('rootless')
        self.assertEqual(rootless[:9], ['/usr/bin/setpriv', '--reuid', '1234', '--regid', '1234',
                                       '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all', '/usr/bin/podman'])
        self.assertIn(str(m.ROOTLESS), rootless)
        rootful = native.prefix('rootful')
        for path in (m.ROOTFUL, m.RUNFUL, m.NETWORK):
            self.assertIn(str(path), rootful)
        self.assertNotIn('PYTHONPATH', native.environment('rootless'))
        calls = []
        def call(actor, args, payload=None):
            calls.append((actor, args, payload))
            return 0, b''
        with patch.object(native, 'call', side_effect=call):
            native.create('rootful', 'boot-shared', {'p0.machine.owner': 'a' * 32}, b'SYNTHETIC_ONLY')
        self.assertNotIn('SYNTHETIC_ONLY', repr(calls[0][1]))
        self.assertEqual(calls[0][2], b'SYNTHETIC_ONLY')
        self.assertNotIn('--replace', calls[0][1])

    def test_native_info_rejects_unexpected_graphroot_before_secret_ops(self):
        native = m.Native(types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
        calls = []
        def call(actor, args, payload=None):
            calls.append(args)
            return 0, b'{"store":{"graphRoot":"/default","runRoot":"/default","graphDriverName":"overlay"}}'
        with patch.object(m, 'directory'), patch.object(m, 'trusted_binary'), \
             patch.object(m.Path, 'lstat', return_value=types.SimpleNamespace(st_gid=0, st_uid=0, st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700)), \
             patch.object(native, 'call', side_effect=call):
            with self.assertRaisesRegex(m.Refused, '^native-store-mismatch$'):
                native.preflight(['rootful'])
        self.assertEqual(calls, [['info', '--format', 'json']])

    def test_missing_or_unexpected_actor_config_prevents_all_native_calls(self):
        native = m.Native(types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
        with patch.object(m, 'trusted_binary'), \
             patch.object(m, 'directory', side_effect=FileNotFoundError()), \
             patch.object(native, 'call') as call:
            with self.assertRaises(FileNotFoundError):
                native.preflight(['rootful'])
            call.assert_not_called()
        with patch.object(m, 'trusted_binary'), patch.object(m, 'directory'), \
             patch.object(m.Path, 'lstat', return_value=types.SimpleNamespace(st_uid=1234, st_gid=1234, st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700)), \
             patch.object(m, 'read_exact', return_value=(b'foreign storage configuration', None)), \
             patch.object(native, 'call') as call:
            with self.assertRaisesRegex(m.Refused, '^actor-storage-config$'):
                native.preflight(['rootless'])
            call.assert_not_called()

    def test_actor_account_is_exact_and_has_no_extra_groups(self):
        entry = types.SimpleNamespace(pw_uid=1234, pw_gid=1234, pw_dir=str(m.HOME), pw_shell='/usr/sbin/nologin')
        group = types.SimpleNamespace(gr_name='p0-runtime', gr_mem=[])
        with patch.object(m.pwd, 'getpwnam', return_value=entry), \
             patch.object(m.grp, 'getgrgid', return_value=group), patch.object(m.grp, 'getgrall', return_value=[]):
            self.assertIs(m.actor_identity(), entry)
            entry.pw_shell = '/bin/bash'
            with self.assertRaisesRegex(m.Refused, '^actor-identity$'):
                m.actor_identity()
            entry.pw_shell = '/usr/sbin/nologin'
            group.gr_mem = ['another-user']
            with self.assertRaisesRegex(m.Refused, '^actor-groups$'):
                m.actor_identity()

    def test_native_inspect_never_requests_values(self):
        native = m.Native(types.SimpleNamespace())
        outputs = [(0, b''), (0, json.dumps([{'ID': 'x' * 25,
                    'Spec': {'Name': 'p0-boot-shared', 'Labels': {}, 'Driver': {'Name': 'file', 'Options': {}}}}]).encode())]
        with patch.object(native, 'call', side_effect=outputs) as call:
            native.inspect('rootful', 'boot-shared')
        self.assertEqual(call.call_args_list[1].args[1], ['secret', 'inspect', 'p0-boot-shared'])
        with patch.object(native, 'call', return_value=(125, b'SYNTHETIC_SENSITIVE_DIAGNOSTIC')):
            with self.assertRaisesRegex(m.Refused, '^native-exists-uncertain$'):
                native.inspect('rootful', 'boot-shared')

    def test_native_canonical_file_driver_metadata_path_is_actor_bound(self):
        native = m.Native(types.SimpleNamespace())
        for actor, graph in (('rootless', m.ROOTLESS), ('rootful', m.ROOTFUL)):
            item = {'ID': 'x' * 24, 'Spec': {'Name': 'p0-boot-shared', 'Labels': {},
                    'Driver': {'Name': 'file', 'Options': {'path': str(graph / 'secrets/filedriver')}}}}
            with self.subTest(actor=actor), patch.object(native, 'call', side_effect=[(0, b''), (0, json.dumps([item]).encode())]):
                self.assertEqual(native.inspect(actor, 'boot-shared'), {'id': 'x' * 24, 'labels': {}})
            for options in ({'path': '/tmp/foreign'}, {'path': '/proc/self/fd/7/secrets/filedriver'},
                            {'path': str(graph / 'secrets/filedriver') + '/'},
                            {'path': str(graph / 'secrets/filedriver'), 'unknown': 'x'},
                            {'path': str((m.ROOTFUL if actor == 'rootless' else m.ROOTLESS) / 'secrets/filedriver')}):
                item['Spec']['Driver']['Options'] = options
                with self.subTest(actor=actor, options=options), \
                     patch.object(native, 'call', side_effect=[(0, b''), (0, json.dumps([item]).encode())]):
                    with self.assertRaisesRegex(m.Refused, '^native-metadata$'):
                        native.inspect(actor, 'boot-shared')

    def test_resume_without_exact_record_never_generates_or_creates(self):
        with self.assertRaisesRegex(m.Refused, '^resume-record-required$'):
            self.run_supply('resume')
        self.assertFalse(self.base.exists())
        self.assertFalse(self.native.calls)

    def test_real_reserve_logic_refuses_ram_and_each_disk_floor(self):
        with patch('builtins.open', return_value=io.StringIO('MemAvailable: 1 kB\n')):
            with self.assertRaisesRegex(m.Refused, '^ram-reserve$'):
                self.real_reserves()
        for failing_index in range(3):
            floors = [types.SimpleNamespace(f_bavail=1000, f_frsize=1024**3) for _ in range(3)]
            floors[failing_index] = types.SimpleNamespace(f_bavail=0, f_frsize=1024**3)
            with patch('builtins.open', return_value=io.StringIO('MemAvailable: 999999999 kB\n')), \
                 patch.object(m.os, 'statvfs', side_effect=floors):
                with self.assertRaisesRegex(m.Refused, '^disk-reserve$'):
                    self.real_reserves()

    def test_native_deadline_terminates_only_own_unreaped_process_group(self):
        native = m.Native(types.SimpleNamespace())
        reader, writer = os.pipe()
        output = os.fdopen(reader, 'rb')
        self.addCleanup(os.close, writer)
        process = types.SimpleNamespace(stdout=output, stdin=None, returncode=None, pid=7391)
        events = []
        process.poll = lambda: self.fail('must not reap before group cancellation')
        process.wait = lambda **kwargs: events.append(('wait', kwargs)) or 0
        with patch.object(native, 'check_authority'), patch.object(m.subprocess, 'Popen', return_value=process), \
             patch.object(m.os, 'killpg', side_effect=lambda pid, sig: events.append(('killpg', pid, sig))), \
             patch.object(m.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(m.Refused, '^native-timeout$'):
                native.call('rootful', ['info', '--format', 'json'])
        self.assertEqual(events, [('killpg', 7391, m.signal.SIGKILL), ('wait', {'timeout': 5})])

    def test_claim_is_durable_before_each_native_effect(self):
        create = self.native.create
        def checked(actor, name, labels, payload):
            persisted = self.c.load()
            self.assertEqual(persisted['resources'][name]['actors'][actor], {'state': 'claimed', 'id': None})
            m.validate_record(persisted, self.intent, self.digest)
            create(actor, name, labels, payload)
        with patch.object(self.native, 'create', side_effect=checked):
            self.run_supply()
        self.assertEqual(len(self.native.inputs), 2)

    def test_record_wrong_mode_and_duplicate_json_fail_closed(self):
        self.run_supply()
        path = self.base / 'active.json'
        path.chmod(0o600)
        self.reopen()
        with self.assertRaisesRegex(m.Refused, '^file-mode$'):
            self.run_supply('status')
        self.c.close()
        path.write_text('{"version":1,"version":1}')
        path.chmod(0o400)
        with self.assertRaisesRegex(m.Refused, '^duplicate-json-key$'):
            self.run_supply('status')

    def test_main_intent_hash_and_helper_hash_refuse_before_any_custody(self):
        source = SOURCE.read_bytes()
        for helper_hash, intent_hash in ((('0' * 64), self.digest),
                                         (hashlib.sha256(source).hexdigest(), '0' * 64)):
            with patch.object(m.os, 'geteuid', return_value=0), \
                 patch.object(m.resource, 'setrlimit'), patch.object(m.os, 'umask'), \
                 patch.object(m.Path, 'is_relative_to', return_value=True), \
                 patch.object(m, 'directory'), \
                 patch.object(m, 'read_exact', side_effect=[(source, None), (self.raw, None)]), \
                 patch.object(m.Custody, 'open') as opened:
                with self.assertRaises(m.Refused):
                    m.main(['apply', '--intent', '/synthetic/intent.json', '--intent-uid', '1000',
                            '--intent-sha256', intent_hash, '--helper-sha256', helper_hash])
                opened.assert_not_called()

    def test_native_output_bounded_and_stderr_discarded(self):
        native = m.Native(types.SimpleNamespace())
        reader, writer = os.pipe()
        os.write(writer, b'X' * 256)
        os.close(writer)
        output = os.fdopen(reader, 'rb')
        process = types.SimpleNamespace(stdout=output, stdin=None, returncode=0, pid=7391)
        process.poll = lambda: self.fail('must not reap before group cancellation')
        process.wait = lambda **kwargs: 0
        with patch.object(native, 'check_authority'), patch.object(m.os, 'killpg') as killpg, \
             patch.object(m.subprocess, 'Popen', return_value=process) as popen, patch.object(m, 'LIMIT', 128):
            with self.assertRaisesRegex(m.Refused, '^native-output-limit$'):
                native.call('rootful', ['secret', 'inspect', 'p0-boot-shared'])
        killpg.assert_called_once_with(7391, m.signal.SIGKILL)
        self.assertEqual(popen.call_args.kwargs['stderr'], m.subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs['cwd'], '/')
        self.assertTrue(output.closed)

    def test_native_create_uses_only_small_stdin_pipe(self):
        native = m.Native(types.SimpleNamespace())
        reader, writer = os.pipe()
        os.close(writer)
        output = os.fdopen(reader, 'rb')
        class Pipe(io.BytesIO):
            def close(self):
                self.saved = self.getvalue()
                super().close()
        stdin = Pipe()
        process = types.SimpleNamespace(stdout=output, stdin=stdin, returncode=0)
        process.poll = lambda: 0
        process.wait = lambda **kwargs: 0
        payload = b'SYNTHETIC_ONLY_NOT_A_CREDENTIAL'
        with patch.object(native, 'check_authority'), patch.object(m.subprocess, 'Popen', return_value=process) as popen:
            native.create('rootful', 'boot-shared', {'p0.machine.owner': 'a' * 32}, payload)
        self.assertTrue(stdin.saved == payload, 'stdin bytes changed')
        self.assertNotIn(payload.decode(), repr(popen.call_args))
        self.assertEqual(popen.call_args.kwargs['stdin'], m.subprocess.PIPE)

    def test_both_strong_formats_are_exact_canonical_base64_and_shared(self):
        import base64
        self.intent['resources'] = [
            {'name': 'format-small', 'actors': ['rootless', 'rootful'],
             'policy': {'encoding': 'base64url', 'entropyBytes': 32}},
            {'name': 'format-large', 'actors': ['rootless', 'rootful'],
             'policy': {'encoding': 'base64url', 'entropyBytes': 48}}]
        self.digest = hashlib.sha256(json.dumps(self.intent).encode()).hexdigest()
        result = self.run_supply()
        record = self.c.load()
        for index, size in enumerate((32, 48)):
            a, b = self.native.inputs[index * 2][1], self.native.inputs[index * 2 + 1][1]
            self.assertTrue(a == b, 'actor encoding differs')
            self.assertTrue(len(base64.b64decode(a, altchars=b'-_', validate=True)) == size, 'wrong entropy length')
            self.assertTrue(base64.urlsafe_b64encode(base64.b64decode(a, altchars=b'-_', validate=True)) == a,
                            'noncanonical URL-safe encoding')
            self.assertTrue(len(a) == (44 if size == 32 else 64), 'wrong encoded length')
            self.assertTrue((a.endswith(b'=') if size == 32 else not a.endswith(b'=')), 'wrong padding')
            self.assertTrue(not any(ch in a for ch in (b'+', b'/')), 'unsafe encoding alphabet')
            self.assertNotIn(a.decode(), json.dumps(result))
            self.assertNotIn(hashlib.sha256(a).hexdigest(), json.dumps(result))
        m.validate_record(record, self.intent, self.digest)
        for item in record['resources'].values():
            self.assertEqual(item['policy']['encoding'], 'base64url')
        changed = copy.deepcopy(self.intent)
        changed['resources'][0]['policy']['entropyBytes'] = 48
        with self.assertRaisesRegex(m.Refused, '^record-policy$'):
            m.validate_record(record, changed, self.digest)

    def test_urlsafe_encoding_is_canonical_and_standard_alphabet_record_refuses(self):
        import base64
        self.intent['resources'][0]['policy'] = {'encoding': 'base64url', 'entropyBytes': 32}
        self.c.open(True)
        with patch.object(m.secrets, 'token_bytes', side_effect=lambda size: b'\xfb' * size):
            record = m.prepared(self.intent, self.digest)
        self.c.save(record)
        m.validate_record(record, self.intent, self.digest)
        value = record['resources']['boot-shared']['value']
        self.assertTrue('-' in value or '_' in value, 'fixture did not exercise URL-safe alphabet')
        self.assertTrue(value.endswith('=') and len(value) == 44, 'incorrect canonical padding')
        changed = copy.deepcopy(record)
        changed['resources']['boot-shared']['value'] = base64.b64encode(b'\xfb' * 32).decode('ascii')
        changed['integrity'] = m.record_integrity(changed)
        with self.assertRaisesRegex(m.Refused, '^record-value-encoding$'):
            m.validate_record(changed, self.intent, self.digest)

    def test_32_byte_format_survives_metadata_bound_resume_without_regeneration(self):
        self.intent['resources'][0]['policy'] = {'encoding': 'base64url', 'entropyBytes': 32}
        self.digest = hashlib.sha256(json.dumps(self.intent).encode()).hexdigest()
        self.native.crash = True
        with self.assertRaises(Crash):
            self.run_supply()
        self.reopen()
        token_bytes = m.secrets.token_bytes
        def metadata_only(size):
            # token_hex(16) still generates opaque atomic-publication filenames;
            # neither credential policy size may be generated on resume.
            self.assertNotIn(size, (32, 48), 'resume regenerated credential material')
            return token_bytes(size)
        with patch.object(m.secrets, 'token_bytes', side_effect=metadata_only):
            result = self.run_supply('resume')
        self.assertTrue(self.native.inputs[0][1] == self.native.inputs[1][1], 'resume bytes changed')
        self.assertEqual(len(self.native.inputs[0][1]), 44)
        self.assertNotIn(self.native.inputs[0][1].decode(), json.dumps(result))

    def test_policy_rejects_weak_unknown_or_malformed_formats(self):
        for policy in ({'encoding': 'base64url', 'entropyBytes': 16},
                       {'encoding': 'base64', 'entropyBytes': 48},
                       {'encoding': 'hexadecimal', 'entropyBytes': 48},
                       {'encoding': 'base64url', 'entropyBytes': True},
                       {'encoding': 'base64url', 'entropyBytes': 32, 'extra': 1}, None):
            value = copy.deepcopy(self.intent)
            value['resources'][0]['policy'] = policy
            with self.assertRaises(m.Refused):
                m.intent(json.dumps(value).encode())

    def test_generic_encoding_matrix_exact_lengths_alphabet_and_policy_binding(self):
        import base64
        for encoding, size, length in (('base64url', 32, 44), ('base64url', 48, 64),
                                       ('base64url-unpadded', 32, 43), ('base64url-unpadded', 48, 64),
                                       ('hex', 32, 64), ('hex', 48, 96)):
            with self.subTest(encoding=encoding, entropyBytes=size):
                spec = copy.deepcopy(self.intent)
                spec['resources'][0]['policy'] = {'encoding': encoding, 'entropyBytes': size}
                m.intent(json.dumps(spec).encode())
                record = m.prepared(spec, self.digest)
                record['integrity'] = m.record_integrity(record)
                m.validate_record(record, spec, self.digest)
                value = record['resources']['boot-shared']['value']
                self.assertEqual(len(value), length)
                if encoding == 'hex':
                    self.assertTrue(all(c in '0123456789abcdef' for c in value), 'noncanonical hex alphabet')
                    decoded = bytes.fromhex(value)
                else:
                    self.assertTrue(all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-='
                                        for c in value), 'noncanonical URL-safe alphabet')
                    if encoding == 'base64url-unpadded':
                        self.assertTrue('=' not in value, 'unpadded format contains padding')
                    decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
                self.assertEqual(len(decoded), size)
                changed = copy.deepcopy(spec)
                changed['resources'][0]['policy']['encoding'] = 'hex' if encoding != 'hex' else 'base64url-unpadded'
                with self.assertRaisesRegex(m.Refused, '^record-policy$'):
                    m.validate_record(record, changed, self.digest)

    def test_identical_48_byte_base64_encodings_do_not_erase_policy_binding(self):
        spec = copy.deepcopy(self.intent)
        spec['resources'][0]['policy'] = {'encoding': 'base64url-unpadded', 'entropyBytes': 48}
        record = m.prepared(spec, self.digest)
        record['integrity'] = m.record_integrity(record)
        m.validate_record(record, spec, self.digest)
        spec['resources'][0]['policy']['encoding'] = 'base64url'
        with self.assertRaisesRegex(m.Refused, '^record-policy$'):
            m.validate_record(record, spec, self.digest)

    def test_unpadded_and_hex_canonical_rejections_do_not_normalize_stored_values(self):
        cases = {
            'base64url-unpadded': ('A' * 43 + '=', 'A' * 42 + 'B', 'A' * 42 + '+',
                                   'A' * 42 + '/', 'A' * 42 + ' ', 'A' * 43 + '\n',
                                   'fb' * 32, 'A' * 64),
            'hex': ('FB' * 32, '0x' + 'fb' * 32, 'fb ' * 32, 'f' * 63, 'g' * 64,
                    'fb' * 32 + '\n', 'A' * 43)}
        for encoding, values in cases.items():
            spec = copy.deepcopy(self.intent)
            spec['resources'][0]['policy'] = {'encoding': encoding, 'entropyBytes': 32}
            record = m.prepared(spec, self.digest)
            for value in values:
                record['resources']['boot-shared']['value'] = value
                record['integrity'] = m.record_integrity(record)
                with self.subTest(encoding=encoding, length=len(value)), \
                     self.assertRaisesRegex(m.Refused, '^record-value-encoding$'):
                    m.validate_record(record, spec, self.digest)

    def test_all_encoding_policies_resume_original_bytes_without_regeneration(self):
        self.intent['resources'] = [
            {'name': f'{encoding}-{size}', 'actors': ['rootless', 'rootful'],
             'policy': {'encoding': encoding, 'entropyBytes': size}}
            for encoding in ('base64url', 'base64url-unpadded', 'hex') for size in (32, 48)]
        self.digest = hashlib.sha256(json.dumps(self.intent).encode()).hexdigest()
        self.native.crash = True
        with self.assertRaises(Crash):
            self.run_supply()
        before = copy.deepcopy(self.c.load()['resources'])
        self.reopen()
        token_bytes = m.secrets.token_bytes
        def metadata_only(size):
            self.assertNotIn(size, (32, 48), 'resume regenerated entropy')
            return token_bytes(size)
        with patch.object(m.secrets, 'token_bytes', side_effect=metadata_only):
            result = self.run_supply('resume')
        after = self.c.load()['resources']
        for name, item in before.items():
            self.assertTrue(after[name]['value'] == item['value'], 'resume changed value')
            self.assertEqual(after[name]['policy'], item['policy'])
            self.assertTrue(item['value'] not in json.dumps(result), 'value leaked in report')
        self.assertEqual(len(self.native.inputs), 12)
        for i in range(0, 12, 2):
            self.assertTrue(self.native.inputs[i][1] == self.native.inputs[i + 1][1], 'actor payload differs')

    def test_five_independent_consumer_formats_use_five_entropy_draws_not_app_inventory(self):
        self.intent['resources'] = [
            {'name': f'independent-{i}', 'actors': ['rootless'],
             'policy': {'encoding': 'hex' if i < 4 else 'base64url-unpadded', 'entropyBytes': 32}}
            for i in range(5)]
        self.digest = hashlib.sha256(json.dumps(self.intent).encode()).hexdigest()
        token_bytes, draws = m.secrets.token_bytes, []
        def counted(size):
            if size == 32:
                draws.append(size)
            return token_bytes(size)
        with patch.object(m.secrets, 'token_bytes', side_effect=counted):
            result = self.run_supply()
        payloads = [entry[1] for entry in self.native.inputs]
        self.assertEqual(len(draws), 5)
        self.assertEqual(len(set(payloads)), 5)
        self.assertEqual([len(value) for value in payloads], [64, 64, 64, 64, 43])
        self.assertTrue(all(b'=' not in value and b'\n' not in value for value in payloads), 'padding or terminator')
        self.assertTrue(all(value.decode() not in json.dumps(result) for value in payloads), 'value report leak')

    def intent_custody(self, digest):
        other = m.IntentCustody(Path(self.temp.name) / 'authority', digest)
        self.addCleanup(other.close)
        return other

    def test_incremental_independent_intents_preserve_values_and_old_records(self):
        first = self.intent_custody(self.digest)
        first.open(True)
        m.supply(self.intent, self.digest, first, self.native, 'apply')
        original = (first.base / 'active.json').read_bytes()
        original_id = first.base.stat().st_ino
        first.close()
        second_spec = {'version': 1, 'classification': 'ordinary-service', 'resources': [
            {'name': 'later-app', 'actors': ['rootless'], 'policy': {'encoding': 'base64url', 'entropyBytes': 32}}]}
        second_digest = hashlib.sha256(json.dumps(second_spec).encode()).hexdigest()
        second = self.intent_custody(second_digest)
        second.open(True)
        m.supply(second_spec, second_digest, second, self.native, 'apply')
        self.assertTrue(original == (first.base / 'active.json').read_bytes(), 'prior intent changed')
        self.assertEqual(first.base.stat().st_ino, original_id)
        self.assertNotEqual(first.base, second.base)
        self.assertEqual(len(self.native.inputs), 3)
        second.close()
        inspect = self.intent_custody(self.digest)
        inspect.open(False)
        before = len(self.native.calls)
        m.supply(self.intent, self.digest, inspect, self.native, 'status')
        self.assertEqual(len(self.native.calls), before)

    def test_cross_intent_claim_collision_rejected_even_before_native_effect(self):
        first = self.intent_custody(self.digest)
        first.open(True)
        # A prepared record already owns the name, even if no native actor exists.
        first.save(m.prepared(self.intent, self.digest))
        first.close()
        changed = copy.deepcopy(self.intent)
        changed['resources'][0]['policy'] = {'encoding': 'base64url', 'entropyBytes': 32}
        digest = hashlib.sha256(json.dumps(changed).encode()).hexdigest()
        second = self.intent_custody(digest)
        second.open(True)
        with self.assertRaisesRegex(m.Refused, '^cross-intent-name-collision$'):
            m.supply(changed, digest, second, self.native, 'apply')
        self.assertFalse((second.base / 'active.json').exists())
        self.assertFalse(self.native.calls)

    def test_global_authority_lock_serializes_cross_intent_claims(self):
        first = self.intent_custody(self.digest)
        first.open(True)
        second = self.intent_custody('e' * 64)
        with self.assertRaises(BlockingIOError):
            second.open(True)

    def test_aggregate_resource_and_intent_count_bounds(self):
        for group in range(8):
            digest = f'{group:064x}'
            spec = {'version': 1, 'classification': 'ordinary-service', 'resources': [
                {'name': f'group-{group}-resource-{i}', 'actors': ['rootless']} for i in range(64)]}
            existing = self.intent_custody(digest)
            existing.open(True)
            existing.save(m.prepared(spec, digest))
            existing.close()
        prospective = self.intent_custody(self.digest)
        prospective.open(True)
        with self.assertRaisesRegex(m.Refused, '^aggregate-resource-bound$'):
            m.supply(self.intent, self.digest, prospective, self.native, 'apply')
        self.assertFalse(self.native.calls)
        self.assertFalse((prospective.base / 'active.json').exists())
        prospective.close()
        intents = prospective.authority / 'intents'
        # Include the prospective directory plus 63 distinct fixed hash dirs.
        for index in range(63):
            (intents / f'{index:064x}').mkdir(mode=0o700, exist_ok=True)
        full = self.intent_custody('f' * 64)
        with self.assertRaisesRegex(m.Refused, '^intent-catalog-full$'):
            full.open(True)
        self.assertFalse(full.base.exists())

    def test_legacy_root_record_is_never_auto_migrated(self):
        authority = Path(self.temp.name) / 'authority'
        authority.mkdir(mode=0o700)
        path = authority / 'active.json'
        path.write_text('{"version":1}')
        path.chmod(0o400)
        c = self.intent_custody(self.digest)
        with self.assertRaisesRegex(m.Refused, '^unknown-credential-authority-entry$'):
            c.open(True)
        self.assertTrue(path.exists())
        self.assertFalse((authority / 'intents').exists())

    def test_intent_catalog_status_and_dry_run_never_create_authority(self):
        for mode in ('status', 'dry-run'):
            c = self.intent_custody(self.digest)
            c.open(False)
            m.supply(self.intent, self.digest, c, self.native, mode)
            self.assertFalse(c.authority.exists())
        self.assertFalse(self.native.calls)

    def test_helper_imports_only_stdlib_no_user_source_hooks(self):
        tree = ast.parse(SOURCE.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(n.name.split('.')[0] in sys.stdlib_module_names for n in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split('.')[0], sys.stdlib_module_names)
        text = SOURCE.read_text()
        for forbidden in ('--showsecret', 'sys.path', 'importlib', 'shell=True', '--replace'):
            self.assertNotIn(forbidden, text)

    def test_generated_native_error_is_redacted(self):
        self.native.fail = True
        with self.assertRaises(m.Refused) as caught:
            self.run_supply()
        secret = self.native.inputs[0][1].decode()
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, json.dumps(m.report(self.c.load(), self.intent, 'status')))


if __name__ == '__main__':
    unittest.main()
