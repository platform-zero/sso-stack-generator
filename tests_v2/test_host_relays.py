"""Paused06 mechanism fixtures. Never execute Root/native/services/mount APIs.

Critical07: FakeAuthority is explicitly NOT production Authority; real Authority
is disabled before any publication. Critical containment is tested independently
in test_native_view.py. These fixtures never qualify mutable-parent custody.
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
spec = importlib.util.spec_from_file_location('host_relay_fixture', ROOT / 'ops/host-admin/provision-p0-v2-relays.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)


def definition():
    relay = {'id': 'search-http', 'address': '127.0.0.1', 'port': 18200,
             'serviceSha256': 'a' * 64, 'socketSha256': 'b' * 64}
    service, socket = n.relay_names(relay)
    sources = n.relay_sources(relay)
    relay.update(serviceSha256=n.sha(sources[service]), socketSha256=n.sha(sources[socket]))
    return n.intent(n.encoded({'version': 1, 'relays': [relay]}))


class Store:
    def __init__(self):
        self.record, self.writes, self.hook = None, [], None

    def load(self):
        return copy.deepcopy(self.record)

    def save(self, record):
        if self.hook:
            self.hook(record)
        record['integrity'] = n.sha(n.encoded({k: v for k, v in record.items() if k != 'integrity'}))
        self.record = copy.deepcopy(record)
        self.writes.append(copy.deepcopy(record))


class FakeFiles:
    def __init__(self, declaration, store):
        self.plan, self.store = n.plan(declaration), store
        self.nodes, self.effects, self.counter = {}, [], 10
        self.prepare_fault, self.publish_fault = None, None

    def probe(self, key, nonce, temporary=False):
        return copy.deepcopy(self.nodes.get((key, temporary)))

    def inventory(self, rows, nonce, **kwargs):
        pass

    def prepare(self, key, nonce):
        assert self.store.record['objects'][key]['state'] == 'prepare-claimed'
        self.effects.append(('prepare', key))
        if self.prepare_fault == 'before':
            raise RuntimeError('SYNTHETIC_BEFORE_PREPARE')
        self.counter += 1
        value = {'device': 1, 'inode': self.counter, 'uid': 0, 'gid': 0, 'mode': self.plan[key]['mode']}
        self.nodes[key, True] = value
        if self.prepare_fault == 'after':
            raise RuntimeError('SYNTHETIC_AFTER_PREPARE')
        return copy.deepcopy(value)

    def publish(self, key, nonce):
        assert self.store.record['objects'][key]['state'] == 'publish-claimed'
        self.effects.append(('publish', key))
        if self.publish_fault == 'before':
            raise RuntimeError('SYNTHETIC_BEFORE_PUBLICATION')
        assert (key, False) not in self.nodes
        self.nodes[key, False] = self.nodes.pop((key, True))
        if self.publish_fault == 'after':
            raise RuntimeError('SYNTHETIC_AFTER_PUBLICATION')


class SupplyTests(unittest.TestCase):
    def setUp(self):
        self.declaration = definition()
        self.digest = n.sha(n.encoded(self.declaration))
        self.store = Store()
        self.files = FakeFiles(self.declaration, self.store)
        self.authority = types.SimpleNamespace(check=lambda: None, record={
            'namespace': {'device': 1, 'inode': 2, 'filesystemId': 3}, 'owner': 'a' * 32,
            'bootId': '12345678-1234-1234-1234-123456789abc'})
        self.native = types.SimpleNamespace(entry=object(), stopped_units=lambda *a, **k: None)
        self.proof = {'version': 1, 'namespace': self.authority.record['namespace'], 'units': {'rootless': [], 'rootful': []}}
        self.supply = n.Supply(self.store, self.files, self.authority, self.native, self.proof, 'b' * 64)
        for name in ('reserves', 'closed_relay_listener', 'no_native_dropins', 'owned_unit'):
            self.enterContext(patch.object(n, name))

    def run_supply(self, mode='apply'):
        return self.supply.run(self.declaration, self.digest, mode)

    def test_first_apply_durable_claim_before_every_effect_and_exact_handoff(self):
        result = self.run_supply()
        self.assertEqual(result['state'], 'needs-review-units')
        self.assertEqual(result['priorEvidenceSha256'], 'b' * 64)
        self.assertTrue(result['daemonReloadRequired'])
        self.assertFalse(result['installationCertified'])
        self.assertFalse(result['activationPerformed'])
        self.assertEqual(len(result['sources']), 2)
        self.assertTrue(all(row['state'] == 'published' for row in self.store.record['objects'].values()))
        n.validate_record(self.store.record, self.declaration, self.digest)
        old_effects = list(self.files.effects)
        self.run_supply()  # Owned complete recheck, not matching-file adoption.
        self.assertEqual(self.files.effects, old_effects)

    def test_offline_status_has_no_gates_or_effects(self):
        self.authority.check = lambda: self.fail('offline authority access')
        self.assertEqual(self.run_supply('status')['state'], 'absent')
        self.assertFalse(self.files.effects)
        self.assertFalse(self.store.writes)

    def test_matching_foreign_target_is_never_adopted(self):
        self.files.nodes['base', False] = {'device': 1, 'inode': 99, 'uid': 0, 'gid': 0, 'mode': 0o711}
        with self.assertRaisesRegex(n.Refused, '^foreign-target$'):
            self.run_supply()
        self.assertFalse(self.store.writes)
        self.assertFalse(self.files.effects)

    def test_resume_without_record_cannot_first_create(self):
        with self.assertRaisesRegex(n.Refused, '^relay-record-required$'):
            self.run_supply('resume')
        self.assertFalse(self.files.effects)

    def test_prepare_claim_missing_or_present_without_inode_proof_never_replays(self):
        for fault in ('before', 'after'):
            with self.subTest(fault=fault):
                self.setUp()
                self.files.prepare_fault = fault
                with self.assertRaises(RuntimeError):
                    self.run_supply()
                effects = list(self.files.effects)
                self.files.prepare_fault = None
                with self.assertRaisesRegex(n.Refused, '^preparation-indeterminate$'):
                    self.run_supply('resume')
                self.assertEqual(self.files.effects, effects)

    def test_publish_claim_recovers_exact_prepared_or_published_inode_without_recreate(self):
        for fault in ('before', 'after'):
            with self.subTest(fault=fault):
                self.setUp()
                self.files.publish_fault = fault
                with self.assertRaises(RuntimeError):
                    self.run_supply()
                self.files.publish_fault = None
                with self.assertRaisesRegex(n.Refused, '^explicit-relay-resume-required$'):
                    self.run_supply()
                self.run_supply('resume')
                self.assertEqual([k for action, k in self.files.effects if action == 'prepare'].count('base'), 1)

    def test_claimed_publication_both_absent_or_both_present_refuses(self):
        for shape in ('absent', 'both', 'foreign'):
            with self.subTest(shape=shape):
                self.setUp()
                self.files.publish_fault = 'before'
                with self.assertRaises(RuntimeError):
                    self.run_supply()
                if shape == 'absent':
                    self.files.nodes.clear()
                elif shape == 'both':
                    self.files.nodes['base', False] = copy.deepcopy(self.files.nodes['base', True])
                else:
                    self.files.nodes['base', True]['inode'] += 100
                effects = list(self.files.effects)
                with self.assertRaisesRegex(n.Refused, '^publication-indeterminate$'):
                    self.run_supply('resume')
                self.assertEqual(self.files.effects, effects)

    def test_published_missing_or_replaced_even_same_bytes_cannot_be_recreated(self):
        for change in ('missing', 'inode'):
            with self.subTest(change=change):
                self.setUp()
                self.run_supply()
                key = next(k for k in self.files.plan if k.endswith('.service'))
                if change == 'missing':
                    del self.files.nodes[key, False]
                else:
                    self.files.nodes[key, False]['inode'] += 100
                effects = list(self.files.effects)
                with self.assertRaisesRegex(n.Refused, '^published-inode-changed$'):
                    self.run_supply('resume')
                self.assertEqual(self.files.effects, effects)

    def test_before_claim_gate_or_cas_failure_has_no_target_effect(self):
        for failure in ('unit', 'namespace', 'cas'):
            with self.subTest(failure=failure):
                self.setUp()
                def refused(*args, **kwargs):
                    raise n.Refused('fixture-refusal')
                if failure == 'unit':
                    self.native.stopped_units = refused
                elif failure == 'namespace':
                    self.authority.check = refused
                else:
                    self.store.hook = refused
                with self.assertRaises(n.Refused):
                    self.run_supply()
                self.assertFalse(self.files.effects)

    def test_post_publication_authority_loss_retains_effect_and_claim(self):
        original = self.files.publish
        def changed(key, nonce):
            original(key, nonce)
            self.authority.check = lambda: (_ for _ in ()).throw(n.Refused('namespace-marker-changed'))
        self.files.publish = changed
        with self.assertRaisesRegex(n.Refused, '^namespace-marker-changed$'):
            self.run_supply()
        self.assertIn(('base', False), self.files.nodes)
        self.assertNotEqual(self.store.record['phase'], 'complete')

    def test_bad_record_schema_checksum_intent_and_state_refuse_without_mutation(self):
        self.run_supply()
        good = copy.deepcopy(self.store.record)
        for key, value in (('integrity', 'a' * 64), ('intentSha256', 'f' * 64), ('extra', 1), ('phase', 'foreign')):
            self.store.record = copy.deepcopy(good)
            self.store.record[key] = value
            with self.subTest(key=key), self.assertRaises(n.Refused):
                self.run_supply('resume')
        self.assertEqual(len(self.files.effects), 8)

    def new_boot(self):
        self.authority.record = copy.deepcopy(self.authority.record)
        self.authority.record['bootId'] = '87654321-1234-1234-1234-123456789abc'
        self.proof.update(version=2, relays=copy.deepcopy(self.declaration['relays']))
        self.supply.evidence_digest = 'c' * 64
        for key, item in self.files.plan.items():
            if item['bytes'] is None:
                self.files.nodes.pop((key, False), None)  # Simulated volatile disappearance; no Host deletion.

    def test_new_boot_requires_explicit_rematerialize_and_preserves_persistent_sources(self):
        self.run_supply()
        sources = {k: copy.deepcopy(v) for k, v in self.files.nodes.items() if k[0].endswith(('.service', '.socket'))}
        self.new_boot()
        with self.assertRaisesRegex(n.Refused, '^explicit-relay-rematerialize-required$'):
            self.run_supply('resume')
        self.run_supply('rematerialize')
        self.assertEqual({k: v for k, v in self.files.nodes.items() if k in sources}, sources)
        self.assertEqual(len(self.store.record['previousBoots']), 1)
        self.assertEqual(sum(a == 'prepare' for a, k in self.files.effects), 6)
        n.validate_record(self.store.record, self.declaration, self.digest)

    def test_same_boot_rematerialize_cannot_reset_owned_or_uncertain_claims(self):
        self.run_supply()
        effects = list(self.files.effects)
        with self.assertRaisesRegex(n.Refused, '^relay-rematerialize-not-new-complete-boot$'):
            self.run_supply('rematerialize')
        self.assertEqual(self.files.effects, effects)

    def test_new_boot_wrong_namespace_foreign_directory_or_missing_source_refuses(self):
        for kind in ('namespace', 'directory', 'source', 'evidence'):
            with self.subTest(kind=kind):
                self.setUp()
                self.run_supply()
                self.new_boot()
                if kind == 'namespace':
                    self.authority.record['owner'] = 'f' * 32
                elif kind == 'directory':
                    self.files.nodes['base', False] = {'device': 1, 'inode': 999, 'uid': 0, 'gid': 0, 'mode': 0o711}
                elif kind == 'source':
                    del self.files.nodes[next(k for k in self.files.nodes if k[0].endswith('.service'))]
                else:
                    self.proof['relays'] = []
                effects = list(self.files.effects)
                with self.assertRaises(n.Refused):
                    self.run_supply('rematerialize')
                self.assertEqual(self.files.effects, effects)

    def test_explicit_completed_private_binding_review_after_parent_review_units(self):
        self.run_supply()
        self.proof.update(version=2, relays=copy.deepcopy(self.declaration['relays']))
        self.supply.evidence_digest = 'c' * 64
        effects = list(self.files.effects)
        with self.assertRaisesRegex(n.Refused, '^explicit-relay-evidence-review-required$'):
            self.run_supply()
        self.run_supply('resume')
        self.assertEqual(self.store.record['evidenceSha256'], 'c' * 64)
        self.assertEqual(self.files.effects, effects)


class ContractTests(unittest.TestCase):
    def test_root_socket_constant_and_proxy_runtime_user_not_configurable(self):
        declaration = definition()
        source = n.relay_sources(declaration['relays'][0])
        socket = next(v for k, v in source.items() if k.endswith('.socket'))
        service = next(v for k, v in source.items() if k.endswith('.service'))
        self.assertIn(b'SocketUser=0\nSocketGroup=0\nSocketMode=0600\n', socket)
        self.assertIn(b'User=p0-runtime\nGroup=p0-runtime\n', service)
        self.assertNotIn(b'CAP_DAC_OVERRIDE', service + socket)
        for mutation in ({'user': 'root'}, {'address': 'localhost'}, {'port': True}, {'socketMode': '0660'},
                         {'command': '/bin/sh'}, {'path': '/tmp/socket'}, {'resources': {'capabilities': ['all']}}):
            value = copy.deepcopy(declaration)
            value['relays'][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(n.Refused):
                n.intent(n.encoded(value))
        value = copy.deepcopy(declaration)
        value['relays'][0]['socketSha256'] = 'd' * 64
        with self.assertRaisesRegex(n.Refused, '^intent-source-hash$'):
            n.intent(n.encoded(value))

    def test_standalone_no_application_import_activation_delete_or_alias_interface(self):
        text = (ROOT / 'ops/host-admin/provision-p0-v2-relays.py').read_text()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                self.assertTrue(all(v.name.split('.')[0] in sys.stdlib_module_names for v in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split('.')[0], sys.stdlib_module_names)
        for forbidden in ('importlib', 'sys.path', 'shell=True', 'os.unlink', 'os.rmdir', "'daemon-reload'", "'restart'", "'enable'", "'start'", "'/usr/bin/podman'"):
            self.assertNotIn(forbidden, text)

    def test_native_owned_unit_typed_properties_reject_active_alias_dropin_pid_job_trigger(self):
        name = 'p0-v2-search-http.service'
        props = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'ControlPID': '0', 'ControlGroup': '',
                 'Job': '', 'SourcePath': '', 'FragmentPath': str(n.RELAY_UNITS / name), 'DropInPaths': '',
                 'TriggeredBy': '', 'NeedDaemonReload': 'yes', 'MainPID': '0', 'User': 'p0-runtime', 'Group': 'p0-runtime'}
        native = types.SimpleNamespace(call=lambda *a: ''.join(k + '=' + v + '\n' for k, v in props.items()).encode())
        n.owned_unit(native, name)
        for key, value in (('ActiveState', 'active'), ('MainPID', '1'), ('ControlPID', '2'), ('ControlGroup', '/own'),
                           ('Job', '3/start'), ('SourcePath', '/etc/containers/systemd/foreign.container'),
                           ('FragmentPath', '/run/systemd/system/alias.service'), ('DropInPaths', '/extra'),
                           ('User', 'root'), ('TriggeredBy', 'p0-v2-foreign.socket')):
            old = props[key]
            props[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(n.Refused, '^owned-unit-not-stopped$'):
                n.owned_unit(native, name)
            props[key] = old

    def test_unknown_scoped_units_or_triggers_still_refuse_with_owned_rows(self):
        proof = {'units': {'rootless': [], 'rootful': []}}
        native = n.Native(types.SimpleNamespace(pw_uid=1234, pw_gid=1234))
        for unknown in ('p0-v2-unknown.service', 'p0-v2-unknown.socket', 'p0-v2-unknown.timer', 'p0-v2-unknown.path'):
            with patch.object(native, 'call', return_value=(unknown + ' loaded inactive dead\n').encode()):
                with self.subTest(unknown=unknown), self.assertRaises(n.Refused):
                    native.stopped_units(proof, owned=('p0-v2-search-http.service', 'p0-v2-search-http.socket'))

    def test_kernel_listener_is_checked_not_inferred_from_source(self):
        relay = definition()['relays'][0]
        path = n.RELAY_BASE / relay['id'] / 'http.sock'
        view = types.SimpleNamespace(st_dev=4, st_ino=5)
        table = b'Num RefCount Protocol Flags Type St Inode Path\n' + f'0: 2 0 10000 1 1 123 {path}\n'.encode()
        with patch.object(n.os, 'stat', return_value=view), patch.object(n.os.path, 'lexists', return_value=False), \
             patch.object(n, 'bounded_read', return_value=table):
            with self.assertRaisesRegex(n.Refused, '^relay-kernel-socket-remains$'):
                n.closed_relay_listener(relay, None)


class FilesystemTests(unittest.TestCase):
    """Real NEW user inodes; test-local Root mapping; fake rename ABI only."""
    def setUp(self):
        from contextlib import ExitStack
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix='.p0-relay-source06-', dir=Path.home()))
        self.root = Path(self.temp)
        self.run, self.units = self.root / 'run', self.root / 'units'
        self.run.mkdir(mode=0o755)
        self.units.mkdir(mode=0o755)
        self.stack = self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(n, 'RELAY_BASE', self.run / 'upstreams'))
        self.stack.enter_context(patch.object(n, 'RELAY_UNITS', self.units))
        self.stack.enter_context(patch.object(n, 'strict_directory'))
        real_stat, real_fstat = os.stat, os.fstat
        def mapped(s):
            values = {k: getattr(s, k) for k in dir(s) if k.startswith('st_')}
            values.update(st_uid=0, st_gid=0)
            return types.SimpleNamespace(**values)
        self.stack.enter_context(patch.object(n.os, 'stat', side_effect=lambda *a, **k: mapped(real_stat(*a, **k))))
        self.stack.enter_context(patch.object(n.os, 'fstat', side_effect=lambda *a, **k: mapped(real_fstat(*a, **k))))
        self.chown = self.stack.enter_context(patch.object(n.os, 'fchown'))
        self.stack.enter_context(patch.object(n.os, 'fstatvfs', return_value=types.SimpleNamespace(f_bavail=2**30, f_frsize=4096)))
        self.rename_calls = []
        def rename(source_fd, source, target_fd, target, flags):
            self.rename_calls.append((source_fd, source, target_fd, target, flags))
            self.assertEqual(source_fd, target_fd)
            self.assertEqual(flags, 1)
            try:
                real_stat(target, dir_fd=target_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.rename(source, target, src_dir_fd=source_fd, dst_dir_fd=target_fd)
                return 0
            return -1
        self.stack.enter_context(patch.object(n.ctypes, 'CDLL', return_value=types.SimpleNamespace(renameat2=rename)))
        self.declaration = definition()
        self.files = n.Files(self.declaration)
        self.addCleanup(self.files.close)
        self.nonce = 'a' * 32

    def prepare_publish(self, key):
        value = self.files.prepare(key, self.nonce)
        self.assertIsNone(self.files.probe(key, self.nonce))
        self.files.publish(key, self.nonce)
        self.assertEqual(self.files.probe(key, self.nonce), value)
        self.assertIsNone(self.files.probe(key, self.nonce, True))
        return value

    def test_real_new_inode_modes_ignore_umask_and_only_new_inodes_normalized(self):
        old = os.umask(0o077)
        try:
            for key in self.files.plan:
                self.prepare_publish(key)
        finally:
            os.umask(old)
        self.assertEqual(self.chown.call_count, 4)
        self.assertEqual(stat.S_IMODE(n.RELAY_BASE.stat().st_mode), 0o711)
        self.assertEqual(stat.S_IMODE((n.RELAY_BASE / 'search-http').stat().st_mode), 0o710)
        for item in self.files.plan.values():
            if item['bytes'] is not None:
                self.assertEqual(stat.S_IMODE(item['path'].stat().st_mode), 0o400)
                self.assertEqual(item['path'].read_bytes(), item['bytes'])
        self.assertEqual(len(self.rename_calls), 4)

    def test_exclusive_publication_refuses_existing_matching_target_without_overwrite(self):
        key = next(k for k in self.files.plan if k.endswith('.service'))
        self.files.prepare(key, self.nonce)
        target = self.files.plan[key]['path']
        target.write_bytes(b'EXACT-NEW-FOREIGN-FIXTURE')
        before = target.stat().st_ino
        with self.assertRaisesRegex(n.Refused, '^publication-indeterminate$'):
            self.files.publish(key, self.nonce)
        self.assertEqual(target.read_bytes(), b'EXACT-NEW-FOREIGN-FIXTURE')
        self.assertEqual(target.stat().st_ino, before)
        self.assertIsNotNone(self.files.probe(key, self.nonce, True))

    def test_source_symlink_hardlink_wrong_mode_and_changed_bytes_are_not_adopted(self):
        key = next(k for k in self.files.plan if k.endswith('.service'))
        target = self.files.plan[key]['path']
        target.symlink_to(self.units / 'absent-fixture')
        with self.assertRaisesRegex(n.Refused, '^target-custody$'):
            self.files.probe(key, self.nonce)
        target.unlink()  # Only this new test-created symlink, never production cleanup.
        target.write_bytes(self.files.plan[key]['bytes'])
        target.chmod(0o400)
        link = self.units / 'fixture-hardlink'
        os.link(target, link)
        with self.assertRaisesRegex(n.Refused, '^target-custody$'):
            self.files.probe(key, self.nonce)
        link.unlink()
        target.chmod(0o600)
        with self.assertRaisesRegex(n.Refused, '^target-custody$'):
            self.files.probe(key, self.nonce)
        target.write_bytes(b'wrong bytes')
        target.chmod(0o400)
        with self.assertRaisesRegex(n.Refused, '^target-source-changed$'):
            self.files.probe(key, self.nonce)

    def test_held_parent_inode_replacement_is_detected_before_create(self):
        key = next(k for k in self.files.plan if k.endswith('.service'))
        self.files.parent(key)
        self.units.rename(self.root / 'retained-original-units-fixture')
        self.units.mkdir(mode=0o755)
        with self.assertRaisesRegex(n.Refused, '^target-parent-changed$'):
            self.files.prepare(key, self.nonce)
        self.assertFalse(list(self.units.iterdir()))

    def test_unknown_staged_publication_and_nonempty_prepared_directory_refuse(self):
        (self.run / '.p0-relay-unowned-evidence').write_bytes(b'new fixture retained')
        rows = {k: {'state': 'planned', 'inode': None} for k in self.files.plan}
        with self.assertRaisesRegex(n.Refused, '^unknown-publication-entry$'):
            self.files.inventory(rows, self.nonce)
        value = self.files.prepare('base', self.nonce)
        path = self.run / self.files.temp('base', self.nonce)
        (path / 'unexpected').write_bytes(b'new fixture only')
        with self.assertRaisesRegex(n.Refused, '^prepared-directory-not-empty$'):
            self.files.probe('base', self.nonce, True)
        self.assertIsNotNone(value)

    def test_real_files_and_canonical_json_record_resume_after_exact_publication(self):
        store = n.Marker(self.root / 'private-resume')
        store.open(True)
        self.addCleanup(store.close)
        authority = types.SimpleNamespace(check=lambda: None, record={
            'namespace': {'device': 1, 'inode': 2, 'filesystemId': 3}, 'owner': 'a' * 32,
            'bootId': '12345678-1234-1234-1234-123456789abc'})
        native = types.SimpleNamespace(entry=None, stopped_units=lambda *a, **k: None)
        proof = {'units': {'rootless': [], 'rootful': []}}
        for name in ('reserves', 'closed_relay_listener', 'no_native_dropins', 'owned_unit'):
            self.stack.enter_context(patch.object(n, name))
        supply = n.Supply(store, self.files, authority, native, proof, 'b' * 64)
        original = self.files.publish
        def crash(key, nonce):
            original(key, nonce)
            raise RuntimeError('NEW_FIXTURE_AFTER_RENAME')
        with patch.object(self.files, 'publish', side_effect=crash):
            with self.assertRaises(RuntimeError):
                supply.run(self.declaration, n.sha(n.encoded(self.declaration)), 'apply')
        retained = store.load()
        self.assertEqual(retained['objects']['base']['state'], 'publish-claimed')
        result = supply.run(self.declaration, n.sha(n.encoded(self.declaration)), 'resume')
        self.assertEqual(result['state'], 'needs-review-units')
        self.assertEqual(len(self.rename_calls), 4)
        self.assertTrue(all(row['state'] == 'published' for row in store.load()['objects'].values()))

    def test_real_private_marker_cas_and_interrupted_publish_evidence(self):
        base = self.root / 'private'
        marker = n.Marker(base)
        marker.open(True)
        self.addCleanup(marker.close)
        record = {'fixture': 'one'}
        marker.save(record)
        current = base / 'active.json'
        raw = current.read_bytes()
        current.unlink()  # Exact new private TEST fixture only.
        current.write_bytes(raw)
        current.chmod(0o400)
        with self.assertRaisesRegex(n.Refused, '^marker-cas$'):
            marker.save(record)
        marker.close()
        (base / '.publish-retained-fixture').write_bytes(b'new failed publication fixture')
        with self.assertRaisesRegex(n.Refused, '^unknown-marker-entry$'):
            marker.open(True)

    def test_alternate_fragments_and_all_native_dropin_shapes_refuse(self):
        name = 'p0-v2-search-http.service'
        alternate = self.root / 'alternate'
        alternate.mkdir()
        (alternate / name).write_bytes(b'new fixture only')
        with patch.object(n, 'NATIVE_UNIT_ROOTS', (alternate,)):
            with self.assertRaisesRegex(n.Refused, '^native-alternate-fragment$'):
                n.no_native_dropins(name)
        for shape in ('service.d', name + '.d', 'p0-.service.d', 'p0-v2-.service.d', 'p0-v2-search-.service.d'):
            path = self.units / shape
            path.mkdir()
            with patch.object(n, 'NATIVE_UNIT_ROOTS', (self.units,)):
                with self.subTest(shape=shape), self.assertRaisesRegex(n.Refused, '^native-source-dropins$'):
                    n.no_native_dropins(name)
            path.rmdir()


if __name__ == '__main__':
    unittest.main()
