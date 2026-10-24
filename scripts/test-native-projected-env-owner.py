#!/usr/bin/env python3
"""Temp-root real-FD tests; synthetic UID/ACL/lease/system observations only.

No root operations, subprocess/service calls, live records, environment access,
packages or native installation. Every mutation stays in a 077-umask fixture.
"""
import errno
import importlib.util
import os
import shutil
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


e = load('environment_owner_tested', BASE / 'runtime-generator/podman-ops/native-projected-env-owner.py')
f = load('environment_fixture', BASE / 'scripts/test-native-runtime-projection-owner.py')
# Reuse the source-owning fixture's synthetic account/FD model, not an adapter
# callback in the production API. The actual projector and owner run together.
f.o, f.p = e.owner, e.p
p, o = e.p, e.owner


class Environment(f.Owner):
    def setUp(self):
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        super().setUp()
        if self._testMethodName.startswith('test_root_public_volume_'):
            node = self.scope / 'volumes'
            node.chmod(0o755); self.set_owner(node, 0, 1000)
            self.acls[self.key(node)] = (
                f.acl([(2, 7, 1000), *[(2, 1, row['uid']) for row in self.rows]],
                      group=7, mask=5, other=5),
                f.acl([(2, 7, 1000)], group=7, mask=7))
        self.empty = self._testMethodName == 'test_empty_domain_no_aggregate_or_store'
        if self.empty:
            self.row['services'] = []
            self.ir['services'] = {name: service for name, service in self.ir['services'].items()
                                   if service.get('rootlessDomain') != self.domain}
            self.reseal()
        if self._testMethodName != 'test_real_journal_records_copy_after_projection_seal':
            self.prepare(); self.publish()
            if self.empty:
                original = p.read_at
                def read_no_aggregate(fd, name, *args, **kwargs):
                    self.assertNotIn(name, ('stack.env', 'runtime/stack.env'))
                    return original(fd, name, *args, **kwargs)
                patch.object(p, 'read_at', side_effect=read_no_aggregate).start()
            self.proof = self.run_owner()
            self.intent = dict(self.new, domainRuntimeProjections={self.domain: self.proof})
            self.write_records(self.intent)
        self.store = self.state / 'runtime-env'
        self.source_env = self.destination / 'service-env'
        # All ownership changes remain virtual. Production fchown is NEVER
        # invoked, even if this test is accidentally run by a privileged user.
        def chown(fd, uid, gid):
            path = self.fd_paths.get(fd)
            self.assertIsNotNone(path)
            self.assertTrue(path == self.store or path.is_relative_to(self.store)
                            or path == self.slot or path.is_relative_to(self.destination))
            info = self.raw_fstat(fd)
            self.virtual[info.st_dev, info.st_ino] = uid, gid
            self.mutations.append((path, uid, gid))
        patch.object(os, 'fchown', side_effect=chown).start()

    def run_copy(self):
        return e.copy_environment(self.install, self.release, self.intent, self.domain)

    def private_store(self):
        self.mkdir(self.store)
        self.set_owner(self.store, self.row['uid'], self.accounts[self.row['user']].pw_gid)

    def operation(self):
        value = e.Copy(self.install, self.release, self.intent, self.domain)
        self.addCleanup(value.close)
        return value

    def record_copy(self, proof):
        projections = dict(self.intent['domainRuntimeProjections'])
        projections[self.domain] = dict(projections[self.domain], environmentStoreHandoff=proof)
        self.intent = dict(self.intent, domainRuntimeProjections=projections)
        self.write_records(self.intent)

    def test_real_journal_records_copy_after_projection_seal(self):
        # Only dynamic loading is redirected to the already UID/lease-modelled
        # real modules. The journal, projector, owner, copy and record writes
        # execute their actual source, confined to this temporary root.
        original = importlib.util.spec_from_file_location
        class ExistingLoader:
            def __init__(self, module):
                self.module = module
            def create_module(self, spec):
                return self.module
            def exec_module(self, module):
                pass
        def spec(name, path, *args, **kwargs):
            module = {'native-runtime-projection-owner.py': o,
                      'native-projected-env-owner.py': e}.get(Path(path).name)
            if module is not None:
                return importlib.util.spec_from_loader(name, ExistingLoader(module))
            return original(name, path, *args, **kwargs)
        with patch.object(importlib.util, 'spec_from_file_location', side_effect=spec):
            result = o.journal.project_domain(self.install, self.release, self.domain)
        receipt = p.strict((self.release / 'installation-receipt.json').read_bytes())
        intent = p.strict((self.install / '.install-intent.json').read_bytes())
        self.assertEqual(receipt, intent)
        self.assertEqual(intent['domainRuntimeProjections'][self.domain], result)
        self.assertEqual(result['environmentStoreHandoff']['status'], 'completed')
        self.assertEqual(set(result['environmentStoreHandoff']['files']), {'runner80.env', 'test-runner.env'})
        self.assertTrue(result['environmentStoreHandoff']['runtimeDeferred'])
        self.assertFalse(result['activationAuthorized'])

    def test_fresh_absent_store_exact_files_and_metadata_only_proof(self):
        before = (self.install / '.install-intent.json').read_bytes()
        result = self.run_copy()
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['runtimeDeferred'])
        self.assertFalse(result['activationAuthorized'])
        self.assertFalse(result['readinessAuthorized'])
        self.assertEqual(set(result['files']), {'runner80.env', 'test-runner.env'})
        self.assertEqual(set(self.store.iterdir()), {self.store / name for name in result['files']})
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o700)
        for name, record in result['files'].items():
            info = (self.store / name).stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                             (self.row['uid'], self.accounts[self.row['user']].pw_gid, 0o600, 1))
            self.assertEqual(record['sha256'], self.proof['environmentHandoff']['files'][name]['sha256'])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertNotIn('selected-token', p.encoded(result).decode())
        self.assertFalse(any(path.parts[:3] == ('/', 'run', 'user') for path, *_ in self.mutations))

    def test_fresh_existing_empty_private_store(self):
        self.private_store()
        inode = self.store.stat().st_ino
        self.assertEqual(self.run_copy()['status'], 'completed')
        self.assertEqual(self.store.stat().st_ino, inode)

    def test_unselected_siblings_preserved_without_open(self):
        self.private_store()
        other = self.store / 'unselected.env'
        self.put(other, b'synthetic-unselected\n')
        before = p.identity(other.stat())
        self.assertEqual(self.run_copy()['status'], 'completed')
        self.assertEqual(p.identity(other.stat()), before)

    def test_olddev16_unproven_selected_file_refused_and_untouched(self):
        self.private_store()
        selected = self.store / 'runner80.env'
        self.put(selected, b'synthetic-legacy\n')
        before = p.identity(selected.stat())
        with self.assertRaisesRegex(e.Refused, 'complete-clean-reset dependency'):
            self.run_copy()
        self.assertEqual(p.identity(selected.stat()), before)
        self.assertEqual(set(os.listdir(self.store)), {'runner80.env'})

    def test_current_canonical_copy_exact_inode_cas_replacement(self):
        first = self.run_copy()
        self.record_copy(first)
        result = self.run_copy()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(set(first['files']), set(result['files']))
        for name in first['files']:
            self.assertNotEqual(first['files'][name]['identity'][1], result['files'][name]['identity'][1])
            self.assertEqual(first['files'][name]['sha256'], result['files'][name]['sha256'])
        self.assertFalse(any(name.startswith('.projected-env-') for name in os.listdir(self.store)))

    def test_existing_copy_inode_aba_refused(self):
        first = self.run_copy(); self.record_copy(first)
        selected = self.store / 'runner80.env'
        body = selected.read_bytes(); selected.rename(self.store / 'retained-old')
        self.put(selected, body); self.set_owner(selected, self.row['uid'], self.accounts[self.row['user']].pw_gid)
        with self.assertRaisesRegex(e.Refused, 'CAS changed'):
            self.run_copy()
        self.assertTrue((self.store / 'retained-old').exists())

    def prepare_next_release(self):
        first = self.run_copy(); self.record_copy(first)
        self.intent = dict(self.intent, phase='active')
        self.write_records(self.intent)
        old_release, old_slot = self.release, self.slot
        new_release = self.install / 'releases/next'
        shutil.copytree(old_release, new_release)
        new_slot = self.state / 'releases/next'
        self.mkdir(new_slot)
        shutil.copytree(old_slot / 'build', new_slot / 'build')
        (self.install / 'current').symlink_to(old_release)
        (self.state / 'current').symlink_to(old_slot)
        self.release, self.slot = new_release, new_slot
        self.destination = new_slot / 'runtime'; self.source_env = self.destination / 'service-env'
        self.prior = dict(schemaVersion=1, phase='preparing', release=str(new_release),
            previousRelease=str(old_release), steps=['preparing'], inputs=self.intent['inputs'])
        self.write_records(self.prior)
        def chown(fd, uid, gid):
            path = self.fd_paths.get(fd)
            self.assertIsNotNone(path)
            self.assertTrue(path == self.slot or path.is_relative_to(self.destination)
                            or path == self.store or path.is_relative_to(self.store))
            info = self.raw_fstat(fd)
            self.virtual[info.st_dev, info.st_ino] = uid, gid
        with patch.object(os, 'fchown', side_effect=chown):
            self.prepare(); self.publish(); self.proof = self.run_owner()
        self.intent = dict(self.new, domainRuntimeProjections={self.domain: self.proof})
        self.write_records(self.intent)
        return old_release, first

    def test_previous_canonical_active_receipt_cas_replacement(self):
        old_release, first = self.prepare_next_release()
        result = self.run_copy()
        self.assertEqual(result['status'], 'completed')
        for name in first['files']:
            self.assertEqual(first['files'][name]['sha256'], result['files'][name]['sha256'])
            self.assertNotEqual(first['files'][name]['identity'][1], result['files'][name]['identity'][1])
        self.assertEqual(p.strict((old_release / 'installation-receipt.json').read_bytes())['phase'], 'active')

    def test_previous_receipt_cas_rechecked_after_staging(self):
        old_release, _ = self.prepare_next_release()
        real_write = os.write
        fired = False
        def write(fd, body):
            nonlocal fired
            count = real_write(fd, body)
            if not fired:
                fired = True
                self.put(old_release / 'installation-receipt.json', b'{}\n')
            return count
        with patch.object(os, 'write', side_effect=write):
            with self.assertRaisesRegex(e.Refused, 'previous canonical receipt/input CAS'):
                self.run_copy()
        self.assertTrue(any(name.startswith('.projected-env-') for name in os.listdir(self.store)))

    def test_source_symlink_refused(self):
        path = self.source_env / 'runner80.env'
        path.rename(self.source_env / 'original')
        path.symlink_to('original')
        with self.assertRaises((e.Refused, OSError)):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_hardlink_refused(self):
        os.link(self.source_env / 'runner80.env', self.base / 'hardlink')
        with self.assertRaisesRegex(e.Refused, 'nlink'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_byte_hash_refused(self):
        (self.source_env / 'runner80.env').write_bytes(b'changed-synthetic\n')
        with self.assertRaisesRegex(e.Refused, 'source SHA'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_projection_metadata_hash_refused(self):
        (self.destination / 'projection.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(e.Refused, 'source SHA'):
            self.run_copy()

    def test_source_private_acl_refused(self):
        path = self.source_env / 'runner80.env'
        self.acls[self.key(path)] = f.acl([(2, 4, 1000)], group=0, mask=4), b''
        with self.assertRaisesRegex(e.Refused, 'file ACL'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_default_acl_refused(self):
        self.acls[self.key(self.source_env)] = b'', f.acl([(2, 7, 1000), (8, 7, 1000)])
        with self.assertRaisesRegex(e.Refused, 'unsafeInheritedDefaultACL'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_projection_hash_required(self):
        self.proof.pop('projectionSha256')
        self.write_records(self.intent)
        with self.assertRaisesRegex(e.Refused, 'projection binding'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_private_mode_required(self):
        (self.source_env / 'runner80.env').chmod(0o640)
        with self.assertRaisesRegex(e.Refused, 'mode/nlink'):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_source_uid_refused(self):
        self.set_owner(self.source_env / 'runner80.env', 999, 999)
        with self.assertRaisesRegex(e.Refused, 'UID'):
            self.run_copy()

    def test_source_sha_seal_forgery_refused(self):
        self.intent['domainRuntimeProjections'][self.domain]['files']['service-env/runner80.env'] = '0' * 64
        self.write_records(self.intent)
        with self.assertRaises(e.Refused):
            self.run_copy()

    def test_parent_escape_handoff_refused(self):
        self.proof['environmentHandoff']['stateStore'] = str(self.state / '../other')
        self.write_records(self.intent)
        with self.assertRaisesRegex(e.Refused, 'handoff differs'):
            self.run_copy()

    def test_runtime_store_cannot_be_redirected_or_created(self):
        self.proof['environmentHandoff']['runtimeStore'] = str(self.base / 'fake-runtime')
        self.write_records(self.intent)
        with self.assertRaisesRegex(e.Refused, 'handoff differs'):
            self.run_copy()
        self.assertFalse((self.base / 'fake-runtime').exists())
        self.assertFalse(self.store.exists())

    def test_root_receipt_intent_mismatch_refused(self):
        self.put(self.release / 'installation-receipt.json', p.encoded(dict(self.intent, phase='active')))
        with self.assertRaisesRegex(e.Refused, 'receipt/intent CAS'):
            self.run_copy()

    def test_root_receipt_inode_aba_after_open_refused(self):
        operation = self.operation()
        path = self.release / 'installation-receipt.json'
        body = path.read_bytes(); path.rename(self.release / 'retained-receipt')
        self.put(path, body)
        with self.assertRaisesRegex(e.Refused, 'inode ABA'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_public_source_core_hash_refused(self):
        self.put(self.release / 'bundle.json', b'{"changed":true}\n')
        with self.assertRaisesRegex(e.Refused, 'source input hash'):
            self.run_copy()

    def test_source_inode_aba_after_open_refused(self):
        operation = self.operation()
        path = self.source_env / 'runner80.env'
        body = path.read_bytes(); path.rename(self.source_env / 'retained-source')
        self.put(path, body); self.set_owner(path, self.row['uid'], self.accounts[self.row['user']].pw_gid)
        with self.assertRaises(e.Refused):
            operation.copy()

    def test_mount_identity_change_after_open_refused(self):
        operation = self.operation()
        p.mount_id.return_value = 92
        with self.assertRaises(e.Refused):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_mount_crossing_open_refused(self):
        real_child = p.child_open.side_effect
        def child(fd, name, flags):
            if name == 'runner80.env':
                raise OSError(errno.EXDEV, 'synthetic mount boundary')
            return real_child(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=child):
            with self.assertRaises(OSError):
                self.run_copy()
        self.assertFalse(self.store.exists())

    def test_store_symlink_refused(self):
        self.store.symlink_to(self.source_env)
        with self.assertRaises(OSError):
            self.run_copy()
        self.assertTrue(self.store.is_symlink())

    def test_store_default_acl_refused_unchanged(self):
        self.private_store()
        body = f.acl([(2, 7, 1000), (8, 7, 1000)], other=0)
        self.acls[self.key(self.store)] = b'', body
        with self.assertRaisesRegex(e.Refused, 'unsafeInheritedDefaultACL'):
            self.run_copy()
        self.assertEqual(self.acls[self.key(self.store)], (b'', body))
        self.assertEqual(os.listdir(self.store), [])

    def test_root_public_volume_parent_mask_and_defaults_preserved(self):
        node = self.scope / 'volumes'
        acl = self.acls[self.key(node)]
        info = p.identity(node.stat())
        self.assertEqual(self.run_copy()['status'], 'completed')
        self.assertEqual(self.acls[self.key(node)], acl)
        self.assertEqual(p.identity(node.stat()), info)
        self.assertNotIn(node, [path for path, *_ in self.mutations])

    def test_root_public_volume_foreign_default_writer_refused(self):
        node = self.scope / 'volumes'
        self.acls[self.key(node)] = self.acls[self.key(node)][0], f.acl([(2, 7, 1001)])
        with self.assertRaises(e.Refused):
            self.run_copy()
        self.assertFalse(self.store.exists())

    def test_existing_known_destination_hardlink_refused(self):
        first = self.run_copy(); self.record_copy(first)
        os.link(self.store / 'runner80.env', self.base / 'retained-hardlink')
        with self.assertRaisesRegex(e.Refused, 'CAS changed'):
            self.run_copy()
        self.assertEqual((self.store / 'runner80.env').stat().st_nlink, 2)

    def test_store_uid_refused(self):
        self.private_store(); self.set_owner(self.store, 999, 999)
        with self.assertRaises(e.Refused):
            self.run_copy()

    def test_stopped_actor_gate_rechecked_no_mutation(self):
        operation = self.operation()
        o.inactive.side_effect = e.Refused('synthetic actor process/manager is active')
        with self.assertRaisesRegex(e.Refused, 'actor process/manager'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_marker_byte_race_refused(self):
        operation = self.operation()
        self.put(self.scope / '.stack-installation.json', b'{}\n')
        with self.assertRaisesRegex(e.Refused, 'marker changed'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_actor_account_drift_refused(self):
        operation = self.operation()
        self.accounts[self.row['user']].pw_gid += 1
        with self.assertRaisesRegex(e.Refused, 'account/group authority'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_namespace_range_drift_refused(self):
        operation = self.operation()
        o.storage.namespace_root_id.side_effect = lambda user: 4000000
        with self.assertRaisesRegex(e.Refused, 'namespace-root authority'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_lock_gate_rechecked(self):
        operation = self.operation()
        o.lock_held.side_effect = e.Refused('synthetic canonical FD9 lease changed')
        with self.assertRaisesRegex(e.Refused, 'FD9'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_current_pointer_race_refused(self):
        operation = self.operation()
        (self.state / 'current').symlink_to('releases/unrelated')
        with self.assertRaisesRegex(e.Refused, 'current pointer changed'):
            operation.copy()
        self.assertFalse(self.store.exists())

    def test_rename_failure_retains_private_stage_and_journal(self):
        before = (self.install / '.install-intent.json').read_bytes()
        with patch.object(e, 'rename', side_effect=OSError(errno.EEXIST, 'synthetic CAS failure')):
            with self.assertRaises(OSError):
                self.run_copy()
        names = os.listdir(self.store)
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].startswith('.projected-env-'))
        self.assertEqual(stat.S_IMODE((self.store / names[0]).stat().st_mode), 0o600)
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())

    def test_fresh_name_cas_race_does_not_replace_foreign(self):
        real_rename = e.rename
        def race(parent, source, destination, exchange=False):
            self.put(self.store / destination, b'synthetic-raced-file\n')
            return real_rename(parent, source, destination, exchange)
        with patch.object(e, 'rename', side_effect=race):
            with self.assertRaises(FileExistsError):
                self.run_copy()
        self.assertEqual((self.store / 'runner80.env').read_bytes(), b'synthetic-raced-file\n')
        self.assertTrue(any(name.startswith('.projected-env-') for name in os.listdir(self.store)))

    def test_exchange_race_restores_foreign_without_read_or_delete(self):
        first = self.run_copy(); self.record_copy(first)
        real_rename = e.rename
        fired = False
        def race(parent, source, destination, exchange=False):
            nonlocal fired
            if exchange and not fired:
                fired = True
                (self.store / destination).rename(self.store / 'retained-original')
                self.put(self.store / destination, b'synthetic-raced-foreign\n')
            return real_rename(parent, source, destination, exchange)
        with patch.object(e, 'rename', side_effect=race):
            with self.assertRaisesRegex(e.Refused, 'original name restored'):
                self.run_copy()
        self.assertEqual((self.store / 'runner80.env').read_bytes(), b'synthetic-raced-foreign\n')
        self.assertTrue((self.store / 'retained-original').exists())
        self.assertTrue(any(name.startswith('.projected-env-') for name in os.listdir(self.store)))

    def test_empty_domain_no_aggregate_or_store(self):
        result = self.run_copy()
        self.assertEqual(result['files'], {})
        self.assertEqual(result['sourceFiles'], {})
        self.assertIsNone(result['store'])
        self.assertFalse(self.store.exists())
        self.assertTrue(result['runtimeDeferred'])


class External(Environment):
    external = True

    def test_exact_operator_named_rwx_and_defaults_above_scope_unchanged(self):
        before = dict(self.acls)
        self.assertEqual(self.run_copy()['status'], 'completed')
        self.assertEqual(self.acls, before)


def load_tests(loader, tests, pattern):
    # The reused fixture has its own suite; run ONLY this file's tests here.
    suite = unittest.TestSuite()
    for cls in (Environment, External):
        for name in cls.__dict__:
            if name.startswith('test_'):
                suite.addTest(cls(name))
    return suite


if __name__ == '__main__':
    unittest.main()
