#!/usr/bin/env python3
"""Real temp FD/rename/cursor tests, modeled NSS/mount/UID/offline facts only.
No host activation, Root service imports, deletion of data or installed proof.
"""
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]
import importlib.util

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module

f = load('disposition_fixture', BASE / 'scripts/test-native-rootful-env-owner.py')
d = load('disposition_subject', BASE / 'runtime-generator/podman-ops/native-unselected-disposition.py')
m, p = f.m, f.p
# Share owning implementations so the fixture-only UID/mount/NSS mocks apply.
d.m.o, d.m.p, d.m.native, d.m.storage, d.m.v = m.o, p, m.native, m.storage, m.v
d.o, d.p, d.native, d.storage = m.o, p, m.native, m.storage
d.r = f.r

class Disposition(f.Rootful):
    def setUp(self):
        super().setUp()
        patch.object(d, 'reserves', return_value=None).start()
        patch.object(d.m, 'HOST', self.host).start()
        patch.object(d.m, 'stopped', m.stopped).start()
        patch.object(m.v, 'FAILED_ROOT', self.install).start()
        patch.object(m.v, 'FAILED_SCOPE', self.scope).start()
        self.quarantines = []
        patch.object(d.o.journal, 'verify_quarantined', side_effect=lambda *a, **kw: self.quarantines.append(a)).start()
        # Original installed targets are fixture conveniences, not newly
        # published custody. Remove them before the cold publication.
        for entry in m.native.inventory(self.release).values():
            for rel in entry['files']: self.dest(rel).unlink(missing_ok=True)
        self.environment = self.copy_env()
        self.prior = dict(self.intent, rootfulEnvironmentStoreHandoff=self.environment)
        self.write_records(self.prior)
        self.prepare_files(); self.publish_files(); self.units = self.apply_files()
        self.failed = dict(self.new_intent, nativeUnitFiles=self.units, phase='failed', steps=['preparing', 'failed'])
        self.write_records(self.failed)
        self.expected = p.sha((self.install / '.install-intent.json').read_bytes())
        self.before = (self.install / '.install-intent.json').read_bytes()
        self.data = self.scope / 'synthetic-sentinel'; self.put(self.data, b'data-must-survive')

    def session(self):
        return d.Disposition(self.install, self.release, self.failed, self.expected)

    def test_complete_removes_only_exact_published_files_retains_data_and_original_failure(self):
        result = d.dispose(self.install, self.release, self.failed, self.expected)
        self.assertEqual(result['unitFiles'], len(self.units['files']))
        self.assertEqual(result['rootEnvironmentFiles'], 2)
        self.assertFalse(result['activationAuthorized']); self.assertTrue(result['dataPreserved'])
        self.assertEqual((self.install / '.install-intent.json').read_bytes(), self.before)
        self.assertEqual((self.release / 'installation-receipt.json').read_bytes(), self.before)
        self.assertEqual((self.release / 'never-selected-original-failure.json').read_bytes(), self.before)
        self.assertEqual(self.data.read_bytes(), b'data-must-survive')
        self.assertTrue(self.quarantines)
        self.assertTrue(all(not Path(name).exists() for name in self.units['files']))
        self.assertEqual(list(self.store.iterdir()), [])
        self.assertEqual(d.completed_report(self.install, self.release, self.failed, self.expected), result)
        cursor = self.release / d.PROGRESS
        bad = p.strict(cursor.read_bytes()); bad['removed'] = []; cursor.write_bytes(p.encoded(bad))
        with self.assertRaises(ValueError): d.completed_report(self.install, self.release, self.failed, self.expected)

    def test_existing_adopted_file_custody_refuses_before_deletion(self):
        changed = copy.deepcopy(self.failed)
        next(iter(changed['nativeUnitFileCustody']['files'].values()))['before'] = {'foreign': True}
        with self.assertRaises(ValueError): d.publication(changed)
        self.assertTrue(self.path.exists())

    def test_admission_phases_and_runtime_adjuncts_refuse(self):
        for key, value in [('phase', 'active'), ('steps', ['preparing', 'units-selected', 'failed']),
                ('previousRelease', str(self.release)), ('nativeRuntimeEnvUnitCustody', {})]:
            changed = dict(self.failed, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError): d.publication(changed)

    def test_file_hash_or_inode_change_refuses_entire_sweep_before_first_unlink(self):
        self.path.write_bytes(self.path.read_bytes() + b'# drift')
        with self.assertRaises(ValueError): self.session()
        self.assertTrue(all(Path(name).exists() for name in self.units['files']))
        self.assertFalse((self.release / 'native-unselected-disposition.json').exists())

    def test_root_environment_replacement_with_identical_bytes_refuses(self):
        path = self.store / 'edge.env'; body = path.read_bytes()
        held = os.open(path, os.O_RDONLY)
        try:
            path.unlink(); self.put(path, body); path.chmod(0o600)
            with self.assertRaises(ValueError): self.session()
        finally: os.close(held)
        self.assertTrue(self.path.exists())

    def test_unrecorded_absence_refuses(self):
        self.path.unlink()
        with self.assertRaises(ValueError): self.session()
        self.assertTrue((self.store / 'edge.env').exists())

    def test_foreign_store_leaf_refuses_without_deletion(self):
        self.put(self.store / 'foreign.env', b'not-owned'); (self.store / 'foreign.env').chmod(0o600)
        with self.assertRaises(ValueError): self.session()
        self.assertTrue(self.path.exists()); self.assertTrue((self.store / 'foreign.env').exists())

    def test_offline_refusal_preserves_every_published_inode(self):
        with patch.object(d.o.journal, 'verify_quarantined', side_effect=ValueError('fixture active trigger')):
            with self.assertRaises(ValueError): self.session()
        self.assertTrue(all(Path(name).exists() for name in self.units['files']))

    def test_interruption_after_rename_recovers_exact_pending_stage(self):
        session = self.session(); real_unlink = os.unlink
        def interrupt(name, *args, **kwargs):
            if str(name).startswith('.unselected-'): raise OSError('fixture interruption before unlink')
            return real_unlink(name, *args, **kwargs)
        try:
            with patch.object(os, 'unlink', side_effect=interrupt), self.assertRaises(OSError): session.run()
        finally: session.close()
        result = d.dispose(self.install, self.release, self.failed, self.expected)
        self.assertEqual(result['status'], 'completed'); self.assertTrue(self.data.exists())

    def test_running_unpublished_timer_refuses_before_deletion(self):
        self.status['webservices-auto-update.timer'] = {'ActiveState': 'active'}
        with self.assertRaises(ValueError): self.session()
        self.assertTrue(self.path.exists())

    def test_actor_selection_pointer_is_not_never_selected(self):
        row = next(row for row in self.rows if row['name'] == 'apps')
        current = Path(row['stateRoot']) / 'current'
        current.symlink_to(Path(row['stateRoot']) / 'releases' / self.release.name)
        with self.assertRaises(ValueError): self.session()
        self.assertTrue(self.path.exists())

    def test_changed_cursor_or_source_after_review_refuses(self):
        session = self.session()
        try:
            aggregate = self.release / 'runtime/stack.env'
            aggregate.write_bytes(aggregate.read_bytes() + b'\n# changed\n')
            with self.assertRaises(ValueError): session.run()
        finally: session.close()
        self.assertTrue(self.path.exists())

    def test_reserve_refusal_precedes_any_disposition_write(self):
        with patch.object(d, 'reserves', side_effect=ValueError('fixture reserve')):
            with self.assertRaises(ValueError): self.session()
        self.assertFalse((self.release / d.ORIGINAL).exists())
        self.assertTrue(self.path.exists())

    def test_completed_reentry_is_idempotent_and_does_not_adopt_reappearing_file(self):
        d.dispose(self.install, self.release, self.failed, self.expected)
        self.assertEqual(d.dispose(self.install, self.release, self.failed, self.expected)['status'], 'completed')
        self.put(self.path, b'reappeared'); self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.session()
        self.assertEqual(self.path.read_bytes(), b'reappeared')

if __name__ == '__main__':
    # Do not accidentally rerun every inherited fixture test in this batch.
    names = [name for name in Disposition.__dict__ if name.startswith('test_')]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Disposition(name) for name in names))
    raise SystemExit(0 if result.wasSuccessful() else 1)
