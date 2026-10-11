#!/usr/bin/env python3
"""Run as root: journal permissions, ordered phases, CAS and unchanged inputs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-journal.py'
spec = importlib.util.spec_from_file_location('install_journal', source)
journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)

class InstallationJournal(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / 'state'; self.root.mkdir()
        self.bundle = base / 'bundle'; self.bundle.mkdir()
        for name in ('bundle.json', 'stack.ir.json', 'source-provenance.json'):
            (self.bundle / name).write_text('{}')
        self.release = self.root / 'releases/20261012T010000Z-111111111111'
        self.path = self.root / '.install-intent.json'

    def test_ordered_phases_and_private_receipt(self):
        for phase in journal.PHASES[:-1]:
            journal.update(self.root, self.bundle, self.release, phase)
        self.assertEqual(journal.read(self.path)['phase'], 'active')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.read(self.release / 'installation-receipt.json'), journal.read(self.path))
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.release, 'failed')

    def test_pending_cas_and_unchanged_inputs(self):
        journal.update(self.root, self.bundle, self.release, 'preparing')
        original = self.path.read_bytes()
        next_release = self.root / 'releases/20261012T020000Z-111111111111'
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, next_release, 'preparing')
        self.assertEqual(self.path.read_bytes(), original)
        expected = journal.digest(self.path)
        (self.bundle / 'bundle.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, next_release, 'preparing', expected)
        self.assertEqual(self.path.read_bytes(), original)
        (self.bundle / 'bundle.json').write_text('{}')
        value = journal.update(self.root, self.bundle, next_release, 'preparing', expected)
        self.assertEqual(value['resumedFrom'], str(self.release))
        self.assertEqual(journal.read(self.release / 'installation-receipt.json')['phase'], 'preparing')

    def test_phase_mismatch_failed_attempt_and_retry(self):
        journal.update(self.root, self.bundle, self.release, 'preparing')
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.release, 'starting')
        journal.update(self.root, self.bundle, self.release, 'failed')
        next_release = self.root / 'releases/20261012T020000Z-111111111111'
        journal.update(self.root, self.bundle, next_release, 'preparing', journal.digest(self.path))
        self.assertEqual(journal.read(self.release / 'installation-receipt.json')['phase'], 'failed')

    def test_links_permissions_and_escaped_receipts_refused(self):
        journal.update(self.root, self.bundle, self.release, 'preparing')
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): journal.read(self.path)
        self.path.chmod(0o600)
        self.path.unlink(); self.path.symlink_to(self.release / 'installation-receipt.json')
        with self.assertRaises(ValueError): journal.read(self.path)
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.root / 'escaped', 'preparing')

if __name__ == '__main__': unittest.main()
