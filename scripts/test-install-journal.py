#!/usr/bin/env python3
"""Run as root: journal permissions, ordered phases, CAS and unchanged inputs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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
        for phase in journal.PHASES[:5]:
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

    def test_failed_retirement_requires_cas_review_and_native_quarantine(self):
        journal.update(self.root,self.bundle,self.release,'preparing')
        with self.assertRaises(ValueError):journal.retire_failed(self.root,journal.digest(self.path),True,lambda p:None)
        journal.update(self.root,self.bundle,self.release,'failed')
        for name in journal.fingerprint(self.bundle):(self.release/name).write_bytes((self.bundle/name).read_bytes())
        expected=journal.digest(self.path);original=self.path.read_bytes()
        with self.assertRaises(ValueError):journal.retire_failed(self.root,expected,False,lambda p:None)
        with self.assertRaises(ValueError):journal.retire_failed(self.root,'0'*64,True,lambda p:None)
        def unsafe(p):raise ValueError('Still active')
        with self.assertRaises(ValueError):journal.retire_failed(self.root,expected,True,unsafe)
        self.assertEqual(self.path.read_bytes(),original)
        seen=[];value=journal.retire_failed(self.root,expected,True,lambda p:seen.append(p))
        self.assertEqual(seen,[self.release]);self.assertFalse(value['dataCompatibilityProved'])
        self.assertEqual(value['phase'],'retired-failed')
        (self.bundle/'bundle.json').write_text('{"reviewed-new-input":true}')
        next_release=self.root/'releases/20261012T020000Z-222222222222'
        journal.update(self.root,self.bundle,next_release,'preparing')
        self.assertEqual(journal.read(self.release/'installation-receipt.json')['phase'],'retired-failed')

    def test_native_quarantine_verifier_denies_active_units_enabled_targets_and_jobs(self):
        self.release.mkdir(parents=True)
        (self.release/'podman-domains.json').write_text('{"domains":[]}')
        units=self.release/'quadlet/rootful';units.mkdir(parents=True)
        (units/'webservices-caddy.container').write_text('[Container]\n')
        def result(command,**kwargs):
            if 'show' in command:return SimpleNamespace(returncode=0,stdout='inactive\n\ninactive\n')
            if 'is-enabled' in command:return SimpleNamespace(returncode=1,stdout='disabled\n')
            return SimpleNamespace(returncode=0,stdout='')
        with patch.object(journal.subprocess,'run',side_effect=result):journal.verify_quarantined(self.release)
        for kind in ('show','is-enabled','list-jobs'):
            def unsafe(command,**kwargs):
                if kind in command:
                    return SimpleNamespace(returncode=0,stdout={'show':'inactive\nactive\n','is-enabled':'enabled\n','list-jobs':'9 webservices-caddy.service start running\n'}[kind])
                return result(command,**kwargs)
            with patch.object(journal.subprocess,'run',side_effect=unsafe):
                with self.assertRaises(ValueError):journal.verify_quarantined(self.release)

    def test_links_permissions_and_escaped_receipts_refused(self):
        journal.update(self.root, self.bundle, self.release, 'preparing')
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): journal.read(self.path)
        self.path.chmod(0o600)
        self.path.unlink(); self.path.symlink_to(self.release / 'installation-receipt.json')
        with self.assertRaises(ValueError): journal.read(self.path)
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.root / 'escaped', 'preparing')

if __name__ == '__main__': unittest.main()
