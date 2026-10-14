#!/usr/bin/env python3
"""Run as root: journal permissions, ordered phases, CAS and unchanged inputs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
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

    def selected_fixture(self):
        self.release.mkdir(parents=True, exist_ok=True)
        (self.release/'podman-domains.json').write_text(json.dumps({'domains':[
            {'name':'platform','user':'webservices-platform','uid':992}]}))
        rootful=self.release/'quadlet/rootful';rootful.mkdir(parents=True)
        (rootful/'webservices-caddy.container').write_text('[Container]\n')
        rootless=self.release/'quadlet/rootless-platform';rootless.mkdir(parents=True)
        (rootless/'webservices-postgres.container').write_text('[Container]\n')
        return SimpleNamespace(pw_uid=992,pw_dir='/home/webservices-platform')

    def test_native_quarantine_verifier_denies_active_units_enabled_targets_and_jobs(self):
        account=self.selected_fixture()
        def result(command,**kwargs):
            if 'show' in command:
                count=command.index('-p')-command.index('show')-1
                return SimpleNamespace(returncode=0,stdout='\n'.join(['inactive']*count)+'\n')
            if 'is-enabled' in command:return SimpleNamespace(returncode=1,stdout='disabled\n')
            return SimpleNamespace(returncode=0,stdout='')
        with patch.object(journal.pwd,'getpwnam',return_value=account),patch.object(journal.subprocess,'run',side_effect=result):
            journal.verify_quarantined(self.release)
            for kind in ('show','is-enabled','list-jobs'):
                def unsafe(command,**kwargs):
                    if kind in command:
                        return SimpleNamespace(returncode=0,stdout={'show':'inactive\nactive\n','is-enabled':'enabled\n','list-jobs':'9 webservices-caddy.service start running\n'}[kind])
                    return result(command,**kwargs)
                with patch.object(journal.subprocess,'run',side_effect=unsafe):
                    with self.assertRaises(ValueError):journal.verify_quarantined(self.release)

    def test_exact_failed_quarantine_only_stops_selected_units_and_keeps_intent(self):
        account=self.selected_fixture()
        journal.update(self.root,self.bundle,self.release,'preparing')
        journal.update(self.root,self.bundle,self.release,'failed')
        for name in journal.fingerprint(self.bundle):
            (self.release/name).write_bytes((self.bundle/name).read_bytes())
        (self.root/'current').symlink_to(self.release)
        expected=journal.digest(self.path);original=self.path.read_bytes()
        commands=[]
        def succeed(command,**kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=0,stdout='')
        with patch.object(journal.pwd,'getpwnam',return_value=account),patch.object(journal.subprocess,'run',side_effect=succeed):
            proof=journal.quarantine_failed(self.root,expected,True,lambda p:self.assertEqual(p,self.release))
        self.assertTrue(proof['quarantined']);self.assertFalse(proof['intentRetired'])
        self.assertEqual(self.path.read_bytes(),original)
        self.assertEqual(len([c for c in commands if '--no-block' in c]),2)
        for command in commands:
            self.assertNotIn('rm',command)
            self.assertNotIn('--force',command)
            self.assertFalse(any('obelisks' in v for v in command))
        self.assertTrue(any(c[-2:]==['disable','webservices.target']for c in commands))
        with patch.object(journal.subprocess,'run',side_effect=succeed):
            with self.assertRaises(ValueError):journal.quarantine_failed(self.root,'f'*64,True,lambda p:None)
        self.assertEqual(self.path.read_bytes(),original)

    def test_partial_stop_never_retires_or_restarts_and_requires_native_proof(self):
        account=self.selected_fixture()
        journal.update(self.root,self.bundle,self.release,'preparing')
        journal.update(self.root,self.bundle,self.release,'failed')
        for name in journal.fingerprint(self.bundle):
            (self.release/name).write_bytes((self.bundle/name).read_bytes())
        (self.root/'current').symlink_to(self.release)
        expected=journal.digest(self.path);original=self.path.read_bytes()
        commands=[]
        def partial(command,**kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=1 if '--no-block' in command and 'runuser' in command else 0,stdout='')
        with patch.object(journal.pwd,'getpwnam',return_value=account),patch.object(journal.subprocess,'run',side_effect=partial):
            with self.assertRaises(ValueError):journal.quarantine_failed(self.root,expected,True,lambda p:None)
        self.assertEqual(self.path.read_bytes(),original)
        self.assertEqual(len([c for c in commands if '--no-block' in c]),2)
        self.assertFalse(any('start' in c or '--force' in c for c in commands))
        commands.clear()
        def succeeds(command,**kwargs):
            commands.append(command);return SimpleNamespace(returncode=0,stdout='')
        with patch.object(journal.pwd,'getpwnam',return_value=account),patch.object(journal.subprocess,'run',side_effect=succeeds):
            with self.assertRaises(ValueError):
                journal.quarantine_failed(self.root,expected,True,
                    lambda p:(_ for _ in ()).throw(ValueError('still running')),wait_seconds=0)
        self.assertEqual(self.path.read_bytes(),original)

    def test_quarantine_refuses_active_or_unbound_selection_before_stop(self):
        account=self.selected_fixture()
        journal.update(self.root,self.bundle,self.release,'preparing')
        journal.update(self.root,self.bundle,self.release,'failed')
        for name in journal.fingerprint(self.bundle):
            (self.release/name).write_bytes((self.bundle/name).read_bytes())
        expected=journal.digest(self.path)
        with patch.object(journal.pwd,'getpwnam',return_value=account),patch.object(journal.subprocess,'run')as stop:
            with self.assertRaises(ValueError):journal.quarantine_failed(self.root,expected,True,lambda p:None)
            stop.assert_not_called()
            (self.root/'current').symlink_to(self.release)
            (self.release/'quadlet/rootful/webservices-caddy.container').unlink()
            (self.release/'quadlet/rootful/webservices-caddy.container').symlink_to(self.path)
            with self.assertRaises(ValueError):journal.quarantine_failed(self.root,expected,True,lambda p:None)
            stop.assert_not_called()
            (self.release/'quadlet/rootful/webservices-caddy.container').unlink()
            (self.release/'quadlet/rootful/webservices-caddy.container').write_text('[Container]\n')
            journal.write(self.path,dict(journal.read(self.path),phase='retired-failed'))
            with self.assertRaises(ValueError):journal.quarantine_failed(self.root,journal.digest(self.path),True,lambda p:None)
            stop.assert_not_called()

    def test_links_permissions_and_escaped_receipts_refused(self):
        journal.update(self.root, self.bundle, self.release, 'preparing')
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): journal.read(self.path)
        self.path.chmod(0o600)
        self.path.unlink(); self.path.symlink_to(self.release / 'installation-receipt.json')
        with self.assertRaises(ValueError): journal.read(self.path)
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.root / 'escaped', 'preparing')

if __name__ == '__main__': unittest.main()
