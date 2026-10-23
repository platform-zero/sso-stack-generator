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

    def copy_pins_to_release(self):
        for name, sha in journal.fingerprint(self.bundle).items():
            if sha is None: continue
            target=self.release/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((self.bundle/name).read_bytes())

    def test_ordered_phases_and_private_receipt(self):
        for phase in journal.PHASES[:5]:
            journal.update(self.root, self.bundle, self.release, phase)
        self.assertEqual(journal.read(self.path)['phase'], 'active')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.read(self.release / 'installation-receipt.json'), journal.read(self.path))
        with self.assertRaises(ValueError): journal.update(self.root, self.bundle, self.release, 'failed')

    def test_native_release_identity_collision_refuses_before_selected_stop(self):
        script=(source.parent/'install-podman-bundle.sh').read_text()
        guard='[ -z "$RESUME_INTENT" ] && { [ -e "$release" ] || [ -L "$release" ]; }'
        self.assertIn(guard,script)
        self.assertLess(script.index(guard),script.index('journal preparing'))
        self.assertLess(script.index(guard),script.index('systemctl stop webservices.target'))

    def test_active_predecessor_must_be_selected_and_retains_exact_pins_on_resume(self):
        for phase in journal.PHASES[:5]:
            journal.update(self.root,self.bundle,self.release,phase)
        self.copy_pins_to_release()
        next_release=self.root/'releases/20261012T020000Z-111111111111'
        with self.assertRaises(ValueError):
            journal.update(self.root,self.bundle,next_release,'preparing')
        (self.root/'current').symlink_to(self.release)
        (self.release/'bundle.json').write_text('{"tampered":true}')
        with self.assertRaises(ValueError):
            journal.update(self.root,self.bundle,next_release,'preparing')
        self.copy_pins_to_release()
        value=journal.update(self.root,self.bundle,next_release,'preparing')
        self.assertEqual(value['previousRelease'],str(self.release))
        journal.update(self.root,self.bundle,next_release,'failed')
        expected=journal.digest(self.path)
        resumed=journal.update(self.root,self.bundle,next_release,'preparing',expected)
        self.assertEqual(resumed['previousRelease'],str(self.release))
        self.assertEqual(resumed['resumedFrom'],str(next_release))

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
        self.copy_pins_to_release()
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

    def test_only_inactive_fragmentless_not_found_units_are_unconfigured(self):
        from types import SimpleNamespace
        absent='LoadState=not-found\nActiveState=inactive\nFragmentPath=\nUnitFileState=\n'
        for result, expected in ((absent,True), (absent.replace('inactive','active'),False),
                (absent.replace('FragmentPath=','FragmentPath=/foreign.service'),False),
                ('',False), (absent.replace('not-found','loaded'),False)):
            with patch.object(journal.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=result)):
                self.assertEqual(journal.unconfigured_unit(['systemctl'],'fixture.service'),expected)

    def test_unselected_stage_seal_refuses_links_before_any_owner_change(self):
        journal.update(self.root,self.bundle,self.release,'preparing'); self.copy_pins_to_release()
        import os
        scope=self.root/'synthetic-scope'; scope.mkdir(); os.chown(scope,1000,1000)
        os.chown(self.release,1000,1000)
        for name in journal.CORE_INPUTS: os.chown(self.release/name,1000,1000)
        expected=journal.digest(self.path)
        binding={'scope':{'root':str(scope),'dataClass':'synthetic'}}
        with patch.object(journal,'unselected_preparation_binding',return_value=binding):
            with self.assertRaises(ValueError):journal.seal_unselected(self.root,expected,False)
            os.link(self.bundle/'bundle.json',self.release/'linked-fixture')
            with self.assertRaises(ValueError):journal.seal_unselected(self.root,expected,True)
            self.assertEqual(self.release.stat().st_uid,1000)
            (self.release/'linked-fixture').unlink()
            proof=journal.seal_unselected(self.root,expected,True)
        self.assertTrue(proof['sealed']); self.assertEqual(self.release.stat().st_uid,0)
        self.assertEqual(self.release.stat().st_mode&0o777,0o700)
        self.assertEqual(journal.digest(self.path),expected)
        self.assertTrue(all((self.release/name).stat().st_uid==0 for name in journal.CORE_INPUTS))

    def test_unselected_retirement_is_exact_reviewed_and_preserves_failure_evidence(self):
        journal.update(self.root,self.bundle,self.release,'preparing'); self.copy_pins_to_release()
        expected=journal.digest(self.path); original=self.path.read_bytes(); seen=[]
        verify=lambda root,release,value:seen.append((root,release,value['phase']))
        with self.assertRaises(ValueError):journal.retire_unselected(self.root,expected,False,verify)
        with self.assertRaises(ValueError):journal.retire_unselected(self.root,'0'*64,True,verify)
        self.assertEqual(self.path.read_bytes(),original); self.assertEqual(seen,[])
        value=journal.retire_unselected(self.root,expected,True,verify)
        self.assertEqual(seen,[(self.root,self.release,'preparing')])
        self.assertEqual(value['steps'],['preparing','failed','retired-failed'])
        self.assertTrue(value['neverSelectedProved']); self.assertFalse(value['dataCompatibilityProved'])
        self.assertEqual(value['retiredIntentSha256'],expected)

    def test_unselected_retirement_refuses_selection_history_input_and_receipt_drift(self):
        journal.update(self.root,self.bundle,self.release,'preparing'); self.copy_pins_to_release()
        expected=journal.digest(self.path)
        (self.release/'bundle.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError):journal.retire_unselected(self.root,expected,True,lambda *a:None)
        self.copy_pins_to_release()
        value=journal.read(self.path); value['previousRelease']=str(self.root/'releases/prior')
        journal.write(self.path,value)
        with self.assertRaises(ValueError):journal.retire_unselected(self.root,journal.digest(self.path),True,lambda *a:None)
        value['previousRelease']=None; value['steps']=['preparing','units-selected','failed']; value['phase']='failed'
        journal.write(self.path,value)
        with self.assertRaises(ValueError):journal.retire_unselected(self.root,journal.digest(self.path),True,lambda *a:None)

    def test_never_selected_native_proof_does_not_accept_files_pointers_active_jobs_or_production(self):
        account=self.selected_fixture()
        binding={'scope':{'dataClass':'synthetic'},'domains':[{'user':'webservices-platform','stateRoot':str(self.root/'actor')}]}
        configs=self.root/'unit-fixture'; configs.mkdir()
        commands=[]
        def result(command,**kwargs):
            commands.append(command)
            if 'show' in command:
                count=command.index('-p')-command.index('show')-1
                return SimpleNamespace(returncode=0,stdout='\n\n'.join(['inactive']*count)+'\n')
            if 'is-enabled' in command:return SimpleNamespace(returncode=4,stdout='not-found\n')
            return SimpleNamespace(returncode=0,stdout='')
        with patch.object(journal,'standalone_binding',return_value=binding), \
             patch.object(journal,'unselected_configuration_roots',return_value=[configs]), \
             patch.object(journal.pwd,'getpwnam',return_value=account), \
             patch.object(journal.subprocess,'run',side_effect=result):
            journal.verify_unselected_preparation(self.root,self.release,{})
            (configs/'webservices-fixture.service').write_text('fixture')
            with self.assertRaises(ValueError):journal.verify_unselected_preparation(self.root,self.release,{})
            (configs/'webservices-fixture.service').unlink()
            (self.root/'current').symlink_to(self.release)
            with self.assertRaises(ValueError):journal.verify_unselected_preparation(self.root,self.release,{})
            (self.root/'current').unlink()
            for kind in ('show','is-enabled','list-jobs'):
                def unsafe(command,**kwargs):
                    base=result(command,**kwargs)
                    if kind in command:
                        return SimpleNamespace(returncode=0,stdout={
                            'show':base.stdout.replace('inactive','active',1),
                            'is-enabled':'enabled\n',
                            'list-jobs':'1 webservices-fixture.service start running\n'}[kind])
                    return base
                with patch.object(journal.subprocess,'run',side_effect=unsafe):
                    with self.assertRaises(ValueError):journal.verify_unselected_preparation(self.root,self.release,{})
            binding['scope']['dataClass']='production'
            with self.assertRaises(ValueError):journal.verify_unselected_preparation(self.root,self.release,{})
        self.assertFalse(any(word in ('start','stop','restart','enable','disable') for cmd in commands for word in cmd))

    def test_ciphertext_and_base_pin_changes_refuse_pending_resume(self):
        settings=self.bundle/'site/global.settings'; settings.mkdir(parents=True)
        for name in ('webservices.sops.json','build-base-image-ids.json'): (settings/name).write_text('{}')
        journal.update(self.root,self.bundle,self.release,'preparing'); expected=journal.digest(self.path)
        (settings/'webservices.sops.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError):journal.update(self.root,self.bundle,self.release,'preparing',expected)
        (settings/'webservices.sops.json').write_text('{}')
        (settings/'build-base-image-ids.json').write_text('{"changed":true}')
        with self.assertRaises(ValueError):journal.update(self.root,self.bundle,self.release,'preparing',expected)

    def selected_fixture(self):
        self.release.mkdir(parents=True, exist_ok=True)
        manifest=json.dumps({'domains':[{'name':'platform','user':'webservices-platform','uid':992}]})
        (self.release/'podman-domains.json').write_text(manifest)
        (self.bundle/'podman-domains.json').write_text(manifest)
        rootful=self.release/'quadlet/rootful';rootful.mkdir(parents=True)
        (rootful/'webservices-caddy.container').write_text('[Container]\n')
        rootless=self.release/'quadlet/rootless-platform';rootless.mkdir(parents=True)
        (rootless/'webservices-postgres.container').write_text('[Container]\n')
        return SimpleNamespace(pw_uid=992,pw_dir='/home/webservices-platform')

    def test_site_vm_and_domain_pins_are_cas_bound_and_absence_is_pinned(self):
        site=self.bundle/'site';site.mkdir()
        vm=site/'agent-vm.json';vm.write_text('{"controlCommit":"a"}')
        journal.update(self.root,self.bundle,self.release,'preparing')
        receipt=journal.read(self.path)
        self.assertEqual(receipt['inputs']['site/agent-vm.json'],journal.digest(vm))
        self.assertIsNone(receipt['inputs']['site/components.lock.json'])
        vm.write_text('{"controlCommit":"b"}')
        with self.assertRaises(ValueError):journal.update(self.root,self.bundle,self.release,'units-selected')
        vm.write_text('{"controlCommit":"a"}')
        (site/'components.lock.json').write_text('{}')
        with self.assertRaises(ValueError):journal.update(self.root,self.bundle,self.release,'units-selected')
        (site/'components.lock.json').unlink()
        journal.update(self.root,self.bundle,self.release,'units-selected')

    def test_historical_three_pin_failed_receipt_remains_read_only_verifiable(self):
        journal.update(self.root,self.bundle,self.release,'preparing')
        journal.update(self.root,self.bundle,self.release,'failed')
        self.copy_pins_to_release()
        old=journal.read(self.path);old['inputs']={k:old['inputs'][k]for k in journal.CORE_INPUTS}
        journal.write(self.path,old)
        self.assertEqual(journal.fingerprint(self.release,old['inputs'].keys()),old['inputs'])
        self.assertEqual(journal.retire_failed(self.root,journal.digest(self.path),True,lambda p:None)['phase'],'retired-failed')

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
        self.copy_pins_to_release()
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
        self.copy_pins_to_release()
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
        self.copy_pins_to_release()
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
