#!/usr/bin/env python3
"""Synthetic owned bridge intent ordering, never actual host network proof."""
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

OPS=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
spec=importlib.util.spec_from_file_location('owned_network',OPS/'render-existing-host-guest-network.py')
net=importlib.util.module_from_spec(spec);spec.loader.exec_module(net)

@unittest.skipUnless(os.geteuid()==0,'root-private synthetic network receipt')
class Owned(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='p0-network-unit-',dir='/run');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.journal=self.root/'network.json'
        self.selector=self.root/'selector.json';self.selector.write_text('{}')
        self.runtime=self.root/'run';self.runtime.mkdir(mode=0o700)
        self.uuid='12345678-1234-1234-1234-123456789abc'
        self.xml='<network><name>p0-venue-r1</name><uuid>'+self.uuid+'</uuid><bridge name="virbr140"/></network>'
        self.info={'subnet':'192.168.140.0/24','network':'p0-venue-r1','bridge':'virbr140','guest':'p0-venue-r1-agents'}
        self.commands=[];self.fenced=False;self.created=False;self.autostart=False
        life,_=net.owned_helpers()
        self.context=NS(runtime=self.runtime,digest='b'*64,physical_reserves=lambda:None)
        patches=[patch.object(net,'owned_helpers',return_value=(life,NS(render=lambda *a:{'table':'p0_test_fence','nftables':'table inet p0_test_fence {}\n'}))),
                 patch.object(life.stage,'owned_plan',return_value={'prefix':'p0test-r1','selectorSha256':'a'*64,'bundleIrSha256':'c'*64}),
                 patch.object(life,'host_context',return_value=self.context),
                 patch.object(life,'lifecycle',side_effect=lambda *a:nullcontext()),
                 patch.object(life.units,'units_idle',return_value=None),
                 patch.object(net,'render',return_value=(self.xml,self.info)),
                 patch.object(net,'HOOK_DIRECTORY',self.root/'hooks/network.d'),
                 patch.object(net,'screen_host',return_value={}),
                 patch.object(net.subprocess,'check_output',side_effect=self.output),
                 patch.object(net.subprocess,'run',side_effect=self.native_run)]
        for p in patches:p.start();self.addCleanup(p.stop)
    def output(self,command,**kwargs):
        self.commands.append(command)
        if command[0]=='nft':return b'{"nftables":[]}' if not kwargs.get('text') else '{"nftables":[]}'
        if command[0]=='ip':return '[]'
        if 'net-list' in command:return self.uuid+'\n' if self.created else ''
        if 'list' in command:return ''
        if 'net-uuid' in command:return self.uuid+'\n'
        if 'net-dumpxml' in command:return self.xml
        if command[:2]==['systemctl','is-active']:return 'active\n'
        if 'net-info' in command:return 'Active: yes\nPersistent: yes\nAutostart: '+('yes' if self.autostart else 'no')+'\n'
        self.fail('unexpected native query')
    def native_run(self,command,**kwargs):
        self.commands.append(command)
        state=json.loads(self.journal.read_text())
        if command[:2]==['nft','-f']:
            self.assertEqual(state['phase'],'fence-installing');self.fenced=True
        if 'net-create' in command:
            self.assertTrue(self.fenced);self.assertEqual(state['phase'],'network-create-intended');self.created=True
        if 'net-define' in command:
            self.assertTrue(self.created)
            body=Path(command[-1]).read_text();self.assertIn(self.uuid,body)
        if 'net-destroy' in command:
            self.assertTrue(self.fenced);self.assertIn(state['phase'],('network-retire-intended','network-runtime-ready'));self.assertEqual(command[-1],self.uuid)
            if state['phase']=='network-runtime-ready':self.assertEqual(state['bootFence']['phase'],'native-proof-intended')
        if 'net-start' in command:
            policy=state['bootFence']['policy'];proof=Path(policy['proofPath'])
            proof.write_text(json.dumps({'schemaVersion':1,'activationAuthorized':False,'network':self.info['network'],
                'networkXmlFingerprint':policy['networkXmlFingerprint'],'networkUuid':self.uuid,'namespace':'p0test-r1','hookSha256':state['bootFence']['sha256'],
                'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'event':'start/begin','nativeFenceFingerprint':policy['nativeFenceFingerprint']}));proof.chmod(0o600)
        if 'net-autostart' in command:self.autostart=True
        if 'net-undefine' in command:self.created=False
        if command[:2]==['nft','delete']:
            self.assertFalse(self.created);self.assertEqual(state['phase'],'network-undefined-fence-held');self.fenced=False
        return NS(returncode=0)
    def test_fence_and_intent_precede_atomic_create_then_persist_exact_uuid(self):
        result=net.prepare_owned(self.root,self.selector,self.journal)
        self.assertEqual(result['status'],'network-runtime-ready')
        self.assertFalse(result['guestCreated']);self.assertFalse(result['activationAuthorized'])
        self.assertEqual(json.loads(self.journal.read_text())['networkUuid'],self.uuid)
        self.assertFalse(any('net-start' in c or 'destroy' in c for c in self.commands))
    def test_exact_uuid_destroy_and_undefine_precede_own_fence_removal(self):
        net.prepare_owned(self.root,self.selector,self.journal);self.commands=[]
        result=net.retire_owned(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertEqual(result['status'],'network-retired');self.assertFalse(result['guestDataTouched'])
        self.assertFalse(self.fenced);self.assertFalse(self.created)
    def test_native_blank_domain_separator_is_not_an_empty_domain_argument(self):
        net.prepare_owned(self.root,self.selector,self.journal);query=self.output
        def blank(command,**kwargs):
            if command[0]=='virsh' and 'list' in command:return '\n'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=blank):
            self.assertEqual(net.retire_owned(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())['status'],'network-retired')
    def test_wrong_retirement_cas_refuses_before_native_mutation(self):
        net.prepare_owned(self.root,self.selector,self.journal);self.commands=[]
        with self.assertRaises(net.Refusal):net.retire_owned(self.root,self.selector,self.journal,'0'*64)
        self.assertFalse(self.commands);self.assertTrue(self.fenced)
    def test_any_domain_reference_blocks_even_if_not_selected_guest_name(self):
        net.prepare_owned(self.root,self.selector,self.journal);self.commands=[];query=self.output
        def busy(command,**kwargs):
            if command[0]=='virsh' and 'list' in command:return 'foreign-domain-uuid\n'
            if 'dumpxml' in command:return '<domain><devices><interface><source network="p0-venue-r1"/></interface></devices></domain>'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=busy):
            with self.assertRaisesRegex(net.Refusal,'a domain references'):
                net.retire_owned(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('net-destroy' in command or command[:2]==['nft','delete'] for command in self.commands))
    def stage_boot(self):
        net.prepare_owned(self.root,self.selector,self.journal)
        return net.stage_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
    def test_staging_hook_never_enables_autostart_or_restarts_daemon(self):
        self.assertEqual(self.stage_boot()['status'],'owned-boot-hook-staged');self.assertFalse(self.autostart)
        state=json.loads(self.journal.read_text());body=Path(state['bootFence']['path']).read_text();self.assertIn('POLICY = {',body)
        self.assertFalse(any('restart' in cmd or 'net-autostart' in cmd for cmd in self.commands))
    def test_native_hook_invocation_proof_precedes_autostart(self):
        self.stage_boot();self.commands=[]
        result=net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertEqual(result['status'],'owned-network-native-boot-fence-proven');self.assertTrue(self.autostart);self.assertFalse(result['hostRebootPerformed'])
        self.assertLess(next(i for i,cmd in enumerate(self.commands) if 'net-start' in cmd),next(i for i,cmd in enumerate(self.commands) if 'net-autostart' in cmd))
    def test_live_domain_blocks_daemon_restart_and_boot_proof(self):
        self.stage_boot();self.commands=[];query=self.output
        def busy(command,**kwargs):
            if command[0]=='virsh' and 'list' in command:return 'another-uuid\n'
            if 'domstate' in command:return 'running\n'
            if 'dominfo' in command:return 'Autostart: disable\n'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=busy):
            with self.assertRaisesRegex(net.Refusal,'domain live/autostart'):
                net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('restart' in cmd or 'net-autostart' in cmd for cmd in self.commands))
    def test_stopped_autostart_domain_blocks_daemon_restart(self):
        self.stage_boot();self.commands=[];query=self.output
        def autostart(command,**kwargs):
            if command[0]=='virsh' and 'list' in command:return 'original-uuid\n'
            if 'domstate' in command:return 'shut off\n'
            if 'dominfo' in command:return 'Autostart: enable\n'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=autostart):
            with self.assertRaisesRegex(net.Refusal,'domain live/autostart'):
                net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('restart' in cmd for cmd in self.commands))
    def test_stopped_autostart_network_blocks_daemon_restart(self):
        self.stage_boot();self.commands=[];query=self.output
        def stopped_network(command,**kwargs):
            if 'net-list' in command:return 'original-network\n'
            if 'net-info' in command and command[-1]=='original-network':return 'Autostart: yes\nActive: no\n'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=stopped_network):
            with self.assertRaisesRegex(net.Refusal,'stopped autostart network'):
                net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('restart' in cmd for cmd in self.commands))
    def test_inactive_daemon_is_not_restarted(self):
        self.stage_boot();self.commands=[];query=self.output
        def inactive(command,**kwargs):
            if command[:2]==['systemctl','is-active']:return 'inactive\n'
            return query(command,**kwargs)
        with patch.object(net.subprocess,'check_output',side_effect=inactive):
            with self.assertRaisesRegex(net.Refusal,'daemon is not active'):
                net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('restart' in cmd for cmd in self.commands))
    def test_missing_native_hook_proof_does_not_enable_autostart(self):
        self.stage_boot();run=self.native_run
        def missing(command,**kwargs):
            if 'net-start' in command:return NS(returncode=0,stdout='',stderr='')
            return run(command,**kwargs)
        with patch.object(net.subprocess,'run',side_effect=missing):
            with self.assertRaises(OSError):net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(self.autostart);self.assertTrue(self.fenced)
    def test_exact_network_retirement_removes_only_its_staged_hook(self):
        self.stage_boot();state=json.loads(self.journal.read_text());hook=Path(state['bootFence']['path']);self.assertTrue(hook.exists())
        result=net.retire_owned(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertEqual(result['status'],'network-retired');self.assertFalse(hook.exists());self.assertEqual(json.loads(self.journal.read_text())['bootFence']['phase'],'retired')
    def test_changed_staged_hook_refuses_before_daemon_restart(self):
        self.stage_boot();state=json.loads(self.journal.read_text());Path(state['bootFence']['path']).write_text('authored replacement');self.commands=[]
        with self.assertRaises(net.Refusal):net.prove_boot_fence(self.root,self.selector,self.journal,net.hashlib.sha256(self.journal.read_bytes()).hexdigest())
        self.assertFalse(any('restart' in cmd for cmd in self.commands))
    def test_existing_receipt_is_not_adopted_or_replayed(self):
        self.journal.write_text('{}');self.journal.chmod(0o600)
        with self.assertRaisesRegex(net.Refusal,'inspect before retry'):
            net.prepare_owned(self.root,self.selector,self.journal)
        self.assertFalse(self.commands)

if __name__=='__main__':unittest.main()
