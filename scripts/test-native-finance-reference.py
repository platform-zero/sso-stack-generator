#!/usr/bin/env python3
"""Synthetic exact source/reference custody models. NOT real Root/installed proof."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
OPS=ROOT/'runtime-generator/podman-ops'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); module=importlib.util.module_from_spec(spec); sys.modules[name]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__); return module
v=load('finance_reference_static',OPS/'verify-agent-vm-bundle.py')
n=load('finance_reference_native',OPS/'native-readiness-owner.py')

def fixture_ir():
    return {'services':{'keycloak-configure':{'placement':'rootful','lifecycle':'oneshot','environment':{'FIREFLY_NATIVE_OWNERSHIP_FILE':'/run/p0-finance/input.json'},
                         'volumes':['/var/lib/webservices-native-finance:/run/p0-finance:ro']},
                        'keycloak':{},'postgres':{},'firefly-identity-check':{}},'volumes':{}}

class ExactDescriptor(unittest.TestCase):
    def test_exact_source_only_descriptor(self):
        descriptor=v.native_finance_reference(fixture_ir())
        self.assertEqual(descriptor['publisher'],'ops/native-finance-ownership.py')
        self.assertTrue(descriptor['readOnly']); self.assertEqual(descriptor['origin'],'root-native-finance-ownership')
        self.assertEqual(v.standalone_boundaries(fixture_ir(),{},v.canonical_path('/fixture/data'))['keycloak-configure'][0],
                         (v.canonical_path('/var/lib/webservices-native-finance'),'/run/p0-finance',True))
    def test_old_source_without_feature_is_unchanged(self):
        self.assertIsNone(v.native_finance_reference({'services':{'ordinary':{}},'volumes':{}}))
    def test_existing_source_profile_body_is_byte_unchanged(self):
        text=(OPS/'verify-agent-vm-bundle.py').read_text()
        start=text.index("NATIVE_FINANCE_SOURCE ="); end=text.index('def standalone_boundaries(',start)
        text=text[:start]+text[end:]
        added='    # Classification is lexical source proof only. Actual Root publisher/CAS,\n    # inode/ACL/mount custody is observed after arm before original consumption.\n    native_finance_reference(ir, domains)\n'
        text=text.replace(added,'')
        self.assertEqual(n.r.sha(text.encode()),'1a1b73b12357086bd3d53d1d038804460d6e840e46d33ed4a084467fb12314fc')
    def test_existing_readiness_interfaces_byte_unchanged(self):
        text=(OPS/'native-readiness-owner.py').read_text()
        a=text.index('def finance_actor(descriptor):'); b=text.index('class Selection:',a); text=text[:a]+text[b:]
        a=text.index("        result = {'intentSha256': self.cas"); b=text.index('        return result',a)+len('        return result')
        old="""        return {'intentSha256': self.cas, 'release': str(self.release), 'inputs': pins,
                'renderedInputs': rendered_pins, 'storageBinding': storage_pin, 'readiness': readiness,
                'rootfulEnvironmentBindingSha256': rootful['bindingSha256'],
                'runtimeUnitSourceSha256': prepared['selectionSourceSha256'],
                'runtimeCopiesBindingSha256': copies_binding}"""
        text=text[:a]+old+text[b:]
        added="""    if 'nativeFinanceReferenceBindingSha256' in binding:
        require(type(binding['nativeFinanceReferenceBindingSha256']) is str
                and r.HEX.fullmatch(binding['nativeFinanceReferenceBindingSha256']),
                'Selected finance reference has not been Root-published')
        require(prior_intent.get('nativeFinanceOwnershipReceipt', {}).get('kind') == 'root-native-finance-ownership'
                and prior_intent['nativeFinanceOwnershipReceipt'].get('status') == 'completed'
                and prior_intent.get('nativeFinanceReference', {}).get('input', {}).get('content', {}).get('status') == 'retained',
                'Original successful native finance frame absent; fresh transport is not readiness')
"""
        text=text.replace(added,'')
        self.assertEqual(n.r.sha(text.encode()),'16a22ef7f4fba4150e27d577f84007a03b0a5b835cae6c8a4145794aa07a84ac')
    def test_no_parent_prefix_alias_writable_or_other_service(self):
        for mount in ('/var/lib:/run/p0-finance:ro','/var/lib/webservices-native-finance/child:/run/p0-finance:ro',
                      '/var/lib/webservices-native-finance:/run/p0-finance:rw',
                      '/var/lib/webservices-native-finance:/elsewhere:ro',
                      '/var/lib/webservices-native-finance:/run/p0-finance:ro,U'):
            ir=fixture_ir(); ir['services']['keycloak-configure']['volumes']=[mount]
            with self.subTest(mount=mount),self.assertRaises(ValueError): v.native_finance_reference(ir)
        ir=fixture_ir(); ir['services']['foreign']=ir['services'].pop('keycloak-configure')
        with self.assertRaises(ValueError): v.native_finance_reference(ir)
    def test_no_manual_reference_env_rootless_or_daemon(self):
        for key,value in [('placement','rootless'),('lifecycle','daemon')]:
            ir=fixture_ir(); ir['services']['keycloak-configure'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): v.native_finance_reference(ir)
        ir=fixture_ir(); ir['services']['keycloak-configure']['environment']['FIREFLY_NATIVE_OWNERSHIP_FILE']='/manual.json'
        with self.assertRaises(ValueError): v.native_finance_reference(ir)
    def test_missing_mount_or_selected_cohort_refuses(self):
        ir=fixture_ir(); ir['services']['keycloak-configure']['volumes']=[]
        with self.assertRaises(ValueError): v.native_finance_reference(ir)
        ir=fixture_ir(); del ir['services']['postgres']
        with self.assertRaises(ValueError): v.native_finance_reference(ir)

class CurrentRootReference(unittest.TestCase):
    def setUp(self):
        self.root=Path('/fixture/root'); self.release=self.root/'releases/one'; self.ir=fixture_ir()
        self.publisher=b'synthetic selected publisher source'; self.finance=b'synthetic selected finance source'
        self.edge={'clientId':'firefly-identity-reader','clientUuid':'00000001-1111-4111-8111-000000000000','serviceAccountSubject':'00000002-1111-4111-8111-000000000000'}
        self.content=dict(kind='root-native-finance-input',root=str(self.root),release=str(self.release),intentSha256='a'*64,
                          sourceSha256=n.r.sha(self.finance),status='retained',nativeFinanceOwnership=self.edge)
        self.physical=dict(directory={'path':'/var/lib/webservices-native-finance','identity':[1,2,0,0,16877,2,4096,3,4],'mountId':17},
                           input={'path':'/var/lib/webservices-native-finance/input.json','identity':[1,3,0,0,33060,1,1024,4,5],'mountId':17,'sha256':'b'*64,'content':self.content})
        self.ref=dict(schemaVersion=1,kind='root-native-finance-reference',status='completed',root=str(self.root),release=str(self.release),
                      inputs={'stack.ir.json':n.r.sha(n.r.frozen(self.ir).encode())},intentSha256='a'*64,descriptor=v.native_finance_reference(self.ir),
                      publisher={'path':'ops/native-finance-ownership.py','sha256':n.r.sha(self.publisher),'origin':'root-native-finance-ownership'},**self.physical)
        self.intent=dict(release=str(self.release),inputs=self.ref['inputs'],nativeFinanceReference=self.ref,
                         nativeFinanceOwnershipReceipt={'kind':'root-native-finance-ownership','status':'completed',
                           'original':{'kind':'original-live-systemd-cid-keycloak-native-link'},'nativeFinanceOwnership':self.edge})
    def observe(self,physical=None,bad_dual=False):
        def read(path,**kw):
            relative=str(path)
            if path==self.release/'stack.ir.json': return n.r.frozen(self.ir).encode()
            if path==self.root/'.install-intent.json': return n.r.frozen(self.intent).encode()
            if path==self.release/'installation-receipt.json': return b'{}' if bad_dual else n.r.frozen(self.intent).encode()
            if path==self.release/'bundle.json': return n.r.frozen({'liveOps':{'ops/native-finance-ownership.py':n.r.sha(self.publisher)}}).encode()
            if path==self.release/'ops/native-finance-ownership.py': return self.publisher
            if path==self.release/'runtime/configs/keycloak/configure-finance.sh': return self.finance
            raise AssertionError('Unclaimed fixture read: '+relative)
        with patch.object(n,'read_file',side_effect=read),patch.object(n,'lock_held'),patch.object(n,'directory_pin',return_value=(0,1000,0o700)),\
             patch.object(n,'pointer'),patch.object(n,'finance_reference_files',return_value=physical or self.physical):
            return n.verify_native_finance_reference(self.root,self.release,self.intent)
    def test_actual_observer_accepts_exact_synthetic_custody(self):
        result=self.observe(); self.assertEqual(result['status'],'completed'); self.assertEqual(len(result['bindingSha256']),64)
    def test_source_and_data_are_never_permission(self):
        self.ref['publisher']['origin']='source-lease'
        with self.assertRaises(ValueError): self.observe()
    def test_unknown_root_origin_refuses(self):
        self.intent['nativeFinanceOwnershipReceipt']['original']['kind']='logger-json'
        with self.assertRaises(ValueError): self.observe()
    def test_current_dual_cas_mismatch_refuses(self):
        with self.assertRaises(ValueError): self.observe(bad_dual=True)
    def test_original_physical_inode_or_mount_or_content_replacement_refuses(self):
        for key,value in [('identity',[99]*9),('mountId',99),('sha256','f'*64)]:
            changed=copy.deepcopy(self.physical); changed['input'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): self.observe(physical=changed)
    def test_source_consumer_mismatch_refuses(self):
        self.finance=b'changed source'
        with self.assertRaises(ValueError): self.observe()
    def test_unarmed_source_is_deferred_not_admitted(self):
        del self.intent['nativeFinanceReference']; self.assertEqual(self.observe()['status'],'deferred')
    def test_original_edge_replacement_refuses(self):
        self.intent['nativeFinanceOwnershipReceipt']['nativeFinanceOwnership']={}
        with self.assertRaises(ValueError): self.observe()
    def test_old_no_feature_cannot_adopt_new_reference(self):
        self.ir={'services':{},'volumes':{}}; self.intent['inputs']['stack.ir.json']=n.r.sha(n.r.frozen(self.ir).encode())
        with self.assertRaises(ValueError): self.observe()

if __name__=='__main__': unittest.main(verbosity=2)
