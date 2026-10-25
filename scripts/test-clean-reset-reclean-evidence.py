#!/usr/bin/env python3
"""Prior reset evidence models, never stopped leases or installed/reset proof."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/host-clean-reset.py'
spec=importlib.util.spec_from_file_location('reclean_evidence_models',SOURCE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PriorEvidence(unittest.TestCase):
    def setUp(self):
        self.root=Path('/model/root');self.release=self.root/'releases/model'
        inputs={name:'a'*64 for name in m.CORE}
        self.plan=dict(kind='complete-owned-synthetic-clean-reset',root=str(self.root),scope=str(m.SCOPE),
            authority=dict(release=str(self.release),sourceInputs={name:dict(sha256=value) for name,value in inputs.items()}))
        plan_sha=m.sha(m.canonical(self.plan));attempt=plan_sha+'-'+'1'*32
        self.path=self.root/'.host-clean-reset'/(attempt+'-result.json')
        self.intent_path=self.path.with_name(attempt+'-intent.json')
        self.result=dict(schemaVersion=1,kind='complete-owned-synthetic-clean-reset',phase='complete-owned-synthetic-clean',
            completeCleanReset=True,requiredJournalTransition='journal-owner-exact-CAS-retired-clean-no-restart',
            intentSha256='b'*64,planSha256=plan_sha,claimPrefix='.clean-reset-'+attempt+'-')
        self.operation=dict(self.result,plan=self.plan)
        self.receipt=dict(phase='retired-clean',release=str(self.release),inputs=inputs,
            completeCleanReset=dict(intentSha256='b'*64,planSha256=plan_sha,resultPath=str(self.path),
                resultSha256=m.sha(m.canonical(self.result)),applicationAcceptance=False,
                rootfulStoreColdAcceptance=False,automaticRestart=False,dataCompatibilityProven=False))
        self.patch=patch.object(m,'read_file',side_effect=self.read);self.patch.start();self.addCleanup(self.patch.stop)
    def read(self,path,**kwargs):
        self.assertEqual(kwargs,dict(private=True,gid=0))
        if path==self.path:return m.canonical(self.result),{'model':'result-pin'}
        if path==self.intent_path:return m.canonical(self.operation),{'model':'intent-pin'}
        raise FileNotFoundError('model missing source-owned evidence')
    def validate(self):return m.prior_completed_reset(self.root,self.receipt)
    def test_authenticated_history_returns_pins_not_operation_authority(self):
        result=self.validate();self.assertEqual(set(result),{'result','intent'})
        self.assertEqual(result['result']['stat'],{'model':'result-pin'})
        self.assertNotIn('lease',result);self.assertNotIn('plan',result)
    def test_missing_history_and_nonfalse_credit_refused(self):
        for changes in ({'completeCleanReset':None},{'phase':'active'}):
            with self.subTest(changes=changes),self.assertRaises(m.Refusal):
                m.prior_completed_reset(self.root,{**self.receipt,**changes})
        for key in ('applicationAcceptance','automaticRestart','rootfulStoreColdAcceptance','dataCompatibilityProven'):
            for value in (True,0,None):
                bad=copy.deepcopy(self.receipt);bad['completeCleanReset'][key]=value
                with self.subTest(key=key,value=value),self.assertRaises(m.Refusal):m.prior_completed_reset(self.root,bad)
    def test_path_escape_or_foreign_operation_refused(self):
        for value in ('/model/foreign/'+self.path.name,str(self.path.parent/'other-result.json')):
            bad=copy.deepcopy(self.receipt);bad['completeCleanReset']['resultPath']=value
            with self.assertRaises(m.Refusal):m.prior_completed_reset(self.root,bad)
    def test_changed_result_and_boolean_schema_refused(self):
        self.result['schemaVersion']=True
        with self.assertRaises(m.Refusal):self.validate()
        self.receipt['completeCleanReset']['resultSha256']=m.sha(m.canonical(self.result))
        with self.assertRaises(m.Refusal):self.validate()
    def test_changed_intent_plan_scope_source_or_claim_refused(self):
        original=copy.deepcopy(self.operation)
        for key,value in (('root','/foreign'),('scope','/foreign'),('kind','foreign')):
            self.operation=copy.deepcopy(original);self.operation['plan'][key]=value
            with self.assertRaises(m.Refusal):self.validate()
        self.operation=copy.deepcopy(original);self.operation['claimPrefix']='foreign'
        with self.assertRaises(m.Refusal):self.validate()
        self.operation=copy.deepcopy(original);self.receipt['inputs'][m.CORE[0]]='c'*64
        with self.assertRaises(m.Refusal):self.validate()
    def test_source_change_not_hidden_by_rehashed_history(self):
        self.plan['authority']['release']='/model/root/releases/foreign'
        # Rehashing just one historical field cannot rebind the operation/result.
        self.receipt['completeCleanReset']['planSha256']=m.sha(m.canonical(self.plan))
        with self.assertRaises(m.Refusal):self.validate()

class MappedReadonlyCache(unittest.TestCase):
    def setUp(self):
        self.image='a'*64;self.original='b'*64;self.clone='c'*64
        self.base=dict(id=self.original,parent='d'*64,created='model',**{'diff-digest':'sha256:'+'e'*64,
            'diff-size':100,'compressed-diff-digest':'sha256:'+'f'*64,'compressed-size':50,'compression':1})
        self.layer=dict(self.base,id=self.clone,uidmap=[dict(container_id=0,host_id=780,size=1),dict(container_id=1,host_id=2000000,size=65536)],
            gidmap=[dict(container_id=0,host_id=780,size=1),dict(container_id=1,host_id=2000000,size=65536)])
        self.images=[{'id':self.image,'layer':self.original,'mapped-layers':[self.clone]}]
        services={name:dict(image='registry.invalid/'+name,rootlessDomain='apps' if name=='seafile' else 'platform') for name in ('seafile','mariadb','valkey')}
        rows=[dict(name=name,user='model-'+name) for name in ('apps','platform')]
        registry={('model-'+value['rootlessDomain'])+'|'+value['image']:'sha256:'+self.image for value in services.values()}
        self.body=m.canonical(registry);self.pin={'fixture':'source-stat'}
        self.quadlets={};selection={}
        for name,service in services.items():
            scope='rootless-'+service['rootlessDomain'];relative='quadlet/'+scope+'/webservices-'+name+'.container'
            body=('[Container]\nImage='+service['image']+'\n').encode();self.quadlets[Path('/model/release')/relative]=body
            selection.setdefault(scope,dict(files={}))['files'][relative]=dict(sha256=m.sha(body))
            # IR spellings need not equal renderer-canonical registry references.
            service['image']='unqualified/'+name
        self.selection=dict(release=Path('/model/release'),ir=dict(services=services),rows=rows,
            actors={name:dict(uid=uid,gid=uid,start=start) for name,uid,start in (('apps',780,2000000),('platform',781,2100000))},
            pin=dict(selection=selection,sourceInputs={'site/global.settings/registry-image-ids.json':dict(sha256=m.sha(self.body),stat=self.pin)}))
        patcher=patch.object(m,'read_file',side_effect=self.read);patcher.start();self.addCleanup(patcher.stop)
    def read(self,path,**kwargs):
        if path in self.quadlets:return self.quadlets[path],{'fixture':'quadlet-stat'}
        return self.body,self.pin
    def classify(self):return m.mapped_readonly_layers(self.selection,[self.base,self.layer],self.images)
    def test_exact_scoped_image_clone_is_only_retained_not_cold_or_execution_proof(self):
        result=self.classify();self.assertEqual(result[self.clone]['uid'],780)
        self.assertTrue(result[self.clone]['retainedReadOnlyCache']);self.assertFalse(result[self.clone]['coldStoreAcceptance'])
    def test_unknown_image_or_unindexed_clone_has_no_owner_exception(self):
        self.images[0]['id']='0'*64;self.assertEqual(self.classify(),{})
        self.images[0]['id']=self.image;self.images[0]['mapped-layers']=[];self.assertEqual(self.classify(),{})
        self.assertEqual(m.mapped_readonly_layers(None,[self.base,self.layer],self.images),{})
    def test_foreign_or_boolean_namespace_refused(self):
        original=copy.deepcopy(self.layer)
        for key,value in (('host_id',1000),('size',True),('container_id',True)):
            self.layer=copy.deepcopy(original);self.layer['uidmap'][0][key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):self.classify()
    def test_changed_payload_parent_or_writable_metadata_refused(self):
        original=copy.deepcopy(self.layer)
        for key,value in (('diff-digest','sha256:'+'0'*64),('parent','0'*64),('flags',{'writable':True}),('diff-size',True)):
            self.layer=copy.deepcopy(original);self.layer[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):self.classify()
    def test_registry_source_drift_or_missing_actor_refused(self):
        self.selection['pin']['sourceInputs']['site/global.settings/registry-image-ids.json']['sha256']='0'*64
        with self.assertRaises(m.Refusal):self.classify()
    def test_closed_historical_selector_envelope_preserves_release_receipt_binding(self):
        scopes=self.selection['pin']['selection'];self.selection['receipt']={'phase':'retired-clean'}
        self.selection['pin']['intentSha256']='1'*64
        wrapper=dict(bundle=str(self.selection['release']),inputs={},receipt={'phase':'retired-clean','sha256':'1'*64},scopes=scopes)
        self.selection['pin']['selection']=wrapper
        self.assertIn(self.clone,self.classify())
        for key,value in (('bundle','/foreign'),('receipt',{'phase':'active','sha256':'1'*64})):
            original=wrapper[key];wrapper[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):self.classify()
            wrapper[key]=original
    def test_changed_or_unselected_quadlet_has_no_cache_authority(self):
        path=next(iter(self.quadlets));self.quadlets[path]+=b'Image=registry.invalid/foreign\n'
        with self.assertRaises(m.Refusal):self.classify()
        self.selection['pin']['selection']={}
        with self.assertRaises(m.Refusal):self.classify()
    def test_indexed_clone_requires_exact_layer_and_unique_declared_map(self):
        self.images[0]['mapped-layers']=['0'*64]
        with self.assertRaises(m.Refusal):self.classify()
        self.images[0]['mapped-layers']=[self.clone,self.clone]
        with self.assertRaises(m.Refusal):self.classify()

class EmptyLogNamespaces(unittest.TestCase):
    def setUp(self):
        self.caddy=dict(module='caddy',placement='rootful',rootlessDomain=None,
            volumes=[str(m.SCOPE/'volumes/_logs/caddy')+':/var/log/caddy'])
        self.selection=dict(receipt={'phase':'retired-clean'},ir=dict(services={'caddy':self.caddy}))
    def test_only_three_exact_empty_source_parent_roles_not_fixture_or_data_authority(self):
        profiles=m.empty_rootful_log_namespaces(self.selection)
        self.assertEqual(len(profiles),3)
        leaf=profiles[str(m.SCOPE/'volumes/_logs/caddy')]
        self.assertEqual(leaf['children'],[]);self.assertEqual((leaf['uid'],leaf['gid'],leaf['mode']),(0,1000,0o2770))
        self.assertEqual(leaf['acl'],leaf['defaultAcl'])
    def test_source_namespace_phase_or_module_drift_has_no_role(self):
        for key,value in (('module','foreign'),('placement','rootless'),('rootlessDomain','apps')):
            old=self.caddy[key];self.caddy[key]=value
            self.assertEqual(m.empty_rootful_log_namespaces(self.selection),{});self.caddy[key]=old
        self.selection['receipt']['phase']='active'
        self.assertEqual(m.empty_rootful_log_namespaces(self.selection),{})
    def test_foreign_or_duplicate_mount_cannot_authorize_namespace(self):
        self.caddy['volumes']=['/foreign:/var/log/caddy']
        self.assertEqual(m.empty_rootful_log_namespaces(self.selection),{})
        self.caddy['volumes']=[str(m.SCOPE/'volumes/_logs/caddy')+':/var/log/caddy']*2
        self.assertEqual(m.empty_rootful_log_namespaces(self.selection),{})

class PriorNetworkProvenance(unittest.TestCase):
    def setUp(self):
        self.root=Path('/model/root');self.sources={'webservices_safe':{'model':'source'}}
        self.mapping=dict(inspect={'name':'webservices_safe','network_interface':'podman9','id':'e'*64},
            bridge='podman9',absenceAttested=True,kernel=None,kernelIdentity=None)
        self.plan=dict(root=str(self.root),scope=str(m.SCOPE),rootfulNetworkSources=self.sources,
            rootfulDefault={'networks':{'webservices_safe':self.mapping}})
        self.plan_sha=m.sha(m.canonical(self.plan));self.attempt=self.plan_sha+'-'+'1'*32
        self.operation=dict(intentSha256='a'*64,planSha256=self.plan_sha,plan=self.plan)
        self.authenticated={'fixture':'authenticated-original-completion'}
        self.selection=dict(root=self.root,receipt=dict(phase='retired-clean',completeCleanReset=dict(
            resultPath=str(self.root/'.host-clean-reset'/(self.attempt+'-result.json')),intentSha256='a'*64,planSha256=self.plan_sha)),
            pin=dict(intentSha256='b'*64,priorCompletedReset=self.authenticated))
        patches=[patch.object(m.os,'open',return_value=100),patch.object(m.os,'close'),patch.object(m,'root_directory'),
            patch.object(m.os,'listdir',return_value=[self.attempt+'-intent.json']),
            patch.object(m,'read_at',side_effect=lambda *a,**kw:(m.canonical(self.operation),{'model':'pin'})),
            patch.object(m,'prior_completed_reset',return_value=self.authenticated)]
        for item in patches:item.start();self.addCleanup(item.stop)
    def recover(self):return m.prior_network_mappings(99,self.selection,self.sources)
    def test_verified_history_recovers_inspect_identity_only_not_old_clean_state(self):
        result=self.recover();self.assertEqual(result,{'webservices_safe':self.mapping})
        self.assertNotIn('lease',result);self.assertNotIn('plan',result)
    def test_unverified_history_wrong_source_or_hash_has_no_mapping(self):
        self.selection['pin']['priorCompletedReset']={'foreign':'pin'}
        with self.assertRaises(m.Refusal):self.recover()
        self.selection['pin']['priorCompletedReset']=self.authenticated
        self.assertEqual(m.prior_network_mappings(99,self.selection,{'foreign':'source'}),{})
        self.operation['plan']['scope']='/foreign'
        with self.assertRaises(m.Refusal):self.recover()
    def test_inspect_provenance_survives_a_new_successful_reset_without_replaying_it(self):
        self.plan['rootfulDefault']['networks']={'webservices_safe':dict(self.mapping,inspect=None)}
        self.plan['rootfulNetworkInspectionProvenance']={'webservices_safe':self.mapping}
        digest=m.sha(m.canonical(self.plan));attempt=digest+'-'+'2'*32
        self.operation['planSha256']=digest
        self.selection['receipt']['completeCleanReset'].update(planSha256=digest,
            resultPath=str(self.root/'.host-clean-reset'/(attempt+'-result.json')))
        with patch.object(m.os,'listdir',return_value=[attempt+'-intent.json']):
            self.assertEqual(self.recover(),{'webservices_safe':self.mapping})
    def test_nonhistorical_wrong_intent_is_not_accepted(self):
        self.selection['receipt']['phase']='retired-failed'
        self.assertEqual(self.recover(),{})

if __name__=='__main__':unittest.main()
