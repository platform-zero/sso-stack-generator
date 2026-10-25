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

if __name__=='__main__':unittest.main()
