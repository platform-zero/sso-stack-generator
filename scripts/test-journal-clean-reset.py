#!/usr/bin/env python3
"""Source-only canonical reset callback/evidence ordering, not data deletion proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-journal.py'
spec=importlib.util.spec_from_file_location('clean_journal_tests',SOURCE)
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)

def canonical(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(value): return hashlib.sha256(value).hexdigest()

class CleanJournal(unittest.TestCase):
    def setUp(self):
        self.root=Path('/model/root');self.release=self.root/'releases/selected'
        self.intent=self.root/'.install-intent.json';self.receipt=self.release/'installation-receipt.json'
        old=dict(schemaVersion=1,phase='retired-failed',release=str(self.release),steps=['preparing','failed','retired-failed'],previousRelease='/model/old')
        self.records={self.intent:old,self.receipt:old};self.events=[]
        self.fail_execute=self.bad_result=self.bad_evidence=self.drift=False
        self.expected_mode=self.bad_cold_claim=self.bad_default_preservation=False
        self.plan={'kind':'model-owned-synthetic-plan'};self.plan_sha=sha(canonical(self.plan));self.lease=object()
        self.lock=ModuleType('lock_owner');self.lock.lock_held=lambda root:self.events.append('lock')
        self.backend=ModuleType('reset_owner')
        self.backend.prior_completed_reset=self.prior_completed_reset
        self.backend.review_runtime_custody=lambda root,expected:{'cleanResetCustody':{'externalTrees':{}},'intentSha256':expected}
        self.backend.review=self.review;self.backend.issue_stopped_lease=self.issue
        self.backend.execute=self.execute;self.backend.read_file=self.evidence
        self.backend.strict=json.loads;self.backend.canonical=canonical;self.backend.sha=sha
        contexts=[patch.object(j,'directory'),patch.object(j,'read',side_effect=self.records.get),
          patch.object(j,'digest',side_effect=lambda path:sha(canonical(self.records[path]))),
          patch.object(j,'write',side_effect=self.write),
          patch.object(j.importlib.util,'spec_from_file_location',side_effect=self.load),
          patch.object(j.importlib.util,'module_from_spec',side_effect=lambda spec:spec.module),patch.dict(sys.modules)]
        for context in contexts: context.start();self.addCleanup(context.stop)
        self.expected=sha(canonical(old))

    def load(self,name,path):
        module=self.lock if path.name=='native-runtime-projection-owner.py' else self.backend
        return SimpleNamespace(name=name,module=module,loader=SimpleNamespace(exec_module=lambda module:None))
    def write(self,path,value): self.events.append('write');self.records[path]=value
    def prior_completed_reset(self,root,receipt):
        self.events.append('prior-history-only')
        if receipt.get('completeCleanReset') != {'model':True}: raise ValueError('model prior evidence refused')
    def review(self,root,expected,data_only=False):
        self.assertIs(data_only,self.expected_mode)
        self.plan=dict(self.plan,dataOnly=data_only);self.plan_sha=sha(canonical(self.plan))
        self.events.append('review');self.assertEqual(j.digest(self.intent),expected)
        self.assertEqual(self.records[self.intent],self.records[self.receipt])
        self.assertIn('cleanResetCustody',self.records[self.intent])
        return {'plan':self.plan,'planSha256':self.plan_sha}
    def issue(self,root,expected,plan,data_only=False):
        self.assertIs(data_only,self.expected_mode)
        self.events.append('lease');self.assertEqual(plan,self.plan_sha);return self.lease
    def execute(self,root,expected,plan,lease,data_only=False):
        self.assertIs(data_only,self.expected_mode)
        self.events.append('execute');self.assertIs(lease,self.lease)
        if self.fail_execute: raise ValueError('model deletion refusal')
        self.result=dict(schemaVersion=1,intentSha256=expected,planSha256=plan,
            phase='complete-owned-synthetic-data-only' if data_only else 'complete-owned-synthetic-clean',
            completeCleanReset=(data_only if self.bad_result else not data_only),
            defaultStorePreserved=not self.bad_default_preservation,
            rootfulStoreColdAcceptance=self.bad_cold_claim,
            requiredJournalTransition='journal-owner-exact-CAS-data-only-no-restart' if data_only else 'journal-owner-exact-CAS-retired-clean-no-restart',
            claimPrefix='.clean-reset-'+plan+'-'+'1'*32+'-')
        self.operation=dict(self.result,plan=self.plan)
        if self.drift: self.records[self.intent]=dict(self.records[self.intent],unexpected=True)
        return self.result
    def evidence(self,path,**kwargs):
        self.events.append('evidence')
        value=self.operation if path.name.endswith('-intent.json') else self.result
        if self.bad_evidence: value=dict(value,planSha256='0'*64)
        return canonical(value),{'modelPin':True}

    def test_canonical_seal_new_sha_lease_execute_evidence_then_retirement(self):
        proof=j.complete_clean_reset(self.root,self.expected)
        self.assertEqual(self.events,['lock','write','write','review','lease','execute','evidence','evidence','lock','write','write'])
        self.assertEqual(self.records[self.intent],self.records[self.receipt])
        self.assertEqual(self.records[self.intent]['phase'],'retired-clean')
        self.assertIsNone(self.records[self.intent]['previousRelease'])
        self.assertFalse(proof['applicationAcceptance']);self.assertFalse(proof['automaticRestart'])
        self.assertNotEqual(proof['intentSha256'],self.expected)
    def test_backend_failure_never_retires_or_restarts(self):
        self.fail_execute=True
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,self.expected)
        self.assertEqual(self.records[self.intent]['phase'],'retired-failed')
    def test_false_success_report_never_retires(self):
        self.bad_result=True
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,self.expected)
        self.assertEqual(self.records[self.intent]['phase'],'retired-failed')
    def test_changed_evidence_never_retires(self):
        self.bad_evidence=True
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,self.expected)
        self.assertEqual(self.records[self.intent]['phase'],'retired-failed')
    def test_post_execution_intent_drift_never_retires(self):
        self.drift=True
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,self.expected)
        self.assertEqual(self.records[self.receipt]['phase'],'retired-failed')
    def test_stale_cas_before_custody_publication(self):
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,'0'*64)
        self.assertEqual(self.events,['lock'])
    def test_retired_clean_cannot_replay(self):
        old=dict(self.records[self.intent],phase='retired-clean')
        self.records[self.intent]=self.records[self.receipt]=old
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,j.digest(self.intent))
        self.assertNotIn('execute',self.events)
    def test_authenticated_retired_clean_still_gets_new_review_lease_and_execution(self):
        old=dict(self.records[self.intent],phase='retired-clean',completeCleanReset={'model':True})
        self.records[self.intent]=self.records[self.receipt]=old
        proof=j.complete_clean_reset(self.root,j.digest(self.intent))
        self.assertIn('prior-history-only',self.events)
        self.assertEqual(self.events.count('review'),1);self.assertEqual(self.events.count('lease'),1)
        self.assertEqual(self.events.count('execute'),1);self.assertEqual(self.events.count('evidence'),2)
        self.assertFalse(proof['applicationAcceptance']);self.assertFalse(proof['dataCompatibilityProven'])
    def test_prior_clean_does_not_bypass_new_stopped_or_data_failure(self):
        old=dict(self.records[self.intent],phase='retired-clean',completeCleanReset={'model':True})
        self.records[self.intent]=self.records[self.receipt]=old;self.fail_execute=True
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,j.digest(self.intent))
        self.assertIn('lease',self.events);self.assertIn('execute',self.events);self.assertNotIn('evidence',self.events)
    def data_only_source(self):
        old=dict(self.records[self.intent],phase='retired-clean',previousRelease=None,completeCleanReset={'model':True})
        self.records[self.intent]=self.records[self.receipt]=old;self.expected_mode=True
        return j.digest(self.intent)
    def test_data_only_requires_new_lease_and_keeps_full_clean_history_unchanged(self):
        expected=self.data_only_source()
        proof=j.complete_clean_reset(self.root,expected,data_only=True)
        current=self.records[self.intent]
        self.assertEqual(current['completeCleanReset'],{'model':True})
        self.assertEqual(current['syntheticDataOnlyReset'],proof)
        self.assertEqual(current['phase'],'retired-clean')
        self.assertEqual(self.events.count('lease'),1);self.assertEqual(self.events.count('execute'),1)
        self.assertIn('prior-history-only',self.events)
        self.assertFalse(proof['rootfulStoreColdAcceptance']);self.assertFalse(proof['applicationAcceptance'])
        self.assertIs(self.result['completeCleanReset'],False)
        self.assertIs(self.operation['plan']['dataOnly'],True)
    def test_data_only_rejects_complete_clean_claim(self):
        expected=self.data_only_source();self.bad_result=True
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,expected,data_only=True)
        self.assertNotIn('syntheticDataOnlyReset',self.records[self.intent])
    def test_data_only_rejects_cold_store_credit(self):
        expected=self.data_only_source();self.bad_cold_claim=True
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,expected,data_only=True)
        self.assertNotIn('syntheticDataOnlyReset',self.records[self.intent])
    def test_data_only_requires_default_store_preservation(self):
        expected=self.data_only_source();self.bad_default_preservation=True
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,expected,data_only=True)
    def test_data_only_rejects_other_terminal_phase(self):
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,self.expected,data_only=True)
        self.assertNotIn('review',self.events);self.assertNotIn('lease',self.events)
    def test_data_only_rejects_non_boolean_mode(self):
        expected=self.data_only_source()
        with self.assertRaises(ValueError):j.complete_clean_reset(self.root,expected,data_only=1)
        self.assertNotIn('review',self.events)
    def test_missing_lock_refuses_before_record_read_or_backend(self):
        self.lock.lock_held=lambda root:(_ for _ in ()).throw(ValueError('missing inherited lock'))
        with self.assertRaises(ValueError): j.complete_clean_reset(self.root,self.expected)
        self.assertFalse(self.events)

if __name__=='__main__': unittest.main()
