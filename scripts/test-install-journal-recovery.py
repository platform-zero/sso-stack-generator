#!/usr/bin/env python3
"""Focused canonical dual-publication unit models; NOT source/stopped permits.

Genuine native producer/observer integration is exercised separately by
 test-native-recovery-owner.py. This fixture isolates publication ordering/CAS.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BASE=Path(__file__).absolute().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,BASE/file);module=importlib.util.module_from_spec(spec)
    exec(compile((BASE/file).read_bytes(),str(BASE/file),'exec'),module.__dict__);return module
j=load('focused_recovery_journal','runtime-generator/podman-ops/install-journal.py')
a=load('focused_recovery_ofd','scripts/lib/stackctl-operations.py')
FINANCE_LOADER=j.native_finance_owner
sha=lambda body:hashlib.sha256(body).hexdigest()

class Publication(unittest.TestCase):
    def setUp(self):
        previous=os.umask(0o077);self.addCleanup(os.umask,previous)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.release=self.root/'releases/r';self.release.mkdir(parents=True,mode=0o700)
        self.intent=dict(schemaVersion=1,phase='active',release=str(self.release),inputs={},steps=['active'])
        self.paths=[self.root/'.install-intent.json',self.release/'installation-receipt.json']
        for path in self.paths:path.write_text(json.dumps(self.intent)+'\n');path.chmod(0o600)
        self.lock=open(self.root/'.install.lock','w+b');fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB);self.addCleanup(self.lock.close)
        self.operations=SimpleNamespace(body=lambda path,**kwargs:path.read_bytes())
        def directory(path):
            self.assertTrue(path.is_relative_to(self.root));self.assertFalse(path.stat().st_mode&0o077)
        patch.object(j,'directory',side_effect=directory).start()
        patch.object(j,'read',side_effect=lambda path:json.loads(path.read_bytes()) if path.exists() else None).start()
        self.addCleanup(patch.stopall)
        test=self
        class Lease:
            def __init__(self):self.intent=dict(test.intent);self.release=test.release;self.custody={'fixtureOnly':True};self.closed=False;self.bound=False
            def guard(self):
                if test.paths[0].read_bytes()!=test.paths[1].read_bytes():raise ValueError('fixture dual CAS changed')
            def close(self):self.closed=True
            def bind_published(self,value):
                for path in test.paths:test.assertEqual(json.loads(path.read_bytes()),value)
                self.bound=True
        self.lease=Lease()
        def lock_held(root):self.assertIn('FLOCK',Path('/proc/self/fdinfo/9').read_text())
        self.lease.api=SimpleNamespace(o=SimpleNamespace(lock_held=lock_held))
        self.owner=SimpleNamespace(capture=lambda *args:self.lease,h=SimpleNamespace(sha=sha),execute=lambda lease:{'fixtureOnly':True})
        patch.object(j,'native_recovery_owner',return_value=self.owner).start()
    def call(self):
        with a.canonical_lock_fd(self.lock.fileno()):return j.prepare_native_recovery(self.root,sha(self.paths[0].read_bytes()),{},self.operations)
    def test_publish_only_new_custody_in_both_records_without_phase_rewrite(self):
        result=self.call();self.assertTrue(result.bound)
        expected=dict(self.intent,recoveryCustody=self.lease.custody)
        for path in self.paths:self.assertEqual(json.loads(path.read_bytes()),expected)
        self.assertEqual(self.paths[0].read_bytes(),self.paths[1].read_bytes())
    def test_existing_custody_drift_is_not_rebased(self):
        self.lease.intent['recoveryCustody']={'old':True}
        with self.assertRaisesRegex(ValueError,'drift'):self.call()
        self.assertTrue(self.lease.closed)
    def test_dual_mismatch_never_publishes_or_returns_lease(self):
        self.paths[1].write_text('{}\n')
        with self.assertRaises(ValueError):self.call()
        self.assertTrue(self.lease.closed);self.assertFalse(self.lease.bound)
    def test_crash_between_writes_preserves_inert_mismatch_no_rollback(self):
        original=j.write;calls=[]
        def write(path,value):
            calls.append(path)
            if len(calls)==2:raise OSError('synthetic power loss')
            original(path,value)
        with patch.object(j,'write',side_effect=write),self.assertRaises(OSError):self.call()
        self.assertTrue(self.lease.closed);self.assertFalse(self.lease.bound)
        self.assertNotEqual(self.paths[0].read_bytes(),self.paths[1].read_bytes())

class FinancePublication(unittest.TestCase):
    """Typed finance publication/carry MODELS, not native origin acceptance."""
    def setUp(self):
        Publication.setUp(self)
        self.intent['phase']='starting';self.events=[];self.closed=False;self.action='arm'
        for path in self.paths:path.write_text(json.dumps(self.intent)+'\n')
        (self.root/'current').symlink_to(self.release)
        @contextlib.contextmanager
        def directory(path):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:yield fd
            finally:os.close(fd)
        def read_at(fd,name,**kwargs):
            file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            try:return os.pread(file,1024*1024,0),None
            finally:os.close(file)
        p=SimpleNamespace(directory=directory,read_at=read_at,strict=json.loads,sha=sha,
            current_record=lambda fd:{'target':str(self.release),'identity':[0,0,0,0]})
        reader=SimpleNamespace(p=p,o=self.lease.api.o)
        patch.object(j,'native_file_owner',return_value=reader).start()
        patch.object(j,'native_stop_selection',return_value={'fixtureOnly':True}).start()
        test=self;key=object()
        class RootFinanceReference:
            def __init__(self,issued,prepared):
                if issued is not key:raise ValueError('fixture issuer key required')
                self.prepared=prepared;self.record=dict(schemaVersion=1,kind='root-native-finance-reference',status='completed')
            def recheck(self,value):
                test.events.append('reference-check');test.assertEqual(value,self.prepared)
                test.assertEqual(test.paths[0].read_bytes(),test.paths[1].read_bytes())
                test.assertEqual(json.loads(test.paths[0].read_bytes()),value)
        class RootFinanceResult:
            def __init__(self,issued):
                if issued is not key:raise ValueError('fixture issuer key required')
                self.field='financeOwnershipCustody' if test.action=='arm' else 'nativeFinanceOwnershipReceipt'
                self.record=dict(schemaVersion=1,kind='root-finance-arm' if test.action=='arm' else 'root-native-finance-ownership',
                                 status='armed' if test.action=='arm' else 'completed')
            def recheck(self):test.events.append('result-check')
            def publish(self,value):
                test.events.append('leaf-publish')
                test.assertEqual(test.paths[0].read_bytes(),test.paths[1].read_bytes())
                test.assertEqual(json.loads(test.paths[0].read_bytes()),value)
                return RootFinanceReference(key,value)
            def close(self):test.closed=True
        self.result=RootFinanceResult(key)
        self.finance=SimpleNamespace(RootFinanceResult=RootFinanceResult,RootFinanceReference=RootFinanceReference,
            transact=lambda *args:self.result)
        patch.object(j,'native_finance_owner',return_value=self.finance).start()
        write=j.write
        def observed(path,value):
            self.events.append(('receipt' if path==self.paths[1] else 'intent')+('-reference' if 'nativeFinanceReference' in value else '-result'))
            write(path,value)
        self.writer=patch.object(j,'write',side_effect=observed).start()
    def call(self):
        with a.canonical_lock_fd(self.lock.fileno()):return j.publish_native_finance(self.root,self.release,self.action)
    def test_selected_finance_loader_checks_original_bundle_and_complete_actual_ops_bytes(self):
        ops=self.release/'ops';ops.mkdir(mode=0o700)
        source=ops/'native-finance-ownership.py';source.write_bytes(b'fixtureOnly = True\n')
        body=json.dumps({'liveOps':{'ops/native-finance-ownership.py':sha(source.read_bytes())}}).encode()
        (self.release/'bundle.json').write_bytes(body);old={'inputs':{'bundle.json':sha(body)}}
        native=SimpleNamespace(strict=json.loads,read_file=lambda path:path.read_bytes(),children=lambda path:os.listdir(path),sha=sha)
        with patch.object(j,'native_file_owner',return_value=SimpleNamespace(native=native)):
            self.assertTrue(FINANCE_LOADER(self.release,old).fixtureOnly)
            source.write_bytes(b'fixtureOnly = False\n')
            with self.assertRaisesRegex(ValueError,'source SHA'):FINANCE_LOADER(self.release,old)
            source.write_bytes(b'fixtureOnly = True\n');(ops/'unclaimed').write_bytes(b'not selected')
            with self.assertRaisesRegex(ValueError,'namespace'):FINANCE_LOADER(self.release,old)
            (ops/'unclaimed').unlink();(self.release/'bundle.json').write_bytes(body+b' ')
            with self.assertRaisesRegex(ValueError,'bundle input SHA'):FINANCE_LOADER(self.release,old)

    def test_typed_result_then_actual_leaf_then_typed_reference_both_dual_records(self):
        result=self.call();self.assertIn('nativeFinanceReference',result);self.assertTrue(self.closed)
        self.assertEqual(self.events,['result-check','receipt-result','intent-result','leaf-publish','reference-check','receipt-reference','intent-reference'])
        self.assertEqual(self.paths[0].read_bytes(),self.paths[1].read_bytes())
    def test_json_cannot_replace_either_process_local_typed_result(self):
        self.finance.transact=lambda *args:{'field':'financeOwnershipCustody','record':{}}
        with self.assertRaises(ValueError):self.call()
        self.assertEqual(self.events,[])
    def test_final_reference_partial_write_is_retained_not_rolled_back(self):
        original=self.writer.side_effect;count=0
        def fail(path,value):
            nonlocal count
            count+=1
            if count==4:raise OSError('synthetic final reference power loss')
            original(path,value)
        self.writer.side_effect=fail
        with self.assertRaises(OSError):self.call()
        self.assertTrue(self.closed);self.assertNotEqual(self.paths[0].read_bytes(),self.paths[1].read_bytes())
        self.assertIn('nativeFinanceReference',json.loads(self.paths[1].read_bytes()))
        self.assertNotIn('nativeFinanceReference',json.loads(self.paths[0].read_bytes()))
    def test_capture_uses_original_receipt_field_without_arming_again(self):
        self.action='capture';self.result.field='nativeFinanceOwnershipReceipt'
        result=self.call();self.assertIn('nativeFinanceOwnershipReceipt',result);self.assertNotIn('financeOwnershipCustody',result)
    def test_nonstarting_and_mismatched_records_refuse_before_leaf(self):
        self.intent['phase']='active'
        for path in self.paths:path.write_text(json.dumps(self.intent)+'\n')
        with self.assertRaises(ValueError):self.call()
        self.assertEqual(self.events,[])
        self.intent['phase']='starting';self.paths[0].write_text(json.dumps(self.intent)+'\n')
        with self.assertRaises(ValueError):self.call()
        self.assertEqual(self.events,[])
    def test_original_receipt_and_reference_carry_into_preparing_and_resume_only_as_provenance(self):
        original=dict(schemaVersion=1,kind='root-native-finance-ownership',status='completed',
            activationAuthorized=False,readinessAuthorized=False,journalWritten=False,original={'fixtureOnly':True})
        reference=dict(schemaVersion=1,kind='root-native-finance-reference',status='completed')
        self.intent.update(phase='active',nativeFinanceOwnershipReceipt=original,nativeFinanceReference=reference)
        for path in self.paths:path.write_text(json.dumps(self.intent)+'\n')
        target=self.root/'releases/second';bundle=self.root/'bundle';bundle.mkdir(mode=0o700)
        with patch.object(j,'fingerprint',return_value={}):
            first=j.update(self.root,bundle,target,'preparing')
            second=j.update(self.root,bundle,target,'preparing',sha(self.paths[0].read_bytes()))
        self.assertEqual(first['nativeFinanceOwnershipReceipt'],original);self.assertEqual(first['nativeFinanceReference'],reference)
        self.assertEqual(second['nativeFinanceOwnershipReceipt'],original);self.assertEqual(second['nativeFinanceReference'],reference)
        self.assertEqual(first['phase'],'preparing');self.assertNotIn('financeOwnershipCustody',first)

if __name__=='__main__':unittest.main(verbosity=2)
