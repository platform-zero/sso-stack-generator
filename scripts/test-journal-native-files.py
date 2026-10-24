#!/usr/bin/env python3
"""Source-only journal-to-file-owner callback ordering; not installed proof."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-journal.py'
spec=importlib.util.spec_from_file_location('file_journal_tests',SOURCE)
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)

def raw(value):return (json.dumps(value,sort_keys=True)+'\n').encode()

class NativeFiles(unittest.TestCase):
 def setUp(self):
  self.root=Path('/model/root');self.release=self.root/'releases/new'
  self.intent=self.root/'.install-intent.json';self.receipt=self.release/'installation-receipt.json'
  old=dict(schemaVersion=1,phase='preparing',release=str(self.release),inputs={'model':'pin'})
  self.records={self.intent:old,self.receipt:old};self.events=[];self.closed=0
  self.fail_prepare=self.fail_publish=self.drift=self.bad_proof=False
  self.owner=SimpleNamespace(o=SimpleNamespace(lock_held=lambda root:self.events.append('lock')),
   _sessions={},prepare_custody=self.prepare,project_and_handoff=self.publish)
  for context in (patch.object(j,'native_file_owner',return_value=self.owner),patch.object(j,'directory'),
   patch.object(j,'read',side_effect=self.records.get),patch.object(j,'digest',side_effect=self.digest),
   patch.object(j,'write',side_effect=self.write)):
   context.start();self.addCleanup(context.stop)
 def digest(self,path):return hashlib.sha256(raw(self.records[path])).hexdigest()
 def write(self,path,value):self.events.append('write');self.records[path]=value
 def close(self):self.closed+=1
 def prepare(self,root,release,intent):
  self.events.append('prepare')
  if self.fail_prepare:raise ValueError('model preparation refusal')
  self.owner._sessions[str(root),str(release)]=SimpleNamespace(close=self.close)
  if self.drift:self.records[self.intent]=dict(intent,unexpected=True)
  return {'modelOriginalFDs':'retained'}
 def publish(self,root,release,intent):
  self.events.append('publish')
  self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(intent['nativeUnitFileCustody'],{'modelOriginalFDs':'retained'})
  try:
   if self.fail_publish:raise ValueError('model publication refusal')
   return dict(kind='native-selected-unit-files',status='completed',release=str(release),inputs=intent['inputs'],
    intentSha256=self.digest(self.intent),receiptSha256=self.digest(self.receipt),
    activationAuthorized=self.bad_proof,readinessAuthorized=False)
  finally:self.owner._sessions.pop((str(root),str(release))).close()
 def test_dual_custody_then_same_process_publish_then_dual_completion(self):
  result=j.install_selected_files(self.root,self.release)
  self.assertEqual(self.events,['lock','prepare','write','write','publish','write','write'])
  self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(self.records[self.intent]['nativeUnitFiles'],result)
  self.assertFalse(result['activationAuthorized']);self.assertEqual(self.closed,1)
 def test_existing_custody_cannot_replay(self):
  for name in ('nativeUnitFileCustody','nativeUnitFiles'):
   with self.subTest(name=name):
    value=dict(self.records[self.intent],**{name:{}})
    self.records[self.intent]=self.records[self.receipt]=value
    with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertNotIn('prepare',self.events)
 def test_divergent_receipt_refuses_before_publication(self):
  self.records[self.receipt]=dict(self.records[self.receipt],different=True)
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertEqual(self.events,['lock'])
 def test_preparation_refusal_no_journal_changes(self):
  self.fail_prepare=True
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertNotIn('write',self.events)
 def test_preparation_cas_drift_closes_retained_fds_without_seal(self):
  self.drift=True
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertNotIn('write',self.events);self.assertEqual(self.closed,1)
 def test_publication_failure_retains_preparing_custody_not_completion(self):
  self.fail_publish=True
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertIn('nativeUnitFileCustody',self.records[self.intent])
  self.assertNotIn('nativeUnitFiles',self.records[self.intent]);self.assertEqual(self.closed,1)
 def test_forged_activation_claim_is_not_recorded(self):
  self.bad_proof=True
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertNotIn('nativeUnitFiles',self.records[self.intent])
 def test_only_preparing_can_publish(self):
  value=dict(self.records[self.intent],phase='active');self.records[self.intent]=self.records[self.receipt]=value
  with self.assertRaises(ValueError):j.install_selected_files(self.root,self.release)
  self.assertNotIn('prepare',self.events)
 def test_cli_rejects_combined_recovery_and_publication(self):
  with patch.object(j.os,'geteuid',return_value=0),patch.object(sys,'argv',['journal','--root',str(self.root),'--retire-failed','a'*64,'--install-selected-files']):
   with self.assertRaises(SystemExit) as error:j.main()
   self.assertEqual(error.exception.code,2)

class RootfulEnvironment(unittest.TestCase):
 prepare=NativeFiles.prepare
 close=NativeFiles.close
 digest=NativeFiles.digest
 write=NativeFiles.write
 def setUp(self):
  NativeFiles.setUp(self)
  self.owner.p=SimpleNamespace(encoded=raw,sha=lambda value:hashlib.sha256(value).hexdigest())
  self.owner.copy_environment=self.publish
  context=patch.object(j,'rootful_environment_owner',return_value=self.owner);context.start();self.addCleanup(context.stop)
 def publish(self,root,release,intent):
  self.events.append('publish');self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(intent['rootfulEnvCustody'],{'modelOriginalFDs':'retained'})
  try:
   if self.fail_publish:raise ValueError('model rootful publication refusal')
   return dict(kind='rootful-persistent-environment',status='completed',release=str(release),inputs=intent['inputs'],
    sourceCustodySha256=self.owner.p.sha(raw(intent['rootfulEnvCustody'])),stateStore=str(root/'runtime-env'),
    runtimeDeferred=True,activationAuthorized=False,readinessAuthorized=self.bad_proof,removeUnselected=False,files={})
  finally:self.owner._sessions.pop((str(root),str(release))).close()
 def test_rootful_dual_custody_copy_then_dual_handoff(self):
  proof=j.project_rootful_environment(self.root,self.release)
  self.assertEqual(self.events,['lock','prepare','write','write','publish','write','write'])
  self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(self.records[self.intent]['rootfulEnvironmentStoreHandoff'],proof);self.assertEqual(self.closed,1)
 def test_rootful_refusal_preserves_custody_not_completion(self):
  self.fail_publish=True
  with self.assertRaises(ValueError):j.project_rootful_environment(self.root,self.release)
  self.assertIn('rootfulEnvCustody',self.records[self.intent]);self.assertNotIn('rootfulEnvironmentStoreHandoff',self.records[self.intent])
  self.assertEqual(self.closed,1)
 def test_rootful_prepare_drift_closes_fds_before_any_seal(self):
  self.drift=True
  with self.assertRaises(ValueError):j.project_rootful_environment(self.root,self.release)
  self.assertNotIn('write',self.events);self.assertEqual(self.closed,1)
 def test_rootful_readiness_permission_claim_refused(self):
  self.bad_proof=True
  with self.assertRaises(ValueError):j.project_rootful_environment(self.root,self.release)
  self.assertNotIn('rootfulEnvironmentStoreHandoff',self.records[self.intent])
 def test_rootful_completion_not_replayable(self):
  j.project_rootful_environment(self.root,self.release)
  with self.assertRaises(ValueError):j.project_rootful_environment(self.root,self.release)
  self.assertEqual(self.closed,1)

class RuntimeEnvironmentUnits(unittest.TestCase):
 prepare=NativeFiles.prepare
 close=NativeFiles.close
 digest=NativeFiles.digest
 write=NativeFiles.write
 def setUp(self):
  NativeFiles.setUp(self)
  self.owner.p=SimpleNamespace(encoded=raw,sha=lambda value:hashlib.sha256(value).hexdigest())
  self.owner.publish=self.publish;self.owner.seal_running_copies=self.observe
  context=patch.object(j,'runtime_environment_unit_owner',return_value=self.owner);context.start();self.addCleanup(context.stop)
 def publish(self,root,release,intent):
  self.events.append('publish');self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(intent['nativeRuntimeEnvUnitCustody'],{'modelOriginalFDs':'retained'})
  try:
   if self.fail_publish:raise ValueError('model adjunct refusal')
   return dict(kind='native-runtime-env-units',status='completed',release=str(release),inputs=intent['inputs'],
    custodySha256=self.owner.p.sha(raw(intent['nativeRuntimeEnvUnitCustody'])),
    intentSha256=self.digest(self.intent),receiptSha256=self.digest(self.receipt),
    runtimeDeferred=True,updaterOwned=self.bad_proof,activationAuthorized=False,readinessAuthorized=False)
  finally:self.owner._sessions.pop((str(root),str(release))).close()
 def observe(self,root,release,intent):
  self.events.append('observe')
  if self.fail_publish:raise ValueError('model Root actual-runtime observation refusal')
  if self.drift:self.records[self.intent]=dict(intent,unexpected=True)
  return dict(kind='root-runtime-copy-observation',status='completed',release=str(release),inputs=intent['inputs'],
   intentSha256=self.digest(self.intent),receiptSha256=self.digest(self.receipt),copies={},bootId='model',
   activationAuthorized=False,readinessAuthorized=False,resetAuthorized=False,journalWritten=self.bad_proof)
 def test_dual_adjunct_custody_then_same_process_publish(self):
  proof=j.publish_runtime_environment_units(self.root,self.release)
  self.assertEqual(self.events,['lock','prepare','write','write','publish','write','write'])
  self.assertEqual(self.records[self.intent]['nativeRuntimeEnvUnits'],proof);self.assertEqual(self.closed,1)
 def test_adjunct_refusal_keeps_pending_custody_not_completion(self):
  self.fail_publish=True
  with self.assertRaises(ValueError):j.publish_runtime_environment_units(self.root,self.release)
  self.assertIn('nativeRuntimeEnvUnitCustody',self.records[self.intent]);self.assertNotIn('nativeRuntimeEnvUnits',self.records[self.intent])
 def test_adjunct_updater_authority_refused(self):
  self.bad_proof=True
  with self.assertRaises(ValueError):j.publish_runtime_environment_units(self.root,self.release)
  self.assertNotIn('nativeRuntimeEnvUnits',self.records[self.intent])
 def test_adjunct_custody_not_replayable(self):
  j.publish_runtime_environment_units(self.root,self.release)
  with self.assertRaises(ValueError):j.publish_runtime_environment_units(self.root,self.release)
 def test_runtime_copies_observed_then_dual_recorded(self):
  proof=j.seal_runtime_environment_copies(self.root,self.release)
  self.assertEqual(self.events,['lock','observe','write','write'])
  self.assertEqual(self.records[self.intent],self.records[self.receipt])
  self.assertEqual(self.records[self.intent]['nativeRuntimeEnvironmentCopies'],proof)
 def test_runtime_observation_cas_drift_refused(self):
  self.drift=True
  with self.assertRaises(ValueError):j.seal_runtime_environment_copies(self.root,self.release)
  self.assertNotIn('write',self.events)
 def test_runtime_observation_refusal_not_committed(self):
  self.fail_publish=True
  with self.assertRaises(ValueError):j.seal_runtime_environment_copies(self.root,self.release)
  self.assertNotIn('write',self.events)
 def test_runtime_observation_cannot_claim_own_journal_write(self):
  self.bad_proof=True
  with self.assertRaises(ValueError):j.seal_runtime_environment_copies(self.root,self.release)
  self.assertNotIn('write',self.events)

class StopSelection(unittest.TestCase):
 """Callback models only: source/FD filesystem checks have separate suites."""
 def setUp(self):
  self.root=Path('/model/root');self.release=self.root/'releases/new';self.previous=self.root/'releases/old'
  self.scope=Path('/model/scope');self.inputs={'model':'pin'};self.expected={'scope':{'root':str(self.scope)}}
  self.current={'target':str(self.release),'identity':[1,2,0,0]}
  names=('platform','apps','homeassistant','finance','ci-runner','workloads','test-runners')
  ids={name:(780+i,'svc-'+name) for i,name in enumerate(names)}
  self.accounts={name:dict(uid=uid,user=user,gid=uid,home='/home/'+user,subuidStart=uid*65536)
   for name,(uid,user) in ids.items()}
  self.db={v['user']:SimpleNamespace(pw_uid=v['uid'],pw_gid=v['gid'],pw_name=v['user'],pw_dir=v['home'])
   for v in self.accounts.values()}
  self.old_source={'old':'sealed'}
  self.marker=raw(self.expected);self.old=dict(release=str(self.release),phase='failed',inputs=self.inputs,
   nativeUnitFileCustody=dict(accounts=self.accounts,inputs=self.inputs,scopeMarkerSha256=hashlib.sha256(self.marker).hexdigest(),
    stopOnlyPrevious=dict(release=str(self.previous),source=self.old_source)),
   nativeUnitFiles=dict(status='completed',release=str(self.release),inputs=self.inputs))
  self.records={self.root/'.install-intent.json':raw(self.old),self.release/'installation-receipt.json':raw(self.old),
   self.scope/'.marker':self.marker}
  self.plan={'scopes':{'rootful':{'units':['webservices-old-network.service','webservices-new.service']}}}
  self.native=SimpleNamespace(IDENTITIES=ids,source_plan=lambda *a,**kw:self.old_source,
   validate_installed=lambda *a:{'plan':self.plan})
  @contextmanager
  def directory(path):yield path
  p=SimpleNamespace(directory=directory,read_at=lambda fd,name,private:(self.records[fd/name],{}),
   current_record=lambda fd:self.current,strict=json.loads,INPUTS={'model'},canonical=Path,relative=lambda v:v,
   sha=lambda value:hashlib.sha256(value).hexdigest(),custody_record=lambda fd:{'acl':False,'defaultAcl':False})
  pwd=SimpleNamespace(getpwnam=lambda name:self.db[name],getpwuid=lambda uid:next(v for v in self.db.values() if v.pw_uid==uid))
  grp=SimpleNamespace(getgrnam=lambda name:SimpleNamespace(gr_gid=self.db[name].pw_gid),
   getgrgid=lambda gid:SimpleNamespace(gr_name=next(k for k,v in self.db.items() if v.pw_gid==gid)))
  storage=SimpleNamespace(authority=lambda release:(self.scope,object(),self.expected),MARKER='.marker',
   namespace_root_id=lambda user:self.db[user].pw_uid*65536)
  self.owner=SimpleNamespace(p=p,native=self.native,storage=storage,
   o=SimpleNamespace(lock_held=lambda root:None,root_directory=lambda *a,**k:None,open_absolute=lambda *args:(self.scope,{}),pwd=pwd,grp=grp))
  for context in (patch.object(j,'native_file_owner',return_value=self.owner),patch.object(j,'directory'),
   patch.object(j,'fingerprint',return_value=self.inputs),patch.object(j,'standalone_binding',return_value=self.expected),
   patch.object(j.os,'close'),patch.object(j.os,'fstat',return_value=None)):
   context.start();self.addCleanup(context.stop)
 def records_value(self,value):
  self.records[self.root/'.install-intent.json']=self.records[self.release/'installation-receipt.json']=raw(value)
 def test_exact_source_union_read_only(self):
  before=dict(self.records)
  self.assertEqual(j.native_stop_selection(self.root,self.release),self.plan);self.assertEqual(before,self.records)
 def test_stop_only_old_current_is_accepted_without_restart_grant(self):
  self.current['target']=str(self.previous)
  self.assertEqual(j.native_stop_selection(self.root,self.release),self.plan)
 def test_foreign_current_refused(self):
  self.current['target']='/foreign/release'
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_retired_selected_source_refused(self):
  for phase in ('retired-clean','retired-failed'):
   with self.subTest(phase=phase):
    self.records_value(dict(self.old,phase=phase))
    with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_absent_selected_file_completion_refused(self):
  value=dict(self.old);value.pop('nativeUnitFiles');self.records_value(value)
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_receipt_drift_refused(self):
  self.records[self.release/'installation-receipt.json']=raw(dict(self.old,changed=True))
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_marker_hash_drift_refused(self):
  value=json.loads(raw(self.old));value['nativeUnitFileCustody']['scopeMarkerSha256']='0'*64;self.records_value(value)
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_old_source_drift_refused(self):
  self.native.source_plan=lambda *a,**kw:{'different':'old'}
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_old_source_escape_refused(self):
  value=json.loads(raw(self.old));value['nativeUnitFileCustody']['stopOnlyPrevious']['release']='/foreign/release';self.records_value(value)
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_actor_nss_home_drift_refused(self):
  self.db['svc-platform'].pw_dir='/foreign/home'
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_actor_subrange_drift_refused(self):
  self.owner.storage.namespace_root_id=lambda user:1
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_stop_plan_failure_does_not_fallback_to_prefix(self):
  def refuse(*args):raise ValueError('model native source refusal')
  self.native.validate_installed=refuse
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)
 def test_record_changes_after_selection_refused(self):
  def drift(*args):
   self.records[self.root/'.install-intent.json']=raw(dict(self.old,changed=True));return {'plan':self.plan}
  self.native.validate_installed=drift
  with self.assertRaises(ValueError):j.native_stop_selection(self.root,self.release)

if __name__=='__main__':unittest.main()
