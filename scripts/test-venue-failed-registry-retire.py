#!/usr/bin/env python3
"""SOURCE/fake-only exact failed-pull retirement. No root/service/storage access."""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

path=Path(__file__).resolve().parents[1]/'ops/host-admin/retire-failed-venue-registry-image.py'
spec=importlib.util.spec_from_file_location('failed_registry_retire_source',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ACTUAL='sha256:'+'8'*64;SELECTED='sha256:'+'c'*64;VERIFIED='sha256:'+'1'*64;KEY='SYNTHETIC-user|docker.io/library/example:tag';RAW=b'{}';SHA=hashlib.sha256(RAW).hexdigest()

class RetirementSourceFake(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name);self.ledger=self.base/'ledger.json';self.ledger.write_bytes(RAW);self.ledger.chmod(0o600);self.present=True;self.aliases=[KEY.partition('|')[2]];self.commands=[];self.writes=[];self.probes=[];self.foreign=False;self.fail_after_delete=False;self.cas=SHA;self.raw_epoch=RAW;self.idle=True;self.rootok=True
  self.data={'venueRegistryPhase':'preparing','venueRegistryPlan':{KEY:SELECTED,'SYNTHETIC-user|'+VERIFIED:VERIFIED},'venueRegistryFrozenSha256':'frozen','venueRegistryPending':KEY,'venueRegistryVerified':{'SYNTHETIC-user|'+VERIFIED:VERIFIED}}
  self.source={'imageIds':copy.deepcopy(self.data['venueRegistryPlan']),'frozenRegistrySha256':'frozen'}
  def require_idle(plan):m.require(self.idle)
  def probe(bundle,plan,data,expected):
   self.probes.append(copy.deepcopy(expected));actual={VERIFIED}|({ACTUAL}if self.present else set());m.require(not self.foreign and set(expected.values())==actual)
   if self.fail_after_delete and not self.present:raise m.Refused()
   return {'SYNTHETIC-user':(self.base,['FAKE-PODMAN'])},{}
  def run(argv,timeout):
   self.commands.append(argv);self.assertNotIn('--force',argv)
   if argv[1:3]==['image','inspect']:return NS(returncode=0,stdout=json.dumps(self.aliases))
   self.assertEqual(argv,['FAKE-PODMAN','image','rm',ACTUAL]);self.present=False;return NS(returncode=0,stdout='')
  def write(p,data):
   self.writes.append(copy.deepcopy(data));self.raw_epoch=(json.dumps(data,sort_keys=True,indent=2)+'\n').encode();self.cas=hashlib.sha256(self.raw_epoch).hexdigest()
  lifecycle=NS(host_context=lambda b,p:NS(),lifecycle=lambda c:contextlib.nullcontext())
  self.registry=NS(journal=lambda *args:(self.ledger,self.data,{},self.source),load=lambda *args:lifecycle,
   stage=NS(sha=lambda p:self.cas,write_ledger=write),composite=NS(units=NS(units_idle=require_idle)),
   command_graphs=lambda *args:{'SYNTHETIC-user':(self.base,['FAKE-PODMAN'])},pulled=lambda *args:ACTUAL if self.present else None,
   reserve=lambda:None,probe=probe,graph=NS(run=run))
  self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  for name,value in [('root_admission',lambda:m.require(self.rootok)),('protected_tree',lambda p:None),('protected_file',lambda p,n:self.raw_epoch if Path(p)==self.ledger else RAW),('load_registry',lambda b:self.registry)]:self.stack.enter_context(patch.object(m,name,value))
 def go(self,**kw):return m.retire(self.base,'SYNTHETIC-selector',self.ledger,kw.get('reviewed',hashlib.sha256(self.raw_epoch).hexdigest()),kw.get('provenance',SHA),kw.get('actual',ACTUAL))
 def refuse_no_delete(self,**kw):
  with self.assertRaises(m.Refused):self.go(**kw)
  self.assertFalse(any(x[1:3]==['image','rm']for x in self.commands))
 def test_exact_drift_delete_no_pin_promotion_or_activation(self):
  result=self.go();self.assertFalse(self.present);self.assertEqual(len(self.commands),4);self.assertEqual(len(self.writes),3);self.assertEqual(self.writes[0]['venueRegistryFailedPendingRetirement']['phase'],'intent');self.assertIn('venueRegistryPending',self.writes[0]);self.assertNotIn('venueRegistryPending',self.data);self.assertEqual(self.data['venueRegistryVerified'],{'SYNTHETIC-user|'+VERIFIED:VERIFIED});self.assertEqual(self.data['venueRegistryPlan'],self.source['imageIds']);self.assertEqual(result['registryPhase'],'preparing');self.assertFalse(result['activationAuthorized']);self.assertEqual(result['acceptedIntegratedInstalls'],0);self.assertEqual(self.data['venueRegistryFailedPendingRetirement']['selectedImageId'],SELECTED)
 def test_wrong_initial_cas(self):self.refuse_no_delete(reviewed='0'*64)
 def test_changed_locked_cas(self):self.cas='0'*64;self.refuse_no_delete()
 def test_wrong_provenance(self):self.refuse_no_delete(provenance='0'*64)
 def test_root_gate(self):self.rootok=False;self.refuse_no_delete()
 def test_not_idle(self):self.idle=False;self.refuse_no_delete()
 def test_registry_complete_not_partial(self):self.data['venueRegistryPhase']='inert-ready';self.refuse_no_delete()
 def test_started_target(self):self.data['venueStartPhase']='failed-quarantined';self.refuse_no_delete()
 def test_source_plan_changed(self):self.data['venueRegistryPlan']={};self.refuse_no_delete()
 def test_progress_changed(self):self.data['venueRegistryVerified']['SYNTHETIC-user|'+VERIFIED]=ACTUAL;self.refuse_no_delete()
 def test_pending_already_verified(self):self.data['venueRegistryVerified'][KEY]=SELECTED;self.refuse_no_delete()
 def test_missing_pending(self):self.data.pop('venueRegistryPending');self.refuse_no_delete()
 def test_actual_selected_not_drift(self):self.refuse_no_delete(actual=SELECTED)
 def test_malformed_actual(self):self.refuse_no_delete(actual='8'*64)
 def test_foreign_graph(self):self.foreign=True;self.refuse_no_delete()
 def test_absence_without_intent(self):self.present=False;self.refuse_no_delete()
 def test_extra_alias(self):self.aliases.append('SYNTHETIC-foreign:tag');self.refuse_no_delete()
 def test_wrong_alias(self):self.aliases=['SYNTHETIC-other:tag'];self.refuse_no_delete()
 def test_postdelete_failure_retains_intent_and_exact_resume_no_second_rm(self):
  self.fail_after_delete=True
  with self.assertRaises(m.Refused):self.go()
  self.assertFalse(self.present);self.assertEqual(self.data['venueRegistryFailedPendingRetirement']['phase'],'delete-issued');self.assertIn('venueRegistryPending',self.data);self.fail_after_delete=False;self.go();self.assertEqual(sum(x[1:3]==['image','rm']for x in self.commands),1)
 def test_completed_operation_not_replayed(self):self.go();self.refuse_no_delete_after_completion()
 def refuse_no_delete_after_completion(self):
  before=len(self.commands)
  with self.assertRaises(m.Refused):self.go()
  self.assertEqual(len(self.commands),before)
 def test_wrong_intent_source(self):
  self.fail_after_delete=True
  with self.assertRaises(m.Refused):self.go()
  self.data['venueRegistryFailedPendingRetirement']['operationSourceSha256']='0'*64;self.refuse_no_delete_after_completion()
 def test_wrong_intent_identity(self):
  self.fail_after_delete=True
  with self.assertRaises(m.Refused):self.go()
  self.data['venueRegistryFailedPendingRetirement']['retiredImageId']='sha256:'+'9'*64;self.refuse_no_delete_after_completion()

 def test_late_inventory_cas_change_no_write_or_rm(self):
  probe=self.registry.probe
  def changed(*a):
   result=probe(*a);self.cas='e'*64;return result
  self.registry.probe=changed;self.refuse_no_delete();self.assertEqual(self.writes,[])
 def test_late_alias_after_intent_no_rm(self):
  write=self.registry.stage.write_ledger
  def changed(*a):write(*a);self.aliases.append('SYNTHETIC-foreign:tag')
  self.registry.stage.write_ledger=changed;self.refuse_no_delete()
 def test_late_alias_after_issued_marker_no_rm(self):
  write=self.registry.stage.write_ledger
  def changed(*a):
   write(*a)
   if len(self.writes)==2:self.aliases.append('SYNTHETIC-foreign:tag')
  self.registry.stage.write_ledger=changed;self.refuse_no_delete()
 def test_unknown_postwrite_cas_not_adopted(self):
  write=self.registry.stage.write_ledger
  def changed(*a):write(*a);self.cas='e'*64
  self.registry.stage.write_ledger=changed;self.refuse_no_delete()
 def test_postdelete_reappearance_never_second_rm(self):
  self.fail_after_delete=True
  with self.assertRaises(m.Refused):self.go()
  self.assertEqual(self.data['venueRegistryFailedPendingRetirement']['phase'],'delete-issued');self.fail_after_delete=False;self.present=True;before=len(self.commands)
  with self.assertRaises(m.Refused):self.go()
  self.assertFalse(any(x[1:3]==['image','rm']for x in self.commands[before:]))
 def test_postdelete_cas_change_prevents_final_overwrite(self):
  probe=self.registry.probe
  def changed(*a):
   result=probe(*a)
   if not self.present:self.cas='e'*64
   return result
  self.registry.probe=changed
  with self.assertRaises(m.Refused):self.go()
  self.assertEqual(len(self.writes),2);self.assertEqual(self.data['venueRegistryFailedPendingRetirement']['phase'],'delete-issued')
 def test_late_final_alias_time_cas_change_prevents_rm(self):
  run=self.registry.graph.run
  def changed(*a,**kw):
   result=run(*a,**kw)
   if len(self.commands)==3:self.cas='e'*64
   return result
  self.registry.graph.run=changed;self.refuse_no_delete()

class ImportClosureSourceFake(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.bundle=Path(self.tmp.name);self.ops=self.bundle/'ops';self.ops.mkdir();(self.ops/'venue-registry-images.py').write_text('BENIGN_SOURCE_ONLY=True\n');self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close);self.stack.enter_context(patch.object(m,'protected_tree',lambda p:None));self.stack.enter_context(patch.object(m,'protected_file',lambda p,n:Path(p).read_bytes()))
 def test_clean_modeled_protected_source_executes(self):self.assertTrue(m.load_registry(self.bundle).BENIGN_SOURCE_ONLY)
 def test_timestamp_valid_writable_cache_rejects_before_execution(self):
  import importlib._bootstrap_external as bytecode
  source=self.ops/'venue-registry-images.py';cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir();s=source.stat();cache.write_bytes(bytecode._code_to_timestamp_pyc(compile('UNVERIFIED_CACHE_EXECUTED=True\n',str(source),'exec'),int(s.st_mtime),s.st_size));cache.chmod(0o666)
  with self.assertRaises(m.Refused):m.load_registry(self.bundle)
 def test_transitive_nested_cache_refuses(self):
  nested=self.ops/'nested';nested.mkdir();(nested/'__pycache__').mkdir()
  with self.assertRaises(m.Refused):m.load_registry(self.bundle)
 def test_legacy_bytecode_refuses(self):
  (self.ops/'SYNTHETIC.pyc').write_bytes(b'not-code')
  with self.assertRaises(m.Refused):m.load_registry(self.bundle)
 def test_alternate_cache_prefix_refuses(self):
  with patch.object(m.sys,'pycache_prefix','SYNTHETIC-cache'):
   with self.assertRaises(m.Refused):m.load_registry(self.bundle)

class ProtectedReaderSourceFake(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)/'own-public-fixture';self.p.write_bytes(b'public');self.p.chmod(0o600);self.realstat=os.fstat
  def modeled_root(fd):
   s=self.realstat(fd);values={k:getattr(s,k)for k in ['st_mode','st_nlink','st_size','st_dev','st_ino','st_gid','st_mtime_ns','st_ctime_ns']};return NS(**values,st_uid=0)
  self.patch=patch.object(m.os,'fstat',modeled_root);self.patch.start();self.addCleanup(self.patch.stop)
 def test_positive_actual_own_bytes_root_metadata_explicit_model(self):self.assertEqual(m.protected_file(self.p,64),b'public')
 def test_bound_before_read(self):
  with patch.object(m.os,'read')as read:
   with self.assertRaises(m.Refused):m.protected_file(self.p,5)
   read.assert_not_called()
 def test_hardlink(self):
  os.link(self.p,self.p.parent/'own-hardlink')
  with self.assertRaises(m.Refused):m.protected_file(self.p,64)
 def test_symlink(self):
  alias=self.p.parent/'own-symlink';alias.symlink_to(self.p)
  with self.assertRaises(OSError):m.protected_file(alias,64)
 def test_group_write(self):
  self.p.chmod(0o620)
  with self.assertRaises(m.Refused):m.protected_file(self.p,64)
 def test_growth_during_read(self):
  read=os.read;changed=False
  def grow(fd,n):
   nonlocal changed
   if not changed:
    changed=True
    with self.p.open('ab')as f:f.write(b'x')
   return read(fd,n)
  with patch.object(m.os,'read',grow):
   with self.assertRaises(m.Refused):m.protected_file(self.p,64)
 def test_duplicate_json(self):
  with self.assertRaises(m.Refused):json.loads('{"duplicate":1,"duplicate":2}',object_pairs_hook=m.unique)

if __name__=='__main__':unittest.main()
