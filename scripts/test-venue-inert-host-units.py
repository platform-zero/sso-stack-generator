#!/usr/bin/env python3
"""Ordinary USER TEMP models of never-started v1 host-unit retirement.
Root metadata is explicitly mocked, NOT authenticated. No real systemd/native dirs.
"""
import copy,importlib.util,json,os,unittest
from pathlib import Path
from unittest.mock import patch
fixture=Path(__file__).with_name('test-venue-host-unit-retirement.py');spec=importlib.util.spec_from_file_location('inert_unit_fixture',fixture);base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);m=base.m
class InertHostUnits(unittest.TestCase):
 def setUp(self):
  # All accesses are to own fixture; these stand-ins model protected root metadata.
  for function in ['stat','lstat']:
   actual=getattr(Path,function)
   def fake(path,*args,_actual=actual,**kwargs):values=list(_actual(path,*args,**kwargs));values[4]=0;return os.stat_result(values)
   p=patch.object(Path,function,new=fake);p.start();self.addCleanup(p.stop)
  actual_fstat=os.fstat
  def fstat(fd):values=list(actual_fstat(fd));values[4]=0;return os.stat_result(values)
  p=patch.object(m.os,'fstat',side_effect=fstat);p.start();self.addCleanup(p.stop)
  base.Units.setUp(self);self.capability.unlink();self.state.update(venueInstallerVersion=1,venueRegistryPreparationAbandoned=True,venueRegistryPhase='retired-inert',venueRegistryFailedPendingRetirement={'phase':'retired-drifted-pending'},installedUnits=[{'dev':1,'ino':i+1,'path':'/fixture/unit-'+str(i)}for i in range(190)],retiredUnits=['/fixture/unit-'+str(i)for i in range(190)]);self.persist()
 native=base.Units.native
 retire=base.Units.retire
 def persist(self):self.ledger.write_text(json.dumps(self.state));self.ledger.chmod(0o600)
 def test_exact_v1_removes_three_inactive_units_without_creating_capability(self):
  result=self.retire();self.assertEqual(result['retiredExactInactiveUnits'],3);self.assertTrue(result['runtimeAuthorityAbsentNeverStarted']);self.assertNotIn('runtimeAuthorityRetainedFalse',result);self.assertFalse(self.capability.exists());self.assertTrue(all(not p.exists()for p in self.paths));d=json.loads(self.ledger.read_text());self.assertEqual(d['venueInstallerVersion'],1);self.assertFalse(d['activationAuthorized']);self.assertEqual(d['venueHostUnitsRetirement']['neverStartedInstallerVersion'],1);self.assertEqual(self.commands[-1],['systemctl','daemon-reload'])
 def test_never_started_predicate_typed_negative_matrix(self):
  changes={'venueInstallerVersion':True,'activationAuthorized':0,'venueStartPhase':None,'venueRegistryPreparationAbandoned':1,'venueRegistryPhase':'preparing','venueRegistryFailedPendingRetirement':{'phase':'delete-issued'},'venueRegistryPending':None,'installedUnits':[],'retiredUnits':['duplicate']*190}
  for key,value in changes.items():
   with self.subTest(key=key):s=copy.deepcopy(self.state);s[key]=value;self.assertFalse(m.never_started_host_unit_retirement(s))
 def test_wrong_installed_identity_and_mismatched_path_refuse(self):
  for key,value in [('dev',True),('ino',0),('path','/foreign/unit'),('extra','unexpected')]:
   with self.subTest(key=key):s=copy.deepcopy(self.state);s['installedUnits'][0][key]=value;self.assertFalse(m.never_started_host_unit_retirement(s))
 def test_required_common_graph_env_stage_guards_refuse_without_unlink(self):
  for key,value in [('status','units-staged'),('venueInstallerPhase','inert-ready'),('venueCompositeMode','inert-ready'),('venueRuntimeEnvPhase','inert-ready'),('graphCleared',['root'])]:
   with self.subTest(key=key):saved=copy.deepcopy(self.state);self.state[key]=value;self.persist();self.commands.clear()
   with self.assertRaises(m.Refusal):self.retire()
   self.assertTrue(all(p.exists()for p in self.paths));self.state=saved;self.persist()
 def test_even_false_runtime_authority_refuses_v1_no_unlinks(self):
  self.capability.write_text(json.dumps({'activationAuthorized':False}));self.capability.chmod(0o600)
  with self.assertRaisesRegex(m.Refusal,'runtime authority or foreign'):self.retire()
  self.assertTrue(all(p.exists()for p in self.paths));self.assertFalse(self.commands)
 def test_foreign_runtime_file_refuses_without_unlink(self):
  (self.runtime/'foreign').write_text('synthetic')
  with self.assertRaisesRegex(m.Refusal,'runtime authority or foreign'):self.retire()
  self.assertTrue(all(p.exists()for p in self.paths))
 def test_authored_unit_unchanged_refusal_preserves_all(self):
  self.paths[-1].write_text('synthetic human edits')
  with self.assertRaisesRegex(m.Refusal,'authored/foreign'):self.retire()
  self.assertTrue(all(p.exists()for p in self.paths))
 def test_active_unit_unchanged_refusal_preserves_all(self):
  self.active=True
  with self.assertRaisesRegex(m.Refusal,'active/enabled'):self.retire()
  self.assertTrue(all(p.exists()for p in self.paths))
 def test_wrong_cas_refuses_before_commands(self):
  with self.assertRaisesRegex(m.Refusal,'exact retiring-ledger'):m.retire_host_units(self.root,'selector',self.ledger,'0'*64)
  self.assertFalse(self.commands);self.assertTrue(all(p.exists()for p in self.paths))
 def test_legacy_v2_false_receipt_behavior_retained(self):
  self.state['venueInstallerVersion']=2;self.capability.write_text(json.dumps({'schemaVersion':2,'namespace':'p0test-r1','hostContextSha256':'b'*64,'phase':'failed-quarantined','activationAuthorized':False}));self.capability.chmod(0o600);self.persist();result=self.retire();self.assertTrue(result['runtimeAuthorityRetainedFalse']);self.assertNotIn('runtimeAuthorityAbsentNeverStarted',result);self.assertTrue(self.capability.exists())
if __name__=='__main__':unittest.main()
