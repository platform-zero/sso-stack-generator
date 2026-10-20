#!/usr/bin/env python3
"""Actual coordinator source, synthetic journal/adapters; NO host operations."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-install-inert.py'
s=importlib.util.spec_from_file_location('interrupted_installer',source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'root-private native journal fixture')
class Interrupted(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)/'journal';self.plan={'accounts':[{'name':'apps'}]}
  self.data={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'preparing','activationAuthorized':False,'installedUnits':list(range(190)),'venueReleasePhase':'inert-ready','venueDomainRuntimePhase':'inert-ready','venueRuntimeEnvPhase':'inert-ready','venueCompositeMode':'images-importing','status':'units-staged','venueCompositeImageInputSha256':'b'*64}
  self.save();self.ctx=patch.object(m,'context',return_value=(Path(self.tmp.name),self.p,self.plan));self.ctx.start();self.addCleanup(self.ctx.stop)
 def save(self):self.p.write_text(json.dumps(self.data));self.p.chmod(0o600)
 def finish_composite(self,*args):
  d=m.receipt(self.p);d.update(venueCompositeMode='retired-inert',status='managers-ready',retiredUnits=list(range(190)),graphCleared=['root','apps'],podmanImageCacheRetired=True);m.stage.write_ledger(self.p,d)
 def finish_installer(self,*args):
  d=m.receipt(self.p);self.assertEqual(d['venueInstallerPhase'],'retiring');self.assertNotEqual(d['venueInstallerPhase'],'inert-ready');d.update(venueInstallerPhase='retired-inert',status='retired-empty');m.stage.write_ledger(self.p,d);return {'status':'retired-inert'}
 def test_exact_abort_reuses_native_retirement_never_ready_or_activation(self):
  with patch.object(m.composite,'recover_failed_import',side_effect=self.finish_composite) as c,patch.object(m,'retire',side_effect=self.finish_installer) as r:
   result=m.retire_interrupted_import(None,None,None,self.p,m.stage.sha(self.p))
  c.assert_called_once();r.assert_called_once();self.assertTrue(result['retiredIncompletePreparation']);self.assertFalse(result['servicesStarted']);d=m.receipt(self.p);self.assertFalse(d['activationAuthorized']);self.assertEqual(d['venueInterruptedImportRetirement']['phase'],'retired-incomplete')
 def test_stale_cas_no_intent_or_native_mutation(self):
  before=self.p.read_bytes()
  with patch.object(m.composite,'recover_failed_import') as c,self.assertRaisesRegex(m.Refusal,'CAS changed'):m.retire_interrupted_import(None,None,None,self.p,'c'*64)
  c.assert_not_called();self.assertEqual(self.p.read_bytes(),before)
 def test_activation_partial_unit_transport_and_registry_are_refused(self):
  for key,value in [('venueInstallerVersion',2),('activationAuthorized',True),('installedUnits',list(range(189))),('venueStartPhase','starting'),('venueIngressPhase','inert-ready'),('venueRegistryPhase','preparing'),('venueBuildBasePhase','preparing')]:
   with self.subTest(key=key):
    original=dict(self.data);self.data[key]=value;self.save();before=self.p.read_bytes()
    with patch.object(m.composite,'recover_failed_import') as c,self.assertRaises(m.Refusal):m.retire_interrupted_import(None,None,None,self.p,m.stage.sha(self.p))
    c.assert_not_called();self.assertEqual(before,self.p.read_bytes());self.data=original
 def test_recovery_refusal_keeps_incomplete_intent_and_original_phase(self):
  with patch.object(m.composite,'recover_failed_import',side_effect=m.Refusal('foreign object')),patch.object(m,'retire') as r,self.assertRaisesRegex(m.Refusal,'foreign object'):m.retire_interrupted_import(None,None,None,self.p,m.stage.sha(self.p))
  r.assert_not_called();d=m.receipt(self.p);self.assertEqual(d['venueInstallerPhase'],'preparing');self.assertEqual(d['venueCompositeMode'],'images-importing');self.assertEqual(d['venueInterruptedImportRetirement']['phase'],'retiring-incomplete')
 def test_incomplete_native_graph_result_never_unwinds_private_inputs(self):
  with patch.object(m.composite,'recover_failed_import'),patch.object(m,'retire') as r,self.assertRaisesRegex(m.Refusal,'did not finish'):m.retire_interrupted_import(None,None,None,self.p,m.stage.sha(self.p))
  r.assert_not_called();self.assertEqual(m.receipt(self.p)['venueInstallerPhase'],'preparing')
 def test_malformed_intent_and_input_hash_refused_before_mutation(self):
  for extra in ({'venueInterruptedImportRetirement':{}},{'venueCompositeImageInputSha256':'not-a-hash'}):
   original=dict(self.data);self.data.update(extra);self.save();before=self.p.read_bytes()
   with self.subTest(extra=extra),patch.object(m.composite,'recover_failed_import') as c,self.assertRaises(m.Refusal):m.retire_interrupted_import(None,None,None,self.p,m.stage.sha(self.p))
   c.assert_not_called();self.assertEqual(before,self.p.read_bytes());self.data=original
if __name__=='__main__':unittest.main()
