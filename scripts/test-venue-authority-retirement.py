#!/usr/bin/env python3
"""Synthetic false-capability retirement; never native host/guest proof."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-start-quarantine.py'
s=importlib.util.spec_from_file_location('authority_retirement',source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'protected root fixture')
class Retirement(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name);self.runtime=self.root/'run';self.runtime.mkdir(mode=0o700)
  self.capability=self.runtime/'runtime-authority.json';self.context=NS(runtime=self.runtime,namespace='p0test-r1',digest='b'*64,data={'sourceProvenanceSha256':'c'*64})
  self.plan={'accounts':[{'name':'p0test-r1-fixture'+str(i),'uid':3200+i} for i in range(7)]}
  retired=str(self.root/'absent-owned-path');self.ledger=self.root/'ledger.json'
  self.state={'plan':self.plan,'status':'retired-empty','venueInstallerVersion':2,'venueInstallerPhase':'retired-inert','activationAuthorized':False,
              'venueStartHostContextSha256':self.context.digest,'venueOwnedReset':{'phase':'empty-owned'},'graphCleared':['root']+[a['name'] for a in self.plan['accounts']],
              'managerStopped':[a['name'] for a in self.plan['accounts']],'createdPaths':[retired],'pathIdentities':{retired:{'dev':1,'ino':2}}}
  self.ledger.write_text(json.dumps(self.state));self.ledger.chmod(0o600)
  self.receipt={'schemaVersion':2,'namespace':self.context.namespace,'hostContextSha256':self.context.digest,'sourceProvenanceSha256':'c'*64,'phase':'failed-quarantined','activationAuthorized':False}
  self.save_receipt()
  for p in [patch.object(m.stage,'owned_plan',return_value=self.plan),patch.object(m,'host_context',return_value=self.context),
            patch.object(m.stage.pwd,'getpwnam',side_effect=KeyError),patch.object(m.stage.pwd,'getpwuid',side_effect=KeyError)]:p.start();self.addCleanup(p.stop)
 def save_receipt(self):self.capability.write_text(json.dumps(self.receipt));self.capability.chmod(0o600)
 def retire(self):return m.retire_authority(self.root,'selector',self.ledger,m.stage.sha(self.ledger))
 def test_exact_false_capability_removed_after_full_retired_proof(self):
  self.assertEqual(self.retire()['status'],'retired-runtime-authority');self.assertFalse(self.capability.exists())
  state=json.loads(self.ledger.read_text());self.assertEqual(state['venueRuntimeAuthorityRetired']['contextSha256'],self.context.digest)
  self.assertFalse(state['activationAuthorized']);self.assertNotIn('venueRuntimeAuthorityRetireIntent',state)
 def test_boot_lost_missing_capability_requires_positive_monotonic_reset(self):
  self.capability.unlink();self.state.update(venueStartPhase='failed-quarantined',venueStartMonotonicUsec=1000000)
  self.ledger.write_text(json.dumps(self.state))
  with patch.object(m.stage,'boot_observation',return_value={'bootId':'new-boot','monotonicUsec':1000,'runTmpfs':True}):
   self.assertEqual(self.retire()['status'],'retired-runtime-authority')
  self.assertTrue(json.loads(self.ledger.read_text())['venueRuntimeAuthorityRetired']['bootLost'])
 def test_missing_capability_on_same_boot_does_not_qualify(self):
  self.capability.unlink()
  with patch.object(m.stage,'boot_observation',return_value={'bootId':'same-boot','monotonicUsec':1000,'runTmpfs':True}):
   with self.assertRaises(m.Refusal):self.retire()
 def retire_directory(self):return m.retire_runtime_directory(self.root,'selector',self.ledger,m.stage.sha(self.ledger))
 def test_capability_must_be_retired_before_directory_operation(self):
  with self.assertRaises(m.Refusal):self.retire_directory()
  self.assertTrue(self.capability.exists());self.assertTrue(self.runtime.exists())
 def test_empty_old_control_lease_directory_exactly_retires(self):
  self.retire();self.assertEqual(self.retire_directory()['status'],'retired-empty-control-runtime');self.assertFalse(self.runtime.exists())
 def test_unreviewed_control_runtime_content_blocks_all_directory_deletion(self):
  self.retire();(self.runtime/'human-work').write_text('preserve')
  with self.assertRaises(m.Refusal):self.retire_directory()
  self.assertEqual((self.runtime/'human-work').read_text(),'preserve')
 def test_directory_removal_crash_resumes_only_from_original_intent(self):
  self.retire();rmdir=Path.rmdir
  def interrupted(path,*args,**kwargs):
   rmdir(path,*args,**kwargs)
   if path==self.runtime:raise OSError('synthetic crash after rmdir')
  with patch.object(Path,'rmdir',new=interrupted):
   with self.assertRaises(OSError):self.retire_directory()
  self.assertFalse(self.runtime.exists());self.assertEqual(self.retire_directory()['status'],'retired-empty-control-runtime')
 def test_live_capability_is_never_removed(self):
  self.receipt['activationAuthorized']=True;self.save_receipt()
  with self.assertRaises(m.Refusal):self.retire()
  self.assertTrue(self.capability.exists());self.assertNotIn('venueRuntimeAuthorityRetireIntent',json.loads(self.ledger.read_text()))
 def test_reused_uid_blocks_before_capability_removal(self):
  with patch.object(m.stage.pwd,'getpwuid',return_value=NS(pw_uid=3200)):
   with self.assertRaisesRegex(m.Refusal,'reused'):self.retire()
  self.assertTrue(self.capability.exists())
 def test_unlink_crash_resumes_only_from_saved_exact_intent(self):
  unlink=Path.unlink
  def interrupted(path,*args,**kwargs):
   unlink(path,*args,**kwargs)
   if path==self.capability:raise OSError('synthetic crash after unlink')
  with patch.object(Path,'unlink',new=interrupted):
   with self.assertRaises(OSError):self.retire()
  self.assertFalse(self.capability.exists());self.assertIn('venueRuntimeAuthorityRetireIntent',json.loads(self.ledger.read_text()))
  self.assertEqual(self.retire()['status'],'retired-runtime-authority')
if __name__=='__main__':unittest.main()
