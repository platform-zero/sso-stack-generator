#!/usr/bin/env python3
"""Pure classification: a reboot never permits adopting/replacing /run paths."""
import importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-owned-stage.py'
s=importlib.util.spec_from_file_location('boot_lost_paths',source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class BootLost(unittest.TestCase):
 def setUp(self):
  self.plan={'prefix':'p0test-r1','roots':{'runtime':'/run/p0test-r1','runroot':'/run/p0test-r1-podman','data':'/mnt/private-owned'},'accounts':[{'name':'fixture'+str(i)} for i in range(7)]}
  self.state={'venueInstallerVersion':2,'venueInstallerPhase':'retiring','activationAuthorized':False,'venueOwnedReset':{'phase':'empty-owned'},
              'venueStartMonotonicUsec':1000000,'createdPaths':list(self.plan['roots'].values()),'managerStopped':[a['name'] for a in reversed(self.plan['accounts'])],
              'graphCleared':['root']+[a['name'] for a in self.plan['accounts']]}
  self.state.update({key:'retired-inert' for key in ('venueReleasePhase','venueDomainRuntimePhase','venueRuntimeEnvPhase','venueCompositeMode')})
  self.boot={'bootId':'new-boot','monotonicUsec':1000,'runTmpfs':True}
 def classify(self):return m.boot_lost_runtime_paths(self.plan,self.state,self.boot)
 def test_only_two_source_selected_absent_tmpfs_paths_are_classified(self):
  with patch.object(m.os.path,'lexists',return_value=False):self.assertEqual(self.classify(),{'/run/p0test-r1','/run/p0test-r1-podman'})
  self.assertEqual(self.state['venueBootLostRuntimePaths']['bootId'],'new-boot')
 def test_same_boot_monotonic_does_not_excuse_missing_paths(self):
  self.boot['monotonicUsec']=2000000
  self.assertFalse(self.classify());self.assertNotIn('venueBootLostRuntimePaths',self.state)
 def test_persistent_run_mount_never_qualifies(self):
  self.boot['runTmpfs']=False;self.assertFalse(self.classify())
 def test_incomplete_retirement_never_qualifies(self):
  self.state['venueRuntimeEnvPhase']='inert-ready';self.assertFalse(self.classify())
 def test_repopulated_runtime_root_is_not_adopted_after_receipt(self):
  with patch.object(m.os.path,'lexists',return_value=False):self.classify()
  with patch.object(m.os.path,'lexists',return_value=True):
   with self.assertRaises(m.Refusal):self.classify()
 def test_changed_boot_refuses_reuse_of_prior_missing_path_receipt(self):
  with patch.object(m.os.path,'lexists',return_value=False):self.classify()
  self.boot['bootId']='another-boot'
  with self.assertRaises(m.Refusal):self.classify()
if __name__=='__main__':unittest.main()
