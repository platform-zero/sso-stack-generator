#!/usr/bin/env python3
"""Canonical journal callback sequencing; fixture-only, no host calls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('journal_admission_test',ROOT/'runtime-generator/podman-ops/install-journal.py')
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)
class Admission(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.root=Path(self.t.name);self.release=self.root/'releases/candidate';self.bundle=self.root/'input';self.bundle.mkdir()
  self.inputs={'bundle.json':'a'*64};self.old={'schemaVersion':1,'release':str(self.release),'inputs':self.inputs,'phase':'preparing','steps':['preparing'],'readiness':{'original':True}}
  self.owner=Mock();self.owner.seal_selection.return_value={'bootId':'fixture','startMonotonicUSec':1,'renderedInputs':{}}
  self.owner.capture_images.return_value={'bootId':'fixture','startMonotonicUSec':1,'renderedInputs':{},'images':{}}
  self.owner.verify_active_transition.return_value={'applicationAcceptance':False,'nativeReady':True}
  self.writes=[]
  for name,value in [('directory',lambda p:None),('read',lambda p:self.old),('fingerprint',lambda p:self.inputs),('standalone_profile',lambda p:True),('readiness_owner',lambda:self.owner),('write',lambda p,v:self.writes.append((p,v.copy())))]:
   p=patch.object(j,name,value);p.start();self.addCleanup(p.stop)
 def advance(self,phase):
  result=j.update(self.root,self.bundle,self.release,phase);self.old=result;return result
 def test_attempt_seal_precedes_early_bootstrap_and_survives_building(self):
  old=self.old;selected=self.advance('units-selected');self.owner.seal_selection.assert_called_once_with(self.root,self.release,old)
  self.assertEqual(len(self.writes),2);self.assertEqual(selected['readiness']['startMonotonicUSec'],1)
  built=self.advance('building');self.assertEqual(built['readiness'],selected['readiness']);self.owner.capture_images.assert_not_called()
 def test_starting_captures_images_and_active_calls_real_owner(self):
  self.advance('units-selected');self.advance('building');old=self.old;starting=self.advance('starting');self.owner.capture_images.assert_called_once_with(self.root,self.release,old)
  old=self.old;active=self.advance('active');self.owner.verify_active_transition.assert_called_once_with(self.root,self.release,old)
  self.assertEqual(active['readiness'],starting['readiness']);self.assertFalse(active['nativeReadiness']['applicationAcceptance'])
  self.assertEqual(self.writes[-1][1],self.writes[-2][1])
 def test_failed_whole_graph_never_writes_active(self):
  for phase in ('units-selected','building','starting'):self.advance(phase)
  before=len(self.writes);self.owner.verify_active_transition.side_effect=ValueError('unready selected graph')
  with self.assertRaises(ValueError):self.advance('active')
  self.assertEqual(len(self.writes),before);self.assertEqual(self.old['phase'],'starting')
 def test_legacy_profile_keeps_legacy_admission(self):
  with patch.object(j,'standalone_profile',return_value=False):self.advance('units-selected')
  self.owner.seal_selection.assert_not_called()
 def test_required_owner_missing_never_degrades_to_target_active(self):
  with patch.object(j,'readiness_owner',side_effect=FileNotFoundError('missing sealed operation')):
   with self.assertRaises(FileNotFoundError):self.advance('units-selected')
  self.assertEqual(self.writes,[])
 def test_native_source_fresh_graph_handoff_precedes_namespace_proof(self):
  text=(ROOT/'runtime-generator/podman-ops/install-podman-bundle.sh').read_text();body=text.split('ensure_rootless_domain() {',1)[1].split('\n}',1)[0]
  self.assertLess(body.index('chown "$user:$user"'),body.index('python3 "$BUNDLE/ops/grant-rootless-volume-parent-traverse.py"'))
  self.assertLess(body.index('chmod 0700 "$graph_root"'),body.index('python3 "$BUNDLE/ops/grant-rootless-volume-parent-traverse.py"'))
  self.assertIn('python3 -B "$JOURNAL_TOOL"',text)
if __name__=='__main__':unittest.main()
