#!/usr/bin/env python3
"""Ordinary SOURCE/fakes: abandoned partial preparation retains import evidence.
No root/native/image operations; existing canonical alias gates remain required.
"""
import ast,copy,importlib.util,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-graph-clear.py'
spec=importlib.util.spec_from_file_location('partial_frozen_clear',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PartialFrozenRetirement(unittest.TestCase):
 def setUp(self):
  self.image='sha256:'+'a'*64;self.user='p0test-example-platform';self.alias='localhost/webservices/example:bundle';self.digest='sha256:'+'b'*64;self.state={'venueRegistryPhase':'preparing','venueRegistryVerified':{self.user+'|'+self.image:self.image},'venueInstallerVersion':1,'venueInstallerPhase':'retiring','venueCompositeVersion':2,'venueCompositeMode':'retiring','status':'graphs-clearing','activationAuthorized':False,'venueRegistryPreparationAbandoned':True,'venueRegistryFailedPendingRetirement':{'phase':'retired-drifted-pending'},'retiredUnits':['example-'+str(i)+'.service'for i in range(190)],'venueCompositeOfflineImages':[{'image':self.image,'authorities':[self.user]}]}
 def allowed(self,state=None):return m.verified_frozen_import_retirement(self.state if state is None else state,self.user,self.image)
 def details(self,extra=False):
  tags={self.alias,'localhost/sha256:'+self.image.removeprefix('sha256:')}
  if extra:tags.add('localhost/foreign/example:bundle')
  return json.dumps(sorted(tags))+'|'+json.dumps(sorted(t.rsplit(':',1)[0]+'@'+self.digest for t in tags))
 def test_partial_preverified_import_is_eligible_without_ready_promotion(self):
  before=copy.deepcopy(self.state);self.assertTrue(self.allowed());self.assertEqual(self.state,before);self.assertEqual(self.state['venueRegistryPhase'],'preparing')
 def test_completed_preparation_existing_eligibility_unchanged(self):
  self.state={'venueRegistryPhase':'inert-ready','venueRegistryVerified':{self.user+'|'+self.image:self.image}};self.assertTrue(self.allowed())
 def test_missing_or_wrong_config_verification_is_never_eligible(self):
  for verified in [{},{self.user+'|'+self.image:'sha256:'+'c'*64},{'other|'+self.image:self.image}]:
   with self.subTest(verified=verified):s=copy.deepcopy(self.state);s['venueRegistryVerified']=verified;self.assertFalse(self.allowed(s))
 def test_partial_gate_mutations_each_refuse(self):
  changes={'venueRegistryPhase':'failed','venueInstallerVersion':True,'venueInstallerPhase':'inert-ready','venueCompositeVersion':2.0,'venueCompositeMode':'inert-ready','status':'units-staged','activationAuthorized':True,'venueRegistryPreparationAbandoned':1,'venueRegistryFailedPendingRetirement':{'phase':'delete-issued'},'retiredUnits':['duplicate']*190,'venueRegistryPending':None,'venueStartPhase':None}
  for key,value in changes.items():
   with self.subTest(key=key):s=copy.deepcopy(self.state);s[key]=value;self.assertFalse(self.allowed(s))
 def test_every_required_partial_field_missing_refuses(self):
  for key in self.state:
   if key=='venueCompositeOfflineImages':continue
   with self.subTest(key=key):s=copy.deepcopy(self.state);s.pop(key);self.assertFalse(self.allowed(s))
 def test_partial_removal_untags_only_canonical_import_then_exact_id_no_force(self):
  calls=[]
  def run(command,**kwargs):calls.append(command);return SimpleNamespace(returncode=0,stdout=self.details()if'--format'in command else'')
  with tempfile.TemporaryDirectory()as t,patch.object(m,'run',side_effect=run),patch.object(m.stage,'write_ledger')as write:
   m.remove_exact_frozen_import(Path(t),self.state,Path(t)/'ledger',self.user,self.image,['fake-podman'],aliases={self.alias})
  self.assertEqual(len(calls),3);self.assertEqual(calls[1][:4],['fake-podman','image','untag',self.image]);self.assertEqual(calls[2],['fake-podman','image','rm',self.image]);self.assertNotIn('--force',sum(calls,[]));self.assertEqual(write.call_count,2);self.assertEqual(self.state['venueRegistryPhase'],'preparing');self.assertFalse(self.state['activationAuthorized'])
 def test_foreign_alias_still_refuses_before_any_write_or_untag(self):
  with patch.object(m,'run',return_value=SimpleNamespace(returncode=0,stdout=self.details(extra=True)))as run,patch.object(m.stage,'write_ledger')as write:
   with self.assertRaisesRegex(m.Refusal,'foreign alias/digest'):m.remove_exact_frozen_import(Path('.'),self.state,Path('unused'),self.user,self.image,['fake-podman'],aliases={self.alias})
   self.assertEqual(run.call_count,1);write.assert_not_called()
 def test_import_store_receipt_still_required(self):
  self.state['venueCompositeOfflineImages'][0]['authorities']=['other']
  with patch.object(m,'run')as run:
   with self.assertRaisesRegex(m.Refusal,'store/import/verification'):m.remove_exact_frozen_import(Path('.'),self.state,Path('unused'),self.user,self.image,['fake-podman'],aliases={self.alias})
   run.assert_not_called()
 def test_untag_failure_stops_before_image_rm(self):
  calls=[]
  def run(command,**kwargs):calls.append(command);return SimpleNamespace(returncode=int('untag'in command),stdout=self.details()if'--format'in command else'')
  with patch.object(m,'run',side_effect=run),patch.object(m.stage,'write_ledger'):
   with self.assertRaisesRegex(m.Refusal,'alias untag failed'):m.remove_exact_frozen_import(Path('.'),self.state,Path('unused'),self.user,self.image,['fake-podman'],aliases={self.alias})
  self.assertEqual(len(calls),2);self.assertIn('pendingGraphImageUntag',self.state)
 def test_actual_clear_dispatch_uses_same_eligibility_as_remover(self):
  tree=ast.parse(source.read_text());clear=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='clear');calls=[n for n in ast.walk(clear)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='verified_frozen_import_retirement'];self.assertEqual(len(calls),1);self.assertEqual([ast.unparse(n)for n in calls[0].args],['state','user','image'])
if __name__=='__main__':unittest.main()
