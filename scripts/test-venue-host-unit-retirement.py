#!/usr/bin/env python3
"""Synthetic exact isolated control-unit unlink; no real unit directory used."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-start-quarantine.py'
s=importlib.util.spec_from_file_location('host_unit_retirement',source);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'protected synthetic host units')
class Units(unittest.TestCase):
 def setUp(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.runtime=self.root/'run';self.runtime.mkdir(mode=0o700)
  self.directory=self.root/'system-units';self.directory.mkdir();self.base=self.root/'control';self.base.mkdir();slot=self.base/'slot';(slot/'units').mkdir(parents=True)
  (self.base/'agent-services-current-host').symlink_to(slot);manifest={'files':{}};self.paths=[]
  for name in ('p0-identity-reconcile.service','p0-identity-reconcile.timer','p0-web.service'):
   body='synthetic '+name;member=slot/'units'/name;member.write_text(body);member.chmod(0o644);manifest['files']['units/'+name]=m.stage.sha(member)
   target=self.directory/('p0test-r1-'+name.removeprefix('p0-'));target.write_text(body);target.chmod(0o644);self.paths.append(target)
  (slot/'manifest.json').write_text(json.dumps(manifest));self.context=NS(runtime=self.runtime,source=self.base,digest='b'*64,namespace='p0test-r1',unit=lambda name:'p0test-r1-'+name.removeprefix('p0-'))
  receipt={'schemaVersion':2,'namespace':'p0test-r1','hostContextSha256':'b'*64,'phase':'failed-quarantined','activationAuthorized':False}
  self.capability=self.runtime/'runtime-authority.json';self.capability.write_text(json.dumps(receipt));self.capability.chmod(0o600)
  self.plan={'accounts':[{'name':'fixture'+str(i)} for i in range(7)]};self.ledger=self.root/'ledger'
  self.state={'plan':self.plan,'venueInstallerVersion':2,'status':'managers-ready','venueInstallerPhase':'retiring','venueCompositeMode':'retired-inert','venueRuntimeEnvPhase':'retired-inert',
              'graphCleared':['root']+[a['name'] for a in self.plan['accounts']],'retiredUnits':list(range(190)),'activationAuthorized':False}
  self.ledger.write_text(json.dumps(self.state));self.ledger.chmod(0o600);self.active=False;self.commands=[]
  for p in [patch.object(m.stage,'owned_plan',return_value=self.plan),patch.object(m,'host_context',return_value=self.context),
            patch.object(m,'HOST_UNIT_DIRECTORY',self.directory),patch.object(m.graph,'run',side_effect=self.native)]:p.start();self.addCleanup(p.stop)
 def native(self,command,**kwargs):
  self.commands.append(command)
  if 'show' in command:
   path=self.directory/command[2];return NS(returncode=0,stdout='ActiveState='+('active' if self.active else 'inactive')+'\nUnitFileState=disabled\nDropInPaths=\nFragmentPath='+str(path)+'\n')
  return NS(returncode=0,stdout='')
 def retire(self):return m.retire_host_units(self.root,'selector',self.ledger,m.stage.sha(self.ledger))
 def test_exact_three_inactive_unmodified_units_removed_false_receipt_kept(self):
  result=self.retire();self.assertEqual(result['retiredExactInactiveUnits'],3);self.assertTrue(self.capability.exists())
  self.assertTrue(all(not p.exists() for p in self.paths));saved=json.loads(self.ledger.read_text())['venueHostUnitsRetirement']
  self.assertEqual(saved['phase'],'retired');self.assertEqual(len(saved['identities']),3);self.assertEqual(self.commands[-1],['systemctl','daemon-reload'])
 def test_interrupted_unlink_resumes_from_exact_pending_inode_intent(self):
  unlink=Path.unlink
  def interrupted(path,*args,**kwargs):
   unlink(path,*args,**kwargs)
   if path==self.paths[0]:raise OSError('synthetic unlink crash')
  with patch.object(Path,'unlink',new=interrupted):
   with self.assertRaises(OSError):self.retire()
  self.assertFalse(self.paths[0].exists());self.assertTrue(self.paths[1].exists())
  self.assertEqual(self.retire()['status'],'retired-host-role-units')
 def test_one_authored_unit_blocks_all_deletion(self):
  self.paths[-1].write_text('human work')
  with self.assertRaisesRegex(m.Refusal,'authored/foreign'):self.retire()
  self.assertTrue(all(p.exists() for p in self.paths));self.assertEqual(self.paths[-1].read_text(),'human work')
 def test_live_host_unit_blocks_all_deletion(self):
  self.active=True
  with self.assertRaisesRegex(m.Refusal,'active/enabled'):self.retire()
  self.assertTrue(all(p.exists() for p in self.paths))
if __name__=='__main__':unittest.main()
