#!/usr/bin/env python3
"""Synthetic owned fixture lifecycle; no running media/service acceptance."""
from contextlib import nullcontext
import importlib.util,json,os,stat,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
s=importlib.util.spec_from_file_location('fixture_binds',Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-bind-dirs.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
@unittest.skipUnless(os.geteuid()==0,'root-owned directory/UID fixtures')
class Fixture(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory(prefix='p0-fixture-bind-unit-');self.addCleanup(t.cleanup);self.root=Path(t.name);self.root.chmod(0o700)
  self.base=self.root/'owned';self.base.mkdir();self.bundle=self.root/'bundle';q=self.bundle/'quadlet/rootless-apps';q.mkdir(parents=True)
  self.media=self.base/'fixtures/media'
  for name,target in [('jellyfin','jellyfin-media:/media:ro'),('qbittorrent','qbittorrent:/downloads')]:
   (q/('p0test-r1-'+name+'.container')).write_text('Volume='+str(self.media/target)+'\n')
  self.plan={'prefix':'p0test-r1','roots':{'rootful-graph':str(self.base/'graph')},'accounts':[{'name':'p0test-r1-apps','uid':3201}]}
  info=self.base.stat();self.data={'venueInstallerVersion':1,'pathIdentities':{str(self.base):{'dev':info.st_dev,'ino':info.st_ino}}}
  self.ledger=self.root/'ledger.json';self.save()
  def checked(*args):return self.ledger,json.loads(self.ledger.read_text()),{}
  def reviewed(data,*args,**kwargs):
   if data.get('venueStartPhase')!='failed-quarantined' or data.get('activationAuthorized') is not False:raise m.Refusal('not quarantined')
  lifecycle=NS(host_context=lambda *a:NS(),lifecycle=lambda *a:nullcontext(),units=NS(units_idle=lambda *a:None),reviewed_retry=reviewed)
  for p in [patch.object(m.stage,'owned_plan',return_value=self.plan),patch.object(m,'checked_stage',side_effect=checked),patch.object(m,'load',return_value=lifecycle)]:p.start();self.addCleanup(p.stop)
 def save(self):self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
 def prepare(self,**kwargs):return m.prepare_fixtures(self.bundle,'selector',self.ledger,**kwargs)
 def test_two_source_inputs_and_two_new_parents_are_receipted(self):
  self.assertEqual(self.prepare()['fixtureDirectories'],2);data=json.loads(self.ledger.read_text());self.assertEqual(len(data['venueFixtureBindDirs']),4)
  self.assertEqual(len(m.checked_fixtures(self.bundle,self.plan,data)),4)
  for row in data['venueFixtureBindDirs']:
   info=Path(row['path']).lstat();self.assertEqual((info.st_uid,stat.S_IMODE(info.st_mode)),(row['uid'],row['mode']))
 def test_existing_authored_fixture_parent_is_never_adopted(self):
  (self.base/'fixtures').mkdir();file=self.base/'fixtures/human';file.write_text('preserve')
  with self.assertRaises(m.Refusal):self.prepare()
  self.assertEqual(file.read_text(),'preserve');self.assertFalse(self.media.exists())
 def test_foreign_volume_path_refuses_without_mkdir(self):
  file=self.bundle/'quadlet/rootless-apps/p0test-r1-jellyfin.container';file.write_text('Volume=/foreign/fixtures/media/jellyfin-media:/media:ro\n')
  with self.assertRaises(m.Refusal):self.prepare()
  self.assertFalse((self.base/'fixtures').exists())
 def test_empty_fixture_retirement_removes_only_receipted_nodes(self):
  self.prepare();m.retire_fixtures(self.bundle,'selector',self.ledger);self.assertFalse((self.base/'fixtures').exists());self.assertTrue(self.base.is_dir())
 def test_populated_fixture_refuses_before_any_retirement(self):
  self.prepare();file=self.media/'jellyfin-media/human';file.write_text('preserve')
  with self.assertRaises(m.Refusal):m.retire_fixtures(self.bundle,'selector',self.ledger)
  self.assertEqual(file.read_text(),'preserve');self.assertTrue((self.media/'qbittorrent').exists())
 def test_changed_fixture_inode_refuses(self):
  self.prepare();old=self.media/'jellyfin-media';old.rename(self.media/'original');old.mkdir()
  with self.assertRaises(m.Refusal):m.checked_fixtures(self.bundle,self.plan,json.loads(self.ledger.read_text()))
 def test_failed_consumer_repair_requires_exact_cas_and_quarantine(self):
  self.data.update(venueInstallerVersion=2,venueStartPhase='failed-quarantined',activationAuthorized=False,venueStartMonotonicUsec=123,
                   venueStartFailure={'reason':'native selected service failed: p0test-r1-jellyfin.service'});self.save()
  with self.assertRaises(m.Refusal):self.prepare(repair_sha='wrong')
  self.assertFalse((self.base/'fixtures').exists());self.prepare(repair_sha=m.stage.sha(self.ledger));repair=json.loads(self.ledger.read_text())['venueStartRepair']
  self.assertEqual(repair['kind'],'missing-owned-media-fixture');self.assertEqual(repair['appliesToStartMonotonicUsec'],123)
 def test_initial_creation_does_not_allow_version_two_without_review(self):
  self.data['venueInstallerVersion']=2;self.save()
  with self.assertRaises(m.Refusal):self.prepare()
  self.assertFalse((self.base/'fixtures').exists())
if __name__=='__main__':unittest.main()
