#!/usr/bin/env python3
"""Synthetic scoped native health/inert contracts, not installed readiness."""
import contextlib,datetime,importlib.util,json,os,tempfile,time
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
OPS=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
s=importlib.util.spec_from_file_location('health_adapter',OPS/'venue-root-health.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'root-owned synthetic fixture')
class Health(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.b=self.root/'bundle';self.b.mkdir();self.p=self.root/'journal';self.selector=self.root/'selector';self.selector.write_text('{}');self.units=self.root/'units';self.units.mkdir()
  self.plan={'prefix':'p0test-r1'};self.data={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'preparing','activationAuthorized':False};self.save()
  self.controller=NS(digest='a'*64,require_runtime=lambda:{'phase':'starting'})
  self.native=[];self.held=[];self.returncode=0;self.dropins='';self.epoch=1000;self.unitstate='static'
  self.run=self.root/'run';self.run.mkdir();(self.run/'p0test-r1-caddy.cid').write_text('b'*64);(self.run/'p0test-r1-caddy.cid').chmod(0o644)
  self.proc=self.root/'proc';(self.proc/'12345').mkdir(parents=True);(self.proc/'12345/cgroup').write_text('0::/system.slice/p0test-r1-caddy.service/supervisor\n')
  self.row={'Id':'b'*64,'Name':'p0test-r1-caddy','Image':'sha256:'+'c'*64,'Config':{'Labels':{'io.containers.systemd.unit':'p0test-r1-caddy.service'},'Healthcheck':{'Interval':5000000000}},'State':{'Running':True,'ConmonPid':12345,'Health':{'Log':None}}}
  @contextlib.contextmanager
  def lease(*args):
   self.held.append(True)
   try:yield
   finally:self.held.pop()
  def context(*args):return self.b,self.p,json.loads(self.p.read_text()),self.plan
  def run(cmd,**kwargs):
   self.native.append(cmd)
   if 'ps' in cmd:return NS(returncode=0,stdout=json.dumps([{'Names':['p0test-r1-caddy'],'Id':'b'*64,'State':'running'}]))
   if 'inspect' in cmd:return NS(returncode=0,stdout=json.dumps([self.row]))
   if 'healthcheck' in cmd:
    self.assertTrue(self.held);self.assertIn('venueRootHealthPending',json.loads(self.p.read_text()));self.assertEqual(cmd[:5],['podman','--root','/exclusive','--runroot','/exclusive-run'])
    return NS(returncode=self.returncode,stdout='')
   if 'show' in cmd:
    if 'MainPID' in cmd:return NS(returncode=0,stdout=f'MainPID=67890\nActiveState=activating\nControlGroup=/system.slice/p0test-r1-caddy.service\nExecMainStartTimestampMonotonic={self.epoch}\nDropInPaths={self.dropins}\n')
    if 'LoadState' in cmd:
     path=self.units/cmd[2];present=path.exists()
     return NS(returncode=0,stdout=f'LoadState={"loaded" if present else "not-found"}\nActiveState=inactive\nFragmentPath={str(path) if present else ""}\nDropInPaths={self.dropins}\nUnitFileState={self.unitstate if present else ""}\n')
    return NS(returncode=0,stdout='ActiveState=inactive\nUnitFileState=static\n'*2)
   return NS(returncode=0,stdout='')
  patches=[patch.object(m,'UNIT_DIRECTORY',self.units),patch.object(m,'RUNTIME_DIRECTORY',self.run),patch.object(m,'PROC_DIRECTORY',self.proc),patch.object(m.lifecycle.ingress,'context',side_effect=context),patch.object(m.lifecycle.ingress,'checked',return_value={}),
   patch.object(m.lifecycle.stage,'owned_plan',return_value=self.plan),patch.object(m.lifecycle,'host_context',return_value=self.controller),patch.object(m.lifecycle,'lifecycle',side_effect=lease),patch.object(m.lifecycle.graph,'run',side_effect=run),
   patch.object(m.lifecycle.graph,'stores',return_value=[('root','/exclusive',['podman','--root','/exclusive','--runroot','/exclusive-run'])]),patch.object(m.lifecycle.graph,'selected_pairs',return_value={'root|sha256:'+'c'*64:'sha256:'+'c'*64})]
  for p in patches:p.start();self.addCleanup(p.stop)
  directory=self.b/'quadlet/rootful';directory.mkdir(parents=True);(directory/'p0test-r1-caddy.container').write_text('[Container]\nImage=sha256:'+'c'*64+'\n')
  (self.b/'stack.ir.json').write_text(json.dumps({'services':{'caddy':{'health':{'test':['CMD','true']}}}}))
 def save(self):self.p.write_text(json.dumps(self.data));self.p.chmod(0o600)
 def ready(self):m.prepare(self.b,self.selector,self.p);self.data=json.loads(self.p.read_text())
 def starting(self):
  self.ready();self.data.update(venueInstallerVersion=2,venueInstallerPhase='starting',venueStartPhase='starting',venueStartMonotonicUsec=1000,activationAuthorized=True,venueStartHostContextSha256=self.controller.digest,venueRegistryPhase='inert-ready',venueRegistryVerified={'root|fixture':'sha256:'+'c'*64});self.save();self.native.clear()
 def test_inert_two_static_files_never_enable_start_or_touch_global_manager_environment(self):
  self.ready();self.assertEqual(len(m.checked(self.b,self.selector,self.p)),2)
  self.assertFalse(any(any(x in c for x in ('start','enable','set-environment','reset-failed')) for c in self.native))
  self.assertIn('MemoryMax=4G',(self.units/'p0test-r1-root-health.service').read_text())
 def test_existing_foreign_destination_refuses_untouched(self):
  p=self.units/'p0test-r1-root-health.service';p.write_text('human')
  with self.assertRaises(m.Refusal):m.prepare(self.b,self.selector,self.p)
  self.assertEqual(p.read_text(),'human')
 def test_changed_unit_hash_or_inode_refuses(self):
  self.ready();p=next(self.units.iterdir());p.write_text('changed')
  with self.assertRaises(m.Refusal):m.checked(self.b,self.selector,self.p)
 def test_exact_inactive_retirement_leaves_foreign_files(self):
  self.ready();self.data.update(venueInstallerPhase='retiring');self.save();other=self.units/'foreign.service';other.write_text('keep');m.retire(self.b,self.selector,self.p)
  self.assertEqual(list(self.units.iterdir()),[other]);self.assertEqual(json.loads(self.p.read_text())['venueRootHealthPhase'],'retired-inert')
 def test_active_or_unreadable_retirement_refuses_before_unlink(self):
  self.ready();self.data.update(venueInstallerPhase='retiring');self.save()
  with patch.object(m.lifecycle.graph,'run',return_value=NS(returncode=1,stdout='')):
   with self.assertRaises(m.Refusal):m.retire(self.b,self.selector,self.p)
  self.assertEqual(len(list(self.units.iterdir())),2)
 def test_scoped_native_probe_preserves_native_command_and_records_ack(self):
  self.starting();result=m.tick(self.b,self.selector,self.p);self.assertEqual(result['checked'],1);self.assertNotIn('venueRootHealthPending',json.loads(self.p.read_text()));self.assertFalse(self.held)
 def test_unhealthy_known_exit_is_polling_not_backend_restart(self):
  self.starting();self.returncode=1;self.assertEqual(m.tick(self.b,self.selector,self.p)['checked'],1);self.assertFalse(any('restart' in c or 'start' in c for c in self.native))
 def test_expired_fenced_or_foreign_epoch_never_probes(self):
  self.starting();self.data['activationAuthorized']=False;self.save()
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(self.native)
 def test_foreign_image_or_owner_never_runs_health_command(self):
  self.starting();self.row['Image']='sha256:'+'d'*64
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_unreviewed_native_override_refuses_before_probe(self):
  self.starting();self.dropins='/human/override.conf'
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_enabled_cadence_unit_refuses_before_probe(self):
  self.starting();self.unitstate='enabled'
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_wrong_cid_receipt_refuses_before_probe(self):
  self.starting();(self.run/'p0test-r1-caddy.cid').write_text('d'*64)
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_supervisor_outside_native_unit_refuses(self):
  self.starting();(self.proc/'12345/cgroup').write_text('0::/system.slice/foreign.service\n')
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_stale_native_epoch_refuses(self):
  self.starting();self.epoch=999
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_frozen_custom_image_not_in_registry_receipts_uses_exact_unit_pin(self):
  self.starting();self.data['venueRegistryVerified']={'root|other-registry-image':'sha256:'+'d'*64};self.save()
  self.assertEqual(m.tick(self.b,self.selector,self.p)['checked'],1)
 def test_native_bare_config_id_normalizes_without_changing_identity(self):
  self.starting();self.row['Image']='c'*64;self.assertEqual(m.tick(self.b,self.selector,self.p)['checked'],1)
 def test_other_valid_root_registry_image_cannot_substitute_for_unit_pin(self):
  self.starting();self.row['Image']='sha256:'+'d'*64;self.data['venueRegistryVerified']['root|other']='sha256:'+'d'*64;self.save()
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(any('healthcheck' in c for c in self.native))
 def test_unit_without_exact_frozen_or_registry_image_authority_refuses(self):
  self.starting();m.lifecycle.graph.selected_pairs.return_value={}
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertFalse(self.native)
 def test_recent_native_history_respects_declared_interval(self):
  self.starting();self.row['State']['Health']['Log']=[{'End':datetime.datetime.now(datetime.timezone.utc).isoformat()}];self.assertEqual(m.tick(self.b,self.selector,self.p)['checked'],0)
 def test_unknown_or_failed_native_ack_retains_intent_no_replay(self):
  self.starting();self.returncode=125
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertIn('venueRootHealthPending',json.loads(self.p.read_text()));count=len(self.native)
  with self.assertRaises(m.Refusal):m.tick(self.b,self.selector,self.p)
  self.assertEqual(count,len(self.native))
 def test_unknown_timeout_retains_intent(self):
  self.starting();run=m.lifecycle.graph.run
  def native(cmd,**kwargs):
   if 'healthcheck' in cmd:raise TimeoutError('unknown native ACK')
   return run(cmd,**kwargs)
  with patch.object(m.lifecycle.graph,'run',side_effect=native):
   with self.assertRaises(TimeoutError):m.tick(self.b,self.selector,self.p)
  self.assertIn('venueRootHealthPending',json.loads(self.p.read_text()))

if __name__=='__main__':unittest.main()
