"""Independent C40 full-engine SOURCE tests; no real Root/target operations.
All privilege, filesystem, clock and service observations are explicit internal
models. Assertions and fault-fired checks are outside the privacy catch-all.
"""
import copy, inspect, json, sys, unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent
sys.path.insert(0,str(R))
import run_input as author
m=author.core.m
base=author.core.original.NativeTests
fixture=author.core.fixture

class Independent(base):
 def setUp(self):
  super().setUp(); self.now=0.; self.fired=[]; self.effects=[]; self.origins=[]
  p=patch.object(m.time,'monotonic',lambda:self.now);p.start();self.addCleanup(p.stop)
  init=m._Native.__init__
  def constructed(native):
   init(native);self.origins.append(native.deadline)
  p=patch.object(m._Native,'__init__',constructed);p.start();self.addCleanup(p.stop)
  for name in ('unlink','rmdir','replace','fsync'):
   original=getattr(self.fs,name)
   def record(*args,_fn=original,_name=name,**kw):
    self.effects.append((_name,self.now));return _fn(*args,**kw)
   p=patch.object(self.fs,name,record);p.start();self.addCleanup(p.stop)
 def outcome(self):
  try:return self.run_api()
  except m.Refused as e:return {'status':'refused','reason':str(e)}
 def finish_checks(self,result,reason='operation-timeout'):
  self.assertEqual(len(self.fired),1,'fault must fire exactly once')
  self.assertEqual(result.get('reason'),reason,result)
  self.assertEqual([e for e in self.effects if e[1]>=120],[],self.effects)
  self.assertEqual(self.fs.fds,{})
  self.assertEqual(self.origins,[120])
 def expires_after(self,obj,name,predicate=lambda *a,**kw:True):
  original=getattr(obj,name)
  def wrapped(*a,**kw):
   result=original(*a,**kw)
   if not self.fired and predicate(*a,**kw):self.fired.append(name);self.now=120.
   return result
  return patch.object(obj,name,wrapped)
 def inside(self,name):
  frame=inspect.currentframe()
  while frame:
   if frame.f_code.co_name==name and isinstance(frame.f_locals.get('self'),m._Native):return True
   frame=frame.f_back
  return False
 def test_clock_bind_registry_load(self):
  with self.expires_after(m,'_load'):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.events('unlink'),[])
 def test_clock_bind_plan(self):
  with self.expires_after(self.registry.stage,'owned_plan'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_bind_authority(self):
  with self.expires_after(self.registry.authority,'authority'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_bind_actual_context(self):
  with self.expires_after(self.lifecycle,'host_context'):result=self.outcome()
  self.finish_checks(result);self.assertGreater(len(self.current_calls),0)
 def test_clock_after_full_observe(self):
  with self.expires_after(m._Native,'observe'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_full_check(self):
  with self.expires_after(m._Native,'check'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_nss(self):
  with self.expires_after(m,'_accounts_absent'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_systemd_observation(self):
  with self.expires_after(m,'_fields'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_process_observation(self):
  with self.expires_after(m,'_processes_quiescent'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_source_check(self):
  with self.expires_after(m._Native,'source_now'):result=self.outcome()
  self.finish_checks(result)
 def test_clock_after_unlink_last_stat(self):
  with self.expires_after(m._Native,'runtime_now',lambda *a,**kw:self.inside('unlink')):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.events('unlink'),[])
 def test_clock_after_rmdir_last_stat(self):
  with self.expires_after(m._Native,'runtime_now',lambda *a,**kw:self.inside('rmdir')):result=self.outcome()
  self.finish_checks(result);self.assertEqual(len(self.events('unlink')),1);self.assertEqual(self.events('rmdir'),[])
 def test_clock_temp_open_no_late_write(self):
  with self.expires_after(self.fs,'open',lambda name,*a,**kw:str(name).endswith('.inert-lease-new')):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.events('replace'),[])
  self.assertIn(self.ledger+'.inert-lease-new',self.fs.nodes)
 def test_clock_temp_write_no_late_fsync(self):
  with self.expires_after(self.fs,'write'):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.events('replace'),[])
 def test_clock_temp_fsync_no_late_replace(self):
  with self.expires_after(self.fs,'fsync',lambda fd:self.fs.fds[fd][0].name.endswith('.inert-lease-new')):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.events('replace'),[])
 def test_clock_publication_return_no_undo_no_later_fsync(self):
  with self.expires_after(self.fs,'replace'):result=self.outcome()
  self.finish_checks(result);self.assertEqual(len(self.events('replace')),1)
  self.assertEqual(self.data()[m.KEY]['phase'],'intended')
 def test_clock_rmdir_return_no_undo(self):
  with self.expires_after(self.fs,'rmdir'):result=self.outcome()
  self.finish_checks(result);self.assertEqual(len(self.events('rmdir')),1);self.assertNotIn(self.runtime,self.fs.nodes)
 def test_clock_final_fd_close_rejects_success(self):
  with self.expires_after(self.fs,'close',lambda fd:self.inside('close') and self.data().get(m.KEY,{}).get('phase')=='retired'):result=self.outcome()
  self.finish_checks(result);self.assertEqual(self.data()[m.KEY]['phase'],'retired')
 def test_clock_last_stat_119997_positive(self):
  original=m._Native.runtime_now
  def almost(native,*a,**kw):
   result=original(native,*a,**kw)
   if not self.fired and self.inside('unlink'):self.fired.append(True);self.now=119.997
   return result
  with patch.object(m._Native,'runtime_now',almost):result=self.outcome()
  self.assertEqual(self.fired,[True]);self.assertEqual(result['status'],'retired-inert-control-lease')
  self.assertEqual(self.origins,[120]);self.assertEqual(self.fs.fds,{})
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
 def cfg_change(self,change):
  node=self.fs.nodes[self.flat+'/SOURCE-LOCK.json'];lock=json.loads(node.data)
  change(lock['targetAuthority']['inputConfiguration']);node.data=m.encoded(lock)
 def refuse_cfg(self,change):
  self.cfg_change(change);result=self.outcome()
  self.assertEqual(result['status'],'refused');self.assertEqual(self.events('unlink'),[])
  self.assertEqual(self.events('rmdir'),[]);self.assertEqual(self.fs.fds,{})
 def test_config_bool_schema(self):self.refuse_cfg(lambda c:c.update(schemaVersion=True))
 def test_config_bool_mode(self):self.refuse_cfg(lambda c:next(iter(c['ops'].values())).update(mode=True))
 def test_config_float_mode(self):self.refuse_cfg(lambda c:next(iter(c['ops'].values())).update(mode=420.0))
 def test_config_extra_key(self):self.refuse_cfg(lambda c:c.update(authenticated=True))
 def test_config_missing_receipt(self):self.refuse_cfg(lambda c:c.pop('historicalArtifactReceiptPath'))
 def test_config_generated_unknown(self):self.refuse_cfg(lambda c:c['ops'].update({'foreign.py':{'sha256':'a'*64,'mode':420}}))
 def test_config_generated_missing(self):self.refuse_cfg(lambda c:c['ops'].pop(next(iter(m.GENERATED_OPS))))
 def test_config_opaque_receipt_is_not_output_manifest(self):
  raw=self.fs.nodes['/audit/original-artifact-receipt.json'].data
  self.assertIn(b'NOT historical proof',raw)
  result=self.outcome();self.assertEqual(result['status'],'retired-inert-control-lease')
  # This positive establishes mechanical digest binding ONLY, never Root origin.
  self.assertEqual(self.fs.fds,{})
 def after_process_fault(self,fn):
  original=m._processes_quiescent
  def changed(*a,**kw):
   result=original(*a,**kw)
   if not self.fired:self.fired.append(True);fn()
   return result
  with patch.object(m,'_processes_quiescent',changed):result=self.outcome()
  self.assertEqual(self.fired,[True]);self.assertEqual(result['status'],'refused')
  self.assertEqual(self.events('unlink'),[]);self.assertEqual(self.fs.fds,{})
 def test_late_source_fd_same_size_changed(self):
  def change():
   n=self.fs.nodes[self.slot+'/p0_host_context.py'];n.data=b'X'+n.data[1:]
  self.after_process_fault(change)
 def test_late_selected_pointer_changed(self):
  self.after_process_fault(lambda:setattr(self.fs.nodes[str(self.context.source)+'/agent-services-current-host'],'data',b'/foreign/slot'))
 def test_late_actual_current_role_changed(self):
  self.after_process_fault(lambda:setattr(self.fs.nodes[self.slot+'/host-role.json'],'data',b'{}'))
 def test_late_ledger_cas_changed(self):
  self.after_process_fault(lambda:setattr(self.fs.nodes[self.ledger],'data',self.fs.nodes[self.ledger].data+b' '))
 def test_late_parent_gid_changed(self):
  self.after_process_fault(lambda:setattr(self.fs.nodes['/run'],'gid',1000))
 def test_late_policy_reappears(self):
  self.after_process_fault(lambda:self.fs.put('/etc/tmpfiles.d/'+self.ns+'-control.conf',data=b'SYNTHETIC recreated'))
 def test_full_typed_nested_alias_independent(self):
  self.plan['independent']={'rows':[{'n':1,'flag':False}]};self.plan_sha=m.digest(m.canonical(self.plan))
  state=self.data();state['plan']=copy.deepcopy(self.plan);state['plan']['independent']['rows'][0]['n']=True
  state[m.FENCE]['planSha256']=self.plan_sha;fixture.rechain(state)
  raw=m.encoded(state);self.fs.nodes[self.ledger].data=raw
  self.cfg_change(lambda c:c.update(planSha256=self.plan_sha,initialReviewedLedgerSha256=m.digest(raw)))
  with patch.object(m,'_json_exact',wraps=m._json_exact) as gate:result=self.outcome()
  self.assertTrue(gate.called);self.assertEqual(result.get('reason'),'retirement')
  self.assertEqual(self.events('replace'),[]);self.assertEqual(self.fs.fds,{})
 def test_raw_duplicate_ledger_refuses(self):
  raw=self.fs.nodes[self.ledger].data;raw=b'{"duplicate":1,"duplicate":2,'+raw.lstrip()[1:]
  self.fs.nodes[self.ledger].data=raw
  self.cfg_change(lambda c:c.update(initialReviewedLedgerSha256=m.digest(raw)))
  result=self.outcome();self.assertEqual(result.get('reason'),'json-duplicate')
  self.assertEqual(self.events('replace'),[]);self.assertEqual(self.fs.fds,{})

if __name__=='__main__':
 names=sorted(n for n in Independent.__dict__ if n.startswith('test_'))
 result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Independent(n) for n in names))
 (R/'INDEPENDENT-RESULTS.json').write_text(json.dumps({'tests':result.testsRun,'failures':[{'test':str(t),'trace':v} for t,v in result.failures],'errors':[{'test':str(t),'trace':v} for t,v in result.errors],'skipped':result.skipped,'scope':'SOURCE internal models only; no native authority'},indent=2)+'\n')
 sys.exit(bool(result.failures or result.errors))
