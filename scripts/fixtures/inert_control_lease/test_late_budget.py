"""Deterministic full-engine elapsed-time probes. Explicit INTERNAL clock and
context/ledger observations over existing fakes; all original observations run.
No real wait, Root/proc/target access or public authorization seam.
"""
import inspect,json,unittest
from pathlib import Path
from unittest.mock import patch
import run_typed as previous
m=previous.previous.core.m;original=previous.previous.core.original
R=Path(__file__).resolve().parent
class Clock:
 def __init__(self):self.value=0;self.steps=[]
 def __call__(self):return self.value
 def advance(self,seconds,label):self.value+=seconds;self.steps.append((label,seconds,self.value))
class Late(original.NativeTests):
 def setUp(self):
  super().setUp();self.clock=Clock();self.actions=[];self.armed=False;self.deadlines=set();self.close_delays=0;self.scenario='none'
  p=patch.object(m.time,'monotonic',self.clock);p.start();self.addCleanup(p.stop)
  source=m._Native.source_now;reading=m._Native.read_ledger
  def source_now(native):
   self.deadlines.add(native.deadline);result=source(native)
   if self.active(native):self.clock.advance(.25 if self.scenario=='steady' else 46,'context')
   return result
  def read_ledger(native):
   result=reading(native)
   if self.scenario in ('publish-intended','publish-retired','success','finish') and self.active(native):self.clock.advance(46,'ledger-observation')
   return result
  for p in (patch.object(m._Native,'source_now',source_now),patch.object(m._Native,'read_ledger',read_ledger)):
   p.start();self.addCleanup(p.stop)
  unlink=self.fs.unlink;rmdir=self.fs.rmdir;replace=self.fs.replace;fsync=self.fs.fsync;close=self.fs.close
  def deleting(*a,**kw):
   self.actions.append(('unlink',self.clock.value));return unlink(*a,**kw)
  def removing(*a,**kw):
   self.actions.append(('rmdir',self.clock.value));return rmdir(*a,**kw)
  def publishing(*a,**kw):
   result=replace(*a,**kw);self.actions.append(('publish:'+self.data().get(m.KEY,{}).get('phase','none'),self.clock.value));return result
  def syncing(fd):
   if self.in_frame('finish') and not self.in_frame('publish'):self.actions.append(('finish-fsync',self.clock.value))
   return fsync(fd)
  def closing(fd):
   result=close(fd)
   if self.scenario=='cleanup' and self.in_frame('close') and self.close_delays<3:
    self.close_delays+=1;self.clock.advance(46,'descriptor-close')
   return result
  for name,fn in (('unlink',deleting),('rmdir',removing),('replace',publishing),('fsync',syncing),('close',closing)):
   p=patch.object(self.fs,name,fn);p.start();self.addCleanup(p.stop)
 def in_frame(self,name):
  frame=inspect.currentframe().f_back
  while frame:
   if frame.f_code.co_name==name and frame.f_locals.get('self') is not self and isinstance(frame.f_locals.get('self'),m._Native):return frame
   frame=frame.f_back
  return None
 def active(self,native):
  if self.scenario=='steady':return True
  if self.scenario in ('unlink','rmdir'):return self.in_frame(self.scenario) is not None
  if self.scenario=='finish':return self.in_frame('finish') is not None and self.in_frame('publish') is None
  if self.scenario in ('publish-intended','publish-retired','success'):
   frame=self.in_frame('publish');target='intended' if self.scenario=='publish-intended' else 'retired'
   if frame and frame.f_locals.get('phase')==target and (str(native.ledger)+'.inert-lease-new') in self.fs.nodes:self.armed=True
   return bool(frame and frame.f_locals.get('phase')==target and self.armed)
  return False
 def outcome(self):
  try:return self.run_api()
  except m.Refused as error:return {'status':'refused','reason':str(error)}
 def proof(self,label,outcome):
  evidence={'scope':'full SOURCE engine; clock/Root/backend facts explicitly fake, NOT native exploit',
   'scenario':self.scenario,'outcome':outcome,'clock':self.clock.value,'deadlines':sorted(self.deadlines),
   'steps':self.clock.steps,'actions':self.actions,'modeledUnlink':self.events('unlink'),'modeledRmdir':self.events('rmdir'),
   'phase':self.data().get(m.KEY,{}).get('phase'),'openFakeFDs':len(self.fs.fds),'runtimePresent':self.runtime in self.fs.nodes}
  (R/('LATE-'+label+'.json')).write_text(json.dumps(evidence,indent=2)+'\n');return evidence
 def b_unlink_after_three_bounded_contexts(self):
  self.scenario='unlink';outcome=self.outcome();self.proof('unlink',outcome)
  self.assertEqual([a for a in self.actions if a[0]=='unlink' and a[1]>=120],[],'late actual MODELED unlink after bounded context observations')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_rmdir_after_three_bounded_contexts(self):
  self.scenario='rmdir';outcome=self.outcome();self.proof('rmdir',outcome)
  self.assertEqual([a for a in self.actions if a[0]=='rmdir' and a[1]>=120],[],'late actual MODELED rmdir')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(len(self.events('unlink')),1);self.assertEqual(self.fs.fds,{})
 def b_publish_intended_after_second_check_overrun(self):
  self.scenario='publish-intended';outcome=self.outcome();self.proof('publish-intended',outcome)
  self.assertEqual([a for a in self.actions if a[0]=='publish:intended' and a[1]>=120],[],'late MODELED ledger publication')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_publish_retired_after_second_check_overrun(self):
  self.scenario='publish-retired';outcome=self.outcome();self.proof('publish-retired',outcome)
  self.assertEqual([a for a in self.actions if a[0]=='publish:retired' and a[1]>=120],[],'late MODELED final publication')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_finish_expensive_observation_then_fsync(self):
  self.scenario='finish';outcome=self.outcome();self.proof('finish',outcome)
  self.assertEqual([a for a in self.actions if a[0]=='finish-fsync' and a[1]>=120],[],'late MODELED completion durability primitive')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_no_success_after_final_observation_overrun(self):
  self.scenario='success';outcome=self.outcome();self.proof('success',outcome)
  self.assertNotEqual(outcome.get('status'),'retired-inert-control-lease','late full-engine public SUCCESS')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_no_success_after_cleanup_overrun_all_fds_still_close(self):
  self.scenario='cleanup';outcome=self.outcome();self.proof('cleanup',outcome)
  self.assertNotEqual(outcome.get('status'),'retired-inert-control-lease','public return after three bounded descriptor closes passed120')
  self.assertEqual(outcome.get('reason'),'operation-timeout');self.assertEqual(self.fs.fds,{})
 def b_under_budget_full_flow_positive(self):
  self.scenario='steady';outcome=self.outcome();self.proof('positive',outcome)
  self.assertEqual(outcome['status'],'retired-inert-control-lease');self.assertLess(self.clock.value,120)
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1);self.assertEqual(self.fs.fds,{})
  self.assertEqual(self.deadlines,{120});self.assertTrue(all(value<120 for _,value in self.actions))
