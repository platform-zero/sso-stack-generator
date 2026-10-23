"""Independent C38 boundary checks; actual own USER files/FDs only.
Privileged Root/kernel/NSS/current source/process/manager observations are fake.
No real /proc/cgroup/target reads. No public authority adapter added.
"""
import ast,inspect,stat,unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a
from c30_fd_tests import Monitor

class ReviewBudgetTests(unittest.TestCase):
 def test_independent_nonzero_epoch_just_below_equal_and_above_90(self):
  for boundary in (89.999,90.0,90.001):
   with self.subTest(boundary=boundary),a.World() as w,Monitor(w) as m:
    elapsed=[0.0];calls=[];selected=w.selected;result=None;refused=False
    def context(*args):
     row=selected(*args)
     if w.read().get(p.KEY,{}).get('phase')=='sudo-issued' and len(calls)<2:
      elapsed[0]+=boundary/2;calls.append(True)
     return row
    with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p,'actual_context',side_effect=context):
     try:result=w.run()
     except p.Refused:refused=True
    self.assertEqual(calls,[True,True]);self.assertAlmostEqual(elapsed[0],boundary)
    if boundary<90:
     self.assertFalse(refused);self.assertEqual(result['policiesAbsent'],2)
     self.assertEqual(w.unlinks,[row[0].name for row in w.specs]);self.assertEqual(len(w.read()[p.KEY]['intendedEpochs']),6)
    else:
     self.assertTrue(refused);self.assertIsNone(result);self.assertEqual(w.unlinks,[])
     self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
     before=len(m.opens)
     with self.assertRaises(p.Refused):w.run()
     self.assertEqual(w.unlinks,[]);self.assertEqual(m.opens[before:],[])
    self.assertEqual(m.live,{})

 def test_all_six_real_journal_acknowledgements_equal_and_over_budget_preserve_effects(self):
  for phase in p.PHASES:
   for boundary in (90,90.001):
    with self.subTest(phase=phase,boundary=boundary),a.World() as w,Monitor(w) as m:
     elapsed=[0];fired=[];write=p.Journal.write
     def slow(journal,*args):
      epoch=write(journal,*args)
      if not fired and w.read()[p.KEY]['phase']==phase:elapsed[0]=boundary;fired.append(True)
      return epoch
     with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p.Journal,'write',slow),self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):w.run()
     self.assertEqual(fired,[True]);record=w.read()[p.KEY]
     self.assertEqual(record['phase'],phase);self.assertEqual(len(record['intendedEpochs']),p.PHASES.index(phase)+1)
     count=0 if phase in ('intended','sudo-issued') else 1 if phase in ('sudo-done','tmpfiles-issued') else 2
     self.assertEqual(len(w.unlinks),count);self.assertEqual(m.live,{})

 def test_actual_temporary_file_fsync_overrun_may_publish_but_must_refuse_without_undo(self):
  for phase in ('intended','sudo-issued','fenced'):
   with self.subTest(phase=phase),a.World() as w,Monitor(w) as m:
    elapsed=[0];fired=[];sync=p.os.fsync
    def slow(fd):
     result=sync(fd);s=a.REAL_FSTAT(fd)
     current=w.read().get(p.KEY,{}).get('phase')
     next_phase='intended' if current is None else p.PHASES[p.PHASES.index(current)+1] if current!='fenced' else None
     if not fired and stat.S_ISREG(s.st_mode) and next_phase==phase:
      elapsed[0]=90;fired.append(True)
     return result
    with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p.os,'fsync',slow),self.assertRaises(p.Refused):w.run()
    self.assertEqual(fired,[True]);self.assertEqual(w.read()[p.KEY]['phase'],phase)
    self.assertEqual(len(w.unlinks),2 if phase=='fenced' else 0);self.assertEqual(m.live,{})

 def test_late_cas_read_boundary_cannot_authorize_unlink_on_stale_entry_time(self):
  with a.World() as w,Monitor(w) as m:
   elapsed=[0];calls=[];fired=[];selected=w.selected;check=p.Journal.check
   def context(*args):
    row=selected(*args)
    if w.read().get(p.KEY,{}).get('phase')=='sudo-issued':calls.append(True)
    return row
   def checked(journal,*args):
    row=check(journal,*args)
    if not fired and len(calls)==2 and inspect.currentframe().f_back.f_code.co_name=='fresh':
     elapsed[0]=90;fired.append(True)
    return row
   with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p,'actual_context',context),patch.object(p.Journal,'check',checked),self.assertRaises(p.Refused):w.run()
   self.assertEqual(calls,[True,True]);self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[])
   self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued');self.assertEqual(m.live,{})

 def test_both_immediate_parent_preunlink_boundaries_equal_and_over_refuse(self):
  for index in (0,1):
   for boundary in (90,90.001):
    with self.subTest(index=index,boundary=boundary),a.World() as w,Monitor(w) as m:
     elapsed=[0];fired=[];check=p.Directory.check;phase=('sudo-issued','tmpfiles-issued')[index]
     def checked(parent):
      row=check(parent)
      if not fired and parent.path==w.specs[index][0].parent and inspect.currentframe().f_back.f_code.co_name=='_fence' and w.read().get(p.KEY,{}).get('phase')==phase:
       elapsed[0]=boundary;fired.append(True)
      return row
     with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p.Directory,'check',checked),self.assertRaises(p.Refused):w.run()
     self.assertEqual(fired,[True]);self.assertEqual(w.read()[p.KEY]['phase'],phase)
     self.assertEqual(len(w.unlinks),index);self.assertEqual(m.live,{})
     before=len(m.opens)
     with self.assertRaises(p.Refused):w.run()
     self.assertEqual(len(w.unlinks),index);self.assertEqual(m.opens[before:],[])

 def test_each_real_policy_parent_fsync_overrun_resumes_only_owned_absence(self):
  for index in (0,1):
   for boundary in (90,90.001):
    with self.subTest(index=index,boundary=boundary),a.World() as w,Monitor(w) as m:
     elapsed=[0];fired=[];sync=p.os.fsync;parent=w.sudo if index==0 else w.tmpfiles;s=a.REAL_LSTAT(parent);identity=(s.st_dev,s.st_ino)
     def slow(fd):
      row=sync(fd);s=a.REAL_FSTAT(fd)
      if not fired and (s.st_dev,s.st_ino)==identity and not (parent/w.specs[index][0].name).exists():elapsed[0]=boundary;fired.append(True)
      return row
     with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(p.os,'fsync',slow),self.assertRaises(p.Refused):w.run()
     self.assertEqual(fired,[True]);self.assertEqual(w.read()[p.KEY]['phase'],('sudo-issued','tmpfiles-issued')[index])
     self.assertEqual(len(w.unlinks),index+1);self.assertEqual(m.live,{})
     before=len(m.opens);w.run()
     self.assertEqual([i for i,fd,flags in m.opens[before:]],([1] if index==0 else []))
     self.assertEqual(w.unlinks,[row[0].name for row in w.specs]);self.assertEqual(m.live,{})

 def test_cleanup_overrun_of_lease_operation_journal_or_policy_cannot_return_success(self):
  for kind in ('lease-directory','operation','journal','policy'):
   for boundary in (89.999,90,90.001):
    with self.subTest(kind=kind,boundary=boundary),a.World() as w,Monitor(w) as m:
     elapsed=[0];fired=[];result=None;refused=False
     cls=p.Directory if kind=='lease-directory' else p.HeldOperation if kind=='operation' else p.Journal if kind=='journal' else p.HeldPolicy
     close=cls.close
     def slow(obj):
      row=close(obj)
      if not fired and w.read().get(p.KEY,{}).get('phase')=='fenced' and (kind!='lease-directory' or obj.path==w.context.runtime):
       elapsed[0]=boundary;fired.append(True)
      return row
     with patch.object(p.time,'monotonic',side_effect=lambda:1000+elapsed[0]),patch.object(cls,'close',slow):
      try:result=w.run()
      except p.Refused:refused=True
     self.assertEqual(fired,[True]);self.assertEqual(m.live,{})
     self.assertEqual(w.read()[p.KEY]['phase'],'fenced');self.assertEqual(len(w.unlinks),2)
     self.assertEqual(refused,boundary>=90)
     if boundary<90:self.assertEqual(result['policiesAbsent'],2)
     else:self.assertIsNone(result)

 def test_early_context_error_before_epoch_closes_all_without_uninitialized_clock(self):
  with a.World() as w,Monitor(w) as m:
   with patch.object(p,'actual_context',side_effect=p.Refused('own-early-error')),patch.object(p.time,'monotonic',side_effect=AssertionError('clock before epoch')) as clock,self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):w.run()
   clock.assert_not_called();self.assertEqual(m.live,{})
   self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())

 def test_only_one_original_90_second_epoch_assignment_and_wire_unchanged(self):
  root=p.Path(__file__).parent
  old=ast.parse((root/'baseline/policy_fence.py').read_text());new=ast.parse(p.Path(p.__file__).read_text())
  before=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name=='_fence')
  after=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='_fence')
  def epochs(node):
   return [n for n in ast.walk(node) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='deadline' for t in n.targets) and isinstance(n.value,ast.BinOp)]
  a0=epochs(before);a1=epochs(after)
  self.assertEqual(len(a0),1);self.assertEqual(len(a1),1);self.assertEqual(ast.dump(a0[0]),ast.dump(a1[0]))
  self.assertEqual(p.PHASES,('intended','sudo-issued','sudo-done','tmpfiles-issued','tmpfiles-done','fenced'))
  with a.World() as w:
   result=w.run();record=w.read()[p.KEY]
   self.assertEqual(len(record),14);self.assertEqual(len(set(record['intendedEpochs'])),6)
   self.assertEqual(record['operationSha256'],p.sha(p.Path(p.__file__).read_bytes()))
   self.assertEqual(result['nativeRecoveryAuthorized'],False);self.assertEqual(result['acceptedIntegratedInstalls'],0)
