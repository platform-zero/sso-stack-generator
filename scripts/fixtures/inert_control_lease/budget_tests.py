"""Own-file full-flow monotonic-clock models. No sleeps/native authority."""
import inspect,unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a

class BudgetTests(unittest.TestCase):
 def test_just_below_90_after_two_scans_allows_all_six_publications(self):
  with a.World() as w:
   elapsed=[0];calls=[];selected=w.selected
   def context(*args):
    result=selected(*args)
    if w.read().get(p.KEY,{}).get('phase')=='sudo-issued' and len(calls)<2:elapsed[0]+=44.999;calls.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p,'actual_context',side_effect=context):result=w.run()
   self.assertEqual(calls,[True,True]);self.assertLess(elapsed[0],90)
   self.assertEqual(result['policiesAbsent'],2);self.assertEqual(len(w.unlinks),2)
   self.assertEqual(len(w.read()[p.KEY]['intendedEpochs']),6)
 def test_exact_90_after_scans_refuses_before_unlink_and_issued_present_never_retries(self):
  with a.World() as w:
   elapsed=[0];calls=[];selected=w.selected
   def context(*args):
    result=selected(*args)
    if w.read().get(p.KEY,{}).get('phase')=='sudo-issued':elapsed[0]+=45;calls.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p,'actual_context',side_effect=context),self.assertRaises(p.Refused):w.run()
   self.assertEqual(calls,[True,True]);self.assertEqual(elapsed[0],90)
   self.assertEqual(w.unlinks,[]);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
   with self.assertRaises(p.Refused):w.run()
   self.assertEqual(w.unlinks,[])
 def test_late_private_observation_budget_checked_before_next_expensive_scan(self):
  with a.World() as w:
   elapsed=[0];fired=[];observe=p.native_observations
   def observed(*args):
    observe(*args)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':elapsed[0]=90;fired.append(True)
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p,'native_observations',observed),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[])
 def test_last_direct_held_check_expiry_is_caught_at_actual_preunlink_boundary(self):
  with a.World() as w:
   elapsed=[0];fired=[];old=p.HeldPolicy.check
   def check(policy):
    result=old(policy);caller=inspect.currentframe().f_back
    if not fired and caller.f_code.co_name=='check_held' and caller.f_back.f_code.co_name=='_fence' and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':
     elapsed[0]=90;fired.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.HeldPolicy,'check',check),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[]);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
 def test_final_absence_observation_expiry_cannot_return_success(self):
  with a.World() as w:
   elapsed=[0];fired=[];old=p.Directory.entry
   def entry(parent,name):
    result=old(parent,name);caller=inspect.currentframe().f_back
    if not fired and caller.f_code.co_name=='<genexpr>' and caller.f_back.f_code.co_name=='_fence' and w.read().get(p.KEY,{}).get('phase')=='fenced':
     elapsed[0]=90;fired.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.Directory,'entry',entry),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(len(w.unlinks),2);self.assertEqual(w.read()[p.KEY]['phase'],'fenced')
 def test_expiry_after_issued_journal_ack_preserves_issued_without_delete(self):
  with a.World() as w:
   elapsed=[0];fired=[];old=p.Journal.write
   def write(journal,*args):
    result=old(journal,*args)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':elapsed[0]=90;fired.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.Journal,'write',write),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[]);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
 def test_expiry_after_final_journal_ack_must_refuse_not_report_success(self):
  with a.World() as w:
   elapsed=[0];fired=[];old=p.Journal.write
   def write(journal,*args):
    result=old(journal,*args)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='fenced':elapsed[0]=90;fired.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.Journal,'write',write),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(len(w.unlinks),2);self.assertEqual(w.read()[p.KEY]['phase'],'fenced')
 def test_expiry_after_own_unlink_fsync_keeps_issued_and_new_invocation_resumes_absence_only(self):
  with a.World() as w:
   elapsed=[0];fired=[];old=p.os.fsync;parent=a.REAL_LSTAT(w.sudo)
   def sync(fd):
    result=old(fd);s=a.REAL_FSTAT(fd)
    if not fired and (s.st_dev,s.st_ino)==(parent.st_dev,parent.st_ino) and not (w.sudo/w.specs[0][0].name).exists():elapsed[0]=90;fired.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.os,'fsync',sync),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[w.specs[0][0].name]);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
   w.run();self.assertEqual(w.unlinks,[s[0].name for s in w.specs]);self.assertEqual(w.read()[p.KEY]['phase'],'fenced')

 def test_expiry_during_final_descriptor_cleanup_closes_all_but_cannot_return_success(self):
  with a.World() as w:
   elapsed=[0];closed=[];old=p.HeldPolicy.close
   def close(policy):
    result=old(policy);closed.append(policy.name)
    if w.read().get(p.KEY,{}).get('phase')=='fenced':elapsed[0]=90
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p.HeldPolicy,'close',close),self.assertRaises(p.Refused):w.run()
   self.assertEqual(set(closed),{s[0].name for s in w.specs});self.assertEqual(len(closed),2)
   self.assertEqual(len(w.unlinks),2);self.assertEqual(w.read()[p.KEY]['phase'],'fenced')

if __name__=='__main__':unittest.main(verbosity=2)
