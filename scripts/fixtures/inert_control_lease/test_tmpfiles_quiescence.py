"""Strict tmpfiles writer-quiescence SOURCE observations; no actual PID1/proc."""
import unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as author
SEARCH=['/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system']

def boot(name,**changes):
 row={'LoadState':'loaded','ActiveState':'active','SubState':'exited','FragmentPath':'/usr/lib/systemd/system/'+name,
  'DropInPaths':'','Type':'oneshot','RemainAfterExit':'yes','MainPID':'0','ControlPID':'0','Result':'success','ExecMainStatus':'0','ControlGroup':''}
 row.update(changes);return row

def text(row):return '\n'.join(k+'='+v for k,v in row.items())+'\n'

class TmpfilesTests(unittest.TestCase):
 def query_boot(self,w,changes=None):
  previous=w.sysd
  def query(args):
   if args[0]=='show' and args[1] in p.TMPFILES:return 0,text(boot(args[1],**(changes or {})))
   return previous(args)
  return query
 def test_exact_three_boot_remain_after_exit_oneshots_allow_full_fence(self):
  with author.World() as w,patch.object(p,'_systemctl',side_effect=self.query_boot(w)):
   self.assertEqual(w.run()['policiesAbsent'],2)
   self.assertIn('processes',w.events);self.assertEqual(len(w.unlinks),2)
 def test_running_pids_noncanonical_pids_failure_type_remain_group_and_fragment_refuse(self):
  bad=[{'SubState':'running'},{'ActiveState':'reloading'},{'MainPID':'1'},{'ControlPID':'2'},
   {'MainPID':'00'},{'MainPID':'+0'},{'MainPID':' 0'},{'MainPID':'False'},{'ControlPID':'0.0'},
   {'Result':'exit-code'},{'ExecMainStatus':'1'},{'Type':'simple'},{'RemainAfterExit':'no'},
   {'ControlGroup':'/system.slice/../foreign'},{'ControlGroup':'/foreign.slice/test'},
   {'DropInPaths':'/own/override'},{'FragmentPath':'/usr/lib/systemd/system/wrong.service'},
   {'FragmentPath':'/usr/lib/systemd/../system/systemd-tmpfiles-setup.service'}]
  for changes in bad:
   with self.subTest(changes=changes),author.World() as w,patch.object(p,'_systemctl',side_effect=self.query_boot(w,changes)):
    with self.assertRaises(p.Refused):w.run()
    self.assertEqual(w.unlinks,[])
 def test_cgroup_present_refuses_even_when_both_pids_zero(self):
  with author.World() as w:
   name=p.TMPFILES[0];group=w.mapped('/sys/fs/cgroup/system.slice/'+name);group.mkdir(parents=True,mode=0o700)
   with patch.object(p,'_systemctl',side_effect=self.query_boot(w)),self.assertRaises(p.Refused):w.run()
   self.assertEqual(w.unlinks,[])
 def test_exact_canonical_nonempty_group_metadata_requires_actual_absence(self):
  with author.World() as w:
   name=p.TMPFILES[0]
   with patch.object(p,'_systemctl',return_value=(0,text(boot(name,ControlGroup='/system.slice/'+name)))):
    p._tmpfiles_quiescent(name,SEARCH)
 def test_tmpfiles_queued_job_and_private_root_process_each_refuse(self):
  for kind in ('job','process'):
   with self.subTest(kind=kind),author.World() as w:
    old=self.query_boot(w)
    def query(args):
     if kind=='job' and args[0]=='list-jobs':return 0,'1 '+p.TMPFILES[0]+' start waiting\n'
     return old(args)
    w.block_process=kind=='process'
    with patch.object(p,'_systemctl',side_effect=query),self.assertRaises(p.Refused):w.run()
    self.assertEqual(w.unlinks,[])
 def test_inactive_failed_controls_require_zero_pids_and_absent_cgroup(self):
  for active,sub in (('inactive','dead'),('failed','failed')):
   with self.subTest(active=active),author.World() as w:
    name=p.TMPFILES[0];row=boot(name,ActiveState=active,SubState=sub,Result='exit-code',ExecMainStatus='1')
    with patch.object(p,'_systemctl',return_value=(0,text(row))):p._tmpfiles_quiescent(name,SEARCH)
    row['ControlPID']='3'
    with patch.object(p,'_systemctl',return_value=(0,text(row))),self.assertRaises(p.Refused):p._tmpfiles_quiescent(name,SEARCH)
 def test_notfound_requires_no_unit_path_and_no_process_identity(self):
  with author.World() as w:
   name=p.TMPFILES[0];row=boot(name,LoadState='not-found',ActiveState='inactive',SubState='dead',FragmentPath='',Type='',RemainAfterExit='no')
   with patch.object(p,'_systemctl',return_value=(4,text(row))):p._tmpfiles_quiescent(name,SEARCH)
   definition=w.mapped(SEARCH[0]+'/'+name);definition.parent.mkdir(parents=True,mode=0o700);definition.write_bytes(b'own synthetic unit')
   with patch.object(p,'_systemctl',return_value=(4,text(row))),self.assertRaises(p.Refused):p._tmpfiles_quiescent(name,SEARCH)
 def test_host_and_user_strict_predicate_is_not_changed_to_boot_oneshot_rule(self):
  for missing in (False,True):
   with self.subTest(missing=missing),author.World() as w:
    row={'LoadState':'loaded','ActiveState':'active','SubState':'exited','FragmentPath':'','DropInPaths':''}
    with patch.object(p,'_systemctl',return_value=(0,text(row))),self.assertRaises(p.Refused):p._unit_inactive('own.service',missing=missing)

if __name__=='__main__':unittest.main(verbosity=2)
