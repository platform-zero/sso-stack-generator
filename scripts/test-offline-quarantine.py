#!/usr/bin/env python3
"""Mock offline-manager proof; never run a manager or live host operation."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
p=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-journal.py';spec=importlib.util.spec_from_file_location('offline_journal',p);J=importlib.util.module_from_spec(spec);spec.loader.exec_module(J)
def completed(text='',rc=0):return SimpleNamespace(stdout=text,stderr='',returncode=rc)
class OfflineQuarantine(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.row={'name':'finance','uid':1801,'user':'fixture-finance'}
  (self.root/'podman-domains.json').write_text(json.dumps({'deploymentMode':'standalone','domains':[self.row]}))
  self.command=['runuser','-u','fixture-finance','--','env','HOME=/home/fixture-finance','XDG_RUNTIME_DIR=/run/user/1801','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1801/bus','systemctl','--user']
 def tearDown(self):self.t.cleanup()
 def test_offline_client_never_starts_manager(self):
  cmd=J.offline_control(self.command)
  self.assertEqual(cmd[-4:],['SYSTEMD_OFFLINE=1','systemctl','--user','--no-reload']);self.assertNotIn('start',cmd)
 def test_stopped_manager_is_not_revived(self):
  props='Id=user@1801.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n'
  with patch.object(J.subprocess,'run',return_value=completed(props))as run:
   self.assertEqual(J.offline_actor(self.root,'rootless-finance'),self.row)
   self.assertEqual(run.call_count,1);self.assertEqual(run.call_args.args[0][:2],['systemctl','show'])
 def test_unknown_or_pending_manager_denied(self):
  base='Id=user@1801.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n'
  for bad in ('MainPID=8','Job=123','LoadState=not-found'):
   key=bad.split('=')[0];text='\n'.join(bad if l.startswith(key+'=') else l for l in base.splitlines())
   with self.subTest(bad=bad),patch.object(J.subprocess,'run',return_value=completed(text)),self.assertRaises(ValueError):J.offline_actor(self.root,'rootless-finance')
 def verify(self,states='disabled\ndisabled\n',processes=(),linger=False,jobs=''):
  def run(args,**kwargs):return completed(states,1) if 'is-enabled'in args else completed(jobs)
  with patch.object(J.subprocess,'run',side_effect=run),patch.object(J,'offline_subordinate_start',return_value=2811000),patch.object(J.Path,'exists',return_value=linger),patch.object(J.Path,'is_symlink',return_value=False),patch.object(J.Path,'glob',return_value=processes):
   J.verify_offline_actor(self.row,self.command)
 def test_closed_offline_actor_passes(self):self.verify()
 def test_enabled_api_or_linger_deny(self):
  for states in ('disabled\nenabled\n','enabled\ndisabled\n','disabled\n'):
   with self.subTest(states=states),self.assertRaises(ValueError):self.verify(states)
  with self.assertRaises(ValueError):self.verify(linger=True)
 def test_actor_or_subordinate_process_denies(self):
  for uid in (1801,2811000):
   proc=SimpleNamespace(__truediv__=None)
   class Proc:
    def __truediv__(self,key):return SimpleNamespace(read_text=lambda:'Name:\tfixture\nUid:\t'+('\t'.join([str(uid)]*4))+'\n')
   with self.subTest(uid=uid),self.assertRaises(ValueError):self.verify(processes=[Proc()])
 def test_pending_manager_job_denies(self):
  with self.assertRaises(ValueError):self.verify(jobs='123 user@1801.service start waiting\n')
if __name__=='__main__':unittest.main()
