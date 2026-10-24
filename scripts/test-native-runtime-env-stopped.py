#!/usr/bin/env python3
"""Source-only systemd target interface contract; NO host/systemd reads."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

source=Path(__file__).parents[1]/'runtime-generator/podman-ops/native-runtime-env-units.py'
spec=importlib.util.spec_from_file_location('runtime_env_stopped_source',source)
u=importlib.util.module_from_spec(spec);sys.modules[spec.name]=u;spec.loader.exec_module(u)
class TargetInterface(unittest.TestCase):
 def setUp(self):
  self.props={name:dict(Id=name,Names=name,ActiveState='inactive',Job='',LoadState='not-found',FragmentPath='',SourcePath='',DropInPaths='') for name in ('webservices.target',u.UNIT)}
  self.props[u.UNIT]['MainPID']='0'
  self.session=SimpleNamespace(plan={'scopes':{'rootful':{'units':['webservices.target','example.service']}}},release=Path('/var/lib/test/releases/test'),file_entries={u.HOST/'etc/systemd/system/webservices.target.d'/u.DROPIN:{'before':None}})
 def check(self):
  def query(command,**kwargs):
   self.assertEqual(command[:2],['systemctl','show']);values=self.props[command[2]]
   return SimpleNamespace(returncode=0,stdout='\n'.join(k+'='+v for k,v in values.items()))
  with patch.object(u.m,'stopped') as stopped,patch('subprocess.run',side_effect=query):
   u.Session.check_stopped(self.session)
   self.assertEqual(stopped.call_args.args[1]['scopes']['rootful']['units'],['example.service'])
 def test_target_omitted_inapplicable_main_pid_passes(self):self.check()
 def test_helper_service_requires_explicit_main_pid(self):
  del self.props[u.UNIT]['MainPID']
  with self.assertRaises(ValueError):self.check()
 def test_target_nonzero_pid_active_job_alias_or_override_still_refuses(self):
  for key,value in (('MainPID','7'),('ActiveState','active'),('Job','23'),('Names','webservices.target foreign.target'),('DropInPaths','/foreign')):
   original=dict(self.props['webservices.target']);self.props['webservices.target'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check()
   self.props['webservices.target']=original
if __name__=='__main__':unittest.main()
