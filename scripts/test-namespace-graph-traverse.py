#!/usr/bin/env python3
"""Root-only isolated ACL fixtures, NOT actual installed OCI acceptance."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/grant-rootless-volume-parent-traverse.py'
spec=importlib.util.spec_from_file_location('graph_traverse',P);M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

@unittest.skipUnless(os.geteuid()==0,'isolated root ownership/ACL fixture')
class NamespaceGraph(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name);self.scope=self.root/'scope';self.scope.mkdir(mode=0o700)
  self.parents=self.scope/'graphs';self.parents.mkdir(mode=0o700);self.graph=self.parents/'finance';self.graph.mkdir(mode=0o700);os.chown(self.graph,1801,1801)
  self.bundle=self.root/'bundle';self.bundle.mkdir();self.ir={'services':{'fixture':{'rootlessDomain':'finance','userns':'keep-id:uid=33,gid=33'}}};self.save()
  self.row={'name':'finance','user':'fixture-finance','uid':1801,'graphRoot':str(self.graph)};self.operator=SimpleNamespace(pw_uid=0,pw_gid=0)
 def tearDown(self):self.t.cleanup()
 def save(self):(self.bundle/'stack.ir.json').write_text(json.dumps(self.ir))
 def grant(self):
  with patch.object(M,'namespace_root_id',return_value=2811000),patch.object(M.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=1801)):
   return M.grant_namespace_graph_parents(self.bundle,self.scope,self.operator,self.row)
 def test_exact_unmapped_ancestors_only(self):
  original={p:M.entries(p) for p in (self.root,self.graph)}
  self.assertTrue(self.grant());self.assertFalse(self.grant())
  for p in (self.scope,self.parents):
   acl=M.entries(p);self.assertEqual(acl[('user','2811000')],'--x');self.assertEqual(acl[('other','')],'---');self.assertEqual(acl[('group','')],'---')
  for p,a in original.items():self.assertEqual(M.entries(p),a)
 def test_no_keep_id_no_subordinate_authority_lookup(self):
  self.ir['services']['fixture'].pop('userns');self.save()
  with patch.object(M,'namespace_root_id',side_effect=AssertionError('unnecessary authority')):
   self.assertFalse(M.grant_namespace_graph_parents(self.bundle,self.scope,self.operator,self.row))
 def test_graph_foreign_group_refused(self):
  os.chown(self.graph,1801,1802)
  with self.assertRaises(ValueError):self.grant()
  self.assertNotIn(('user','2811000'),M.entries(self.scope))
 def test_linked_graph_refused(self):
  link=self.parents/'alias';link.symlink_to(self.graph);self.row['graphRoot']=str(link)
  with self.assertRaises(ValueError):self.grant()
 def test_fd_grant_refuses_linked_intermediate(self):
  link=self.root/'alias';link.symlink_to(self.scope)
  with self.assertRaises(OSError):M.exact_execute(link/'graphs','2811000')
  self.assertNotIn(('user','2811000'),M.entries(self.parents))
 def test_existing_execute_acl_under_closed_mask_is_not_success(self):
  import subprocess
  subprocess.run(['setfacl','--no-mask','-m','u:2811000:--x,m::---',str(self.scope)],check=True)
  before=M.entries(self.scope)
  with self.assertRaises(ValueError):M.exact_execute(self.scope,'2811000')
  self.assertEqual(M.entries(self.scope),before)
 def test_subordinate_files_exact_equal_private_authority(self):
  files=[self.root/n for n in ('subuid','subgid')]
  for p in files:p.write_text('fixture-finance:2811000:65536\n');p.chmod(0o600)
  self.assertEqual(M.namespace_root_id('fixture-finance',files=files),2811000)
  files[1].write_text('fixture-finance:2811001:65536\n')
  with self.assertRaises(ValueError):M.namespace_root_id('fixture-finance',files=files)
  files[1].write_text('fixture-finance:2811000:65536\nfixture-finance:2900000:65536\n')
  with self.assertRaises(ValueError):M.namespace_root_id('fixture-finance',files=files)
  files[1].write_text('fixture-finance:2811000:65536\nother:2811001:65536\n')
  with self.assertRaises(ValueError):M.namespace_root_id('fixture-finance',files=files)
  files[1].write_text('fixture-finance:2811000:65536\n');files[1].chmod(0o666)
  with self.assertRaises(ValueError):M.namespace_root_id('fixture-finance',files=files)

if __name__=='__main__':unittest.main()
