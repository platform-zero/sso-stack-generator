#!/usr/bin/env python3
"""Reject ambiguous maintenance authority before a mutation or successful receipt."""
import importlib.util,json,tempfile,unittest,io,contextlib
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'runtime-generator/podman-ops'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
B=load('p0-host-broker');C=load('p0-hostctl')
class Authority(unittest.TestCase):
 def test_duplicate_rpc_and_boolean_version_never_dispatch(self):
  for body in (b'{"version":1,"action":"status","action":"activate"}',b'{"version":1,"action":"status","data":{"secret":"one","secret":"two"}}',b'{"version":true,"action":"status"}',b'[]'):
   with patch.dict(B.ACTIONS,{'status':lambda r:self.fail('dispatch')},clear=True):
    x=B.handle(body);self.assertFalse(x['ok']);self.assertNotIn('one',x['error']);self.assertNotIn('two',x['error'])
 def test_all_bundle_authority_files(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);(root/'ops').mkdir()
   for f in ('platform-zero.nft','install-podman-bundle.sh'):(root/'ops'/f).write_text('table inet platform_zero {\n policy accept\n}\n')
   values={'bundle.json':{'backend':'podman'},'stack.ir.json':{},'podman-domains.json':{'domains':[{'name':'apps','user':'webservices-apps'}]},'podman-loopback-endpoints.json':{}}
   for bad in values:
    for name,v in values.items():(root/name).write_text(json.dumps(v))
    (root/bad).write_text('{"secret":"one","secret":"two"}')
    with self.assertRaisesRegex(B.RequestError,'^JSON authority rejected$'):B.validate_bundle(root)
 def test_restore_rejects_domains_before_any_stop(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'domains';p.write_text('{"domains":[],"domains":[]}')
   with patch.object(B,'DOMAINS_MANIFEST',p),patch.object(B,'snapshot_path',return_value=Path(d)),patch.object(B,'run')as run:
    with self.assertRaises(B.RequestError):B.restore({'confirm':'RESTORE_PLATFORM_ZERO'})
    run.assert_not_called()
 def test_gc_rejects_domains_before_pruning(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);p=root/'domains';p.write_text('{"domains":[],"domains":[]}');active=root/'active';active.write_text('{}')
   with patch.object(B,'DOMAINS_MANIFEST',p),patch.object(B,'ACTIVE_RELEASE',active),patch.object(B.shutil,'rmtree')as remove:
    with self.assertRaises(B.RequestError):B.garbage_collect({})
    remove.assert_not_called()
 def test_client_duplicate_private_receipt_is_generic(self):
  class Socket:
   def __enter__(self):return self
   def __exit__(self,*a):pass
   def connect(self,*a):pass
   def settimeout(self,*a):pass
   def sendall(self,*a):pass
   def recv(self,*a):return b'{"ok":true,"result":{"secret":"one","secret":"two"}}\n'
  out=io.StringIO();err=io.StringIO()
  with patch.object(C.socket,'socket',return_value=Socket()),patch('sys.argv',['p0-hostctl','status']),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):self.assertEqual(C.main(),1)
  self.assertEqual(out.getvalue(),'');self.assertEqual(err.getvalue(),'p0-hostctl: invalid host broker response\n')
if __name__=='__main__':unittest.main()
