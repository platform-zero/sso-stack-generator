#!/usr/bin/env python3
"""Host post-publisher narrow file ACL and chmod-rotation hostile fixtures."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-runner-token-file-acl.py'
spec=importlib.util.spec_from_file_location('venue_token_acl',src)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

@unittest.skipUnless(os.geteuid()==0,'root required for selected host-side ACL fixture')
class FileACL(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/'token';self.path.write_bytes(b'synthetic-token-not-real\n');self.path.chmod(0o400)
        self.addCleanup(lambda:subprocess.run(['setfacl','-b',str(self.path)],capture_output=True) if self.path.exists() else None)
    def test_only_selected_consumer_and_post_chmod_reconcile(self):
        consumer=3204;self.assertEqual(module.acl(self.path),['user::r--','group::---','other::---'])
        first=module.narrow(self.path,{0},consumer)
        self.assertTrue(first['aclExactlyNarrow']);self.assertFalse(first['tokenValueDisclosed'])
        expected=['user::r--',f'user:{consumer}:r--','group::---','mask::r--','other::---']
        self.assertEqual(module.acl(self.path),expected)
        self.path.chmod(0o400)
        self.assertNotEqual(module.acl(self.path),expected)
        self.assertEqual(module.narrow(self.path,{0},consumer)['fileIno'],first['fileIno'])
        self.assertEqual(module.acl(self.path),expected)
    def test_foreign_named_acl_refused_before_mask_expansion(self):
        subprocess.run(['setfacl','-m','u:3201:r--',str(self.path)],check=True,capture_output=True)
        before=module.acl(self.path)
        with self.assertRaises(module.Refusal):module.narrow(self.path,{0},3204)
        self.assertEqual(module.acl(self.path),before)
    def test_unlinked_and_world_writable_inodes_refuse(self):
        self.path.chmod(0o666)
        with self.assertRaises(module.Refusal):module.narrow(self.path,{0},3204)
        self.path.chmod(0o400);link=self.path.with_name('token-link');link.symlink_to(self.path)
        with self.assertRaises(module.Refusal):module.narrow(link,{0},3204)
        link.unlink()

if __name__=='__main__':unittest.main()
