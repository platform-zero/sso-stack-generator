#!/usr/bin/env python3
"""Actual FD byte-pin checks for generated helpers, not execution authority."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/verify-agent-vm-bundle.py'
spec=importlib.util.spec_from_file_location('native_live_ops_test',SOURCE)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class LiveOps(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.ops=self.root/'ops';self.ops.mkdir()
  self.file=self.ops/'helper.py';self.file.write_bytes(b'# public helper source\n')
  self.pins={'ops/helper.py':hashlib.sha256(self.file.read_bytes()).hexdigest()}
 def check(self,pins=...):return v.verify_live_ops(self.root,{'liveOps':self.pins if pins is ... else pins})
 def test_exact_actual_fd_bytes(self):self.assertEqual(self.check(),self.pins)
 def test_actual_first_read_atime_update_is_not_content_mutation(self):
  before=self.file.stat();os.utime(self.file,ns=(0,before.st_mtime_ns))
  self.assertEqual(self.file.stat().st_atime_ns,0)
  self.assertEqual(self.check(),self.pins)
  self.assertGreater(self.file.stat().st_atime_ns,0)
 def test_held_mode_mutation_during_read_refused(self):
  original=v.os.read;changed=False
  def raced(fd,count):
   nonlocal changed
   body=original(fd,count)
   if not changed:
    changed=True;os.fchmod(fd,os.fstat(fd).st_mode ^ 0o040)
   return body
  with patch.object(v.os,'read',side_effect=raced),self.assertRaises(ValueError):self.check()
 def test_same_bytes_inode_mtime_mutation_during_read_refused(self):
  original=v.os.read;changed=False
  def raced(fd,count):
   nonlocal changed
   body=original(fd,count)
   if not changed:
    changed=True;info=os.fstat(fd);os.utime(fd,ns=(info.st_atime_ns,info.st_mtime_ns+1000000000))
   return body
  with patch.object(v.os,'read',side_effect=raced),self.assertRaises(ValueError):self.check()
 def test_legacy_absence_is_not_backfilled(self):
  self.assertIsNone(v.verify_live_ops(self.root,{}));self.assertNotIn('liveOps',{})
 def test_empty_or_non_mapping_refused(self):
  for value in ({},[],None,True):
   with self.subTest(value=value),self.assertRaises(ValueError):self.check(value)
 def test_unknown_extra_namespace_refused(self):
  (self.ops/'foreign.py').write_bytes(b'authored');
  with self.assertRaises(ValueError):self.check()
  self.assertEqual((self.ops/'foreign.py').read_bytes(),b'authored')
 def test_missing_selected_file_refused(self):
  self.file.unlink()
  with self.assertRaises(ValueError):self.check()
 def test_traversal_or_nested_path_refused(self):
  for key in ('ops/../helper.py','ops/a/helper.py','/ops/helper.py','ops/.hidden'):
   with self.subTest(key=key),self.assertRaises(ValueError):self.check({key:'0'*64})
 def test_changed_bytes_refused(self):
  self.file.write_bytes(b'# changed\n')
  with self.assertRaises(ValueError):self.check()
 def test_symlink_refused(self):
  target=self.root/'target';self.file.rename(target);self.file.symlink_to(target)
  with self.assertRaises((ValueError,OSError)):self.check()
 def test_hardlink_refused(self):
  os.link(self.file,self.root/'alias')
  with self.assertRaises(ValueError):self.check()
 def test_directory_in_map_refused(self):
  self.file.unlink();self.file.mkdir()
  with self.assertRaises(ValueError):self.check()
 def test_ops_directory_link_refused(self):
  actual=self.root/'elsewhere';self.ops.rename(actual);self.ops.symlink_to(actual)
  with self.assertRaises(ValueError):self.check()
 def test_named_same_byte_inode_swap_during_read_refused(self):
  original=v.os.read;changed=False
  def raced(fd,count):
   nonlocal changed
   body=original(fd,count)
   if not changed:
    changed=True;replacement=self.root/'replacement';replacement.write_bytes(self.file.read_bytes());os.replace(replacement,self.file)
   return body
  with patch.object(v.os,'read',side_effect=raced),self.assertRaises(ValueError):self.check()

if __name__=='__main__':unittest.main()
