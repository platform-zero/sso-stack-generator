#!/usr/bin/env python3
"""Run the real initial Python metadata guard on temp FDs, modeled UID/GID.

No privileged fixtures or host operations. The separate 60-case metadata owner
suite covers the source-bound post-FD9 seal; this guard MUST NOT chmod anything.
"""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-podman-bundle.sh'
TEXT=SOURCE.read_text()
START='python3 - "$STATE_ROOT" "$STANDALONE" <<\'PY\'\n'
CODE=compile(TEXT.split(START,1)[1].split('\nPY\n',1)[0],str(SOURCE)+'#metadata-guard','exec')

class Guard(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.base=Path(temporary.name);self.root=self.base/'state';self.gid=0
    def run_guard(self, private=True):
        original_lstat=Path.lstat;original_fstat=os.fstat
        def modeled(info):
            fields=list(info);fields[4]=0;fields[5]=self.gid
            return os.stat_result(fields)
        with patch.object(Path,'lstat',lambda path:modeled(original_lstat(path))),patch.object(os,'fstat',lambda fd:modeled(original_fstat(fd))),patch.object(os,'fchmod',side_effect=AssertionError('pre-lock chmod forbidden')),patch.object(sys,'argv',['guard',str(self.root),str(private).lower()]):
            exec(CODE,{})
    def existing(self,mode=0o755):
        self.root.mkdir(mode=mode);self.root.chmod(mode)
    def test_new_native_metadata_is_private_without_chmod(self):
        self.run_guard();self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o700)
        self.assertEqual((self.root/'.install.lock').read_bytes(),b'')
    def test_existing_755_unchanged_until_post_lock_canonical_seal(self):
        self.existing();self.run_guard()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o755)
    def test_existing_700_stays_private(self):
        self.existing(0o700);self.run_guard()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o700)
    def test_unrelated_root_group_refuses_without_chmod(self):
        self.existing();self.gid=1000
        with self.assertRaises(SystemExit):self.run_guard()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o755)
    def test_group_writable_root_refuses(self):
        self.existing(0o775)
        with self.assertRaises(SystemExit):self.run_guard()
        self.assertFalse((self.root/'.install.lock').exists())
    def test_nonempty_lock_is_not_adopted_or_truncated(self):
        self.existing();lock=self.root/'.install.lock';lock.write_bytes(b'authored lock');lock.chmod(0o600)
        with self.assertRaises(SystemExit):self.run_guard()
        self.assertEqual(lock.read_bytes(),b'authored lock')
    def test_linked_lock_refuses_without_target_changes(self):
        self.existing();target=self.base/'authored';target.write_bytes(b'preserve');target.chmod(0o600)
        (self.root/'.install.lock').symlink_to(target)
        with self.assertRaises(OSError):self.run_guard()
        self.assertEqual(target.read_bytes(),b'preserve')
    def test_hardlinked_lock_refuses(self):
        self.existing();target=self.base/'authored';target.touch(mode=0o600)
        os.link(target,self.root/'.install.lock')
        with self.assertRaises(SystemExit):self.run_guard()
        self.assertEqual(target.stat().st_nlink,2)
    def test_metadata_acl_refuses_without_lock_creation(self):
        self.existing()
        with patch.object(os,'getxattr',return_value=b'modeled-acl'):
            with self.assertRaises(SystemExit):self.run_guard()
        self.assertFalse((self.root/'.install.lock').exists())
    def test_source_seals_under_fd9_before_preparing_journal(self):
        lock=TEXT.index('flock -n 9 ||')
        seal=TEXT.index('"$BUNDLE/ops/native-metadata-owner.py" --root')
        preparing=TEXT.index('\njournal preparing\n')
        self.assertLess(lock,seal);self.assertLess(seal,preparing)
        self.assertIn('mktemp "$STATE_ROOT/.native-metadata-seal-',TEXT[lock:seal])

if __name__=='__main__':unittest.main()
