#!/usr/bin/env python3
"""Selected /var/tmp Buildah scratch cannot include foreign or unsafe inodes."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('venue_failed_tmp',Path(__file__).resolve().parents[1]/
    'runtime-generator/podman-ops/venue-build-tmp-retire.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)

@unittest.skipUnless(os.geteuid()==0,'root fixture needs synthetic selected UID')
class ExactScratch(unittest.TestCase):
    def setUp(self):
        scratch=tempfile.TemporaryDirectory();self.addCleanup(scratch.cleanup)
        self.root=Path(scratch.name);self.root.chmod(0o1777)
        self.names=['buildah12345','container_images_storage444']
        for name in self.names:
            p=self.root/name;p.mkdir(mode=0o700);os.chown(p,3206,3206)
            f=p/'1';f.write_bytes(b'abc');f.chmod(0o600);os.chown(f,3206,3206)
    def test_only_two_exact_private_file_and_parent_inodes(self):
        self.assertEqual(len(tool.classify(self.root,self.names,3206)),4)
        with self.assertRaisesRegex(tool.Refusal,'two selected'):
            tool.classify(self.root,['buildah12345'],3206)
        extra=self.root/self.names[0]/'foreign';extra.write_text('leave');
        with self.assertRaisesRegex(tool.Refusal,'unexpected members'):
            tool.classify(self.root,self.names,3206)
        extra.unlink()
        os.chown(self.root/self.names[0]/'1',1003,1003)
        with self.assertRaisesRegex(tool.Refusal,'inode/owner/mode'):
            tool.classify(self.root,self.names,3206)
    def test_symlink_and_hardlink_refuse_without_removal(self):
        file=self.root/self.names[0]/'1';linked=self.root/'foreign-link';os.link(file,linked)
        with self.assertRaisesRegex(tool.Refusal,'inode/owner/mode'):
            tool.classify(self.root,self.names,3206)
        linked.unlink();file.unlink();file.symlink_to('/etc/hosts')
        with self.assertRaisesRegex(tool.Refusal,'inode/owner/mode'):
            tool.classify(self.root,self.names,3206)
        self.assertTrue(Path('/etc/hosts').exists())

if __name__=='__main__':unittest.main()
