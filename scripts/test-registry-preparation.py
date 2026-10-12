#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-pinned-images.py'
spec=importlib.util.spec_from_file_location('pinned_preparation',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
IMAGE='docker.io/library/alpine:3.22@sha256:'+'a'*64

class RegistryPreparation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.bundle=Path(self.temp.name)
        (self.bundle/'podman-domains.json').write_text(json.dumps({'domains':[{'name':'apps','user':'actor'}]}))
        for label in ('rootful','rootless-apps'):(self.bundle/'quadlet'/label).mkdir(parents=True)
        self.path=self.bundle/'quadlet/rootless-apps/a.container'
        self.path.write_text('Image='+IMAGE+'\n')
        self.calls=[];self.present=set()
        def runner(command,**kwargs):
            self.calls.append(command)
            image=command[-1]
            if command[-3:-1]==['image','exists']:return SimpleNamespace(returncode=0 if image in self.present else 1)
            if command[-2]=='pull':self.present.add(image);return SimpleNamespace(returncode=0)
            raise AssertionError(command)
        self.runner=runner
        self.user=patch.object(module.pwd,'getpwnam',return_value=SimpleNamespace(pw_dir='/home/actor',pw_uid=1234))
        self.user.start();self.addCleanup(self.user.stop)

    def run_prepare(self,runner=None):
        with contextlib.redirect_stdout(io.StringIO()):module.prepare_registry(self.bundle,runner=runner or self.runner)

    def test_exact_authority_dedup_and_cached_input(self):
        self.path.with_name('b.container').write_text('Image='+IMAGE+'\n')
        self.path.with_name('build.container').write_text('Image=webservices-source.build\n')
        self.run_prepare()
        pulls=[c for c in self.calls if c[-2]=='pull']
        self.assertEqual(len(pulls),1);self.assertEqual(pulls[0][-1],IMAGE)
        self.assertEqual(pulls[0][:3],['runuser','-u','actor'])
        self.assertIn('HOME=/home/actor',pulls[0])
        self.calls.clear();self.run_prepare();self.assertFalse(any(c[-2]=='pull' for c in self.calls))

    def test_missing_offline_and_unpinned_refuse_without_pull(self):
        for image in ('sha256:'+'b'*64,'docker.io/library/alpine:latest'):
            self.path.write_text('Image='+image+'\n')
            with self.assertRaises(ValueError):self.run_prepare()
            self.assertFalse(any(c[-2]=='pull' for c in self.calls))

    def test_inventory_and_pull_failure_do_not_fallback(self):
        with self.assertRaises(ValueError):self.run_prepare(lambda *a,**k:SimpleNamespace(returncode=125))
        def fail(command,**kwargs):
            if command[-2]=='pull':raise subprocess.CalledProcessError(1,command)
            return SimpleNamespace(returncode=1)
        with self.assertRaises(subprocess.CalledProcessError):self.run_prepare(fail)
        self.assertEqual(self.present,set())

if __name__=='__main__':unittest.main()
