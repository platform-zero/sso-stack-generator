#!/usr/bin/env python3
"""Unprivileged source/fixture checks: shipped CLI paths, not native acceptance."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[1]


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BundleLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='stackctl-layout-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'scripts/lib').mkdir(parents=True)
        for name in ('stackctl-lifecycle.py','stackctl-operations.py','stackctl-recovery.py'):
            shutil.copyfile(REPO/'scripts/lib'/name,self.root/'scripts/lib'/name)
        shutil.copyfile(REPO/'scripts/stackctl.sh',self.root/'scripts/stackctl.sh')

    def fixture(self, bundled=True):
        if bundled:(self.root/'bundle.json').write_text('{}\n')
        native=self.root/('ops' if bundled else 'runtime-generator/podman-ops')
        native.mkdir(parents=True)
        (native/'install-journal.py').write_text('LAYOUT="expected"\n')
        (native/'install-podman-bundle.sh').write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        return native

    def modules(self):
        return [load(self.root/'scripts/lib'/name,name.replace('-','_')) for name in
                ('stackctl-lifecycle.py','stackctl-operations.py')]

    def test_bundle_journal_uses_shipped_ops(self):
        native=self.fixture()
        for module in self.modules():
            self.assertEqual(module.ops_directory(),native)
            self.assertEqual(module.journal_module().LAYOUT,'expected')

    def test_source_checkout_layout_remains_supported(self):
        native=self.fixture(False)
        for module in self.modules():
            self.assertEqual(module.ops_directory(),native)
            self.assertEqual(module.journal_module().LAYOUT,'expected')

    def test_bundle_never_adopts_nested_development_shadow(self):
        native=self.fixture()
        shadow=self.root/'runtime-generator/podman-ops'
        shadow.mkdir(parents=True)
        (shadow/'install-journal.py').write_text('LAYOUT="shadow"\n')
        for module in self.modules():self.assertEqual(module.journal_module().LAYOUT,'expected')
        (native/'install-journal.py').unlink()
        for module in self.modules():
            with self.assertRaises(FileNotFoundError):module.journal_module()

    def test_actual_bundled_cli_dispatch_reaches_shipped_fixture(self):
        self.fixture()
        images=self.root/'image-inputs.json'
        result=subprocess.run(['bash',str(self.root/'scripts/stackctl.sh'),'install',
            '--bundle',str(self.root),'--image-inputs',str(images)],
            text=True,capture_output=True,timeout=10,check=True)
        self.assertEqual(result.stdout.splitlines(),['--bundle',str(self.root),'--image-inputs',str(images)])

    def test_actual_bundled_resume_passes_exact_intent_hash(self):
        self.fixture()
        digest='a'*64
        result=subprocess.run(['bash',str(self.root/'scripts/stackctl.sh'),'install',
            '--bundle',str(self.root),'--resume-intent',digest],
            text=True,capture_output=True,timeout=10,check=True)
        self.assertEqual(result.stdout.splitlines(),['--bundle',str(self.root),'--resume-intent',digest])

    def test_actual_cli_refuses_missing_or_invalid_resume_hash(self):
        self.fixture()
        for tail in (['--resume-intent'],['--resume-intent','bad'],['--resume-intent','A'*64]):
            result=subprocess.run(['bash',str(self.root/'scripts/stackctl.sh'),'install',
                '--bundle',str(self.root),*tail],text=True,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,'')

    def test_actual_source_cli_dispatch_keeps_development_path(self):
        self.fixture(False)
        result=subprocess.run(['bash',str(self.root/'scripts/stackctl.sh'),'install',
            '--bundle',str(self.root)],text=True,capture_output=True,timeout=10,check=True)
        self.assertEqual(result.stdout.splitlines(),['--bundle',str(self.root)])

    def test_both_recovery_consumers_pin_reviewed_operations_source(self):
        expected=hashlib.sha256((REPO/'scripts/lib/stackctl-operations.py').read_bytes()).hexdigest()
        for relative in ('scripts/lib/stackctl-recovery.py','runtime-generator/podman-ops/native-recovery-owner.py'):
            tree=ast.parse((REPO/relative).read_bytes())
            pins=[ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                  and any(isinstance(name,ast.Name) and name.id=='OPERATIONS_SHA256' for name in node.targets)]
            self.assertEqual(pins,[expected])

    def test_recovery_reviewed_operations_support_bundle_and_reject_drift(self):
        self.fixture()
        recovery=load(self.root/'scripts/lib/stackctl-recovery.py','bundle_recovery')
        ops=recovery.operations()
        self.assertEqual(ops.journal_module().LAYOUT,'expected')
        source=self.root/'scripts/lib/stackctl-operations.py'
        source.write_bytes(source.read_bytes()+b'\n# unexpected source drift\n')
        with self.assertRaises(ValueError):recovery.operations()


if __name__=='__main__':unittest.main()
