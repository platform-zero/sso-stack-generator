#!/usr/bin/env python3
"""Status parser/source tests only, never application acceptance."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
p=Path(__file__).resolve().parent/'lib/stackctl-lifecycle.py'
s=importlib.util.spec_from_file_location('lifecycle_status_fixture',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Status(unittest.TestCase):
    def test_native_blank_separated_named_unit_blocks(self):
        text='Id=webservices-a.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\nId=webservices-b.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n'
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=text)) as run:
            rows=m.unit_states(['systemctl'],['webservices-a.service','webservices-b.service'])
            self.assertEqual(len(rows),2);self.assertEqual(rows[1]['LoadState'],'not-found')
            self.assertNotIn('Environment',run.call_args.args[0])
    def test_partial_duplicate_and_foreign_units_refused(self):
        for text in ('','Id=foreign.service\nLoadState=loaded\nActiveState=active\n',
                     'Id=webservices-a.service\nLoadState=loaded\nActiveState=active\n\nId=webservices-a.service\nLoadState=loaded\nActiveState=active\n'):
            with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=text)):
                with self.assertRaises(ValueError):m.unit_states(['systemctl'],['webservices-a.service','webservices-b.service'])
    def test_query_failure_never_reports_empty_success(self):
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='')):
            with self.assertRaises(ValueError):m.unit_states(['systemctl'],['webservices-a.service'])
    def test_install_delegates_without_implicit_activation_or_gate_skips(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bundle=Path(tmp)
            args=m.install_command(bundle)
            self.assertNotIn('--activate',args);self.assertNotIn('--resume-intent',args)
            self.assertIn('install-podman-bundle.sh',args[1])
            self.assertEqual(args[-2:],['--bundle',str(bundle)])
            with patch.object(m.os,'geteuid',return_value=1000):
                with self.assertRaises(ValueError):m.install_command(bundle,activate=True)
            with patch.object(m.os,'geteuid',return_value=0):
                args=m.install_command(bundle,activate=True,image_inputs=bundle/'images',resume=True)
                self.assertIn('--activate',args);self.assertIn('--resume-intent',args)
                self.assertEqual(args[args.index('--image-inputs')+1],str(bundle/'images'))

    def test_absolute_root_is_required_before_inspection(self):
        with self.assertRaises(ValueError):m.status(Path('relative'))
if __name__=='__main__':unittest.main()
