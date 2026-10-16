#!/usr/bin/env python3
"""No host-control unit installed: exact separate source-role CAS fixtures."""
import importlib.util
import json
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-control-source.py'
spec=importlib.util.spec_from_file_location('control_source',src)
role=importlib.util.module_from_spec(spec);spec.loader.exec_module(role)

@unittest.skipUnless(os.geteuid()==0,'protected source-role journal requires root')
class SourceOnlyLifecycle(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.ledger=self.root/'ledger.json'
        self.commit='a'*40
        self.plan={'selectorSha256':'b'*64,'bundleIrSha256':'c'*64}
        self.content={'agent-identity-host.py':b'#!/usr/bin/env python3\n',
                      'units/p0-web.service':b'[Unit]\nDescription=test only\n',
                      'static/index.html':b'<html>test only</html>\n'}
        self.pinned=patch.object(role,'inputs',return_value=(self.plan,self.commit,self.content))
        self.pinned.start();self.addCleanup(self.pinned.stop)
    def test_source_is_distinct_private_and_exactly_retired(self):
        result=role.stage_source(None,None,None,self.root,self.ledger)
        self.assertEqual(result['sourceFiles'],3)
        self.assertFalse(result['manifest']['activationAuthorized'])
        self.assertEqual(result['manifest']['role'],'p0test-r1-host-control-source-only')
        release=self.root/('host-'+self.commit)
        self.assertTrue((release/'static/index.html').exists())
        self.assertFalse((self.root/'usr/local/libexec/p0-control').exists())
        stray=release/'units/foreign.service';stray.write_text('do not delete')
        with self.assertRaises(role.Refusal):role.retire_source(None,None,None,self.root,self.ledger)
        self.assertEqual(stray.read_text(),'do not delete')
        stray.unlink()
        result=role.retire_source(None,None,None,self.root,self.ledger)
        self.assertEqual(result['status'],'source-retired')
        self.assertFalse(release.exists())
        self.assertEqual(json.loads(self.ledger.read_text())['status'],'source-retired')
    def test_modified_pinned_byte_refuses_before_any_removal(self):
        role.stage_source(None,None,None,self.root,self.ledger)
        release=self.root/('host-'+self.commit);file=release/'agent-identity-host.py'
        file.write_text('changed')
        with self.assertRaises(role.Refusal):role.retire_source(None,None,None,self.root,self.ledger)
        self.assertEqual(file.read_text(),'changed')
        self.assertTrue((release/'static/index.html').exists())
    def test_existing_slot_or_ledger_refuses_before_mutation(self):
        release=self.root/('host-'+self.commit);release.mkdir()
        with self.assertRaises(role.Refusal):role.stage_source(None,None,None,self.root,self.ledger)
        self.assertFalse(self.ledger.exists())
        release.rmdir()
        self.ledger.write_text('preserve')
        with self.assertRaises(role.Refusal):role.stage_source(None,None,None,self.root,self.ledger)
        self.assertEqual(self.ledger.read_text(),'preserve')

if __name__=='__main__':unittest.main()
