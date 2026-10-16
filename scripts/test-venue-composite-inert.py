#!/usr/bin/env python3
"""Versioned ledger failure/resume boundaries; no host service activation."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-composite-inert.py'
spec=importlib.util.spec_from_file_location('venue_composite',source)
composite=importlib.util.module_from_spec(spec);spec.loader.exec_module(composite)

@unittest.skipUnless(os.geteuid()==0,'exact root-private journal fixture')
class Journal(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.plan={'prefix':'p0test-r1','roots':{'rootful-state':str(self.state)},
                   'accounts':[{'name':'p0test-r1-apps','uid':3201}]}
        self.ledger=self.root/'journal.json';self.ledger.write_text(json.dumps({
            'plan':self.plan,'status':'managers-ready','managerStarted':['p0test-r1-apps'],
            'managerStopped':[]},sort_keys=True));self.ledger.chmod(0o600)
        p=patch.object(composite.stage,'owned_plan',return_value=self.plan);p.start();self.addCleanup(p.stop)
    def update(self,**updates):
        data=json.loads(self.ledger.read_text());data.update(updates)
        composite.stage.write_ledger(self.ledger,data)
    def test_failure_retains_exact_versioned_phase_no_fake_completion(self):
        def create(*args):self.update(status='data-binds-inert',venueDataBindDirs=['fixture'])
        with patch.object(composite.binds,'create',side_effect=create),patch.object(
                composite.acl,'grant',side_effect=composite.Refusal('selected ACL failed')):
            with self.assertRaisesRegex(composite.Refusal,'selected ACL failed'):
                composite.prepare(None,None,self.ledger)
        data=json.loads(self.ledger.read_text())
        self.assertEqual(data['venueCompositeVersion'],2)
        self.assertEqual(data['venueCompositeMode'],'preparing')
        self.assertEqual(data['status'],'data-binds-inert')
        self.assertNotIn('venueHulyVolumes',data)
        self.assertNotIn('unitFiles',data)
        self.assertEqual(stat.S_IMODE(self.ledger.stat().st_mode),0o600)
    def test_marker_refuses_before_journal_change(self):
        (self.state/'volume-ready-r1.txt').write_text('untrusted')
        original=self.ledger.read_bytes()
        with self.assertRaisesRegex(composite.Refusal,'readiness marker'):
            composite.prepare(None,None,self.ledger)
        self.assertEqual(self.ledger.read_bytes(),original)
    def test_unselected_phase_refuses_before_asset_operation(self):
        self.update(status='huly-volumes-inert')
        original=self.ledger.read_bytes()
        with patch.object(composite.binds,'create') as create:
            with self.assertRaises(composite.Refusal):composite.prepare(None,None,self.ledger)
            create.assert_not_called()
        self.assertEqual(self.ledger.read_bytes(),original)

if __name__=='__main__':unittest.main()
