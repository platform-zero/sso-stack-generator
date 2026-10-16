#!/usr/bin/env python3
"""Failed-start quarantine cannot acquire inert/foreign authority or delete data."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
ops=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
spec=importlib.util.spec_from_file_location('venue_start_quarantine',ops/'venue-start-quarantine.py')
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)

class StartQuarantine(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.ledger=self.root/'receipt.json'
        self.plan={'quadletTreeSha256':'a'*64,'roots':{'rootful-state':str(self.root)},
                   'accounts':[{'name':'p0test-r1-apps','uid':3201,'home':'/no/home'}]}
        self.row={'plan':self.plan,'venueInstallerVersion':2,'venueStartPhase':'starting',
                  'venueStartIntent':'a'*64,'status':'installed-starting','activationAuthorized':True,
                  'managerStarted':['p0test-r1-apps'],'managerStopped':[]}
        self.save()
    def save(self):self.ledger.write_text(json.dumps(self.row));self.ledger.chmod(0o600)
    def run_guard(self,records):
        selected={None:['p0test-r1.target','p0test-r1-alloy.service'],
                  'p0test-r1-apps':['p0test-r1.target','p0test-r1-postgres.service']}
        def written(_path,row):self.ledger.write_text(json.dumps(row))
        def stop(command,**kwargs):records.append(command);return SimpleNamespace(returncode=0)
        with (patch.object(q.stage,'owned_plan',return_value=self.plan),
              patch.object(q,'targets',return_value=selected),
              patch.object(q.stage,'write_ledger',side_effect=written),
              patch.object(q.graph,'run',side_effect=stop),
              patch.object(q.units,'units_idle',return_value=None)):
            return q.quarantine('bundle','selector',self.ledger)
    def test_scope_and_failed_phase_precede_any_stop(self):
        records=[]
        self.assertEqual(self.run_guard(records)['status'],'failed-quarantined')
        self.assertEqual(len(records),4)
        self.assertTrue(all('stop' in command and '--no-block' in command for command in records))
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
        self.row['venueInstallerVersion']=1;self.row['venueStartPhase']='starting';self.save()
        with self.assertRaisesRegex(q.Refusal,'no exact version-2'):
            self.run_guard(records)
        self.assertEqual(len(records),4)
    def test_stop_failure_keeps_partial_receipt_and_never_restarts(self):
        calls=[]
        selected={None:['p0test-r1.target'],'p0test-r1-apps':['p0test-r1.target']}
        def stop(command,**kwargs):calls.append(command);return SimpleNamespace(returncode=1)
        def save(_path,row):self.ledger.write_text(json.dumps(row))
        with (patch.object(q.stage,'owned_plan',return_value=self.plan),
              patch.object(q,'targets',return_value=selected),
              patch.object(q.stage,'write_ledger',side_effect=save),
              patch.object(q.graph,'run',side_effect=stop)):
            with self.assertRaisesRegex(q.Refusal,'stop request failed'):
                q.quarantine('bundle','selector',self.ledger)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantining')
        self.assertEqual(len(calls),1)
        self.assertNotIn('start',calls[0])
    def test_marker_symlink_refuses_before_stop(self):
        marker=self.root/'volume-ready-r1.txt';marker.symlink_to('/etc/hosts')
        records=[]
        with self.assertRaisesRegex(q.Refusal,'readiness marker changed'):
            self.run_guard(records)
        self.assertFalse(records)

if __name__=='__main__':unittest.main()
