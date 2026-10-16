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
        runtime=self.root/'runtime';runtime.mkdir(mode=0o700)
        self.context=SimpleNamespace(runtime=runtime,namespace='p0test-r1',digest='b'*64,
                                     data={'sourceProvenanceSha256':'c'*64})
        context=patch.object(q,'host_context',return_value=self.context)
        context.start();self.addCleanup(context.stop)
        self.plan={'prefix':'p0test-r1','quadletTreeSha256':'a'*64,'roots':{'rootful-state':str(self.root)},
                   'accounts':[{'name':'p0test-r1-apps','uid':3201,'home':'/no/home'}]}
        self.row={'plan':self.plan,'venueInstallerVersion':2,'venueStartPhase':'starting',
                  'venueStartHostContextSha256':'b'*64,'venueStartIntent':'a'*64,'status':'installed-starting','activationAuthorized':True,
                  'managerStarted':['p0test-r1-apps'],'managerStopped':[]}
        self.save()
    def save(self):self.ledger.write_text(json.dumps(self.row));self.ledger.chmod(0o600)
    def run_guard(self,records):
        selected={None:['p0test-r1.target','p0test-r1-alloy.service'],
                  'p0test-r1-apps':['p0test-r1.target','p0test-r1-postgres.service']}
        def stop(command,**kwargs):
            authority=json.loads((self.context.runtime/'runtime-authority.json').read_text())
            self.assertEqual(authority['phase'],'failed-quarantining')
            self.assertFalse(authority['activationAuthorized'])
            records.append(command);return SimpleNamespace(returncode=0,stdout='')
        with (patch.object(q.stage,'owned_plan',return_value=self.plan),
              patch.object(q,'targets',return_value=selected),
              patch.object(q.graph,'run',side_effect=stop),
              patch.object(q.units,'units_idle',return_value=None)):
            return q.quarantine('bundle','selector',self.ledger)
    def test_scope_and_failed_phase_precede_any_stop(self):
        records=[]
        self.assertEqual(self.run_guard(records)['status'],'failed-quarantined')
        self.assertEqual(len(records),6)
        stopped=[command for command in records if 'stop' in command]
        self.assertEqual(len(stopped),2)
        self.assertTrue(all('--no-block' in command for command in stopped))
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
        self.row['venueInstallerVersion']=1;self.row['venueStartPhase']='starting';self.save()
        with self.assertRaisesRegex(q.Refusal,'no exact version-2'):
            self.run_guard(records)
        self.assertEqual(len(records),6)
    def test_stop_failure_keeps_partial_receipt_and_never_restarts(self):
        calls=[]
        selected={None:['p0test-r1.target'],'p0test-r1-apps':['p0test-r1.target']}
        def stop(command,**kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0 if 'list-jobs' in command else 1,stdout='')
        with (patch.object(q.stage,'owned_plan',return_value=self.plan),
              patch.object(q,'targets',return_value=selected),
              patch.object(q.graph,'run',side_effect=stop)):
            with self.assertRaisesRegex(q.Refusal,'stop request failed'):
                q.quarantine('bundle','selector',self.ledger)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantining')
        self.assertEqual(len(calls),2)
        self.assertTrue(all('start' not in command for command in calls))
    def test_cancel_race_requires_fresh_exact_id_absence(self):
        replies=[SimpleNamespace(returncode=0,stdout='41 p0test-r1-app.service start running\n'),
                 SimpleNamespace(returncode=1,stdout=''),SimpleNamespace(returncode=0,stdout='')]
        with patch.object(q.graph,'run',side_effect=replies):
            q.cancel_starts(['systemctl'],['p0test-r1-app.service'])
    def test_cancel_failure_with_same_job_remaining_refuses(self):
        row=SimpleNamespace(returncode=0,stdout='41 p0test-r1-app.service start running\n')
        with patch.object(q.graph,'run',side_effect=[row,SimpleNamespace(returncode=1,stdout=''),row]):
            with self.assertRaisesRegex(q.Refusal,'could not be cancelled'):
                q.cancel_starts(['systemctl'],['p0test-r1-app.service'])
    def test_real_manifest_mapping_preserves_native_target_suffix(self):
        manifest={};records=[]
        for index in range(194):
            name='p0test-r1.target' if index==0 else 'p0test-r1-fixture-'+str(index)+'.container'
            path=self.root/name;path.write_text('[Unit]\n');info=path.stat()
            manifest[str(path)]={'uid':0,'sha256':q.units.hashlib.sha256(path.read_bytes()).hexdigest()}
            records.append({'path':str(path),'dev':info.st_dev,'ino':info.st_ino})
        state={'unitFiles':manifest,'installedUnits':records}
        with patch.object(q.units,'manifest',return_value=manifest):
            names=q.targets(self.root,self.plan,state)[None]
        self.assertIn('p0test-r1.target',names)
        self.assertNotIn('p0test-r1',names)
        self.assertIn('p0test-r1-fixture-1.service',names)
    def test_shared_lifecycle_lock_refuses_competing_stop(self):
        records=[]
        with q.lifecycle(self.context):
            with self.assertRaisesRegex(q.Refusal,'already in progress'):self.run_guard(records)
        self.assertFalse(records)
    def test_marker_symlink_refuses_before_stop(self):
        marker=self.root/'volume-ready-r1.txt';marker.symlink_to('/etc/hosts')
        records=[]
        with self.assertRaisesRegex(q.Refusal,'readiness marker changed'):
            self.run_guard(records)
        self.assertFalse(records)

if __name__=='__main__':unittest.main()
