#!/usr/bin/env python3
"""Synthetic exact-parent log bind creation, refusal and empty retirement."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-bind-dirs.py'
spec=importlib.util.spec_from_file_location('owned_logs',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

@unittest.skipUnless(os.geteuid()==0,'root-owned fixture')
class Logs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.parent=self.root/'logs';self.parent.mkdir(mode=0o700)
        self.scope=self.root/'quadlet/rootful';self.scope.mkdir(parents=True)
        for name in ('caddy','crowdsec'):
            (self.scope/(name+'.container')).write_text('Volume='+str(self.parent/'caddy')+':/logs\n')
        self.plan={'roots':{'log':str(self.parent)}};info=self.parent.stat();self.ledger=self.root/'ledger'
        self.data={'plan':self.plan,'venueInstallerVersion':1,'activationAuthorized':False,
                   'status':'units-staged','venueStartMonotonicUsec':42,
                   'pathIdentities':{str(self.parent):{'dev':info.st_dev,'ino':info.st_ino,'uid':0}}}
        self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        self.addCleanup(patch.stopall)
        patch.object(m.stage,'owned_plan',return_value=self.plan).start()
        patch.object(m,'checked_stage',side_effect=lambda *a:(self.ledger,json.loads(self.ledger.read_text()),{})).start()
    def create(self,repair=False):return m._prepare_logs(self.root,'selector',self.ledger,repair)
    def test_creates_one_shared_owned_log_child_and_receipt(self):
        self.assertEqual(self.create()['preparedLogBindDirs'],1)
        data=json.loads(self.ledger.read_text());self.assertEqual(data['venueLogBindDirs'][0]['consumers'],['caddy.container','crowdsec.container'])
        self.assertEqual((self.parent/'caddy').stat().st_mode&0o777,0o700)
        with self.assertRaises(m.Refusal):self.create()
    def test_unknown_existing_child_never_adopted(self):
        (self.parent/'caddy').mkdir()
        with self.assertRaises(m.Refusal):self.create()
    def test_changed_parent_identity_refuses_precreation(self):
        data=json.loads(self.ledger.read_text());data['pathIdentities'][str(self.parent)]['ino']+=1;self.ledger.write_text(json.dumps(data))
        with self.assertRaises(m.Refusal):self.create()
        self.assertFalse((self.parent/'caddy').exists())
    def test_specific_repair_receipt_consumes_failed_epoch_not_generic_retry(self):
        self.create(True);data=json.loads(self.ledger.read_text())
        self.assertEqual(data['venueStartRepair']['appliesToStartMonotonicUsec'],42)
        self.assertEqual(data['venueStartRepair']['kind'],'missing-owned-log-bind')
    def test_empty_retirement_keeps_parent(self):
        self.create()
        with patch.object(m,'load',return_value=SimpleNamespace(units_idle=lambda p:None)):
            m.retire_logs(self.root,'selector',self.ledger)
        self.assertTrue(self.parent.exists());self.assertFalse((self.parent/'caddy').exists())
    def test_populated_logs_never_empty_retired(self):
        self.create();(self.parent/'caddy/access.log').write_text('retained')
        with patch.object(m,'load',return_value=SimpleNamespace(units_idle=lambda p:None)):
            with self.assertRaises(m.Refusal):m.retire_logs(self.root,'selector',self.ledger)
        self.assertEqual((self.parent/'caddy/access.log').read_text(),'retained')
if __name__=='__main__':unittest.main()
