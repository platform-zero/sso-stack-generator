#!/usr/bin/env python3
"""Do not start or stop arbitrary real user managers from forged stage state."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-user-managers.py'
spec=importlib.util.spec_from_file_location('venue_user_managers',src)
managers=importlib.util.module_from_spec(spec);spec.loader.exec_module(managers)

class ManagerAuthorityTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.ledger=self.root/'ledger.json'
        self.bundle=self.root/'bundle'
        self.selector=self.root/'selector'
        # Never let a source-only fixture observe real installed linger state.
        def fixture_path(*parts):
            path=Path(*parts)
            return self.root/'linger' if path==Path('/var/lib/systemd/linger') else path
        paths=patch.object(managers,'Path',side_effect=fixture_path)
        paths.start();self.addCleanup(paths.stop)
    def test_missing_ledger_refuses_before_subprocess(self):
        with patch.object(managers,'run',side_effect=AssertionError('unexpected systemctl')):
            with self.assertRaises(managers.Refusal):
                managers.read_stage(self.bundle,self.selector,self.ledger)
    def test_empty_store_allows_only_pinned_linger_while_nonempty_refuses(self):
        graph=self.root/'graph';volume=self.root/'volume';graph.mkdir();volume.mkdir()
        account={'name':'p0test-r1-platform','uid':3200,'graph':str(graph),'volume':str(volume)}
        plan={'accounts':[account],'prefix':'p0test-r1'}
        data={'status':'staged-empty'}
        calls=[]
        class IntentReached(Exception):pass
        def guarded_run(*args,**kwargs):
            calls.append(args)
            if args[:3]==('systemctl','is-active','--quiet'):
                return type('Result',(),{'returncode':3})()
            if args[:2]==('loginctl','enable-linger'):
                raise IntentReached()
            raise AssertionError('unexpected systemd operation')
        with (patch.object(managers,'read_stage',return_value=(self.ledger,data,plan)),
              patch.object(managers.stage,'write_ledger'),
              patch.object(managers,'run',side_effect=guarded_run)):
            with self.assertRaises(IntentReached):managers.act(self.bundle,self.selector,self.ledger)
            self.assertEqual(data['status'],'managers-starting')
            self.assertEqual(data['pendingManager'],account['name'])
        (graph/'foreign').write_text('untouched')
        calls.clear();data={'status':'staged-empty'}
        with (patch.object(managers,'read_stage',return_value=(self.ledger,data,plan)),
              patch.object(managers.stage,'write_ledger'),
              patch.object(managers,'run',side_effect=guarded_run)):
            with self.assertRaises(managers.Refusal):managers.act(self.bundle,self.selector,self.ledger)
        self.assertFalse(any(row[:2]==('loginctl','enable-linger') for row in calls))
        self.assertEqual((graph/'foreign').read_text(),'untouched')
        (graph/'foreign').unlink()
        linger=self.root/'linger';linger.mkdir();(linger/account['name']).touch()
        calls.clear();data={'status':'staged-empty'}
        with (patch.object(managers,'read_stage',return_value=(self.ledger,data,plan)),
              patch.object(managers.stage,'write_ledger'),
              patch.object(managers,'run',side_effect=guarded_run)):
            with self.assertRaises(managers.Refusal):managers.act(self.bundle,self.selector,self.ledger)
        self.assertFalse(any(row[:2]==('loginctl','enable-linger') for row in calls))
    def test_out_of_order_manager_record_refuses_before_subprocess(self):
        accounts=[{'name':'p0test-r1-platform','uid':3200,'graph':str(self.root/'g0'),'volume':str(self.root/'v0')},
                  {'name':'p0test-r1-apps','uid':3201,'graph':str(self.root/'g1'),'volume':str(self.root/'v1')}]
        plan={'accounts':accounts,'prefix':'p0test-r1'}
        for broken in ({'status':'managers-ready','managerStarted':[accounts[1]['name']]},
                       {'status':'managers-starting','managerStarted':[],'pendingManager':accounts[1]['name']},
                       {'status':'staged-empty','managerStarted':[]}):
            with (self.subTest(broken=broken),
                  patch.object(managers,'read_stage',return_value=(self.ledger,broken,plan)),
                  patch.object(managers,'run',side_effect=AssertionError('unexpected systemctl'))):
                with self.assertRaises(managers.Refusal):
                    managers.act(self.bundle,self.selector,self.ledger,stop=True)

if __name__=='__main__':unittest.main()
