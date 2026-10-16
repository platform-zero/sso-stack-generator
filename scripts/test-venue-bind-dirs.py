#!/usr/bin/env python3
"""Exact empty directory and hostile injected-content tests; no host binds."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-bind-dirs.py'
spec=importlib.util.spec_from_file_location('venue_bind_dirs',src)
binds=importlib.util.module_from_spec(spec);spec.loader.exec_module(binds)

@unittest.skipUnless(os.geteuid()==0,'root-owned CAS stage fixture required')
class BindFixture(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.rootful=self.root/'rootful';self.apps=self.root/'apps'
        self.rootful.mkdir(mode=0o700);self.apps.mkdir(mode=0o700);os.chown(self.apps,3201,3201)
        self.paths={str(self.rootful/'caddy_ca'):{'owner':0,'parent':str(self.rootful),
                    'label':'caddy_ca','consumers':['rootful','rootless-apps']},
                    str(self.apps/'bookstack_data'):{'owner':3201,'parent':str(self.apps),
                    'label':'bookstack_data','consumers':['rootless-apps']}}
        self.plan={'prefix':'p0test-r1','accounts':[{'name':'p0test-r1-apps','uid':3201}]}
        identities={}
        for p in (self.rootful,self.apps):
            st=p.lstat();identities[str(p)]={'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'mode':0o700}
        self.data={'plan':self.plan,'status':'managers-ready',
                   'managerStarted':['p0test-r1-apps'],'managerStopped':[],'pathIdentities':identities}
        self.ledger=self.root/'ledger.json';self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        self.patches=(patch.object(binds.stage,'owned_plan',return_value=self.plan),
                      patch.object(binds,'inventory',return_value=self.paths))
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def test_exact_two_owner_domains_then_empty_only_retire(self):
        result=binds.create(None,None,self.ledger)
        self.assertEqual(result['actualDataBindDirectories'],2)
        self.assertEqual((self.apps/'bookstack_data').stat().st_uid,3201)
        extra=self.rootful/'caddy_ca'/'outside';extra.write_text('preserve')
        with self.assertRaises(binds.Refusal):binds.retire(None,None,self.ledger)
        self.assertEqual(extra.read_text(),'preserve');extra.unlink()
        self.assertEqual(binds.retire(None,None,self.ledger)['retiredEmptyDataBindDirs'],2)
        self.assertFalse((self.apps/'bookstack_data').exists())
        self.assertFalse((self.rootful/'caddy_ca').exists())
        self.assertEqual(json.loads(self.ledger.read_text())['status'],'managers-ready')
    def test_unrestored_cross_domain_acl_refuses_before_any_bind_removal(self):
        binds.create(None,None,self.ledger)
        data=json.loads(self.ledger.read_text());data['crossDomainAclStatus']='granted'
        binds.stage.write_ledger(self.ledger,data)
        with self.assertRaisesRegex(binds.Refusal,'cross-domain ACL'):
            binds.retire(None,None,self.ledger)
        self.assertTrue((self.rootful/'caddy_ca').is_dir())
        self.assertTrue((self.apps/'bookstack_data').is_dir())
        self.assertEqual(json.loads(self.ledger.read_text())['status'],'data-binds-inert')
    def test_existing_path_refuses_without_touching_other_path(self):
        occupied=self.apps/'bookstack_data';occupied.mkdir();(occupied/'data').write_text('keep')
        with self.assertRaises(binds.Refusal):binds.create(None,None,self.ledger)
        self.assertFalse((self.rootful/'caddy_ca').exists())
        self.assertEqual((occupied/'data').read_text(),'keep')

if __name__=='__main__':unittest.main()
