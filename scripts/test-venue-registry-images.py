#!/usr/bin/env python3
"""Incremental complete-image CAS progress and failure fencing fixtures."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-registry-images.py'
spec=importlib.util.spec_from_file_location('venue_registry_images',src)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class RegistryProgress(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.ledger=self.root/'journal.json'
        self.user='p0test-r1-apps';self.offline='sha256:'+'1'*64
        self.key=self.user+'|'+self.offline
        self.first=self.user+'|docker.io/selected/first:v1'
        self.second='root|docker.io/selected/second:v2@sha256:'+'3'*64
        self.ids={self.key:self.offline,self.first:'sha256:'+'2'*64,self.second:'sha256:'+'4'*64}
        self.plan={'prefix':'p0test-r1'}
        self.source={'imageIds':self.ids,'frozenRegistrySha256':'5'*64}
        self.data={'venueCompositeOfflineImages':[{'authorities':[self.user],'image':self.offline}],
                   'venueHulyVolumes':[{'name':f'huly-{n}'} for n in range(4)]}
        self.stores={self.user:(Path('/unused-apps'),['apps']), 'root':(Path('/unused-root'),['root'])}
        self.images={self.user:{self.offline},'root':set()}
        self.ledger.write_text(json.dumps(self.data));self.root.chmod(0o700);self.ledger.chmod(0o600)
        def read(*args):return self.ledger,json.loads(self.ledger.read_text()),self.plan,self.source
        def write(path,data):path.write_text(json.dumps(data))
        def inspected(cmd,ref):
            user='root' if cmd==['root'] else self.user
            key=user+'|'+ref
            return self.ids[key] if self.ids[key] in self.images[user] else None
        def fetch(cmd,ref):
            user='root' if cmd==['root'] else self.user
            self.images[user].add(self.ids[user+'|'+ref])
        def probe(bundle,plan,data,verified):
            expected={user:set() for user in self.stores}
            for key,value in verified.items():expected[key.split('|',1)[0]].add(value)
            if self.images!=expected:raise module.Refusal('foreign exact image graph')
            return self.stores,self.images
        patches=[patch.object(module,'journal',side_effect=read),patch.object(module.stage,'write_ledger',side_effect=write),
                 patch.object(module,'command_graphs',return_value=self.stores),patch.object(module,'probe',side_effect=probe),
                 patch.object(module,'pulled',side_effect=inspected),patch.object(module,'fetch',side_effect=fetch),
                 patch.object(module,'reserve',return_value=None),
                 # SOURCE fixture only: production prepare now requires the same
                 # actual private lifecycle lease as deletion/start operations.
                 patch.object(module,'preparation_lease',return_value=contextlib.nullcontext())]
        for mock in patches:mock.start();self.addCleanup(mock.stop)
    def test_same_ledger_resumes_one_by_one_and_only_all_three_are_ready(self):
        first=module.prepare('bundle','selector','site','journal',1)
        self.assertEqual((first['status'],first['verifiedImages'],first['remaining']),('preparing',2,1))
        second=module.prepare('bundle','selector','site','journal',1)
        self.assertEqual((second['status'],second['verifiedImages'],second['remaining']),('inert-ready',3,0))
        self.assertEqual(module.prepare('bundle','selector','site','journal',1)['remaining'],0)
    def test_foreign_image_or_pending_drift_refuses_without_further_pulls(self):
        module.prepare('bundle','selector','site','journal',1)
        self.images['root'].add('sha256:'+'f'*64)
        with self.assertRaises(module.Refusal):module.prepare('bundle','selector','site','journal',1)
        self.images['root'].clear()
        data=json.loads(self.ledger.read_text());data['venueRegistryPending']=self.second;self.ledger.write_text(json.dumps(data))
        with self.assertRaises(module.Refusal):module.prepare('bundle','selector','site','journal',1)
        self.assertEqual(json.loads(self.ledger.read_text())['venueRegistryPending'],self.second)
        recovered=module.prepare('bundle','selector','site','journal',1,True)
        self.assertEqual(recovered['status'],'inert-ready')
        self.assertEqual(json.loads(self.ledger.read_text())['venueRegistryRetryCount'][self.second],1)
    def test_explicit_retry_refuses_foreign_graph_prewrite(self):
        module.prepare('bundle','selector','site','journal',1)
        data=json.loads(self.ledger.read_text());data['venueRegistryPending']=self.second
        self.ledger.write_text(json.dumps(data));self.images['root'].add('sha256:'+'f'*64)
        with self.assertRaisesRegex(module.Refusal,'foreign exact image graph'):
            module.prepare('bundle','selector','site','journal',1,True)
        self.assertFalse(json.loads(self.ledger.read_text()).get('venueRegistryRetryCount'))
    def test_source_identity_drift_refuses_before_graph_pulls(self):
        module.prepare('bundle','selector','site','journal',1)
        self.ids[self.second]='sha256:'+'e'*64
        with self.assertRaises(module.Refusal):module.prepare('bundle','selector','site','journal',1)

if __name__=='__main__':unittest.main()
