#!/usr/bin/env python3
"""Synthetic start dispatcher/receipt ordering; NOT installed/native proof."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

OPS=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,OPS/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
q=module('guarded_start','venue-start-quarantine.py')
installer=module('guarded_installer','venue-install-inert.py')

@unittest.skipUnless(os.geteuid()==0,'root-private synthetic lifecycle fixture')
class Start(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.bundle=self.root/'bundle';self.bundle.mkdir()
        (self.bundle/'podman-domains.json').write_text('{}')
        self.runtime=self.root/'runtime';self.runtime.mkdir(mode=0o700)
        self.context=NS(runtime=self.runtime,namespace='p0test-r1',digest='b'*64,
                        data={'sourceProvenanceSha256':'c'*64},physical_reserves=lambda:None)
        self.plan={'prefix':'p0test-r1','quadletTreeSha256':'a'*64,
                   'roots':{'rootful-state':str(self.root)},
                   'accounts':[{'name':'p0test-r1-apps','uid':3201,'home':'/fixture'}]}
        selected={None:['p0test-r1.target','p0test-r1-root.service'],
                  'p0test-r1-apps':['p0test-r1.target','p0test-r1-app.service']}
        for scope,service in (('rootful','root'),('rootless-apps','app')):
            directory=self.bundle/'quadlet'/scope;directory.mkdir(parents=True)
            (directory/'p0test-r1.target').write_text('[Unit]\nWants=p0test-r1-'+service+'.service\n')
        sources={};rows=[]
        for index in range(61):
            path=self.root/('bind-'+str(index));path.mkdir();info=path.stat()
            sources[str(path)]={'owner':0}
            rows.append({'path':str(path),'dev':info.st_dev,'ino':info.st_ino})
        self.ledger=self.root/'receipt.json'
        self.ids={'root|fixture':'sha256:'+'d'*64}
        state={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'inert-ready',
               'status':'units-staged','activationAuthorized':False,
               'venueRegistryPhase':'inert-ready','venueRegistryPlan':self.ids,
               'venueRegistryVerified':self.ids,'managerStarted':['p0test-r1-apps'],
               'managerStopped':[],'venueDataBindDirs':rows}
        self.ledger.write_text(json.dumps(state));self.ledger.chmod(0o600)
        self.selector=self.root/'selector.json';self.selector.write_text('{}')
        registry=NS(authority=NS(authority=lambda *a:{'frozenLocalImagePairs':12,'imageIds':self.ids},
                              pinned_images=NS(frozen_aliases=lambda *a:{})),
                    reserve=lambda:None,probe=lambda *a:None)
        fake={'venue_registry':registry,'venue_screen':NS(port_screen=lambda *a:None),
              'venue_binds':NS(checked_stage=lambda *a:(None,None,sources),log_sources=lambda *a:{})}
        real_load=q.load
        patches=[patch.object(q,'load',side_effect=lambda name,file:fake[name] if name in fake else real_load(name,file)),
                 patch.object(q,'host_context',return_value=self.context),
                 patch.object(q.stage,'owned_plan',return_value=self.plan),
                 patch.object(q,'targets',return_value=selected),
                 patch.object(q.units,'units_idle',return_value=None),
                 patch.object(q.graph,'stores',return_value=[('root','',['podman'])]),
                 patch.object(installer,'load',return_value=q)]
        for p in patches:p.start();self.addCleanup(p.stop)
        self.commands=[];self.fail=False
    def native(self,command,**kwargs):
        self.commands.append(command)
        receipt=json.loads(self.ledger.read_text())
        authority=json.loads((self.runtime/'runtime-authority.json').read_text())
        if 'start' in command:
            self.assertEqual(receipt['venueInstallerVersion'],2)
            self.assertEqual(receipt['venueStartIntent'],self.plan['quadletTreeSha256'])
            self.assertEqual(authority['phase'],'starting')
            self.assertTrue(authority['activationAuthorized'])
        if 'show' in command:
            failed=self.fail and 'p0test-r1-app.service' in command
            return NS(returncode=0,stdout='ActiveState='+('failed' if failed else 'active')+'\nResult=success\n')
        if 'stop' in command:
            self.assertEqual(authority['phase'],'failed-quarantining')
            self.assertFalse(authority['activationAuthorized'])
        return NS(returncode=0,stdout='')
    def test_intent_and_current_boot_authority_before_queue(self):
        with patch.object(q.graph,'run',side_effect=self.native):
            result=installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(result['status'],'running')
        self.assertEqual(result['acceptedIntegratedInstalls'],0)
        self.assertEqual(sum('start' in c for c in self.commands),2)
        self.assertEqual(json.loads((self.runtime/'runtime-authority.json').read_text())['schemaVersion'],2)
    def test_failed_leaf_fences_and_stops_without_retry_or_data_deletion(self):
        self.fail=True
        with patch.object(q.graph,'run',side_effect=self.native):
            with self.assertRaisesRegex(ValueError,'native selected service failed'):
                installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
        self.assertFalse(json.loads((self.runtime/'runtime-authority.json').read_text())['activationAuthorized'])
        self.assertEqual(sum('start' in c for c in self.commands),2)
        self.assertEqual(sum('stop' in c for c in self.commands),2)
        self.assertEqual(len(list(self.root.glob('bind-*'))),61)

if __name__=='__main__':unittest.main()
