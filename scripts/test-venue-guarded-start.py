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
            (directory/('p0test-r1-'+service+'.container')).write_text('[Container]\nPodmanArgs=--sdnotify=healthy\nHealthCmd=["true","ready"]\n')
        (self.bundle/'stack.ir.json').write_text(json.dumps({'services':{
            'root':{'dependencies':{}},'app':{'dependencies':{'root':'healthy'}}}}))
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
              'venue_binds':NS(checked_stage=lambda *a:(None,None,sources),checked_fixtures=lambda *a:[],log_sources=lambda *a:{})}
        self.ingress_events=[]
        def tls(*args):
            self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'starting')
            self.assertEqual(json.loads((self.runtime/'runtime-authority.json').read_text())['phase'],'starting')
            self.assertEqual(sum('start' in c for c in self.commands),0)
            self.ingress_events.append('tls')
        def mail(*args):
            self.assertEqual(sum('start' in c for c in self.commands),2)
            self.ingress_events.append('mail')
        real_load=q.load
        patches=[patch.object(q.ingress,'checked',return_value={}),
                 patch.object(q.ingress,'bootstrap_tls',side_effect=tls),
                 patch.object(q.ingress,'finish_mail',side_effect=mail),patch.object(q,'load',side_effect=lambda name,file:fake[name] if name in fake else real_load(name,file)),
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
            return NS(returncode=0,stdout='ActiveState='+('failed' if failed else 'active')+'\nResult=success\nExecMainStartTimestampMonotonic='+str(receipt['venueStartMonotonicUsec']+1)+'\n')
        if 'stop' in command:
            self.assertEqual(authority['phase'],'failed-quarantining')
            self.assertFalse(authority['activationAuthorized'])
        return NS(returncode=0,stdout='')
    def test_intent_and_current_boot_authority_before_queue(self):
        with patch.object(q.graph,'run',side_effect=self.native):
            result=installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(result['status'],'running')
        self.assertEqual(result['acceptedIntegratedInstalls'],0)
        self.assertEqual(self.ingress_events,['tls','mail'])
        self.assertEqual(sum('start' in c for c in self.commands),2)
        self.assertEqual(json.loads((self.runtime/'runtime-authority.json').read_text())['schemaVersion'],2)
    def test_missing_ingress_receipt_refuses_before_intent_or_native_queue(self):
        with patch.object(q.ingress,'checked',side_effect=ValueError('missing private ingress')),patch.object(q.graph,'run',side_effect=self.native):
            with self.assertRaisesRegex(ValueError,'missing private ingress'):installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(self.commands,[]);self.assertEqual(json.loads(self.ledger.read_text())['venueInstallerVersion'],1)
        self.assertFalse((self.runtime/'runtime-authority.json').exists())
    def test_private_tls_bootstrap_failure_quarantines_without_queuing_consumers(self):
        with patch.object(q.ingress,'bootstrap_tls',side_effect=ValueError('wrong scoped CA')),patch.object(q.graph,'run',side_effect=self.native):
            with self.assertRaisesRegex(ValueError,'wrong scoped CA'):installer.activate(self.bundle,self.selector,self.ledger)
        self.assertFalse(any('start' in c for c in self.commands));self.assertEqual(sum('stop' in c for c in self.commands),2)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
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

    def test_upstream_observation_precedes_downstream_queue(self):
        with patch.object(q.graph,'run',side_effect=self.native):
            installer.activate(self.bundle,self.selector,self.ledger)
        starts=[i for i,c in enumerate(self.commands) if 'start' in c]
        root_observations=[i for i,c in enumerate(self.commands) if 'show' in c and 'p0test-r1-root.service' in c]
        self.assertTrue(any(starts[0]<i<starts[1] for i in root_observations))
    def test_failed_upstream_never_queues_downstream(self):
        def native(command,**kwargs):
            result=self.native(command,**kwargs)
            if 'show' in command and 'p0test-r1-root.service' in command:
                result.stdout=result.stdout.replace('ActiveState=active','ActiveState=failed')
            return result
        with patch.object(q.graph,'run',side_effect=native):
            with self.assertRaisesRegex(ValueError,'native selected service failed'):
                installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(sum('start' in c for c in self.commands),1)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
    def test_unready_upstream_deadline_never_queues_downstream(self):
        clock=[0]
        def native(command,**kwargs):
            result=self.native(command,**kwargs)
            if 'show' in command and 'p0test-r1-root.service' in command:
                result.stdout=result.stdout.replace('ActiveState=active','ActiveState=activating');clock[0]=1000
            return result
        with patch.object(q.graph,'run',side_effect=native),patch.object(q.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(ValueError,'cross-manager healthy startup deadline'):
                installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(sum('start' in c for c in self.commands),1)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')
    def test_operator_fence_between_observation_and_queue_wins(self):
        fenced=[False]
        def native(command,**kwargs):
            result=self.native(command,**kwargs)
            if not fenced[0] and 'show' in command and 'p0test-r1-root.service' in command:
                fenced[0]=True
                state=json.loads(self.ledger.read_text());state.update(venueStartPhase='failed-quarantined',activationAuthorized=False)
                self.ledger.write_text(json.dumps(state))
                q.runtime_receipt(self.context,'failed-quarantined',False)
            return result
        with patch.object(q.graph,'run',side_effect=native):
            with self.assertRaisesRegex(ValueError,'activation was fenced'):
                installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(sum('start' in c for c in self.commands),1)
        self.assertFalse(json.loads(self.ledger.read_text())['activationAuthorized'])

class Batches(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.bundle=Path(temp.name)
        self.plan={'prefix':'p0test-r1','accounts':[{'name':'p0test-r1-'+n,'uid':i+3200,'home':'/fixture'} for i,n in enumerate(('apps','platform'))]}
        self.paths={}
        for owner,name in (('rootful','root'),('rootless-apps','app'),('rootless-platform','db')):
            p=self.bundle/'quadlet'/owner/('p0test-r1-'+name+'.container');p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text('[Container]\nPodmanArgs=--sdnotify=healthy\nHealthCmd=["true","ready"]\n');self.paths[name]=p
        self.services={'root':{'dependencies':{}},'db':{'dependencies':{'root':'healthy'}},'app':{'dependencies':{'db':'healthy'}}}
    def invoke(self):
        (self.bundle/'stack.ir.json').write_text(json.dumps({'services':self.services}))
        with patch.object(q.graph,'run') as native:
            try:return q.activation_batches(self.bundle,self.plan)
            finally:native.assert_not_called()
    def test_actual_edges_override_input_manager_order(self):
        result=self.invoke()
        self.assertEqual([a['name'] if a else None for a,_,_ in result],[None,'p0test-r1-platform','p0test-r1-apps'])
        self.assertEqual(result[-1][2],{('p0test-r1-platform','p0test-r1-db.service')})
    def test_missing_producer_refuses_before_any_native_call(self):
        self.services['app']['dependencies']={'missing':'healthy'}
        with self.assertRaisesRegex(q.Refusal,'no managed native service'):self.invoke()
    def test_missing_native_health_flag_or_probe_refuses(self):
        original=self.paths['db'].read_text()
        for text in (original.replace('--sdnotify=healthy',''),original.replace('HealthCmd=','NotHealthCmd=')):
            self.paths['db'].write_text(text)
            with self.assertRaisesRegex(q.Refusal,'native readiness notification'):self.invoke()
    def test_cross_manager_cycle_refuses_before_queue(self):
        self.services['db']['dependencies']['app']='healthy'
        with self.assertRaisesRegex(q.Refusal,'dependency cycle'):self.invoke()
    def test_same_manager_edge_needs_no_cross_manager_barrier(self):
        p=self.paths['app'].with_name('p0test-r1-peer.container');p.write_text(self.paths['app'].read_text())
        self.services['peer']={'dependencies':{}};self.services['app']['dependencies']={'peer':'healthy'}
        result=self.invoke();app=next(row for row in result if row[0] and row[0]['name']=='p0test-r1-apps')
        self.assertEqual(app[2],set())

if __name__=='__main__':unittest.main()
