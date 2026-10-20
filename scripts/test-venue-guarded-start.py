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
        for index in range(54):
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
        fake={'venue_root_health':NS(checked=lambda *a:{}),'venue_registry':registry,'venue_screen':NS(port_screen=lambda *a:None),
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
        self.assertEqual(len(list(self.root.glob('bind-*'))),54)

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

    def completed_root(self):
        path=self.bundle/'quadlet/rootful/p0test-r1-root.container'
        path.write_text('[Container]\n[Service]\nType=oneshot\nRemainAfterExit=yes\n')
        ir=json.loads((self.bundle/'stack.ir.json').read_text())
        ir['services']['root']['lifecycle']='oneshot'
        ir['services']['app']['dependencies']={'root':'completed'}
        (self.bundle/'stack.ir.json').write_text(json.dumps(ir))
    def test_completed_upstream_exits_before_consumer_queue(self):
        self.completed_root();observations=[0];completed_at=[]
        def native(command,**kwargs):
            result=self.native(command,**kwargs)
            if 'show' in command and 'p0test-r1-root.service' in command:
                observations[0]+=1;epoch=json.loads(self.ledger.read_text())['venueStartMonotonicUsec']
                done=observations[0]>=3
                result.stdout=('ActiveState='+('active' if done else 'activating')+'\nSubState='+('exited' if done else 'start')+'\nResult=success\nExecMainStatus=0\nExecMainCode='+('1' if done else '0')+'\nExecMainStartTimestampMonotonic='+str(epoch+1)+'\nExecMainExitTimestampMonotonic='+str(epoch+2 if done else 0)+'\n')
                if done:completed_at.append(len(self.commands)-1)
            return result
        with patch.object(q.graph,'run',side_effect=native),patch.object(q.time,'sleep'):
            result=installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(result['status'],'running')
        starts=[i for i,c in enumerate(self.commands) if 'start' in c]
        self.assertGreater(starts[1],completed_at[0]);self.assertGreaterEqual(observations[0],3)
    def test_completed_running_success_cannot_queue_downstream(self):
        self.completed_root();clock=[0]
        def native(command,**kwargs):
            result=self.native(command,**kwargs)
            if 'show' in command and 'p0test-r1-root.service' in command:
                result.stdout+='SubState=running\nExecMainStatus=0\nExecMainCode=0\nExecMainExitTimestampMonotonic=0\n';clock[0]=1000
            return result
        with patch.object(q.graph,'run',side_effect=native),patch.object(q.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(q.Refusal,'startup deadline'):
                installer.activate(self.bundle,self.selector,self.ledger)
        self.assertEqual(sum('start' in c for c in self.commands),1)
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartPhase'],'failed-quarantined')

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

    def completed_db(self):
        self.services['db']['lifecycle']='oneshot'
        self.services['app']['dependencies']={'db':'completed'}
        self.paths['db'].write_text('[Container]\n[Service]\nType=oneshot\nRemainAfterExit=yes\n')
    def test_cross_manager_completed_edge_orders_and_requires_native_producer(self):
        self.completed_db();result=self.invoke()
        self.assertEqual([a['name'] if a else None for a,_,_ in result],[None,'p0test-r1-platform','p0test-r1-apps'])
        self.assertEqual(result[-1][2],{('p0test-r1-platform','p0test-r1-db.service')})
    def test_completed_without_retained_native_oneshot_refuses(self):
        self.completed_db();original=self.paths['db'].read_text()
        for text in (original.replace('Type=oneshot',''),original.replace('RemainAfterExit=yes','')):
            self.paths['db'].write_text(text)
            with self.assertRaisesRegex(q.Refusal,'native retained oneshot completion'):self.invoke()
    def test_completed_declared_daemon_refuses_before_native_queue(self):
        self.completed_db();self.services['db']['lifecycle']='daemon'
        with self.assertRaisesRegex(q.Refusal,'native retained oneshot completion'):self.invoke()
    def test_missing_completed_producer_refuses_before_native_queue(self):
        self.services['app']['dependencies']={'absent':'completed'}
        with self.assertRaisesRegex(q.Refusal,'no managed native service'):self.invoke()
    def test_mixed_completed_healthy_manager_cycle_refuses(self):
        self.completed_db();self.services['db']['dependencies']['app']='healthy'
        with self.assertRaisesRegex(q.Refusal,'dependency cycle'):self.invoke()
    def test_unemitted_on_demand_consumer_is_not_automatic_startup(self):
        self.services['manual-runner']={'lifecycle':'on-demand','dependencies':{'db':'completed'}}
        self.assertEqual(len(self.invoke()),3)
    def test_unemitted_daemon_consumer_still_refuses(self):
        self.services['missing-daemon']={'lifecycle':'daemon','dependencies':{'db':'completed'}}
        with self.assertRaisesRegex(q.Refusal,'no managed native service'):self.invoke()
    def test_emitted_on_demand_service_is_not_an_automatic_consumer(self):
        self.services['app']['lifecycle']='on-demand'
        app=next(row for row in self.invoke() if row[0] and row[0]['name']=='p0test-r1-apps')
        self.assertEqual(app[2],set())

    def bootstrap_cycle(self):
        self.completed_db();self.services['root']['lifecycle']='oneshot'
        self.paths['root'].write_text('[Container]\n[Service]\nType=oneshot\nRemainAfterExit=yes\n')
        self.services['caddy']={'dependencies':{'root':'completed'}}
        self.services['db']['dependencies']={'caddy':'healthy','root':'completed'}
        self.services['notification']={'dependencies':{'db':'completed'}}
        directory=self.paths['root'].parent
        for name in ('caddy','notification'):
            (directory/('p0test-r1-'+name+'.container')).write_text(self.paths['app'].read_text())
        (directory/'p0test-r1.target').write_text('[Unit]\nWants=p0test-r1-root.service p0test-r1-caddy.service p0test-r1-notification.service\n')
    def test_tls_bootstrap_breaks_manager_cycle_but_keeps_native_requirements(self):
        self.bootstrap_cycle();result=self.invoke()
        self.assertEqual([a['name'] if a else None for a,_,_ in result],['p0test-r1-platform',None,'p0test-r1-apps'])
        self.assertEqual(result[0][2],{(None,'p0test-r1-caddy.service'),(None,'p0test-r1-root.service')})
        self.assertEqual(result[1][2],{('p0test-r1-platform','p0test-r1-db.service')})
    def test_tls_bootstrap_foreign_prerequisite_refuses_before_native_call(self):
        self.bootstrap_cycle();self.services['caddy']['dependencies']={'db':'completed'}
        with self.assertRaisesRegex(q.Refusal,'not an automatic native root service'):self.invoke()
    def bootstrap_observations(self,*,pending=False):
        self.bootstrap_cycle();self.invoke();commands=[]
        def native(command,**kwargs):
            commands.append(command);oneshot='p0test-r1-root.service' in command
            done=oneshot and not pending
            return NS(returncode=0,stdout='ActiveState=active\nSubState='+('exited' if done else 'running')+'\nResult=success\nExecMainCode='+('1' if done else '0')+'\nExecMainStatus=0\nExecMainStartTimestampMonotonic=21\nExecMainExitTimestampMonotonic='+('22' if done else '0')+'\n')
        selected={None:['p0test-r1.target','p0test-r1-root.service','p0test-r1-caddy.service','p0test-r1-notification.service']}
        with patch.object(q.graph,'run',side_effect=native):
            observed=q.startup_observations(self.bundle,self.plan,{'venueStartQueued':[],'venueStartMonotonicUsec':20},selected)
        self.assertFalse(any('p0test-r1-notification.service' in c or 'p0test-r1.target' in c for c in commands))
        return observed
    def test_pre_target_observation_is_only_actual_bootstrap_prerequisites(self):
        observed=self.bootstrap_observations()
        self.assertEqual(observed,{(None,'p0test-r1-caddy.service'):True,(None,'p0test-r1-root.service'):True})
    def test_bootstrap_oneshot_active_success_is_not_assumed_completed(self):
        observed=self.bootstrap_observations(pending=True)
        self.assertFalse(observed[None,'p0test-r1-root.service'])

@unittest.skipUnless(os.geteuid()==0,'root-private synthetic bootstrap fixture')
class FoundationBootstrap(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.bundle=self.root/'bundle';directory=self.bundle/'quadlet/rootful';directory.mkdir(parents=True)
        (directory/'p0test-r1-caddy.container').write_text('[Container]\n')
        (directory/'p0test-r1-volume-init.container').write_text('[Container]\n[Service]\nType=oneshot\nRemainAfterExit=yes\n')
        (self.bundle/'stack.ir.json').write_text(json.dumps({'services':{'caddy':{'lifecycle':'daemon'},'volume-init':{'lifecycle':'oneshot'}}}))
        runtime=self.root/'runtime';runtime.mkdir(mode=0o700)
        self.context=NS(runtime=runtime,physical_reserves=lambda:None)
        self.plan={'prefix':'p0test-r1','accounts':[]};self.unit='p0test-r1-volume-init.service'
        self.selected={None:[self.unit,'p0test-r1-caddy.service']}
        self.ledger=self.root/'ledger.json';self.ledger.write_text(json.dumps({'venueStartPhase':'starting','activationAuthorized':True,'venueStartQueued':[],'venueStartMonotonicUsec':20}));self.ledger.chmod(0o600)
        self.registry=NS(reserve=lambda:None)
    def invoke(self):
        return q.bootstrap_volume_init(self.bundle,self.plan,self.ledger,self.context,q.time.monotonic()+60,self.selected,self.registry)
    def test_foundation_intent_precedes_exact_queue_and_waits_for_completion(self):
        def native(command,**kwargs):
            self.assertEqual(command,['systemctl','start','--job-mode=fail','--no-block',self.unit])
            self.assertEqual(json.loads(self.ledger.read_text())['venueStartBootstrapPending'],self.unit)
            return NS(returncode=0)
        with patch.object(q.graph,'run',side_effect=native) as run,patch.object(q,'startup_observations',side_effect=[{(None,self.unit):False},{(None,self.unit):True}]) as observe,patch.object(q.time,'sleep'):
            self.invoke()
        self.assertEqual(run.call_count,1);self.assertEqual(observe.call_count,2)
        state=json.loads(self.ledger.read_text());self.assertEqual(state['venueStartBootstrapQueued'],[self.unit]);self.assertNotIn('venueStartBootstrapPending',state)
    def test_failed_foundation_queue_retains_intent_and_never_observes_success(self):
        with patch.object(q.graph,'run',return_value=NS(returncode=1)),patch.object(q,'startup_observations') as observe:
            with self.assertRaisesRegex(q.Refusal,'intent retained'):self.invoke()
        self.assertEqual(json.loads(self.ledger.read_text())['venueStartBootstrapPending'],self.unit);observe.assert_not_called()
    def test_attempted_foundation_never_replays(self):
        state=json.loads(self.ledger.read_text());state['venueStartBootstrapQueued']=[self.unit];self.ledger.write_text(json.dumps(state))
        with patch.object(q.graph,'run') as run:
            with self.assertRaisesRegex(q.Refusal,'already attempted'):self.invoke()
        run.assert_not_called()
    def test_fence_during_foundation_completion_wait_wins(self):
        def observed(*args):
            state=json.loads(self.ledger.read_text());state['venueStartPhase']='failed-quarantined';state['activationAuthorized']=False;self.ledger.write_text(json.dumps(state))
            return {(None,self.unit):False}
        with patch.object(q.graph,'run',return_value=NS(returncode=0)) as run,patch.object(q,'startup_observations',side_effect=observed),patch.object(q.time,'sleep'):
            with self.assertRaisesRegex(q.Refusal,'was fenced'):self.invoke()
        self.assertEqual(run.call_count,1)

if __name__=='__main__':unittest.main()
