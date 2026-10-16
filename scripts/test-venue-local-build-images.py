#!/usr/bin/env python3
"""Only fourteen exact no-pull builds run; three have no network."""
import hashlib
import io
import json
import os
from types import SimpleNamespace
import importlib.util
from pathlib import Path
import tempfile
import time
from datetime import datetime, timezone
import unittest
from unittest.mock import patch
ops=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
spec=importlib.util.spec_from_file_location('venue_local_build_images',ops/'venue-local-build-images.py')
local=importlib.util.module_from_spec(spec);spec.loader.exec_module(local)

class LocalBuildFixtures(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.bundle=Path(temp.name);self.source={'buildUnits':{}}
        for user in set(local.OFFLINE)|set(local.NETWORK):
            for name in local.OFFLINE.get(user,())+local.NETWORK.get(user,()):
                rel='quadlet/rootless-'+user.removeprefix('p0test-r1-')+'/p0test-r1-'+name+'.build'
                p=self.bundle/rel;p.parent.mkdir(parents=True,exist_ok=True)
                offline=name in local.OFFLINE.get(user,())
                p.write_text('[Build]\nImageTag=localhost/webservices/'+name+':bundle\nPull=never\n'+
                             ('Network=none\n' if offline else ''))
                self.source['buildUnits'][rel]={'user':user,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.plan=local.plan_for(self.bundle,self.source)
    def test_targeted_diagnosis_selects_only_exact_missing_output(self):
        key='p0test-r1-workloads|localhost/webservices/jupyter-notebook-build:bundle'
        self.assertNotEqual(sorted(self.plan)[0],key)
        self.assertEqual(local.build_candidates(self.plan,{},[],1,key),[key])
        self.assertEqual(local.build_candidates(self.plan,{key:'sha256:'+'a'*64},[],1,key),[])
        self.assertEqual(local.build_candidates(self.plan,{},[],2),sorted(self.plan)[:2])
        for wrong,skipped in (('foreign|image',[]),(key,[key])):
            with self.subTest(wrong=wrong,skipped=skipped),self.assertRaises(local.Refusal):
                local.build_candidates(self.plan,{},skipped,1,wrong)

    def test_export_requires_complete_exact_plan_and_groups_shared_ids(self):
        image='sha256:'+'a'*64
        data={'venueLocalBuildPhase':'inert-ready','venueLocalBuildPlan':self.plan,
              'venueLocalBuildOutputs':{key:image for key in self.plan}}
        rows=local.export_plan(data,self.plan)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['sourceKeys'],sorted(self.plan))
        self.assertEqual(rows[0]['archiveFilename'],'a'*64+'.oci.tar')
        for update in ({'venueLocalBuildPhase':'preparing'},{'venueLocalBuildPlan':{}},
                       {'venueLocalBuildPending':next(iter(self.plan))},
                       {'venueLocalBuildSkipped':[next(iter(self.plan))]},
                       {'venueLocalBuildOutputs':{}},
                       {'venueLocalBuildOutputs':{key:'not-an-id' for key in self.plan}}):
            with self.subTest(update=update),self.assertRaises(local.Refusal):
                local.export_plan({**data,**update},self.plan)

    def test_export_reserve_failure_cancels_only_its_saver(self):
        process=SimpleNamespace(pid=987654321,poll=lambda:None,wait=lambda **kwargs:0)
        with (patch.object(local.subprocess,'Popen',return_value=process) as start,
              patch.object(local,'export_reserve',side_effect=local.Refusal('reserve')),
              patch.object(local.os,'killpg') as kill):
            with self.assertRaisesRegex(local.Refusal,'reserve'):
                local.save_image(['selected-podman'],'sha256:'+'a'*64,io.BytesIO(),self.bundle)
        kill.assert_called_once_with(process.pid,local.signal.SIGTERM)
        self.assertEqual(start.call_args.args[0],['selected-podman','save','--format','oci-archive','sha256:'+'a'*64])
        self.assertTrue(start.call_args.kwargs['start_new_session'])

    @unittest.skipUnless(os.geteuid()==0,'physical export receipt fixtures require root')
    def test_export_publishes_exclusive_hash_bound_files_and_retains_partial_failure(self):
        image='sha256:'+'a'*64
        data={'venueLocalBuildPhase':'inert-ready','venueLocalBuildPlan':self.plan,
              'venueLocalBuildOutputs':{key:image for key in self.plan}}
        plan={'sourceCommit':'b'*40,'selectorSha256':'c'*64,'quadletTreeSha256':'d'*64}
        (self.bundle/'source-provenance.json').write_text('{}')
        root=self.bundle/'canonical';user=sorted(self.plan)[0].partition('|')[0]
        roots={user:(self.bundle,['selected-podman'])}
        def save(command,image,output,root):output.write(b'synthetic image archive fixture')
        with (patch.object(local.registry,'journal',return_value=(self.bundle/'unused-ledger',data,plan,{})),
              patch.object(local.authority,'authority',return_value=self.source),
              patch.object(local,'probe',return_value=roots),
              patch.object(local,'export_reserve'),patch.object(local,'save_image',side_effect=save)):
            result=local.export_outputs(self.bundle,'selector','site','ledger',root)
            self.assertEqual(result['status'],'exported-discovery')
            receipt=json.loads((root/'manifest.json').read_text())
            row=receipt['images'][0];archive=root/row['archiveFilename']
            self.assertEqual(row['archiveSha256'],hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(archive.stat().st_mode&0o777,0o600)
            self.assertEqual(archive.stat().st_nlink,1)
            self.assertFalse(receipt['activationAuthorized'])
            with self.assertRaises(local.Refusal):local.export_outputs(self.bundle,'selector','site','ledger',root)
            def fail(command,image,output,root):
                output.write(b'partial');raise local.Refusal('synthetic saver failure')
            failed=self.bundle/'failed-canonical'
            with patch.object(local,'save_image',side_effect=fail),self.assertRaises(local.Refusal):
                local.export_outputs(self.bundle,'selector','site','ledger',failed)
            receipt=json.loads((failed/'manifest.json').read_text())
            pending=receipt['pending'];partial=failed/pending['temporaryFilename']
            self.assertEqual(receipt['status'],'exporting-discovery')
            self.assertEqual(partial.stat().st_ino,pending['ino'])
            self.assertEqual(partial.read_bytes(),b'partial')
            self.assertFalse((failed/pending['archiveFilename']).exists())
            with self.assertRaises(local.Refusal):local.export_outputs(self.bundle,'selector','site','ledger',failed)

    def test_fourteen_selected_source_builds_and_hostile_egress_refusal(self):
        self.assertEqual(len(self.plan),14)
        self.assertEqual(sum(row['offline'] for row in self.plan.values()),3)
        p=self.bundle/'quadlet/rootless-platform/p0test-r1-keycloak.build'
        p.write_text(p.read_text().replace('Network=none\n',''))
        with self.assertRaisesRegex(local.Refusal,'pull/network authority differs'):
            local.plan_for(self.bundle,self.source)
        p=self.bundle/'quadlet/rootless-apps/p0test-r1-forgejo.build'
        p.write_text(p.read_text()+'Network=host\n')
        with self.assertRaisesRegex(local.Refusal,'pull/network authority differs'):
            local.plan_for(self.bundle,self.source)
    def test_installed_quadlet_exec_must_disable_pull_and_network(self):
        tag='localhost/webservices/keycloak:bundle';unit='p0test-r1-keycloak-build.service'
        def checked(command,**kwargs):
            if 'cat' in command:return SimpleNamespace(returncode=0,stdout=
                'ExecStart=/usr/bin/podman build --pull=never --network none --tag '+tag+' --file Containerfile /build\n')
            return SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStatus=0\n')
        with patch.object(local.graph,'run',side_effect=checked):
            self.assertEqual(local.selected_unit(['selected-user'],unit,tag)['ActiveState'],'inactive')
            with self.assertRaisesRegex(local.Refusal,'source path changed'):
                local.selected_unit(['selected-user'],unit,tag,'/selected/exact.build')
        def unsafe(command,**kwargs):
            return SimpleNamespace(returncode=0,stdout='ExecStart=/usr/bin/podman build --pull=never --network=host --tag '+tag+' /build\n')
        with patch.object(local.graph,'run',side_effect=unsafe):
            with self.assertRaisesRegex(local.Refusal,'pull/network/tag authority differs'):
                local.selected_unit(['selected-user'],unit,tag)
        with patch.object(local.graph,'run',side_effect=checked):
            with self.assertRaisesRegex(local.Refusal,'lacks bounded systemd start timeout'):
                local.selected_unit(['selected-user'],unit,tag,offline=False)
        def network_default(command,**kwargs):
            if 'cat' in command:return SimpleNamespace(returncode=0,stdout=
                'TimeoutStartSec=1800\nExecStart=/usr/bin/podman build --pull=never --tag '+tag+' --file Containerfile /build\n')
            return SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=inactive\n')
        with patch.object(local.graph,'run',side_effect=network_default):
            self.assertEqual(local.selected_unit(['selected-user'],unit,tag,offline=False)['ActiveState'],'inactive')
        def missing_timeout(command,**kwargs):
            row=network_default(command,**kwargs)
            row.stdout=row.stdout.replace('TimeoutStartSec=1800\n','')
            return row
        with patch.object(local.graph,'run',side_effect=missing_timeout):
            with self.assertRaisesRegex(local.Refusal,'lacks bounded systemd start timeout'):
                local.selected_unit(['selected-user'],unit,tag,offline=False)
    def test_anonymous_multistage_ids_require_selected_job_and_exact_step(self):
        user='p0test-r1-apps';key=user+'|localhost/webservices/forgejo:bundle'
        home=self.bundle/'home';path=home/'.config/containers/systemd/p0test-r1-forgejo.build'
        path.parent.mkdir(parents=True);path.write_text('[Build]\n')
        output='sha256:'+'a'*64;extra='sha256:'+'b'*64;base='sha256:'+'c'*64
        older='sha256:'+'e'*64
        begin=int(time.time()*1000000)+1_000_000;end=begin+2_000_000
        start={'JOB_ID':'41','JOB_TYPE':'start','MESSAGE_ID':'7d4958e842da4a758f6c1cdc7b36dcc5',
               '__REALTIME_TIMESTAMP':str(begin)}
        done={**start,'MESSAGE_ID':'39f53479d3a045ac8e11786248231fbf',
              'JOB_RESULT':'done','__REALTIME_TIMESTAMP':str(end)}
        logs=[{'MESSAGE':[1,2,3],'__REALTIME_TIMESTAMP':str(begin+100000)},
              {'MESSAGE':'--> '+extra[7:19],'__REALTIME_TIMESTAMP':str(begin+200000)},
              {'MESSAGE':'--> '+output[7:19],'__REALTIME_TIMESTAMP':str(end-200000)}]
        created=datetime.fromtimestamp((begin+700000)/1_000_000,timezone.utc).isoformat()
        def seen(command,**kwargs):
            if command[0]=='journalctl':
                rows=(start,done) if 'USER_UNIT=p0test-r1-forgejo-build.service' in command else logs
                return SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,rows)))
            if 'ls' in command:return SimpleNamespace(returncode=0,stdout='\n'.join((base,output,extra,older)))
            if 'inspect' in command:return SimpleNamespace(returncode=0,stdout=json.dumps(
                {'Id':extra,'RepoTags':[],'Created':created,'Labels':{'io.buildah.version':'1.39.3'}}))
            raise AssertionError(command)
        plan={'accounts':[{'name':user,'uid':3201,'home':str(home)}]}
        data={'venueLocalBuildPlan':self.plan,'venueRegistryVerified':{user+'|base':base},
              'venueBuildBaseVerified':{},'venueFailedBuildIntermediates':{user+'|failed':[older]}}
        with (patch.object(local,'selected_unit',return_value={'ActiveState':'inactive','Job':''}),
              patch.object(local.registry,'command_graphs',return_value={user:(home,['selected'])}),
              patch.object(local.graph,'run',side_effect=seen),
              patch.object(local,'probe',return_value={})):
            self.assertEqual(local.classify_intermediates(self.bundle,'selector',plan,data,key,output,{},{}),[extra])
            logs[1]['MESSAGE']='--> '+'f'*12
            with self.assertRaisesRegex(local.Refusal,'absent from exact step transcript'):
                local.classify_intermediates(self.bundle,'selector',plan,data,key,output,{}, {})
        failure={'MESSAGE_ID':'d9b373ed55a64feb8242e02dbe79a49c',
                 'MESSAGE':'p0test-r1-forgejo-build.service: Failed with result \'exit-code\'.',
                 '__REALTIME_TIMESTAMP':str(end)}
        logs[1]['MESSAGE']='--> '+extra[7:19]
        def failed_seen(command,**kwargs):
            if 'USER_UNIT=p0test-r1-forgejo-build.service' in command:
                return SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,(start,failure))))
            if 'ls' in command:return SimpleNamespace(returncode=0,stdout='\n'.join((base,extra,older)))
            return seen(command,**kwargs)
        old='sha256:'+'d'*64
        data['venueFailedBuildIntermediates']={user+'|failed':[older],
            'p0test-r1-test-runners|localhost/webservices/android-test-runner-api34:bundle':[old]}
        def failed_probe(_bundle,_plan,_data,expected):
            self.assertEqual(expected['p0test-r1-test-runners|'+old],old)
            return {},{}
        with (patch.object(local,'selected_unit',return_value={'ActiveState':'failed','Job':''}),
              patch.object(local.registry,'command_graphs',return_value={user:(home,['selected'])}),
              patch.object(local.registry,'pulled',return_value=None),
              patch.object(local.registry,'probe',side_effect=failed_probe),
              patch.object(local.graph,'run',side_effect=failed_seen)):
            self.assertEqual(local.classify_failed_intermediates(self.bundle,'selector',plan,data,key,{},{}),[extra])
            logs[1]['MESSAGE']='--> '+'f'*12
            with self.assertRaisesRegex(local.Refusal,'absent from selected step log'):
                local.classify_failed_intermediates(self.bundle,'selector',plan,data,key,{}, {})
    def test_unloaded_oneshot_needs_exact_post_ledger_journal_pair(self):
        ledger=self.bundle/'ledger';ledger.write_text('{}')
        ts=ledger.stat().st_mtime_ns//1000
        start={'_UID':'3201','USER_UNIT':'selected-build.service','JOB_ID':'42','JOB_TYPE':'start',
               'MESSAGE_ID':'7d4958e842da4a758f6c1cdc7b36dcc5','__REALTIME_TIMESTAMP':str(ts+1)}
        done={**start,'MESSAGE_ID':'39f53479d3a045ac8e11786248231fbf','JOB_RESULT':'done',
              '__REALTIME_TIMESTAMP':str(ts+2)}
        with patch.object(local.graph,'run',return_value=SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,(start,done))))):
            self.assertTrue(local.journaled_unloaded_success(ledger,3201,'selected-build.service'))
            done['JOB_ID']='another'
            with patch.object(local.graph,'run',return_value=SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,(start,done))))):
                self.assertFalse(local.journaled_unloaded_success(ledger,3201,'selected-build.service'))
            done['JOB_ID']='42';done['__REALTIME_TIMESTAMP']=str(ts-1)
            with patch.object(local.graph,'run',return_value=SimpleNamespace(returncode=0,stdout='\n'.join(map(json.dumps,(start,done))))):
                self.assertFalse(local.journaled_unloaded_success(ledger,3201,'selected-build.service'))
    def test_explicit_pending_recovery_checks_unit_invocation_and_all_graphs_prewrite(self):
        key='p0test-r1-platform|localhost/webservices/keycloak:bundle';user='p0test-r1-platform'
        home=self.bundle/'home';source=home/'.config/containers/systemd/p0test-r1-keycloak.build'
        source.parent.mkdir(parents=True);source.write_text('selected build\n')
        ledger=self.bundle/'ledger';ledger.write_text('{}')
        ids={'root|sha256:'+'d'*64:'sha256:'+'d'*64}
        bases={'p0test-r1-apps|docker.io/test/base@sha256:'+'e'*64:'sha256:'+'f'*64}
        result={'imageIds':ids,'buildBaseStores':list(bases),'frozenBuildBaseSha256':'0'*64,
                'buildUnits':self.source['buildUnits']}
        data={'venueRegistryPhase':'inert-ready','venueRegistryVerified':ids,
              'venueBuildBasePhase':'inert-ready','venueBuildBaseVerified':bases,
              'venueBuildBaseFrozenSha256':'0'*64,'venueCompositeMode':'inert-ready',
              'status':'units-staged','venueLocalBuildPhase':'preparing','venueLocalBuildPlan':self.plan,
              'venueLocalBuildOutputs':{},'venueLocalBuildPending':key,
              'venueLocalBuildPriorStartTimestamp':5,
              'installedUnits':[{'path':str(source),'ino':source.stat().st_ino}]}
        plan={'accounts':[{'name':user,'uid':source.stat().st_uid,'home':str(home)}]}
        state={'ActiveState':'inactive','Result':'success','ExecMainStatus':'0',
               'ExecMainStartTimestampMonotonic':'6','ExecMainExitTimestampMonotonic':'7'}
        def save(_path,obj):ledger.write_text(json.dumps(obj))
        def check(_bundle,_selector,_plan,_data,outputs):
            self.assertEqual(outputs,{key:'sha256:'+'a'*64});return {}
        with (patch.object(local.registry,'journal',return_value=(ledger,data,plan,None)),
              patch.object(local.authority,'authority',return_value=result),
              patch.object(local,'selected_unit',return_value=state),
              patch.object(local.registry,'command_graphs',return_value={user:(home,['selected'])}),
              patch.object(local.registry,'pulled',return_value='sha256:'+'a'*64),
              patch.object(local,'classify_intermediates',return_value=[]),
              patch.object(local,'probe',side_effect=check),
              patch.object(local.stage,'write_ledger',side_effect=save)):
            self.assertEqual(local.prepare(self.bundle,'selector','site',ledger,1,True)['builtOutputIds'],1)
            self.assertNotIn('venueLocalBuildPending',data)
        data['venueLocalBuildPending']=key;data['venueLocalBuildOutputs']={}
        data['venueLocalBuildIntermediates']={}
        data['venueLocalBuildPriorStartTimestamp']=6
        with (patch.object(local.registry,'journal',return_value=(ledger,data,plan,None)),
              patch.object(local.authority,'authority',return_value=result),
              patch.object(local,'selected_unit',return_value=state),
              patch.object(local,'journaled_unloaded_success',return_value=False)):
            with self.assertRaisesRegex(local.Refusal,'not proved successful'):
                local.prepare(self.bundle,'selector','site',ledger,1,True)
        failed={**state,'ActiveState':'failed','Result':'exit-code','ExecMainStatus':'1','Job':''}
        with (patch.object(local.registry,'journal',return_value=(ledger,data,plan,None)),
              patch.object(local.authority,'authority',return_value=result),
              patch.object(local,'selected_unit',return_value=failed),
              patch.object(local.registry,'command_graphs',return_value={user:(home,['selected'])}),
              patch.object(local.registry,'pulled',return_value=None),
              patch.object(local,'classify_failed_intermediates',return_value=[]),
              patch.object(local.stage,'write_ledger',side_effect=save)):
            self.assertEqual(local.prepare(self.bundle,'selector','site',ledger,1,False,True)['status'],'preparing')
            self.assertEqual(data['venueLocalBuildFailure']['execMainStatus'],'1')
    def test_output_graph_requires_exact_tag_id_and_no_pending(self):
        graph=local.graph;key='p0test-r1-platform|localhost/webservices/keycloak:bundle'
        image='sha256:'+'a'*64
        state={'venueLocalBuildPhase':'preparing','venueLocalBuildPlan':self.plan,
               'venueLocalBuildOutputs':{key:image}}
        with (patch.object(graph.stage,'owned_plan',return_value={'accounts':[]}),
              patch.object(graph,'stores',return_value=[('p0test-r1-platform','/unused',['selected'])]),
              patch.object(graph,'run',return_value=SimpleNamespace(returncode=0,stdout=image+'\n'))):
            self.assertEqual(graph.journaled_local_output_ids(self.bundle,'unused',state,self.source),
                             {'p0test-r1-platform':{image}})
            state['venueLocalBuildPending']=key
            with self.assertRaisesRegex(graph.Refusal,'journal/source differs'):
                graph.journaled_local_output_ids(self.bundle,'unused',state,self.source)

if __name__=='__main__':unittest.main()
