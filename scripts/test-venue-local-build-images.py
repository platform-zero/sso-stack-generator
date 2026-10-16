#!/usr/bin/env python3
"""Only three no-pull/no-network generated image-build units may run."""
import hashlib
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
ops=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops'
spec=importlib.util.spec_from_file_location('venue_local_build_images',ops/'venue-local-build-images.py')
local=importlib.util.module_from_spec(spec);spec.loader.exec_module(local)

class LocalBuildFixtures(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.bundle=Path(temp.name);self.source={'buildUnits':{}}
        for user,names in local.LOCAL.items():
            for name in names:
                rel='quadlet/rootless-'+user.removeprefix('p0test-r1-')+'/p0test-r1-'+name+'.build'
                p=self.bundle/rel;p.parent.mkdir(parents=True,exist_ok=True)
                p.write_text('[Build]\nImageTag=localhost/webservices/'+name+':bundle\nPull=never\nNetwork=none\n')
                self.source['buildUnits'][rel]={'user':user,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.plan=local.plan_for(self.bundle,self.source)
    def test_three_selected_source_builds_and_hostile_egress_refusal(self):
        self.assertEqual(len(self.plan),3)
        p=self.bundle/'quadlet/rootless-platform/p0test-r1-keycloak.build'
        p.write_text(p.read_text().replace('Network=none\n',''))
        with self.assertRaisesRegex(local.Refusal,'may pull or use build network'):
            local.plan_for(self.bundle,self.source)
    def test_installed_quadlet_exec_must_disable_pull_and_network(self):
        tag='localhost/webservices/keycloak:bundle';unit='p0test-r1-keycloak-build.service'
        def checked(command,**kwargs):
            if 'cat' in command:return SimpleNamespace(returncode=0,stdout=
                'ExecStart=/usr/bin/podman build --pull=never --network=none --tag '+tag+' --file Containerfile /build\n')
            return SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStatus=0\n')
        with patch.object(local.graph,'run',side_effect=checked):
            self.assertEqual(local.selected_unit(['selected-user'],unit,tag)['ActiveState'],'inactive')
            with self.assertRaisesRegex(local.Refusal,'source path changed'):
                local.selected_unit(['selected-user'],unit,tag,'/selected/exact.build')
        def unsafe(command,**kwargs):
            return SimpleNamespace(returncode=0,stdout='ExecStart=/usr/bin/podman build --pull=never --network=host --tag '+tag+' /build\n')
        with patch.object(local.graph,'run',side_effect=unsafe):
            with self.assertRaisesRegex(local.Refusal,'reach network'):
                local.selected_unit(['selected-user'],unit,tag)
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
              patch.object(local,'probe',side_effect=check),
              patch.object(local.stage,'write_ledger',side_effect=save)):
            self.assertEqual(local.prepare(self.bundle,'selector','site',ledger,1,True)['builtOutputIds'],1)
            self.assertNotIn('venueLocalBuildPending',data)
        data['venueLocalBuildPending']=key;data['venueLocalBuildOutputs']={}
        data['venueLocalBuildPriorStartTimestamp']=6
        with (patch.object(local.registry,'journal',return_value=(ledger,data,plan,None)),
              patch.object(local.authority,'authority',return_value=result),
              patch.object(local,'selected_unit',return_value=state)):
            with self.assertRaisesRegex(local.Refusal,'not proved successful'):
                local.prepare(self.bundle,'selector','site',ledger,1,True)
        failed={**state,'ActiveState':'failed','Result':'exit-code','ExecMainStatus':'1','Job':''}
        with (patch.object(local.registry,'journal',return_value=(ledger,data,plan,None)),
              patch.object(local.authority,'authority',return_value=result),
              patch.object(local,'selected_unit',return_value=failed),
              patch.object(local.registry,'command_graphs',return_value={user:(home,['selected'])}),
              patch.object(local.registry,'pulled',return_value=None),
              patch.object(local,'probe',return_value={}),
              patch.object(local.stage,'write_ledger',side_effect=save)):
            self.assertEqual(local.prepare(self.bundle,'selector','site',ledger,1,False,True)['status'],'abandoned-inert')
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
