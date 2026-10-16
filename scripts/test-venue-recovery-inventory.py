#!/usr/bin/env python3
"""Retained native object identity/epoch proof is not foreign-object adoption."""
import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-registry-images.py'
spec=importlib.util.spec_from_file_location('recovery_inventory',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.scope=self.root/'quadlet/rootful';self.scope.mkdir(parents=True)
        (self.scope/'p0test-r1-init.container').write_text('ContainerName=p0test-r1-init\nImage=registry/ref\n')
        (self.scope/'p0test-r1-net.network').write_text('NetworkName=p0test-r1_net\n')
        self.plan={'prefix':'p0test-r1','quadletTreeSha256':'tree','accounts':[]}
        self.data={'venueInstallerVersion':2,'venueStartPhase':'failed-quarantined','activationAuthorized':False,
                   'venueStartIntent':'tree','venueStartMonotonicUsec':20}
        self.expected={'root|registry/ref':'sha256:'+'e'*64}
        self.container={'Id':'a'*64,'Name':'p0test-r1-init','Image':'e'*64,
                        'Config':{'Labels':{'PODMAN_SYSTEMD_UNIT':'p0test-r1-init.service'}},
                        'State':{'Running':False,'Status':'exited','ExitCode':-1}}
        self.native=SimpleNamespace(returncode=0,stdout='ExecMainStatus=0\nExecMainStartTimestampMonotonic=21\n')
        self.inspect=SimpleNamespace(returncode=0,stdout=json.dumps([{'name':'p0test-r1_net','id':'b'*64}]))
        self.addCleanup(patch.stopall)
        patch.object(m,'load',return_value=SimpleNamespace(selected_commands=lambda p:[(None,['systemctl'])])).start()
    def containers(self,row=None,native=None):
        with patch.object(m.graph,'run',side_effect=[SimpleNamespace(returncode=0,stdout=json.dumps([row or self.container])),native or self.native]):
            return m.recovery_containers(self.root,self.plan,self.data,'root',['podman'],{'a'*12},self.expected)
    def test_exact_stopped_native_bootstrap_preserves_interrupted_exit_not_success(self):
        value=self.containers()['root|p0test-r1-init'];self.assertEqual(value['exitCode'],-1);self.assertEqual(value['image'],self.expected['root|registry/ref'])
    def test_live_wrong_image_label_or_name_refuses(self):
        for kind in ('running','image','label','name'):
            row=copy.deepcopy(self.container)
            if kind=='running':row['State']['Running']=True
            if kind=='image':row['Image']='f'*64
            if kind=='label':row['Config']['Labels']['PODMAN_SYSTEMD_UNIT']='foreign.service'
            if kind=='name':row['Name']='foreign'
            with self.subTest(kind=kind),self.assertRaises(m.Refusal):self.containers(row)
    def test_old_container_epoch_refuses(self):
        with self.assertRaises(m.Refusal):self.containers(native=SimpleNamespace(returncode=0,stdout='ExecMainStartTimestampMonotonic=19\n'))
    def test_exact_network_and_native_epoch(self):
        with patch.object(m.graph,'run',side_effect=[self.native,self.inspect]):
            proof=m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'p0test-r1_net'})
        self.assertEqual(proof['root|p0test-r1_net']['id'],'b'*64)
    def test_gc_oneshot_requires_durable_uid_unit_name_and_epoch(self):
        native=SimpleNamespace(returncode=0,stdout='ExecMainStatus=0\nExecMainStartTimestampMonotonic=0\n')
        row={'_COMM':'podman','_SYSTEMD_UNIT':'p0test-r1-net-network.service','_UID':'0','MESSAGE':'p0test-r1_net','__MONOTONIC_TIMESTAMP':'21'}
        for valid in (True,False):
            record=dict(row)
            if not valid:record['_UID']='1000'
            journal=SimpleNamespace(returncode=0,stdout=json.dumps(record))
            with patch.object(m.graph,'run',side_effect=[native,journal,self.inspect]):
                if valid:self.assertTrue(m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'p0test-r1_net'}))
                else:
                    with self.assertRaises(m.Refusal):m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'p0test-r1_net'})
    def test_exact_previous_network_id_proof_survives_later_epoch_gc(self):
        self.data['venueRecoveryNetworks']={'root|p0test-r1_net':{'id':'b'*64,'unit':'p0test-r1-net-network.service'}}
        with patch.object(m.graph,'run',return_value=self.inspect) as run:
            proof=m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'p0test-r1_net'})
        self.assertEqual(proof,self.data['venueRecoveryNetworks']);self.assertEqual(run.call_count,1)
    def test_previous_network_name_never_substitutes_different_id(self):
        self.data['venueRecoveryNetworks']={'root|p0test-r1_net':{'id':'c'*64,'unit':'p0test-r1-net-network.service'}}
        with patch.object(m.graph,'run',return_value=self.inspect):
            with self.assertRaises(m.Refusal):m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'p0test-r1_net'})
    def test_unknown_network_never_adopted(self):
        with self.assertRaises(m.Refusal):m.recovery_networks(self.root,self.plan,self.data,'root',['podman'],{'foreign'})
if __name__=='__main__':unittest.main()
