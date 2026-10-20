#!/usr/bin/env python3
"""Adversarial source-only fixture for the same-host selector preflight."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('venue', Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/verify-existing-host-venue.py')
venue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(venue)

class VenueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name + '/new'
        self.ir = {'services': {str(i): {} for i in range(94)}, 'volumes': {f'volume-{i}': {'hostPath':f'{self.base}/data/volume-{i}'} for i in range(55)} | {f'huly_{x}':{} for x in ('cockroach','elastic','minio','redpanda')}}
        names=('platform','apps','homeassistant','finance','ci-runner','workloads','test-runners')
        self.domains = {'domains':[{'name':name,'user':f'p0test-u{i}','uid':3000+i,'subuidStart':3000000+i*65536,**{k:f'{self.base}/d{i}/{k}' for k in ('stateRoot','graphRoot','volumeRoot')}} for i,name in enumerate(names)]}
        self.selector = {'schemaVersion':1,'rootful':{k:f'{self.base}/root/{k}' for k in ('stateRoot','graphRoot','volumeRoot','runRoot')},
            'domains':{name:{'user':f'p0test-u{i}','uid':3000+i,'subuidStart':3000000+i*65536,**{k:f'{self.base}/d{i}/{k}' for k in ('stateRoot','graphRoot','volumeRoot')}} for i,name in enumerate(names)},
            'volumes':{n:(f'{self.base}/d1/graphRoot/volumes/{n}/_data' if n.startswith('huly_') else f'{self.base}/data/{n}') for n in self.ir['volumes']},
            'unitPrefix':'p0test-r1','socketRoot':f'{self.base}/run',
            'storageRoots':{k:f'{self.base}/{k}' for k in ('pgSsdRoot','vectorDbsRoot','logRoot')},
            'ports':{str(p):p+10000 for p in list(range(25001,25010))+[9100]}}
        self.protected = ['/mnt/stack/volumes',self.tmp.name+'/production']
        self.domains['venue']={'schemaVersion':1,'unitPrefix':self.selector['unitPrefix'],
                               'rootfulStateRoot':self.selector['rootful']['stateRoot'],
                               'rootfulRuntimeRoot':'/run/'+self.selector['unitPrefix'],
                               'rootfulGraphRoot':self.selector['rootful']['graphRoot'],
                               'rootfulRunRoot':self.selector['rootful']['runRoot'],
                               'rootfulVolumeRoot':self.selector['rootful']['volumeRoot'],
                               'pgSsdRoot':self.selector['storageRoots']['pgSsdRoot'],
                               'vectorDbsRoot':self.selector['storageRoots']['vectorDbsRoot'],
                               'controlSocketRoot':self.selector['socketRoot'],
                               'logRoot':self.selector['storageRoots']['logRoot'],
                               'portMap':copy.deepcopy(self.selector['ports'])}
    def valid(self, selector=None, exists=lambda _: False):
        return venue.check(selector or self.selector,self.ir,self.domains,self.protected,exists=exists)
    def test_complete_preflight_is_not_activation_permission(self):
        self.assertEqual(self.valid()['checkedVolumes'],59)
        self.assertFalse(self.valid()['activationAuthorized'])
    def test_legacy_native_installer_refuses_venue_before_host_mutation(self):
        source=(Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-podman-bundle.sh').read_text()
        guard='if [ "$ACTIVATE" = true ] && jq -e \'has("venue")\' "$DOMAINS_FILE" >/dev/null; then'
        self.assertIn(guard,source)
        self.assertLess(source.index(guard),source.index('journal preparing'))
        self.assertLess(source.index(guard),source.index('"$BUNDLE/scripts/deploy/render-runtime.sh"'))
        self.assertLess(source.index(guard),source.index('ensure_rootless_domain "$i"'))
    def test_missing_or_mixed_generator_venue_binding_refused(self):
        missing=copy.deepcopy(self.domains);missing.pop('venue')
        with self.assertRaises(venue.Refusal):venue.check(self.selector,self.ir,missing,self.protected,exists=lambda _:False)
        for key,value in (('unitPrefix','webservices'),('rootfulStateRoot','/var/lib/webservices'),
                          ('rootfulRuntimeRoot','/run/webservices'),
                          ('rootfulGraphRoot','/var/lib/containers/storage'),
                          ('rootfulRunRoot','/run/containers/storage'),
                          ('portMap',{'80':8080}),('rootfulVolumeRoot','/mnt/stack/volumes'),
                          ('controlSocketRoot','/run/p0-control'),('logRoot','/var/log/webservices')):
            changed=copy.deepcopy(self.domains);changed['venue'][key]=value
            with self.subTest(key=key),self.assertRaises(venue.Refusal):
                venue.check(self.selector,self.ir,changed,self.protected,exists=lambda _:False)
    def test_generated_guest_gateway_ports_and_control_pin_are_indivisible(self):
        from pathlib import Path
        import json
        root=Path(self.tmp.name)/'guest-bundle'
        site=root/'site';site.mkdir(parents=True)
        net={'address':'192.168.140.115/24','gateway':'192.168.140.1','nameservers':['192.168.140.1']}
        guest={'name':'p0-venue-r1-agents','network':'p0-venue-r1','networkConfig':net,
               'servicePorts':{'https':56042,'imap':56047,'smtp':56044},
               'diskRoot':'/mnt/lab_debian/agent_vm/p0-venue-r1-agents','controlCommit':'a'*40}
        (site/'agent-vm.json').write_text(json.dumps({**guest,'runtime':{'controlCommit':'a'*40}}))
        x=copy.deepcopy(self.selector)
        x['ports'].update({'443':56042,'993':56047,'587':56044})
        x['guest']=guest
        self.assertEqual(venue.screen_guest_binding(root,x)['gateway'],'192.168.140.1')
        for change in ('guest_missing','port','control','gateway','network','disk_root'):
            y=copy.deepcopy(x)
            if change=='guest_missing':y.pop('guest')
            elif change=='port':y['ports']['993']+=1
            elif change=='control':y['guest']['controlCommit']='b'*40
            elif change=='gateway':y['guest']['networkConfig']['gateway']='192.168.122.1'
            elif change=='disk_root':y['guest']['diskRoot']='/mnt/lab_debian/agent_vm/clean-role'
            else:y['guest']['network']='default'
            with self.subTest(change=change),self.assertRaises(venue.Refusal):
                venue.screen_guest_binding(root,y)

    def test_selector_must_match_generated_authority(self):
        x=copy.deepcopy(self.selector);x['volumes']['volume-0']=f'{self.base}/data/alternate'
        with self.assertRaises(venue.Refusal):self.valid(x)
        domains=copy.deepcopy(self.domains);domains['domains'][0]['user']='prod0'
        with self.assertRaises(venue.Refusal):venue.check(self.selector,self.ir,domains,self.protected,exists=lambda _:False)
        x=copy.deepcopy(self.selector);x['domains']['apps']['subuidStart']+=65536
        with self.assertRaises(venue.Refusal):self.valid(x)
    def test_exclusive_parent_volume_root_allows_only_proved_new_children(self):
        x=copy.deepcopy(self.selector)
        x['rootful']['volumeRoot']=f'{self.base}/data'
        domains=copy.deepcopy(self.domains);domains['venue']['rootfulVolumeRoot']=x['rootful']['volumeRoot']
        self.assertTrue(venue.check(x,self.ir,domains,self.protected,exists=lambda _:False)['pathPreflightPassed'])
        x['rootful']['volumeRoot']='/mnt/stack/volumes'
        domains['venue']['rootfulVolumeRoot']='/mnt/stack/volumes'
        with self.assertRaises(venue.Refusal):venue.check(x,self.ir,domains,self.protected,exists=lambda _:False)
    def test_implicit_volumes_must_match_exclusive_graph(self):
        x=copy.deepcopy(self.selector);x['volumes']['huly_elastic']=f'{self.base}/data/huly_elastic'
        with self.assertRaises(venue.Refusal):self.valid(x)
        x=copy.deepcopy(self.selector);x['volumes']['huly_elastic']=x['domains']['platform']['graphRoot']+'/volumes/huly_elastic/_data'
        with self.assertRaises(venue.Refusal):self.valid(x)
    def test_all_missing_implicit_volumes_refused(self):
        for n in ('huly_cockroach','huly_elastic','huly_minio','huly_redpanda'):
            x=copy.deepcopy(self.selector); del x['volumes'][n]
            with self.subTest(n=n),self.assertRaises(venue.Refusal):self.valid(x)
    def test_hostile_paths(self):
        for value in ('/mnt/stack/volumes/old','/mnt/stack/volumes','/tmp/../tmp/escape','relative','/',self.base+'/root/stateRoot'):
            x=copy.deepcopy(self.selector); x['volumes']['volume-0']=value
            with self.subTest(value=value),self.assertRaises(venue.Refusal):self.valid(x)
    def test_existing_even_empty_refused(self):
        with self.assertRaises(venue.Refusal):self.valid(exists=lambda p:p.endswith('/volume-0'))
    def test_symlinked_ancestor_refused(self):
        Path(self.tmp.name,'link').symlink_to('/mnt/stack/volumes')
        x=copy.deepcopy(self.selector);x['volumes']['volume-0']=self.tmp.name+'/link/new'
        with self.assertRaises(venue.Refusal):self.valid(x)
    def test_readonly_host_root_reader_not_writable_authority(self):
        rows=[{'mounts':[]} for _ in range(75)] + [{'mounts':[{'Type':'bind','Source':'/','RW':False},{'Type':'bind','Source':'/mnt/stack/volumes','RW':True}]}]
        self.assertEqual(venue.protected_sources(rows),{'/mnt/stack/volumes'})
        rows[-1]['mounts'][0]['RW']=True
        with self.assertRaises(venue.Refusal):venue.protected_sources(rows)
    def test_published_ports_require_all_selected_declarations(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootful'
        root.mkdir(parents=True)
        q=root/'webservices-source.container'
        q.write_text(''.join(f'PublishPort=127.0.0.1:{18000+i}:80\n' for i in range(47)))
        required=venue.published_host_ports(root.parents[1])
        self.assertEqual(len(required),50)
        x=copy.deepcopy(self.selector)
        x['ports']={k:40000+i for i,k in enumerate(sorted(required))}
        changed=copy.deepcopy(self.domains);changed['venue']['portMap']=copy.deepcopy(x['ports'])
        self.assertTrue(venue.check(x,self.ir,changed,self.protected,exists=lambda _:False,required_ports=required)['pathPreflightPassed'])
        with self.assertRaises(venue.Refusal):venue.check(x,self.ir,self.domains,self.protected,exists=lambda _:False,required_ports=required|{'465'})
        q.write_text('PublishPort=not-a-port\n')
        with self.assertRaises(venue.Refusal):venue.published_host_ports(root.parents[1])
    def test_venue_volume_init_requires_installer_marker_not_broad_script(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootful';root.mkdir(parents=True)
        state=self.selector['rootful']['stateRoot'];prefix=self.selector['unitPrefix']
        path=root/(prefix+'-volume-init.container')
        safe=('[Unit]\nAssertPathIsRegular='+state+'/volume-ready-r1.txt\n'
              '[Container]\nVolume='+state+'/volume-ready-r1.txt:/run/p0-venue-volume-ready.txt:ro\n'
              'Entrypoint=/bin/sh\nExec="-ec" "grep -qx \'p0test-r1-volume-ready-v1\' /run/p0-venue-volume-ready.txt"\n')
        path.write_text(safe)
        self.assertTrue(venue.screen_venue_volume_init(root.parents[1],self.selector))
        path.write_text(safe.replace('grep -qx ', 'chmod 755 /mnt/stack; grep -qx '))
        with self.assertRaises(venue.Refusal):venue.screen_venue_volume_init(root.parents[1],self.selector)
        path.write_text(safe+'Volume=/mnt/stack/shared:/data\n')
        with self.assertRaises(venue.Refusal):venue.screen_venue_volume_init(root.parents[1],self.selector)

    def test_rootful_store_binding_is_on_every_container_build_and_network(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootful'
        root.mkdir(parents=True)
        expected='Environment=CONTAINERS_STORAGE_CONF='+self.selector['rootful']['stateRoot']+'/containers-storage.conf'
        network='Environment=CONTAINERS_CONF='+self.selector['rootful']['stateRoot']+'/containers.conf'
        for ext in ('container','build','network'):
            (root/('p0test-r1-unit.'+ext)).write_text('[Service]\n'+expected+'\n'+network+'\n')
        self.assertEqual(venue.screen_rootful_store_quadlets(root.parents[1],self.selector),3)
        for ext in ('container','build','network'):
            p=root/('p0test-r1-unit.'+ext)
            p.write_text('[Service]\nEnvironment=CONTAINERS_STORAGE_CONF=/etc/containers/storage.conf\n')
            with self.subTest(ext=ext),self.assertRaises(venue.Refusal):
                venue.screen_rootful_store_quadlets(root.parents[1],self.selector)
            p.write_text('[Service]\n'+expected+'\n'+network+'\n')
            p.write_text('[Service]\n'+expected+'\n')
            with self.assertRaises(venue.Refusal):venue.screen_rootful_store_quadlets(root.parents[1],self.selector)
            p.write_text('[Service]\n'+expected+'\n'+network+'\n')

    def test_generated_port_provenance_requires_all_original_identities(self):
        bundle=Path(self.tmp.name)/'bundle';root=bundle/'quadlet/rootful';root.mkdir(parents=True)
        original=['80','443','9100']+[str(i) for i in range(18001,18045)]+['7880','7881','7882']
        mapping={key:56000+i for i,key in enumerate(original)}
        (bundle/'podman-domains.json').write_text(json.dumps({'venue':{'portMap':mapping}}))
        q=root/'p0test-r1-ports.container'
        q.write_text(''.join('PublishPort=127.0.0.1:'+str(mapping[str(i)])+':80\n' for i in range(18001,18045)))
        rtc=root/'p0test-r1-livekit.container'
        rtc.write_text(f'PublishPort=127.0.0.1:{mapping["7880"]}:7880\n'
                       f'PublishPort=192.168.140.1:{mapping["7881"]}:{mapping["7881"]}/tcp\n'
                       f'PublishPort=192.168.140.1:{mapping["7882"]}:{mapping["7882"]}/udp\n')
        self.assertEqual(venue.published_host_ports(bundle),set(original))
        protected=q.read_text()
        q.write_text(protected.replace('PublishPort=127.0.0.1:', 'PublishPort=', 1))
        with self.assertRaisesRegex(venue.Refusal,'escapes host loopback'):
            venue.published_host_ports(bundle)
        q.write_text(protected)
        selector=copy.deepcopy(self.selector);selector['ports']=mapping
        self.assertEqual(venue.screen_rendered_ports(bundle,selector),47)
        del mapping['18044']
        (bundle/'podman-domains.json').write_text(json.dumps({'venue':{'portMap':mapping}}))
        with self.assertRaises(venue.Refusal):venue.published_host_ports(bundle)

    def test_rendered_ports_are_45_private_and_two_guest_rtc_listeners(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootful'
        root.mkdir(parents=True)
        q=root/'p0test-r1-ports.container'
        selector=copy.deepcopy(self.selector)
        selector['ports']={str(port):40000+i for i,port in enumerate([80,443,9100]+list(range(18001,18045))+[7880,7881,7882])}
        declarations=[f'PublishPort=127.0.0.1:{selector["ports"][str(port)]}:80' for port in range(18001,18045)]
        q.write_text('[Container]\n'+'\n'.join(declarations)+'\n')
        rtc=root/'p0test-r1-livekit.container'
        mapped=selector['ports']
        rtc.write_text(f'PublishPort=127.0.0.1:{mapped["7880"]}:7880\n'
                       f'PublishPort=192.168.140.1:{mapped["7881"]}:{mapped["7881"]}/tcp\n'
                       f'PublishPort=192.168.140.1:{mapped["7882"]}:{mapped["7882"]}/udp\n')
        self.assertEqual(venue.screen_rendered_ports(root.parents[1],selector),47)
        for wrong in ('PublishPort=127.0.0.1:18001:80', 'PublishPort=127.0.0.1:80:80',
                      'PublishPort=40001:80', 'PublishPort=garbage'):
            q.write_text('[Container]\n'+'\n'.join(declarations[:-1]+[wrong])+'\n')
            with self.subTest(wrong=wrong),self.assertRaises(venue.Refusal):
                venue.screen_rendered_ports(root.parents[1],selector)
        q.write_text('[Container]\n'+'\n'.join(declarations[:-1])+'\n')
        with self.assertRaises(venue.Refusal):venue.screen_rendered_ports(root.parents[1],selector)

    def test_unit_and_container_names_must_be_isolated_in_rendered_quadlets(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootful'
        root.mkdir(parents=True)
        q=root/'p0test-r1-caddy.container'
        q.write_text('[Unit]\nPartOf=p0test-r1-core.target\n[Container]\n'
                     'ContainerName=p0test-r1-caddy\nNetwork=p0test-r1-caddy.network\n')
        self.assertEqual(venue.screen_quadlet_names(root.parents[1],self.selector),1)
        for hostile in ('ContainerName=caddy', 'NetworkName=webservices_caddy',
                        'Network=webservices-caddy.network',
                        'PartOf=webservices-core.target',
                        'Requires=webservices-runtime-env.service'):
            q.write_text('[Container]\n'+hostile+'\n')
            with self.subTest(hostile=hostile),self.assertRaises(venue.Refusal):
                venue.screen_quadlet_names(root.parents[1],self.selector)
        q.write_text('[Container]\nContainerName=p0test-r1-caddy\n')
        other=root/'webservices-caddy.container'
        other.write_text(q.read_text())
        with self.assertRaises(venue.Refusal):venue.screen_quadlet_names(root.parents[1],self.selector)

    def test_rendered_quadlet_mounts_must_use_venue_not_just_ir(self):
        root=Path(self.tmp.name)/'bundle/quadlet/rootless-apps'
        root.mkdir(parents=True)
        q=root/'p0test-r1-example.container'
        private=self.selector['domains']['apps']['stateRoot']
        q.write_text(f'[Container]\nVolume={private}/current/runtime/configs/app:/app:ro\n'
                     'Volume=huly_cockroach:/data\nVolume=/etc/localtime:/etc/localtime:ro\n'
                     'Volume=%t/podman/podman.sock:/run/podman/podman.sock\n')
        self.assertEqual(venue.screen_quadlet_mounts(root.parents[1],self.selector),4)
        for hostile in ('Volume=/var/lib/webservices/current/runtime/configs/app:/app:ro',
                        'Volume=/mnt/stack/forgejo-runner-ssh:/root/.ssh:ro',
                        'Volume=/mnt/stack/podman/test-runners/state/test-runner/results:/artifacts',
                        'Volume=/etc/localtime:/etc/localtime',
                        'Volume=/run/p0-control:/run/p0-control:ro',
                        'Volume=huly_unknown:/data',
                        'Network=host'):
            q.write_text('[Container]\n'+hostile+'\n')
            with self.subTest(hostile=hostile),self.assertRaises(venue.Refusal):
                venue.screen_quadlet_mounts(root.parents[1],self.selector)
        q.write_text('[Container]\nVolume=huly_cockroach:/data\n')
        other=root.parents[0]/'rootful/p0test-r1-example.container'
        other.parent.mkdir()
        other.write_text(q.read_text())
        with self.assertRaises(venue.Refusal):venue.screen_quadlet_mounts(root.parents[1],self.selector)
    def test_static_host_network_diagnostic_never_changes_activation_guard(self):
        bundle=Path(self.tmp.name)/'diagnostic';root=bundle/'quadlet/rootful';root.mkdir(parents=True)
        for name in ('alloy','caddy','node-exporter','ntfy-native-auth'):
            (root/f'p0test-r1-{name}.container').write_text('[Container]\nNetwork=host\n')
        with self.assertRaisesRegex(venue.Refusal,'lacks isolated listener proof'):
            venue.screen_quadlet_mounts(bundle,self.selector)
        self.assertEqual(venue.screen_quadlet_mounts(bundle,self.selector,diagnostic_host_network=True),0)
        extra=root/'p0test-r1-extra.container';extra.write_text('[Container]\nNetwork=host\n')
        with self.assertRaisesRegex(venue.Refusal,'unreviewed diagnostic'):
            venue.screen_quadlet_mounts(bundle,self.selector,diagnostic_host_network=True)
        extra.unlink()
        apps=bundle/'quadlet/rootless-apps';apps.mkdir()
        (apps/'p0test-r1-livekit.container').write_text('[Container]\nNetwork=host\n')
        with self.assertRaises(venue.Refusal):
            venue.screen_quadlet_mounts(bundle,self.selector,diagnostic_host_network=True)
    def test_identity_unit_port_and_schema_collision(self):
        variants=[]
        x=copy.deepcopy(self.selector);x['domains']['platform']['user']='prod0';variants.append(x)
        x=copy.deepcopy(self.selector);x['domains']['apps']['uid']=3000;variants.append(x)
        x=copy.deepcopy(self.selector);x['domains']['apps']['subuidStart']=3000001;variants.append(x)
        x=copy.deepcopy(self.selector);x['unitPrefix']='webservices';variants.append(x)
        x=copy.deepcopy(self.selector);x['ports']['25001']=25001;variants.append(x)
        x=copy.deepcopy(self.selector);x['ports'].pop('9100');variants.append(x)
        x=copy.deepcopy(self.selector);x['extraAuthority']=True;variants.append(x)
        x=copy.deepcopy(self.selector);x['schemaVersion']=True;variants.append(x)
        for i,x in enumerate(variants):
            with self.subTest(i=i),self.assertRaises(venue.Refusal):self.valid(x)

if __name__ == '__main__':unittest.main()
