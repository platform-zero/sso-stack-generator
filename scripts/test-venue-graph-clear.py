#!/usr/bin/env python3
"""Eight-store exact-image graph-reset fixtures; no real Podman touched."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-graph-clear.py'
spec=importlib.util.spec_from_file_location('graph_clear',src)
clear=importlib.util.module_from_spec(spec);spec.loader.exec_module(clear)

@unittest.skipUnless(os.geteuid()==0,'protected ledger fixture requires root')
class GraphClearFixtures(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.bundle=self.root/'bundle'
        (self.bundle/'site/global.settings').mkdir(parents=True)
        (self.bundle/'stack.ir.json').write_text('{"services":{}}')
        self.allowed='sha256:'+'a'*64
        (self.bundle/'site/global.settings/registry-image-ids.json').write_text(json.dumps({'root|pinned':self.allowed}))
        accounts=[];roots={'rootful-graph':str(self.root/'graph-root'),'rootful-run':str(self.root/'run-root'),
                           'rootful-state':str(self.root/'state-root')}
        for i,name in enumerate(('platform','apps','homeassistant','vaultwarden','ci-runner','workloads','test-runners')):
            accounts.append({'name':'p0test-r1-'+name,'uid':3200+i,'home':'/home/p0test-r1-'+name,
                             'graph':str(self.root/('graph-'+name))})
        self.plan={'accounts':accounts,'roots':roots}
        self.identities={}
        for path in [roots['rootful-state'],roots['rootful-graph'],*(a['graph'] for a in accounts)]:
            p=Path(path);p.mkdir()
            info=p.lstat();self.identities[path]={'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,
                                                    'mode':stat.S_IMODE(info.st_mode)}
        self.ledger=self.root/'ledger.json'
        self.data={'plan':self.plan,'status':'managers-ready','managerStarted':[a['name'] for a in accounts],
                   'managerStopped':[],'pathIdentities':self.identities}
        self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
    def runner(self,command,**kwargs):
        if command[-2:]==['ps','-aq'] or command[-3:]==['pod','ps','--quiet'] or command[-3:]==['volume','ls','-q']:
            return SimpleNamespace(returncode=0,stdout='')
        if 'image' in command and 'inspect' in command and '{{.Parent}}' in command:
            return SimpleNamespace(returncode=0,stdout='')
        if command[-4:]==['image','ls','--no-trunc','--format'] or 'image' in command and 'ls' in command:
            return SimpleNamespace(returncode=0,stdout='')
        if command[-3:]==['network','ls','--format'] or 'network' in command and 'ls' in command:
            return SimpleNamespace(returncode=0,stdout='podman\n')
        raise AssertionError('unexpected selected Podman call '+str(command))
    def test_only_exact_dual_output_alias_can_be_untagged_without_force(self):
        image='sha256:'+'d'*64
        first='localhost/webservices/workload-spawner-api:bundle'
        second='localhost/webservices/workload-spawner-router:bundle'
        self.data['venueLocalBuildOutputs']={'p0test-r1-workloads|'+first:image,
                                              'p0test-r1-workloads|'+second:image}
        digest='sha256:'+'f'*64
        details=json.dumps([first,second])+'|'+json.dumps([first.partition(':bundle')[0]+'@'+digest,
                                                            second.partition(':bundle')[0]+'@'+digest])
        calls=[]
        def selected(command,**kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0,stdout=details if 'inspect' in command else '')
        with patch.object(clear,'run',side_effect=selected),patch.object(clear.stage,'write_ledger'):
            clear.remove_exact_dual_named_output(self.data,self.ledger,'p0test-r1-workloads',image,['selected'])
        self.assertEqual(calls[1][-4:],['image','untag',image,first])
        self.assertEqual(calls[2][-3:],['image','rm',image])
        self.assertFalse(any('--force' in call for command in calls for call in command))
        self.data['venueLocalBuildOutputs']['p0test-r1-workloads|localhost/webservices/foreign:bundle']=image
        with patch.object(clear,'run') as runner:
            with self.assertRaisesRegex(clear.Refusal,'exact two-tag'):
                clear.remove_exact_dual_named_output(self.data,self.ledger,'p0test-r1-workloads',image,['selected'])
            runner.assert_not_called()
    def test_existing_live_mount_refuses_before_any_podman_identity_inspection(self):
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear,'graph_has_live_mount',return_value=True),
              patch.object(clear,'journaled_build_base_ids') as image_inspect,
              patch.object(clear,'run') as podman,
              patch.object(clear.os,'geteuid',return_value=0)):
            with self.assertRaisesRegex(clear.Refusal,'live mount'):
                clear.clear(self.bundle,self.root/'unused',self.ledger)
            image_inspect.assert_not_called();podman.assert_not_called()
    def test_build_parent_image_retirement_is_child_first(self):
        base='sha256:'+'a'*64;parent='sha256:'+'b'*64;output='sha256:'+'c'*64
        def hierarchy(command,**kwargs):
            if command[-1]==output:return SimpleNamespace(returncode=0,stdout=parent+'\n')
            if command[-1]==parent:return SimpleNamespace(returncode=0,stdout=base+'\n')
            return SimpleNamespace(returncode=0,stdout='')
        with patch.object(clear,'run',side_effect=hierarchy):
            self.assertEqual(clear.removal_order(['selected'],{base,parent,output}),[output,parent,base])
    def test_empty_test_only_metadata_is_removed_without_deleting_graph_root(self):
        child=Path(self.plan['roots']['rootful-graph'])/'metadata';child.mkdir();(child/'runtime.json').write_text('{}')
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'run',side_effect=self.runner),
              patch.object(clear.os,'geteuid',return_value=0)):
            result=clear.clear(self.bundle,self.root/'unused',self.ledger)
        self.assertEqual(result['graphRootsCleared'],8)
        self.assertTrue(Path(self.plan['roots']['rootful-graph']).is_dir())
        self.assertFalse(any(Path(self.plan['roots']['rootful-graph']).iterdir()))
        self.assertEqual(self.data['status'],'managers-ready')
        self.assertTrue(self.data['graphNetworkDirRetired'])
        self.assertFalse((Path(self.plan['roots']['rootful-state'])/'networks').exists())
    def test_only_exact_pinned_image_id_removed_from_exclusive_root_graph(self):
        commands=[];removed=False
        def selected(command,**kwargs):
            nonlocal removed
            commands.append(command)
            if command[-2:]==['image','rm'] or 'image' in command and 'rm' in command:
                self.assertEqual(command[-1],self.allowed)
                removed=True
                return SimpleNamespace(returncode=0,stdout='')
            if 'image' in command and 'ls' in command:
                return SimpleNamespace(returncode=0,stdout='' if removed or 'runuser' in command else self.allowed+'\n')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'run',side_effect=selected),
              patch.object(clear.os,'geteuid',return_value=0)):
            self.assertEqual(clear.clear(self.bundle,self.root/'unused',self.ledger)['graphRootsCleared'],8)
        self.assertTrue(removed)
        self.assertEqual(len([c for c in commands if 'rm' in c]),1)
    def test_exact_owned_blob_cache_retired_and_hostile_extra_refused(self):
        for entry in self.plan['accounts']:
            created=self.root/('fresh-home-'+entry['name']);created.mkdir();os.chown(created,entry['uid'],entry['uid'])
            entry['home']=str(created);info=created.lstat()
            self.identities[str(created)]={'dev':info.st_dev,'ino':info.st_ino,'uid':entry['uid'],'mode':stat.S_IMODE(info.st_mode)}
        account=self.plan['accounts'][1];home=Path(account['home'])
        cache=home/'.local/share/containers/cache';cache.mkdir(parents=True)
        for d in (home/'.local',home/'.local/share',home/'.local/share/containers',cache):
            d.chmod(0o700);os.chown(d,account['uid'],account['uid'])
        file=cache/'blob-info-cache-v1.sqlite';file.write_bytes(b'test-only blob cache');file.chmod(0o644);os.chown(file,account['uid'],account['uid'])
        self.data['graphCleared']=['root',*(a['name'] for a in self.plan['accounts'])]
        self.data['graphNetworkDirRetired']=True
        self.ledger.write_text(json.dumps(self.data))
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear.os,'geteuid',return_value=0)):
            extra=cache/'foreign';extra.write_text('preserve')
            with self.assertRaises(clear.Refusal):clear.retire_image_cache(self.bundle,self.root/'unused',self.ledger)
            self.assertTrue(file.exists());self.assertEqual(extra.read_text(),'preserve')
            extra.unlink()
            self.assertEqual(clear.retire_image_cache(self.bundle,self.root/'unused',self.ledger)['retiredExactImageCaches'],1)
        self.assertFalse((home/'.local').exists())
        self.assertTrue(home.is_dir())
    def test_runroot_exact_metadata_removed_only_after_stopped_graph_proof(self):
        root=Path(self.plan['roots']['rootful-run']);root.mkdir(mode=0o700);root.chmod(0o700)
        info=root.lstat();self.identities[str(root)]={'dev':info.st_dev,'ino':info.st_ino,'uid':0,'mode':0o700}
        layout={'overlay-layers':{'mountpoints.lock'},'overlay-locks':set(),
                'overlay-containers':set(),'overlay':{'native-diff()-true','metacopy()-false','overlay-true'}}
        for name,files in layout.items():
            d=root/name;d.mkdir(mode=0o700)
            for filename in files:
                (d/filename).touch(mode=0o644);(d/filename).chmod(0o644)
        self.data.update({'status':'staged-empty',
                          'managerStopped':[a['name'] for a in reversed(self.plan['accounts'])],
                          'graphCleared':['root',*(a['name'] for a in self.plan['accounts'])],
                          'graphNetworkDirRetired':True,'podmanImageCacheRetired':True})
        self.ledger.write_text(json.dumps(self.data))
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear.os,'geteuid',return_value=0)):
            extra=root/'unreviewed';extra.write_text('preserve')
            with self.assertRaises(clear.Refusal):clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)
            self.assertEqual(extra.read_text(),'preserve');extra.unlink()
            self.assertEqual(clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)['retiredRunrootFiles'],4)
        self.assertFalse(any(root.iterdir()))
        self.assertTrue(root.exists())
    def test_populated_image_runroot_accepts_only_empty_mountpoints_and_exact_lock(self):
        root=Path(self.plan['roots']['rootful-run']);root.mkdir(mode=0o700);root.chmod(0o700)
        info=root.lstat();self.identities[str(root)]={'dev':info.st_dev,'ino':info.st_ino,'uid':0,'mode':0o700}
        layout={'overlay-layers':{'mountpoints.lock','mountpoints.json'},'overlay-locks':set(),
                'overlay-containers':set(),
                'overlay':{'native-diff()-true','metacopy()-false','overlay-true','idmapped-lower-dir-true'}}
        for name,files in layout.items():
            d=root/name;d.mkdir(mode=0o700)
            for filename in files:
                (d/filename).touch(mode=0o644);(d/filename).chmod(0o644)
        lock=root/'overlay-layers/mountpoints.lock';lock.write_bytes(b'x'*64)
        points=root/'overlay-layers/mountpoints.json';points.write_bytes(b'["foreign"]');points.chmod(0o600)
        self.data.update({'status':'staged-empty',
                          'managerStopped':[a['name'] for a in reversed(self.plan['accounts'])],
                          'graphCleared':['root',*(a['name'] for a in self.plan['accounts'])],
                          'graphNetworkDirRetired':True,'podmanImageCacheRetired':True})
        self.ledger.write_text(json.dumps(self.data))
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear.os,'geteuid',return_value=0)):
            with self.assertRaisesRegex(clear.Refusal,'metadata file'):
                clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)
            self.assertTrue(points.exists())
            points.write_bytes(b'[]');lock.write_bytes(b'x'*65)
            with self.assertRaisesRegex(clear.Refusal,'metadata file'):
                clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)
            lock.write_bytes(b'x'*64)
            volatile=root/'overlay/volatile-true';volatile.write_bytes(b'x');volatile.chmod(0o644)
            with self.assertRaisesRegex(clear.Refusal,'metadata file'):
                clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)
            self.assertEqual(volatile.read_bytes(),b'x');volatile.write_bytes(b'')
            self.assertEqual(clear.retire_empty_runroot(self.bundle,self.root/'unused',self.ledger)['retiredRunrootFiles'],7)
        self.assertFalse(any(root.iterdir()))
    def test_build_only_store_image_may_be_exactly_retired_without_direct_image_authority(self):
        apps='p0test-r1-apps';image='sha256:'+'c'*64
        self.data['venueCompositeVersion']=2;self.data['venueCompositeOfflineImages']=[]
        self.ledger.write_text(json.dumps(self.data));removed=False
        def selected(command,**kwargs):
            nonlocal removed
            if 'image' in command and 'rm' in command:
                self.assertEqual(command[-1],image);self.assertIn(apps,command);removed=True
                return SimpleNamespace(returncode=0,stdout='')
            if 'image' in command and 'ls' in command:
                return SimpleNamespace(returncode=0,stdout=image+'\n' if apps in command and not removed else '')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'journaled_build_base_ids',return_value={apps:{image}}),
              patch.object(clear,'run',side_effect=selected),
              patch.object(clear.os,'geteuid',return_value=0)):
            self.assertEqual(clear.clear(self.bundle,self.root/'unused',self.ledger)['graphRootsCleared'],8)
        self.assertTrue(removed)
    def offline_state(self):
        return {'venueInstallerVersion':1,'venueInstallerPhase':'retiring','venueCompositeVersion':2,
                'venueCompositeMode':'retiring','status':'graphs-clearing','activationAuthorized':False,
                'venueCompositeImageInputSha256':'c'*64,'retiredUnits':[{}]*194}
    def frozen_import_aliases(self,*,shared=False,foreign=False,offline=False):
        image='sha256:'+'b'*64;user='p0test-r1-platform';aliases={'localhost/webservices/selected:bundle'}
        if shared:aliases.add('localhost/webservices/selected-twin:bundle')
        tags=aliases|{'localhost/sha256:'+image.removeprefix('sha256:')}
        if foreign:tags.add('localhost/unowned:latest')
        digest='sha256:'+'f'*64;details=json.dumps(sorted(tags))+'|'+json.dumps(sorted(tag.rsplit(':',1)[0]+'@'+digest for tag in tags))
        self.data.update(venueRegistryPhase='inert-ready',venueRegistryVerified={user+'|'+image:image},venueCompositeOfflineImages=[{'image':image,'authorities':[user]}])
        if offline:
            self.data.pop('venueRegistryPhase');self.data.pop('venueRegistryVerified');self.data.update(self.offline_state())
        commands=[]
        def selected(command,**kwargs):
            commands.append(command);self.assertNotIn('--force',command)
            return SimpleNamespace(returncode=0,stdout=details if 'inspect' in command else '')
        with patch.object(clear,'run',side_effect=selected),patch.object(clear.stage,'write_ledger'):
            if foreign:
                with self.assertRaisesRegex(clear.Refusal,'foreign alias/digest'):
                    clear.remove_exact_frozen_import(self.bundle,self.data,self.ledger,user,image,['selected'],aliases=aliases)
                self.assertEqual(len(commands),1)
            else:
                clear.remove_exact_frozen_import(self.bundle,self.data,self.ledger,user,image,['selected'],aliases=aliases)
                self.assertEqual(len(self.data['graphUntaggedFrozenImports']),1)
                self.assertEqual(set(commands[1][4:]),set(sorted(tags)[1:]));self.assertEqual(commands[-1],['selected','image','rm',image])
    def test_frozen_archive_tag_and_seeded_identity_alias_exactly_retire(self):self.frozen_import_aliases()
    def test_frozen_shared_producer_aliases_retire_without_force(self):self.frozen_import_aliases(shared=True)
    def test_frozen_foreign_alias_is_never_untagged(self):self.frozen_import_aliases(foreign=True)
    def test_offline_only_frozen_aliases_retire_without_registry_claim(self):self.frozen_import_aliases(offline=True)
    def test_offline_only_foreign_alias_still_refuses_before_untag(self):self.frozen_import_aliases(offline=True,foreign=True)
    def test_offline_retirement_scope_rejects_partial_active_or_registry_state(self):
        state=self.offline_state();self.assertTrue(clear.offline_frozen_retirement(state))
        for key,value in [('venueInstallerVersion',2),('venueInstallerPhase','preparing'),
                ('venueCompositeVersion',1),('venueCompositeMode','images-importing'),('status','units-staged'),
                ('activationAuthorized',True),('venueStartPhase','starting'),('venueStartIntent','partial'),
                ('venueRegistryPhase','preparing'),('venueRegistryPending','partial'),('venueRegistryVerified',{}),
                ('retiredUnits',[{}]*193),('venueCompositeImageInputSha256','invalid'),('venueInstallerVersion',True)]:
            with self.subTest(key=key):self.assertFalse(clear.offline_frozen_retirement({**state,key:value}))
    def test_verified_frozen_identity_dispatches_exact_alias_cleanup(self):self.frozen_identity_dispatch()
    def test_offline_only_frozen_identity_dispatches_exact_alias_cleanup(self):self.frozen_identity_dispatch(offline=True)
    def frozen_identity_dispatch(self,offline=False):
        approved={'root|'+self.allowed:self.allowed};remaining=True
        self.data.update(venueCompositeVersion=2,venueCompositeOfflineImages=[{'authorities':['root'],'image':self.allowed}],
                         venueRegistryPhase='inert-ready',venueRegistryVerified=approved,venueRegistryPlan=approved)
        if offline:
            self.data.pop('venueRegistryPhase');self.data.pop('venueRegistryVerified');self.data.pop('venueRegistryPlan')
            self.data.update(self.offline_state());self.data['status']='managers-ready'
            (self.bundle/'stack.ir.json').write_text('{"quadletBuildImagesFrozen":true}')
        self.ledger.write_text(json.dumps(self.data))
        def selected(command,**kwargs):
            if 'image' in command and 'rm' in command:return SimpleNamespace(returncode=125,stdout='',stderr='cannot remove by digest with more than one tag')
            if 'image' in command and 'ls' in command:return SimpleNamespace(returncode=0,stdout=self.allowed if remaining and '--root' in command else '')
            return self.runner(command,**kwargs)
        def cleanup(*args):
            nonlocal remaining
            self.assertEqual(args[3:5],('root',self.allowed));remaining=False
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),patch.object(clear,'selected_images',return_value={'root':{self.allowed}}),
              patch.object(clear,'selected_pairs',return_value=approved),patch.object(clear,'run',side_effect=selected),
              patch.object(clear,'remove_exact_frozen_import',side_effect=cleanup) as invoked):
            self.assertEqual(clear.clear(self.bundle,self.root/'unused',self.ledger)['graphRootsCleared'],8)
            invoked.assert_called_once()
    def test_complete_selected_frozen_catalogue_retirement_keeps_legacy_bound(self):
        identities={'sha256:'+format(i,'064x') for i in range(1,14)};remaining=set(identities)
        self.data.update(venueCompositeVersion=2,venueCompositeOfflineImages=[{'authorities':['root'],'image':value} for value in sorted(identities)])
        self.ledger.write_text(json.dumps(self.data))
        def selected(command,**kwargs):
            if 'image' in command and 'rm' in command:
                remaining.remove(command[-1]);return SimpleNamespace(returncode=0,stdout='')
            if 'image' in command and 'ls' in command:
                return SimpleNamespace(returncode=0,stdout='\n'.join(sorted(remaining)) if '--root' in command else '')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),patch.object(clear,'selected_images',return_value={'root':identities}),
              patch.object(clear,'run',side_effect=selected)):
            with self.assertRaisesRegex(clear.Refusal,'frozen/legacy authority'):clear.clear(self.bundle,self.root/'unused',self.ledger)
            self.assertEqual(remaining,identities)
            (self.bundle/'stack.ir.json').write_text('{"quadletBuildImagesFrozen":true}')
            self.assertEqual(clear.clear(self.bundle,self.root/'unused',self.ledger)['graphRootsCleared'],8)
        self.assertFalse(remaining)
    def test_partially_cleared_ledger_never_reopens_cleared_root_and_records_missing_id(self):
        self.data.update({'venueCompositeVersion':2,'venueCompositeOfflineImages':[
            {'authorities':['root'],'image':self.allowed}],
            'status':'graphs-clearing','graphCleared':['root']})
        self.ledger.write_text(json.dumps(self.data))
        def selected(command,**kwargs):
            if 'podman' in command and '--root' in command:
                raise AssertionError('never reopen an already cleared selected root graph')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'run',side_effect=selected),
              patch.object(clear.os,'geteuid',return_value=0)):
            self.assertEqual(clear.clear(self.bundle,self.root/'unused',self.ledger)['graphRootsCleared'],8)
        self.assertEqual(self.data['graphRecoveredMissingSelectedImages']['root'],[self.allowed])
    def test_versioned_graph_refuses_selected_but_not_journaled_image(self):
        marker=Path(self.plan['roots']['rootful-graph'])/'keep';marker.write_text('untouched')
        self.data['venueCompositeVersion']=2;self.data['venueCompositeOfflineImages']=[]
        self.ledger.write_text(json.dumps(self.data))
        def foreign_selected(command,**kwargs):
            if 'image' in command and 'ls' in command:
                return SimpleNamespace(returncode=0,stdout=self.allowed+'\n')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'run',side_effect=foreign_selected),
              patch.object(clear.os,'geteuid',return_value=0)):
            with self.assertRaisesRegex(clear.Refusal,'unjournaled'):
                clear.clear(self.bundle,self.root/'unused',self.ledger)
        self.assertEqual(marker.read_text(),'untouched')
        self.assertEqual(self.data['status'],'managers-ready')
    def test_unselected_image_refuses_before_deletion(self):
        marker=Path(self.plan['roots']['rootful-graph'])/'keep';marker.write_text('untouched')
        def foreign(command,**kwargs):
            if 'image' in command and 'ls' in command:
                return SimpleNamespace(returncode=0,stdout='sha256:'+'b'*64+'\n')
            return self.runner(command,**kwargs)
        with (patch.object(clear.stage,'owned_plan',return_value=self.plan),
              patch.object(clear.stage,'write_ledger',side_effect=lambda path,state:self.data.update(state)),
              patch.object(clear,'run',side_effect=foreign),
              patch.object(clear.os,'geteuid',return_value=0)):
            with self.assertRaises(clear.Refusal):clear.clear(self.bundle,self.root/'unused',self.ledger)
        self.assertEqual(marker.read_text(),'untouched')
        self.assertEqual(self.data['status'],'managers-ready')
        self.assertTrue((Path(self.plan['roots']['rootful-state'])/'networks').is_dir())

if __name__=='__main__':unittest.main()
