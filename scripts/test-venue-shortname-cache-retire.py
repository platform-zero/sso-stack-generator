#!/usr/bin/env python3
"""Hostile exact short-name cache retirement and CAS-interruption fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-shortname-cache-retire.py'
spec=importlib.util.spec_from_file_location('venue_shortname_cache',src)
cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)

@unittest.skipUnless(os.geteuid()==0,'exact selected UID fixture requires root')
class SelectedCache(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.bundle=self.root/'bundle';pins=self.bundle/'site/global.settings/build-base-image-ids.json'
        pins.parent.mkdir(parents=True)
        pins.write_text(json.dumps({'schemaVersion':1,'platform':'linux/amd64',
            'baseImages':{n+'|'+ref:{} for n,ref in cache.NAMES.items()}}))
        self.plan={'roots':{'rootful-state':str(self.root/'rootful')},'accounts':[]}
        (self.root/'rootful').mkdir()
        identities={};verified={}
        for i,(name,ref) in enumerate(cache.NAMES.items()):
            uid=3205+i;home=self.root/name;home.mkdir(mode=0o700);home.chmod(0o700)
            os.chown(home,uid,uid);s=home.lstat()
            identities[str(home)]={'dev':s.st_dev,'ino':s.st_ino,'uid':uid,'mode':0o700}
            self.plan['accounts'].append({'name':name,'uid':uid,'home':str(home)})
            containers=home/'.cache/containers';containers.mkdir(parents=True)
            config=home/'.config';config.mkdir()
            for d in (home/'.cache',containers,config):d.chmod(0o700);os.chown(d,uid,uid)
            lock=containers/'short-name-aliases.conf.lock';lock.touch(mode=0o644)
            lock.chmod(0o644);os.chown(lock,uid,uid)
            verified[name+'|'+ref]='sha256:'+'a'*64
        self.data={'plan':self.plan,'status':'staged-empty','venueInstallerPhase':'retiring',
                   'venueCompositeMode':'retired-inert','venueRegistryPhase':'retired-inert',
                   'venueBuildBasePhase':'retired-inert','graphCleared':['root']+[x['name'] for x in self.plan['accounts']],
                   'managerStopped':[x['name'] for x in reversed(self.plan['accounts'])],
                   'podmanImageCacheRetired':True,'podmanRunrootRetired':True,
                   'retiredPaths':[],'retiredAccounts':[],
                   'venueBuildBaseVerified':verified,
                   'venueBuildBaseFrozenSha256':hashlib.sha256(pins.read_bytes()).hexdigest(),
                   'pathIdentities':identities}
        self.ledger=self.root/'ledger.json';self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        for p in (patch.object(cache.stage,'owned_plan',return_value=self.plan),
                  patch.object(cache,'process_and_mount_check',return_value=None)):
            p.start();self.addCleanup(p.stop)
    def test_foreign_data_refuses_before_unlinking_any_other_cache(self):
        first=Path(self.plan['accounts'][0]['home'])/'.cache/containers/short-name-aliases.conf.lock'
        second=Path(self.plan['accounts'][1]['home'])/'.cache/containers/short-name-aliases.conf.lock'
        second.write_bytes(b'foreign')
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger)
        self.assertTrue(first.exists());self.assertEqual(second.read_bytes(),b'foreign')
        self.assertIsNone(json.loads(self.ledger.read_text()).get('venueShortnameCachePhase'))
        second.write_bytes(b'')
        self.assertEqual(cache.retire(self.bundle,'unused',self.ledger)['retiredExactCacheInodes'],6)
        for a in self.plan['accounts']:self.assertFalse((Path(a['home'])/'.cache').exists())
    def test_resume_after_journaled_lock_unlink_does_not_guess_by_path(self):
        path,data,plan=cache.check_ledger(self.bundle,'unused',self.ledger)
        rows=cache.rows_for(plan,data)
        data.update({'venueShortnameCacheRows':rows,'venueShortnameCacheRetiredPaths':[],
                     'venueShortnameCachePending':rows[0]['path'],'venueShortnameCachePhase':'retiring'})
        cache.stage.write_ledger(path,data)
        Path(rows[0]['path']).unlink()
        self.assertEqual(cache.retire(self.bundle,'unused',self.ledger)['status'],'retired-inert')
        self.assertEqual(len(json.loads(self.ledger.read_text())['venueShortnameCacheRetiredPaths']),6)

    def vault_fixture(self):
        for a in self.plan['accounts']:
            folder=Path(a['home'])/'.cache/containers';(folder/'short-name-aliases.conf.lock').unlink();folder.rmdir();folder.parent.rmdir()
        name='p0test-r1-vaultwarden';uid=3203;home=self.root/name;home.mkdir(mode=0o700);os.chown(home,uid,uid)
        s=home.stat();self.plan['accounts'].append({'name':name,'uid':uid,'home':str(home)})
        self.data['pathIdentities'][str(home)]={'dev':s.st_dev,'ino':s.st_ino,'uid':uid,'mode':0o700}
        for folder in (home/'.config',home/'.cache',home/'.cache/containers'):
            folder.mkdir(mode=0o700);os.chown(folder,uid,uid)
        lock=home/'.cache/containers/short-name-aliases.conf.lock';lock.touch(mode=0o644);os.chown(lock,uid,uid)
        ref=cache.INSPECT_NAMES[name];(self.bundle/'stack.ir.json').write_text(json.dumps({'services':{'vaultwarden':{'image':ref}}}))
        self.data.update(venueInstallerVersion=2,activationAuthorized=False,venueOwnedReset={'phase':'empty-owned'},venueRegistryVerified={name+'|docker.io/'+ref:'sha256:'+'b'*64},graphCleared=['root']+[a['name'] for a in self.plan['accounts']],managerStopped=[a['name'] for a in reversed(self.plan['accounts'])])
        cache.stage.write_ledger(self.ledger,self.data)
        return home,lock

    def test_inspection_mode_requires_exact_cas_and_preserves_foreign_bytes(self):
        home,lock=self.vault_fixture()
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect')
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha='0'*64)
        lock.write_bytes(b'authored')
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))
        self.assertEqual(lock.read_bytes(),b'authored');self.assertIsNone(json.loads(self.ledger.read_bytes()).get('venueShortnameCachePhase'))

    def test_inspection_mode_removes_only_three_exact_inodes_not_config(self):
        home,lock=self.vault_fixture();config=home/'.config/keep';config.write_bytes(b'preserve')
        result=cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))
        self.assertEqual(result['retiredExactCacheInodes'],3);self.assertFalse((home/'.cache').exists());self.assertEqual(config.read_bytes(),b'preserve')
        self.assertEqual(json.loads(self.ledger.read_text())['venueShortnameCacheSelection'],'vaultwarden-inspect')

    def test_frozen_inspection_absent_bases_is_not_partial_base_forgiveness(self):
        home,lock=self.vault_fixture()
        for key in list(self.data):
            if key.startswith('venueBuildBase'):del self.data[key]
        ir=self.bundle/'stack.ir.json';source=json.loads(ir.read_bytes());source['quadletBuildImagesFrozen']=True;ir.write_text(json.dumps(source))
        partial=dict(self.data);partial['venueBuildBasePhase']='preparing';cache.stage.write_ledger(self.ledger,partial)
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))
        self.assertTrue(lock.exists())
        source['quadletBuildImagesFrozen']=False;ir.write_text(json.dumps(source));cache.stage.write_ledger(self.ledger,self.data)
        with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))
        self.assertTrue(lock.exists())
        source['quadletBuildImagesFrozen']=True;ir.write_text(json.dumps(source))
        self.assertEqual(cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))['retiredExactCacheInodes'],3)

    def test_inspection_mode_refuses_wrong_authority_or_selection(self):
        home,lock=self.vault_fixture()
        for field,value in [('venueRegistryVerified',{}),('venueOwnedReset',{'phase':'intent'}),('venueShortnameCacheSelection','build-bases')]:
            data=dict(self.data);data[field]=value;cache.stage.write_ledger(self.ledger,data)
            with self.assertRaises(cache.Refusal):cache.retire(self.bundle,'unused',self.ledger,selection='vaultwarden-inspect',expected_sha=cache.stage.sha(self.ledger))
            self.assertTrue(lock.exists())


class UnknownProcessNamespace(unittest.TestCase):
    def test_permission_error_is_not_an_absent_process(self):
        with patch.object(Path,'iterdir',return_value=iter([Path('/fake/123')])),patch.object(Path,'read_text',side_effect=['Uid:\t1\t1\t1\t1\n',PermissionError('unknown mount namespace')]):
            with self.assertRaisesRegex(cache.Refusal,'unknown process namespace'):
                cache.process_and_mount_check({'accounts':[]})


if __name__=='__main__':unittest.main()
