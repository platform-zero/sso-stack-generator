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
    def test_targeted_build_can_leave_only_one_exact_cache(self):
        absent=Path(self.plan['accounts'][1]['home'])/'.cache'
        (absent/'containers/short-name-aliases.conf.lock').unlink()
        (absent/'containers').rmdir();absent.rmdir()
        result=cache.retire(self.bundle,'unused',self.ledger)
        self.assertEqual(result['retiredExactCacheInodes'],3)
        self.assertEqual(cache.retire(self.bundle,'unused',self.ledger)['status'],'retired-inert')
        for a in self.plan['accounts']:self.assertFalse((Path(a['home'])/'.cache').exists())
    def test_unjournaled_second_cache_blocks_subset_before_first_unlink(self):
        rows=cache.rows_for(self.plan,self.data)[:3]
        self.data.update({'venueShortnameCacheRows':rows,'venueShortnameCacheRetiredPaths':[],
                          'venueShortnameCachePhase':'prepared'})
        cache.stage.write_ledger(self.ledger,self.data)
        with self.assertRaisesRegex(cache.Refusal,'unjournaled selected'):
            cache.retire(self.bundle,'unused',self.ledger)
        self.assertTrue(Path(rows[0]['path']).exists())
    def test_resume_after_journaled_lock_unlink_does_not_guess_by_path(self):
        path,data,plan=cache.check_ledger(self.bundle,'unused',self.ledger)
        rows=cache.rows_for(plan,data)
        data.update({'venueShortnameCacheRows':rows,'venueShortnameCacheRetiredPaths':[],
                     'venueShortnameCachePending':rows[0]['path'],'venueShortnameCachePhase':'retiring'})
        cache.stage.write_ledger(path,data)
        Path(rows[0]['path']).unlink()
        self.assertEqual(cache.retire(self.bundle,'unused',self.ledger)['status'],'retired-inert')
        self.assertEqual(len(json.loads(self.ledger.read_text())['venueShortnameCacheRetiredPaths']),6)

if __name__=='__main__':unittest.main()
