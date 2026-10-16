#!/usr/bin/env python3
"""Bounded Huly four-volume lifecycle fixtures; no live Podman involved."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-huly-volumes.py'
spec=importlib.util.spec_from_file_location('venue_huly_volumes',src)
vol=importlib.util.module_from_spec(spec);spec.loader.exec_module(vol)

@unittest.skipUnless(os.geteuid()==0,'protected stage ledger fixture requires root')
class FourVolumes(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.ledger=self.root/'ledger.json'
        self.plan={'prefix':'p0test-r1','accounts':[{'name':'p0test-r1-apps','uid':3201,'home':'/home/p0test-r1-apps',
                    'graph':str(self.root/'exclusive-apps-graph')}],'configs':{}}
        self.data={'plan':self.plan,'status':'managers-ready','managerStarted':['p0test-r1-apps'],
                   'managerStopped':[],'pathIdentities':{}}
        self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        self.apps=self.plan['accounts'][0]
        self.present=set();self.mounts={}
        for name in vol.NAMES:
            mount=self.root/name/'_data';mount.mkdir(parents=True);self.mounts[name]=mount
    def command(self,apps,*args):
        self.assertEqual(apps,self.apps)
        if args[:2]==('volume','create'):
            self.present.add(args[2]);return args[2]
        if args[:2]==('volume','rm'):
            self.present.remove(args[2]);return args[2]
        raise AssertionError(args)
    def patch(self):
        return (patch.object(vol.stage,'owned_plan',return_value=self.plan),
                patch.object(vol,'check_apps'),
                patch.object(vol,'inventory',side_effect=lambda apps:set(self.present)),
                patch.object(vol,'mountpoint',side_effect=lambda apps,name:self.mounts[name]),
                patch.object(vol,'run',side_effect=self.command))
    def test_exact_four_created_then_empty_only_retired(self):
        self.bundle=self.root/'bundle';q=self.bundle/'quadlet/rootless-apps';q.mkdir(parents=True)
        for name in vol.NAMES:(q/(name+'.container')).write_text('Volume='+name+':/data\n')
        with self.patch()[0],self.patch()[1],self.patch()[2],self.patch()[3],self.patch()[4]:
            self.assertEqual(vol.create(self.bundle,None,self.ledger)['count'],4)
            self.assertEqual(self.present,set(vol.NAMES))
            (self.mounts['huly_minio']/'foreign').write_text('do not delete')
            with self.assertRaises(vol.Refusal):vol.retire(self.bundle,None,self.ledger)
            self.assertEqual(self.present,set(vol.NAMES))
            (self.mounts['huly_minio']/'foreign').unlink()
            self.assertEqual(vol.retire(self.bundle,None,self.ledger)['retired'],4)
            self.assertFalse(self.present)
            self.assertEqual(json.loads(self.ledger.read_text())['status'],'managers-ready')
    def test_foreign_existing_volume_blocks_all_creation(self):
        self.bundle=self.root/'bundle';q=self.bundle/'quadlet/rootless-apps';q.mkdir(parents=True)
        for name in vol.NAMES:(q/(name+'.container')).write_text('Volume='+name+':/data\n')
        self.present.add('foreign')
        with self.patch()[0],self.patch()[1],self.patch()[2],self.patch()[3],self.patch()[4]:
            with self.assertRaises(vol.Refusal):vol.create(self.bundle,None,self.ledger)
        self.assertEqual(self.present,{'foreign'})

if __name__=='__main__':unittest.main()
