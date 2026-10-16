#!/usr/bin/env python3
"""CAS-bound private rendered release pointer and hostile retirement fixtures."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-release-inert.py'
spec=importlib.util.spec_from_file_location('venue_release',src)
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)

@unittest.skipUnless(os.geteuid()==0,'root-private installed-release fixture')
class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.bundle=self.root/'source';self.bundle.mkdir(mode=0o700)
        gen='f'*40;site='e'*40
        (self.bundle/'source-provenance.json').write_text(json.dumps({'generatorCommit':gen,'siteCommit':site,
            'generatorDirty':False,'siteDirty':False}))
        self.state=self.root/'state';self.state.mkdir(mode=0o700);self.state.chmod(0o700)
        self.plan={'prefix':'p0test-r1','sourceCommit':gen,'roots':{
            'rootful-state':str(self.state),'rootful-network':str(self.state/'networks')},
            'configs':{str(self.state/'containers.conf'):'private',str(self.state/'containers-storage.conf'):'private'},
            'accounts':[]}
        for name in ('networks','releases'):(self.state/name).mkdir(mode=0o700)
        for path in self.plan['configs']:Path(path).write_text('private')
        _,self.slot,self.pointer=release.layout(self.bundle,self.plan,self.state)
        self.slot.mkdir(mode=0o700);self.slot.chmod(0o700)
        config=self.slot/'runtime/configs/caddy/Caddyfile';config.parent.mkdir(parents=True);config.write_text('{\nadmin off\n}\n')
        self.pointer.symlink_to('releases/'+self.slot.name)
        state_stat=self.state.stat();s=self.slot.stat();parent=self.slot.parent.stat();cur=self.pointer.lstat()
        self.ledger=self.root/'stage.json'
        self.record={'status':'staged-empty','activationAuthorized':False,'plan':self.plan,
            'pathIdentities':{str(self.state):{'dev':state_stat.st_dev,'ino':state_stat.st_ino,'uid':0,'mode':0o700}},
            'venueReleasePhase':'inert-ready','venueReleaseRoot':str(self.slot),'releaseRoot':str(self.slot),
            'renderedCaddyPath':str(config),'renderedCaddySha256':release.sha(config),
            'venueReleaseManifest':release.inventory(self.slot),
            'venueReleaseIdentity':{'dev':s.st_dev,'ino':s.st_ino,'uid':0,'mode':0o700},
            'venueReleasesParentIdentity':{'dev':parent.st_dev,'ino':parent.st_ino,'uid':0,'mode':0o700},
            'venueCurrentIdentity':{'dev':cur.st_dev,'ino':cur.st_ino,'target':os.readlink(self.pointer)}}
        self.ledger.write_text(json.dumps(self.record));self.ledger.chmod(0o600)
        patcher=patch.object(release.stage,'owned_plan',return_value=self.plan)
        patcher.start();self.addCleanup(patcher.stop)
    def test_unreviewed_file_refuses_before_pointer_unlink(self):
        fixture=self.slot/'foreign';fixture.write_text('preserve')
        with self.assertRaises(release.Refusal):release.retire(self.bundle,None,self.ledger)
        self.assertTrue(self.pointer.is_symlink());self.assertEqual(fixture.read_text(),'preserve')
        self.assertEqual(json.loads(self.ledger.read_text())['venueReleasePhase'],'inert-ready')
        fixture.unlink()
        self.assertEqual(release.retire(self.bundle,None,self.ledger)['status'],'retired-inert')
        self.assertFalse(self.pointer.exists());self.assertFalse(self.slot.exists());self.assertFalse((self.state/'releases').exists())
        self.assertEqual(json.loads(self.ledger.read_text())['venueReleasePhase'],'retired-inert')
    def test_root_release_refuses_while_seven_domain_releases_remain(self):
        self.record['venueDomainRuntimePhase']='inert-ready'
        self.ledger.write_text(json.dumps(self.record));self.ledger.chmod(0o600)
        with self.assertRaises(release.Refusal):release.retire(self.bundle,None,self.ledger)
        self.assertTrue(self.pointer.is_symlink());self.assertTrue(self.slot.exists())

    def test_pointer_retarget_or_inode_drift_refuses_without_removal(self):
        self.pointer.unlink();self.pointer.symlink_to('releases/foreign')
        with self.assertRaises(release.Refusal):release.retire(self.bundle,None,self.ledger)
        self.assertTrue(self.slot.exists());self.assertEqual(os.readlink(self.pointer),'releases/foreign')

    def test_interrupted_renderer_only_known_outputs_recover(self):
        self.pointer.unlink()
        source_config=self.bundle/'runtime/configs/caddy/Caddyfile';source_config.parent.mkdir(parents=True)
        source_config.write_bytes((self.slot/'runtime/configs/caddy/Caddyfile').read_bytes())
        template=self.bundle/'runtime/configs/caddy/allowed.conf.template';template.write_text('encrypted template')
        copied_template=self.slot/'runtime/configs/caddy/allowed.conf.template';copied_template.write_text('encrypted template')
        shutil.copy2(self.bundle/'source-provenance.json',self.slot/'source-provenance.json')
        self.record['venueReleasePhase']='rendering'
        self.record['venueReleaseCopiedManifest']=release.inventory(self.slot)
        self.record['venueReleaseSourceManifest']=release.inventory(self.bundle)
        self.ledger.write_text(json.dumps(self.record));self.ledger.chmod(0o600)
        copied_template.unlink()
        derived=self.slot/'runtime/configs/caddy/allowed.conf';derived.write_text('private rendered output')
        env=self.slot/'runtime/stack.env';env.write_text('private test value');env.chmod(0o600)
        (self.slot/'runtime/configs/caddy/Caddyfile').write_text('private rendered Caddyfile')
        foreign=self.slot/'runtime/configs/caddy/unknown.out';foreign.write_text('foreign')
        with self.assertRaises(release.Refusal):release.recover_interrupted_render(self.bundle,None,self.ledger)
        self.assertTrue(foreign.exists());foreign.unlink()
        original=self.slot/'source-provenance.json';original.write_text('corrupted immutable input')
        with self.assertRaises(release.Refusal):release.recover_interrupted_render(self.bundle,None,self.ledger)
        self.assertTrue(env.exists());original.write_bytes((self.bundle/'source-provenance.json').read_bytes())
        result=release.recover_interrupted_render(self.bundle,None,self.ledger)
        self.assertEqual(result['status'],'retired-interrupted-render')
        self.assertFalse(self.slot.exists());self.assertFalse((self.state/'releases').exists())
        self.assertEqual(json.loads(self.ledger.read_text())['venueReleasePhase'],'retired-interrupted-render')

    def test_interrupted_copy_prefix_and_foreign_file_recovery(self):
        self.pointer.unlink();shutil.rmtree(self.slot);(self.state/'releases').rmdir()
        self.record={k:self.record[k] for k in ('plan','status','activationAuthorized','pathIdentities')}
        self.ledger.write_text(json.dumps(self.record));self.ledger.chmod(0o600)
        units=self.bundle/'quadlet/rootful';units.mkdir(parents=True)
        for i in range(194):(units/('test-%03d.container'%i)).write_text('selected-unit-%03d\n'%i)
        key=self.root/'keys.txt';key.write_text('fake private fixture');key.chmod(0o600)
        def interrupted(source,dest,**kwargs):
            target=Path(dest)/'quadlet/rootful';target.mkdir(parents=True)
            (target/'test-000.container').write_bytes((units/'test-000.container').read_bytes()[:7])
            raise OSError('injected partial copy')
        with patch.object(release.shutil,'copytree',side_effect=interrupted):
            with self.assertRaises(OSError):release.prepare(self.bundle,None,self.ledger,key)
        self.assertEqual(json.loads(self.ledger.read_text())['venueReleasePhase'],'copying')
        foreign=self.slot/'unexpected-file';foreign.write_text('must not remove')
        with self.assertRaises(release.Refusal):release.recover_interrupted_copy(self.bundle,None,self.ledger)
        self.assertTrue(foreign.exists());foreign.unlink()
        copied=self.slot/'quadlet/rootful/test-000.container';copied.write_text('WRONG')
        with self.assertRaises(release.Refusal):release.recover_interrupted_copy(self.bundle,None,self.ledger)
        self.assertTrue(self.slot.exists());copied.write_bytes((units/'test-000.container').read_bytes()[:7])
        result=release.recover_interrupted_copy(self.bundle,None,self.ledger)
        self.assertEqual(result['status'],'retired-interrupted-copy')
        self.assertFalse(self.slot.exists());self.assertFalse((self.state/'releases').exists())
        self.assertEqual(json.loads(self.ledger.read_text())['venueReleasePhase'],'retired-interrupted-copy')

if __name__=='__main__':unittest.main()
