#!/usr/bin/env python3
"""Actual staged rootless build trees, UID isolation and hostile retirement."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-domain-runtime-inert.py'
spec=importlib.util.spec_from_file_location('venue_domain_builds',src)
domain=importlib.util.module_from_spec(spec);spec.loader.exec_module(domain)

@unittest.skipUnless(os.geteuid()==0,'UID-scoped release fixture requires root')
class DomainBuildInputs(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.bundle=self.root/'bundle';self.original=self.root/'source'
        self.original.mkdir();(self.original/'runtime/configs').mkdir(parents=True)
        build=self.original/'build';(build/'stack.containers/app').mkdir(parents=True)
        (build/'stack.containers/app/Containerfile').write_text('FROM scratch\n')
        (build/'script.sh').write_text('#!/bin/sh\nexit 0\n')
        self.data={'venueReleasePhase':'inert-ready','status':'staged-empty','managerStarted':[],
                   'venueReleaseRoot':str(self.original),'releaseRoot':str(self.original),
                   'pathIdentities':{},'createdPaths':[],
                   'venueReleaseManifest':domain.release.inventory(self.original)}
        self.plan={'prefix':'p0test-r1','accounts':[]}
        self.selected={}
        for i,n in enumerate(('apps','platform','homeassistant','vaultwarden','ci-runner','workloads','test-runners')):
            name='p0test-r1-'+n;uid=3200+i;state=self.root/name
            state.mkdir(mode=0o700);os.chown(state,uid,uid);state.chmod(0o700)
            x=state.lstat();self.data['pathIdentities'][str(state)]={'dev':x.st_dev,'ino':x.st_ino,'uid':uid,'mode':0o700}
            self.plan['accounts'].append({'name':name,'uid':uid})
            self.selected[name]={'uid':uid,'state':str(state),'domain':n,'configs':[],
                                 'buildUnits':['p0test-r1-'+n+'.build'] if n in ('apps','platform','workloads','test-runners') else []}
        self.ledger=self.root/'ledger';self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        def context(bundle,selector,ledger):return self.bundle,self.ledger,self.data,self.plan,self.selected,self.original
        def write(path,value):path.write_text(json.dumps(value))
        a=patch.object(domain,'context',side_effect=context);b=patch.object(domain.stage,'write_ledger',side_effect=write)
        for p in (a,b):p.start();self.addCleanup(p.stop)
    def test_four_selected_domains_get_exact_build_context_and_hostile_file_refuses_retirement(self):
        result=domain.prepare(self.bundle,'unused',self.ledger)
        self.assertEqual(result['rootlessCurrentTrees'],7)
        for name,row in self.data['venueDomainRuntimePlan'].items():
            build=Path(row['current'])/'build'
            self.assertEqual(build.is_dir(),bool(row['buildUnits']))
            if build.is_dir():
                source=build/'stack.containers/app/Containerfile';s=source.stat()
                self.assertEqual((s.st_uid,stat.S_IMODE(s.st_mode)),(row['uid'],0o644))
                self.assertEqual(source.read_bytes(),(self.original/'build/stack.containers/app/Containerfile').read_bytes())
        selected=self.data['venueDomainRuntimePlan']['p0test-r1-apps'];foreign=Path(selected['releaseRoot'])/'build/foreign'
        foreign.write_bytes(b'not selected')
        with self.assertRaises(domain.Refusal):domain.retire(self.bundle,'unused',self.ledger)
        self.assertTrue(Path(selected['current']).is_symlink())
        foreign.unlink()
        self.assertEqual(domain.retire(self.bundle,'unused',self.ledger)['status'],'retired-inert')
        for row in self.data['venueDomainRuntimePlan'].values():self.assertFalse(Path(row['current']).exists())
    def runtime_logs(self):
        config=self.original/'runtime/configs/homepage';config.mkdir();(config/'settings.yaml').write_text('title: synthetic\n')
        self.selected['p0test-r1-apps']['configs']=['homepage'];self.bundle.mkdir()
        (self.bundle/'stack.ir.json').write_text(json.dumps({'services':{'portal':{'image':'ghcr.io/gethomepage/homepage:v1.13.2','placement':'rootless','rootlessDomain':'apps','volumes':['./configs/homepage:/app/config']}}}))
        domain.prepare(self.bundle,'unused',self.ledger)
        self.data.update(venueInstallerVersion=2,venueInstallerPhase='retiring',venueOwnedReset={'phase':'empty-owned'},managerStopped=[a['name'] for a in reversed(self.plan['accounts'])])
        self.ledger.write_text(json.dumps(self.data));row=self.data['venueDomainRuntimePlan']['p0test-r1-apps'];root=Path(row['releaseRoot'])/'runtime/configs/homepage'
        logs=root/'logs';logs.mkdir();(logs/'homepage.log').write_text('[2026-10-17] info: synthetic\n')
        for item in (logs,logs/'homepage.log'):os.chown(item,row['uid'],row['uid'])
        p=patch.object(domain,'no_runtime_writers',return_value=None);p.start();self.addCleanup(p.stop)
        return root,logs
    def review_logs(self):return domain.retire_runtime_logs(self.bundle,'unused',self.ledger,domain.stage.sha(self.ledger))
    def test_only_two_new_homepage_log_paths_are_removed_before_normal_retirement(self):
        root,logs=self.runtime_logs();self.assertEqual(self.review_logs()['exactNewRuntimeLogPathsRemoved'],2)
        self.assertFalse(logs.exists());self.assertTrue((root/'settings.yaml').exists())
        self.assertEqual(domain.retire(self.bundle,'unused',self.ledger)['status'],'retired-inert')
    def test_unknown_runtime_file_blocks_log_deletion(self):
        root,logs=self.runtime_logs();extra=root/'human-notes';extra.write_text('preserve');os.chown(extra,3200,3200)
        with self.assertRaises(domain.Refusal):self.review_logs()
        self.assertTrue((logs/'homepage.log').exists());self.assertEqual(extra.read_text(),'preserve')
    def test_changed_original_config_blocks_log_deletion(self):
        root,logs=self.runtime_logs();(root/'settings.yaml').write_text('authored change')
        with self.assertRaises(domain.Refusal):self.review_logs()
        self.assertTrue((logs/'homepage.log').exists())
    def test_log_unlink_interruption_resumes_only_from_saved_intent(self):
        root,logs=self.runtime_logs();unlink=Path.unlink
        def interrupted(path,*args,**kwargs):
            unlink(path,*args,**kwargs)
            if path==logs/'homepage.log':raise OSError('synthetic crash after unlink')
        with patch.object(Path,'unlink',new=interrupted):
            with self.assertRaises(OSError):self.review_logs()
        self.assertTrue(logs.exists());self.assertFalse((logs/'homepage.log').exists())
        self.assertEqual(self.review_logs()['status'],'retired-runtime-logs');self.assertFalse(logs.exists())
    def test_linked_build_source_refuses_before_domain_mutation(self):
        (self.original/'build/link').symlink_to('/etc/passwd')
        with self.assertRaises(domain.Refusal):domain.prepare(self.bundle,'unused',self.ledger)
        self.assertFalse(any((Path(x['state'])/'current').exists() for x in self.selected.values()))

if __name__=='__main__':unittest.main()
