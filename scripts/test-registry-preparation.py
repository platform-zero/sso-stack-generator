#!/usr/bin/env python3
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

source=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/install-pinned-images.py'
spec=importlib.util.spec_from_file_location('pinned_preparation',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
IMAGE='docker.io/library/alpine:3.22@sha256:'+'a'*64

class RegistryPreparation(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.bundle=Path(self.temp.name)
        (self.bundle/'podman-domains.json').write_text(json.dumps({'domains':[{'name':'apps','user':'actor'}]}))
        for label in ('rootful','rootless-apps'):(self.bundle/'quadlet'/label).mkdir(parents=True)
        self.path=self.bundle/'quadlet/rootless-apps/a.container'
        self.path.write_text('Image='+IMAGE+'\n')
        self.calls=[];self.present=set()
        def runner(command,**kwargs):
            self.calls.append(command)
            image=command[-1]
            if 'inspect' in command:return SimpleNamespace(returncode=0,stdout='sha256:'+'c'*64+'\n')
            if command[-3:-1]==['image','exists']:return SimpleNamespace(returncode=0 if image in self.present else 1)
            if command[-2]=='pull':self.present.add(image);return SimpleNamespace(returncode=0)
            raise AssertionError(command)
        self.runner=runner
        self.user=patch.object(module.pwd,'getpwnam',return_value=SimpleNamespace(pw_dir='/home/actor',pw_uid=1234))
        self.user.start();self.addCleanup(self.user.stop)

    def run_prepare(self,runner=None):
        with contextlib.redirect_stdout(io.StringIO()):module.prepare_registry(self.bundle,runner=runner or self.runner)

    def test_venue_rootful_registry_preparation_uses_only_bound_store_command(self):
        rootful=self.bundle/'quadlet/rootful/p0test-r1-caddy.container'
        rootful.write_text('Image='+IMAGE+'\n')
        with patch.object(module,'rootful_command',return_value=[
                'env','CONTAINERS_STORAGE_CONF=/var/lib/p0test-r1/containers-storage.conf',
                'CONTAINERS_CONF=/var/lib/p0test-r1/containers.conf',
                'podman','--root','/mnt/stack/p0-existing-host-venue-r1/rootful-graph',
                '--runroot','/run/p0test-r1-podman','--network-config-dir','/var/lib/p0test-r1/networks']) as bound:
            self.run_prepare()
        bound.assert_called_once_with(self.bundle)
        root_calls=[c for c in self.calls if c[0]=='env']
        self.assertTrue(root_calls)
        self.assertTrue(all('--root' in c and '--runroot' in c and '--network-config-dir' in c and
                            'CONTAINERS_CONF=/var/lib/p0test-r1/containers.conf' in c for c in root_calls))
        self.assertTrue(all(c[0]=='runuser' for c in self.calls if c not in root_calls))

    def test_missing_venue_rootful_store_refuses_before_registry_calls(self):
        (self.bundle/'quadlet/rootful/p0test-r1-caddy.container').write_text('Image='+IMAGE+'\n')
        venue={'schemaVersion':1,'unitPrefix':'p0test-r1','rootfulStateRoot':'/var/lib/p0test-r1',
               'rootfulRuntimeRoot':'/run/p0test-r1','rootfulGraphRoot':'/var/lib/containers/storage',
               'rootfulRunRoot':'/run/containers/storage',
               'rootfulVolumeRoot':'/mnt/stack/p0-existing-host-venue-r1/volumes',
               'pgSsdRoot':'/mnt/stack/p0-existing-host-venue-r1/pg-ssd',
               'vectorDbsRoot':'/mnt/stack/p0-existing-host-venue-r1/vector-dbs',
               'controlSocketRoot':'/run/p0test-r1-control','logRoot':'/var/log/p0test-r1',
               'portMap':{str(i):56000+i for i in range(51)}}
        (self.bundle/'podman-domains.json').write_text(json.dumps({'domains':[],'venue':venue}))
        with self.assertRaises(ValueError):self.run_prepare()
        self.assertEqual(self.calls,[])
        venue['rootfulGraphRoot']='/mnt/stack/p0-existing-host-venue-r1/rootful-graph'
        venue['rootfulRunRoot']='/run/p0test-r1-podman'
        (self.bundle/'podman-domains.json').write_text(json.dumps({'domains':[],'venue':venue}))
        with self.assertRaises(OSError):self.run_prepare()
        self.assertEqual(self.calls,[])

    def test_exact_authority_dedup_and_cached_input(self):
        self.path.with_name('b.container').write_text('Image='+IMAGE+'\n')
        self.path.with_name('build.container').write_text('Image=webservices-source.build\n')
        self.run_prepare()
        pulls=[c for c in self.calls if c[-2]=='pull']
        self.assertEqual(len(pulls),1);self.assertEqual(pulls[0][-1],IMAGE)
        self.assertEqual(pulls[0][:3],['runuser','-u','actor'])
        self.assertIn('HOME=/home/actor',pulls[0])
        self.calls.clear();self.run_prepare();self.assertFalse(any(c[-2]=='pull' for c in self.calls))

    def test_missing_offline_and_unpinned_refuse_without_pull(self):
        for image in ('sha256:'+'b'*64,'docker.io/library/alpine:latest'):
            self.path.write_text('Image='+image+'\n')
            with self.assertRaises(ValueError):self.run_prepare()
            self.assertFalse(any(c[-2]=='pull' for c in self.calls))

    def test_approved_version_tag_records_identity_and_refuses_drift(self):
        image='docker.io/library/alpine:3.22'
        def native_id(command,**kwargs):
            if 'inspect' in command:return SimpleNamespace(returncode=0,stdout='c'*64+'\n')
            return self.runner(command,**kwargs)
        self.path.write_text('Image='+image+'\n');self.run_prepare(native_id)
        ledger=json.loads((self.bundle/'.registry-image-ids.json').read_text())
        self.assertEqual(ledger['actor|'+image],'sha256:'+'c'*64)
        def drift(command,**kwargs):
            if 'inspect' in command:return SimpleNamespace(returncode=0,stdout='sha256:'+'d'*64)
            return self.runner(command,**kwargs)
        with self.assertRaises(ValueError):self.run_prepare(drift)
        self.assertEqual(json.loads((self.bundle/'.registry-image-ids.json').read_text()),ledger)
        self.path.write_text('Image=docker.io/library/alpine\n')
        with self.assertRaises(ValueError):self.run_prepare()

    def test_frozen_site_identity_refuses_first_install_substitution(self):
        image='docker.io/library/alpine:3.22';self.path.write_text('Image='+image+'\n')
        folder=self.bundle/'site/global.settings';folder.mkdir(parents=True)
        (self.bundle/'site/manifest.json').write_text(json.dumps({'imageIdentityPinsPath':'global.settings/registry-image-ids.json'}))
        with self.assertRaises(ValueError):self.run_prepare()
        (folder/'registry-image-ids.json').write_text(json.dumps({'actor|'+image:'sha256:'+'d'*64}))
        with self.assertRaises(ValueError):self.run_prepare()
        self.assertFalse((self.bundle/'.registry-image-ids.json').exists())
        (folder/'registry-image-ids.json').write_text(json.dumps({'actor|'+image:'sha256:'+'c'*64}))
        self.run_prepare()
        self.assertEqual(json.loads((self.bundle/'.registry-image-ids.json').read_text())['actor|'+image],'sha256:'+'c'*64)

    def test_inventory_and_pull_failure_do_not_fallback(self):
        with self.assertRaises(ValueError):self.run_prepare(lambda *a,**k:SimpleNamespace(returncode=125))
        def fail(command,**kwargs):
            if command[-2]=='pull':raise subprocess.CalledProcessError(1,command)
            return SimpleNamespace(returncode=1)
        with self.assertRaises(subprocess.CalledProcessError):self.run_prepare(fail)
        self.assertEqual(self.present,set())

if __name__=='__main__':unittest.main()
