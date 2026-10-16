#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import contextlib
import io
import stat

path = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-pinned-images.py'
spec = importlib.util.spec_from_file_location('pinned_images', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.geteuid() == 0, 'protected image fixtures require root')
class PinnedImages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.image = 'sha256:' + 'a' * 64
        self.ir = {'services': {'selected': {'image': self.image, 'updatePolicy': 'pinned',
                   'placement': 'rootless', 'rootlessDomain': 'apps'}}}
        (self.root / 'stack.ir.json').write_text(json.dumps(self.ir))
        (self.root / 'podman-domains.json').write_text(json.dumps({'domains': [{'name': 'apps', 'user': 'service-apps'}]}))
        self.archive = self.root / 'release.tar'
        self.archive.write_bytes(b'fixture release input')
        self.row = {'image': self.image, 'archiveFilename': self.archive.name,
                    'archiveSha256': hashlib.sha256(self.archive.read_bytes()).hexdigest()}
        self.inputs = self.root / 'inputs.json'
        self.save()

    def save(self):
        self.inputs.write_text(json.dumps({'schemaVersion': 1, 'images': [self.row]}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_selected_authority_only(self):
        self.assertEqual(mod.validate(self.root, self.inputs), [(self.image, self.archive, ['service-apps'])])

    def test_tampered_archive_refused(self):
        self.archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_writable_input_refused(self):
        self.inputs.chmod(0o666)
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_symlink_archive_refused(self):
        target = self.root / 'target'; self.archive.rename(target); self.archive.symlink_to(target)
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_traversal_refused(self):
        self.row['archiveFilename'] = '../release.tar'; self.save()
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_unselected_image_refused(self):
        self.row['image'] = 'sha256:' + 'b' * 64; self.save()
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_missing_input_refused(self):
        self.inputs.write_text(json.dumps({'schemaVersion': 1, 'images': []}))
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)

    def test_complete_venue_schema_routes_rootful_import_off_shared_graph(self):
        prefix='p0test-r1';state='/var/lib/'+prefix;graph='/mnt/stack/p0-existing-host-venue-r1/rootful-graph';run='/run/'+prefix+'-podman'
        venue={'schemaVersion':1,'unitPrefix':prefix,'rootfulStateRoot':state,
               'rootfulRuntimeRoot':'/run/'+prefix,'rootfulGraphRoot':graph,
               'rootfulRunRoot':run,'rootfulVolumeRoot':'/mnt/stack/p0-existing-host-venue-r1/volumes',
               'pgSsdRoot':'/mnt/stack/p0-existing-host-venue-r1/pg-ssd',
               'vectorDbsRoot':'/mnt/stack/p0-existing-host-venue-r1/vector-dbs',
               'controlSocketRoot':'/run/'+prefix+'-control','logRoot':'/var/log/'+prefix,
               'portMap':{str(i):56000+i for i in range(51)}}
        (self.root/'podman-domains.json').write_text(json.dumps({'domains':[],'venue':venue}))
        config=f'[storage]\\ndriver = "overlay"\\nrunroot = "{run}"\\ngraphroot = "{graph}"\\n'.replace('\\n','\n').encode()
        real_lstat=Path.lstat
        real_read_bytes=Path.read_bytes
        def staged_lstat(path):
            if str(path) in (state,graph,run,state+'/networks'):return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
            if str(path) in (state+'/containers-storage.conf',state+'/containers.conf'):
                return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            return real_lstat(path)
        def staged_bytes(path):
            if str(path)==state+'/containers-storage.conf':return config
            if str(path)==state+'/containers.conf':return ('[network]\nnetwork_config_dir = "'+state+'/networks"\n').encode()
            return real_read_bytes(path)
        with patch.object(Path,'lstat',staged_lstat),patch.object(Path,'read_bytes',staged_bytes):
            command=mod.rootful_command(self.root)
            self.assertEqual(command,['env','CONTAINERS_STORAGE_CONF='+state+'/containers-storage.conf',
                                      'CONTAINERS_CONF='+state+'/containers.conf',
                                      'podman','--root',graph,'--runroot',run,'--network-config-dir',state+'/networks'])
            venue['controlSocketRoot']='/run/p0-control'
            (self.root/'podman-domains.json').write_text(json.dumps({'domains':[],'venue':venue}))
            with self.assertRaises(ValueError):mod.rootful_command(self.root)
            venue['controlSocketRoot']='/run/'+prefix+'-control';venue['portMap']={}
            (self.root/'podman-domains.json').write_text(json.dumps({'domains':[],'venue':venue}))
            with self.assertRaises(ValueError):mod.rootful_command(self.root)

    def test_rootless_import_uses_selected_home_not_caller_storage_override(self):
        from unittest.mock import patch
        calls=[]
        def inspect(command,**kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0,stdout=self.image+'\n')
        with (patch.object(mod.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=3201,pw_dir='/home/p0test-r1-apps')),
              patch.object(mod.subprocess,'run',side_effect=inspect),
              contextlib.redirect_stdout(io.StringIO())):
            mod.install([(self.image,self.archive,['p0test-r1-apps'])])
        self.assertEqual(len(calls),1)
        self.assertIn('HOME=/home/p0test-r1-apps',calls[0])
        self.assertIn('XDG_RUNTIME_DIR=/run/user/3201',calls[0])
        self.assertEqual(calls[0][:7],['runuser','-u','p0test-r1-apps','--','env','-u','CONTAINERS_STORAGE_CONF'])

    def test_registry_update_refused(self):
        self.ir['services']['selected']['updatePolicy'] = 'registry'
        (self.root / 'stack.ir.json').write_text(json.dumps(self.ir))
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)


if __name__ == '__main__':
    unittest.main()
