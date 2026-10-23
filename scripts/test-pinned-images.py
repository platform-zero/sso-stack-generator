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
               'portMap':{str(i):56000+i for i in range(50)}}
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
            self.assertEqual(command,['env','TMPDIR='+graph,'CONTAINERS_STORAGE_CONF='+state+'/containers-storage.conf',
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

    def frozen_fixture(self):
        self.ir['quadletBuildImagesFrozen']=True
        self.ir['services']['selected'].update({'build':{},'frozenBuildImage':self.image})
        (self.root/'stack.ir.json').write_text(json.dumps(self.ir))
        graph=self.root/'graph';graph.mkdir(mode=0o700);os.chown(graph,3201,3201)
        (self.root/'podman-domains.json').write_text(json.dumps({'domains':[
            {'name':'apps','user':'service-apps','graphRoot':str(graph)}]}))
        return graph,'localhost/webservices/selected:bundle'

    def test_frozen_import_restores_only_exact_selected_alias_with_private_scratch(self):
        graph,alias=self.frozen_fixture();calls=[];tags={}
        def run(command,**kwargs):
            calls.append(command)
            if 'exists' in command:return SimpleNamespace(returncode=int(alias not in tags))
            if 'tag' in command:
                self.assertEqual(command[-3:],['tag',self.image,alias]);tags[alias]=self.image
                return SimpleNamespace(returncode=0)
            self.assertIn('inspect',command)
            ref=command[command.index('inspect')+1]
            return SimpleNamespace(returncode=0,stdout=self.image if ref==self.image else tags[ref])
        with (patch.object(mod.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=3201,pw_dir='/home/service-apps')),
              patch.object(mod.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO())):
            mod.install(mod.validate(self.root,self.inputs),self.root)
        self.assertEqual(tags,{alias:self.image})
        self.assertTrue(all('TMPDIR='+str(graph) in command for command in calls))

    def test_shared_frozen_id_restores_both_exact_producer_aliases(self):
        graph,alias=self.frozen_fixture();tags={}
        self.ir['services']['selected-twin']=dict(self.ir['services']['selected'])
        (self.root/'stack.ir.json').write_text(json.dumps(self.ir))
        def run(command,**kwargs):
            self.assertIn('TMPDIR='+str(graph),command)
            if 'exists' in command:return SimpleNamespace(returncode=int(command[-1] not in tags))
            if 'tag' in command:
                self.assertEqual(command[-2],self.image);tags[command[-1]]=self.image
                return SimpleNamespace(returncode=0)
            ref=command[command.index('inspect')+1]
            return SimpleNamespace(returncode=0,stdout=self.image if ref==self.image else tags[ref])
        with (patch.object(mod.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=3201,pw_dir='/home/service-apps')),
              patch.object(mod.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO())):
            mod.install(mod.validate(self.root,self.inputs),self.root)
        self.assertEqual(tags,{alias:self.image,'localhost/webservices/selected-twin:bundle':self.image})

    def test_frozen_alias_collision_and_inventory_failure_never_retag(self):
        _,alias=self.frozen_fixture()
        for code in (0,125):
            calls=[]
            def run(command,**kwargs):
                calls.append(command)
                if 'exists' in command:return SimpleNamespace(returncode=code)
                self.assertNotIn('tag',command)
                ref=command[command.index('inspect')+1]
                return SimpleNamespace(returncode=0,stdout=self.image if ref==self.image else 'sha256:'+'b'*64)
            with (patch.object(mod.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=3201,pw_dir='/home/service-apps')),
                  patch.object(mod.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaises(ValueError):mod.install(mod.validate(self.root,self.inputs),self.root)
            self.assertFalse(any('tag' in command for command in calls))

    def test_frozen_alias_requires_explicit_ir_scope_and_matching_id(self):
        self.frozen_fixture();metadata=json.loads((self.root/'podman-domains.json').read_text())
        for flag in (False,1,'true'):
            ir={**self.ir,'quadletBuildImagesFrozen':flag};(self.root/'stack.ir.json').write_text(json.dumps(ir))
            with self.assertRaises(ValueError):mod.frozen_aliases(self.root,metadata)
        self.ir['services']['selected']['frozenBuildImage']='sha256:'+'b'*64
        (self.root/'stack.ir.json').write_text(json.dumps(self.ir))
        with self.assertRaises(ValueError):mod.frozen_aliases(self.root,metadata)

    def test_load_deadline_accounts_for_measured_large_sdk_with_finite_ceiling(self):
        self.assertEqual(mod.image_load_timeout(0), 300)
        self.assertEqual(mod.image_load_timeout(1), 301)
        self.assertEqual(mod.image_load_timeout(4 * 1024 * 1024), 301)
        self.assertEqual(mod.image_load_timeout(4659083776), 1411)
        self.assertEqual(mod.image_load_timeout(1024**4), 1800)

    def test_load_deadline_rejects_invalid_byte_authority(self):
        for value in (-1, True, 1.5, '4659083776', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.image_load_timeout(value)

    def test_native_load_uses_fd_size_budget_then_rechecks_identity(self):
        calls=[]
        def run(command, **kwargs):
            calls.append((command,kwargs))
            if command[-1]=='load':
                self.assertEqual(kwargs['timeout'],mod.image_load_timeout(os.fstat(kwargs['stdin'].fileno()).st_size))
                self.assertTrue(kwargs['check']);self.assertTrue(kwargs['capture_output'])
                return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=0 if len(calls)>1 else 1,stdout=self.image)
        with patch.object(mod.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
            mod.install([(self.image,self.archive,['root'])])
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[1][0],['podman','load'])
        self.assertIn('inspect',calls[2][0])

    def test_load_timeout_is_terminal_without_pull_tag_or_retry(self):
        calls=[]
        def run(command, **kwargs):
            calls.append(command)
            if command[-1]=='load':raise mod.subprocess.TimeoutExpired(command,kwargs['timeout'])
            return SimpleNamespace(returncode=1,stdout='')
        with patch.object(mod.subprocess,'run',side_effect=run),self.assertRaises(mod.subprocess.TimeoutExpired):
            mod.install([(self.image,self.archive,['root'])])
        self.assertEqual(len(calls),2)
        self.assertFalse(any('pull' in x or 'tag' in x for x in calls))

    def test_load_completion_does_not_accept_another_configuration_id(self):
        calls=[]
        def run(command, **kwargs):
            calls.append(command)
            if command[-1]=='load':return SimpleNamespace(returncode=0)
            return SimpleNamespace(returncode=1 if len(calls)==1 else 0,stdout='sha256:'+'b'*64)
        with patch.object(mod.subprocess,'run',side_effect=run),self.assertRaisesRegex(ValueError,'pinned configuration ID'):
            mod.install([(self.image,self.archive,['root'])])
        self.assertEqual(len(calls),3)
        self.assertFalse(any('pull' in x or 'tag' in x for x in calls))

    def test_native_load_failure_is_terminal_without_fallback(self):
        calls=[]
        def run(command, **kwargs):
            calls.append(command)
            if command[-1]=='load':raise mod.subprocess.CalledProcessError(125,command)
            return SimpleNamespace(returncode=1,stdout='')
        with patch.object(mod.subprocess,'run',side_effect=run),self.assertRaises(mod.subprocess.CalledProcessError):
            mod.install([(self.image,self.archive,['root'])])
        self.assertEqual(len(calls),2)

    def test_late_native_registry_admission_uses_sealed_release(self):
        body=path.with_name('install-podman-bundle.sh').read_text()
        self.assertIn('python3 "$release/ops/install-pinned-images.py" --bundle "$release" --prepare-registry',body)
        self.assertNotIn('python3 "$BUNDLE/ops/install-pinned-images.py" --bundle "$BUNDLE" --prepare-registry',body)

    def test_operator_owned_generation_pin_is_not_admitted_as_protected(self):
        os.chown(self.inputs,1000,1000)
        with self.assertRaises(ValueError):mod.protected(self.inputs)
        # This is a NEW isolated derived artifact, not a permission takeover.
        sealed=self.root/'sealed-inputs.json';sealed.write_bytes(self.inputs.read_bytes());sealed.chmod(0o600)
        mod.protected(sealed)

    def test_registry_update_refused(self):
        self.ir['services']['selected']['updatePolicy'] = 'registry'
        (self.root / 'stack.ir.json').write_text(json.dumps(self.ir))
        with self.assertRaises(ValueError): mod.validate(self.root, self.inputs)


if __name__ == '__main__':
    unittest.main()
