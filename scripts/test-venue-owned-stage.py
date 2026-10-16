#!/usr/bin/env python3
"""Source-only hostile fixtures for the empty isolated installation stage."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('venue_stage',Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)

class EmptyStageTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.bundle=self.root/'bundle';self.bundle.mkdir()
        quadlets=self.bundle/'quadlet/rootful';quadlets.mkdir(parents=True)
        for i in range(194):(quadlets/f'p0test-r1-synthetic-{i}.container').write_text('[Container]\n')
        accounts={}
        for i,name in enumerate(('platform','apps','homeassistant','vaultwarden','ci-runner','workloads','test-runners')):
            accounts[name]={'name':name,'user':f'p0test-r1-{name}','uid':3200+i,'subuidStart':52000000+i*65536,
                            'stateRoot':f'/mnt/stack/new/state/{name}','graphRoot':f'/mnt/stack/new/graphs/{name}',
                            'volumeRoot':f'/mnt/stack/new/rootless/{name}'}
        venue={'unitPrefix':'p0test-r1','rootfulRuntimeRoot':'/run/p0test-r1'}
        (self.bundle/'podman-domains.json').write_text(json.dumps({'domains':list(accounts.values()),'venue':venue}))
        (self.bundle/'stack.ir.json').write_text('{}')
        (self.bundle/'source-provenance.json').write_text(json.dumps({'generatorCommit':'f'*40}))
        self.data={'unitPrefix':'p0test-r1','domains':{n:{k:v for k,v in d.items() if k!='name'} for n,d in accounts.items()},
                   'rootful':{'stateRoot':'/var/lib/p0test-r1','graphRoot':'/mnt/stack/new/rootful-graph',
                              'runRoot':'/run/p0test-r1-podman','volumeRoot':'/mnt/stack/new/volumes'},
                   'storageRoots':{'pgSsdRoot':'/mnt/stack/new/pg-ssd','vectorDbsRoot':'/mnt/stack/new/vector-dbs',
                                   'logRoot':'/var/log/p0test-r1'}}
        self.selector=self.root/'selector.json';self.selector.write_text(json.dumps(self.data))
    @unittest.skipUnless(shutil.which('setfacl'), 'physical ACL fixtures require setfacl')
    def test_fresh_directory_drops_inherited_acls_without_changing_parent(self):
        subprocess.run(['setfacl','-m',f'd:u:{os.getuid()+1}:rwx',str(self.root)],check=True)
        original={name:os.getxattr(self.root,name) for name in os.listxattr(self.root)}
        path=self.root/'isolated'
        stage.create_private_directory(path,os.getuid(),0o700)
        self.assertEqual(path.stat().st_mode&0o7777,0o700)
        self.assertFalse(any(n.startswith('system.posix_acl_') for n in os.listxattr(path)))
        child=path/'image-root';child.mkdir(mode=0o755)
        self.assertFalse(any(n.startswith('system.posix_acl_') for n in os.listxattr(child)))
        self.assertEqual(original,{name:os.getxattr(self.root,name) for name in os.listxattr(self.root)})

    def test_existing_directory_and_symlink_are_never_acl_scrubbed(self):
        existing=self.root/'existing';existing.mkdir();existing.chmod(0o755)
        link=self.root/'link';link.symlink_to(existing)
        for path in (existing,link):
            with self.subTest(path=path),self.assertRaises(FileExistsError):
                stage.create_private_directory(path,os.getuid(),0o700)
        self.assertEqual(existing.stat().st_mode&0o777,0o755)

    @unittest.skipUnless(shutil.which('setfacl') and shutil.which('unshare'),
                         'namespace ACL fixture requires setfacl and unshare')
    def test_unmapped_inherited_acl_copy_fails_but_isolated_copy_succeeds(self):
        available=subprocess.run(['unshare','--user','--map-root-user','true'],capture_output=True)
        if available.returncode:self.skipTest('user namespace unavailable in this test environment')
        subprocess.run(['setfacl','-m',f'd:u:{os.getuid()+1}:rwx',str(self.root)],check=True)
        dirty=self.root/'inherited';dirty.mkdir();(dirty/'file').write_text('synthetic\n')
        clean=self.root/'isolated';stage.create_private_directory(clean,os.getuid(),0o700)
        (clean/'file').write_text('synthetic\n')
        command=['unshare','--user','--map-root-user','cp','--preserve=mode']
        bad=subprocess.run(command+[str(dirty/'file'),str(clean/'bad-copy')],capture_output=True,text=True)
        self.assertNotEqual(bad.returncode,0)
        self.assertIn('Invalid argument',bad.stderr)
        good=subprocess.run(command+[str(clean/'file'),str(clean/'good-copy')],capture_output=True,text=True)
        self.assertEqual(good.returncode,0,good.stderr)
        self.assertEqual((clean/'good-copy').read_bytes(),(clean/'file').read_bytes())

    def test_all_seven_and_rootful_stores_have_exact_new_identities(self):
        p=stage.owned_plan(self.bundle,self.selector)
        self.assertEqual(len(p['accounts']),7)
        self.assertEqual(len(p['roots']),38)
        self.assertEqual(p['roots']['ci-runner-ssh'],p['roots']['p0test-r1-ci-runner-state']+'/forgejo-runner-ssh')
        self.assertEqual(len(p['configs']),16)
        self.assertEqual(p['configs']['/var/lib/p0test-r1/containers.conf'],
                         '[network]\nnetwork_config_dir = "/var/lib/p0test-r1/networks"\n')
        self.assertFalse(p['activationAuthorized'])
        self.assertIn('runroot = "/run/p0test-r1-podman"',p['configs']['/var/lib/p0test-r1/containers-storage.conf'])
        self.assertEqual(p['accounts'][0]['subuid'],52000000)
        self.assertEqual(p['bundleIrSha256'],stage.sha(self.bundle/'stack.ir.json'))
        self.assertEqual(len(p['quadletTreeSha256']),64)
        (self.bundle/'quadlet/rootful/p0test-r1-synthetic-1.container').write_text('[Container]\nImage=wrong\n')
        self.assertNotEqual(stage.owned_plan(self.bundle,self.selector)['quadletTreeSha256'],p['quadletTreeSha256'])
    def test_hostile_identity_and_graph_redirection_refuse_before_stage(self):
        for mode in ('missing-domain','user','uid','graph','prefix','duplicate-root'):
            data=copy.deepcopy(self.data)
            if mode=='missing-domain':data['domains'].pop('apps')
            elif mode=='user':data['domains']['apps']['user']='webservices-apps'
            elif mode=='uid':data['domains']['apps']['uid']=1000
            elif mode=='graph':data['domains']['apps']['graphRoot']='/mnt/stack/podman/apps/graph'
            elif mode=='prefix':data['unitPrefix']='webservices'
            else:data['domains']['apps']['stateRoot']=data['domains']['platform']['stateRoot'];
            self.selector.write_text(json.dumps(data))
            with self.subTest(mode=mode),self.assertRaises(stage.Refusal):stage.owned_plan(self.bundle,self.selector)
    def test_symlink_or_existing_root_refuses_planning(self):
        with self.assertRaises(stage.Refusal):stage.safe_parents([str(self.root/'new')])
        (self.root/'redirect').symlink_to('/mnt/stack')
        with self.assertRaises(stage.Refusal):stage.safe_parents([str(self.root/'redirect'/'new')])
    def test_ledger_requires_root_private_parent_and_refuses_replace_collision(self):
        ledger=self.root/'ledger.json';payload={'schemaVersion':1,'status':'preparing'}
        self.root.chmod(0o755)
        with self.assertRaises(stage.Refusal):stage.write_ledger(ledger,payload,create=True)
        # Tests run as a user or root; only root can meet the physical ledger requirement.
        if os.geteuid()!=0:return
        self.root.chmod(0o700)
        stage.write_ledger(ledger,payload,create=True)
        self.assertEqual(json.loads(ledger.read_text()),payload)
        self.assertEqual(ledger.stat().st_mode&0o777,0o600)
        with self.assertRaises(stage.Refusal):stage.write_ledger(ledger,payload,create=True)
        (self.root/'ledger.json.new').symlink_to(ledger)
        with self.assertRaises(stage.Refusal):stage.write_ledger(ledger,payload)

if __name__=='__main__':unittest.main()
