#!/usr/bin/env python3
"""Exact cross-domain ACL grant/restore on fresh test-only root directories."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

src=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/venue-cross-domain-acl.py'
spec=importlib.util.spec_from_file_location('venue_acl',src)
acl=importlib.util.module_from_spec(spec);spec.loader.exec_module(acl)

@unittest.skipUnless(os.geteuid()==0,'ACL/ledger fixture requires root')
class ExactAclFixture(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='.p0-acl-fixture-',dir='/mnt/stack')
        self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.root.chmod(0o700)
        self.parent=self.root/'volumes';self.parent.mkdir(mode=0o700);self.parent.chmod(0o700)
        dirs=[]
        for name in ('caddy_ca','forgejo_runner_token',*(f'other{i}' for i in range(11))):
            p=self.parent/name;p.mkdir(mode=0o700);p.chmod(0o700);s=p.lstat()
            dirs.append({'path':str(p),'parent':str(self.parent),'dev':s.st_dev,'ino':s.st_ino,'uid':0})
        dirs.extend({'path':str(self.root/f'rootless{i}'),'parent':'elsewhere'} for i in range(41))
        self.plan={'prefix':'p0test-r1','roots':{'rootful-volume':str(self.parent),'rootful-state':str(self.root/'state')},
            'accounts':[{'name':'p0test-r1-'+name,'uid':3200+i} for i,name in enumerate(
                ('platform','apps','homeassistant','vaultwarden','ci-runner','workloads','test-runners'))]}
        os.mkdir(self.plan['roots']['rootful-state'])
        s=self.parent.lstat()
        self.data={'plan':self.plan,'status':'data-binds-inert','venueDataBindDirs':dirs,
                   'pathIdentities':{str(self.parent):{'dev':s.st_dev,'ino':s.st_ino}}}
        self.ledger=self.root/'ledger.json';self.ledger.write_text(json.dumps(self.data));self.ledger.chmod(0o600)
        self.paths={str(self.parent/'caddy_ca'):{'consumers':['rootful','rootless-apps','rootless-platform','rootless-vaultwarden']},
                    str(self.parent/'forgejo_runner_token'):{'consumers':['rootless-apps','rootless-ci-runner']}}
        p1=patch.object(acl.stage,'owned_plan',return_value=self.plan)
        p2=patch.object(acl.binds,'inventory',return_value=self.paths)
        p1.start();p2.start();self.addCleanup(p1.stop);self.addCleanup(p2.stop)
        # ACL fixtures test exact POSIX metadata, not a racy whole-host procfs
        # inventory. Mount-screen behavior is tested separately below.
        p3=patch.object(acl,'assert_no_mounts');p3.start();self.addCleanup(p3.stop)
    def test_exact_inherited_acl_restored_without_gerald_access(self):
        original={str(p):acl.acl(p) for p in (self.parent,self.parent/'caddy_ca',self.parent/'forgejo_runner_token')}
        self.assertEqual(acl.grant(None,None,self.ledger)['crossDomainPaths'],3)
        self.assertEqual(acl.permission_rows(self.parent),acl.granted_rows({3200:'--x',3201:'--x',3203:'--x',3204:'--x',3206:'--x'}))
        self.assertNotIn('gerald',acl.acl(self.parent))
        self.assertNotIn('gerald',acl.acl(self.parent/'caddy_ca'))
        self.assertEqual(acl.restore(None,None,self.ledger)['status'],'retired')
        self.assertEqual({str(p):acl.acl(p) for p in (self.parent,self.parent/'caddy_ca',self.parent/'forgejo_runner_token')},original)
    def test_populated_bind_refuses_empty_stage_restore_without_removal(self):
        acl.grant(None,None,self.ledger)
        target=self.parent/'forgejo_runner_token'/'foreign-secret'
        target.write_text('untouched')
        with self.assertRaises(acl.Refusal):acl.restore(None,None,self.ledger)
        self.assertEqual(target.read_text(),'untouched')
        self.assertEqual(json.loads(self.ledger.read_text())['crossDomainAclStatus'],'granted')
    def test_external_acl_change_refuses_restore(self):
        acl.grant(None,None,self.ledger)
        subprocess.run(['setfacl','-m','u:3205:rwx',str(self.parent/'caddy_ca')],check=True)
        with self.assertRaises(acl.Refusal):acl.restore(None,None,self.ledger)
        self.assertEqual(json.loads(self.ledger.read_text())['crossDomainAclStatus'],'granted')
    def test_unreviewed_new_child_refuses_before_acl_change(self):
        outside=self.parent/'foreign';outside.mkdir();(outside/'protected').write_text('untouched')
        with self.assertRaises(acl.Refusal):acl.grant(None,None,self.ledger)
        self.assertEqual((outside/'protected').read_text(),'untouched')
        self.assertFalse(json.loads(self.ledger.read_text()).get('crossDomainAclStatus'))

class MountScreen(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='p0-acl-proc-unit-');self.addCleanup(temp.cleanup)
        self.proc=Path(temp.name);(self.proc/'123').mkdir();self.mountinfo=self.proc/'123/mountinfo'
    def test_selected_namespace_mount_refuses(self):
        self.mountinfo.write_text('1 2 0:1 / /selected/child rw - tmpfs tmpfs rw\n')
        with self.assertRaisesRegex(acl.Refusal,'mounted in a process namespace'):acl.assert_no_mounts('/selected',self.proc)
    def test_unrelated_mount_passes(self):
        self.mountinfo.write_text('1 2 0:1 / /unrelated rw - tmpfs tmpfs rw\n');acl.assert_no_mounts('/selected',self.proc)
    def test_unknown_mountinfo_error_is_a_closed_refusal(self):
        with patch.object(Path,'read_text',side_effect=OSError(22,'Invalid argument')):
            with self.assertRaisesRegex(acl.Refusal,'inspection unavailable'):acl.assert_no_mounts('/selected',self.proc)
    def test_permission_denied_is_not_ignored(self):
        with patch.object(Path,'read_text',side_effect=PermissionError('unreadable')):
            with self.assertRaisesRegex(acl.Refusal,'inspection unavailable'):acl.assert_no_mounts('/selected',self.proc)
    def test_disappeared_process_is_not_a_mount(self):
        acl.assert_no_mounts('/selected',self.proc)

if __name__=='__main__':unittest.main()
