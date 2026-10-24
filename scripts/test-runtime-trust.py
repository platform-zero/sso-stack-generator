#!/usr/bin/env python3
"""Nonroot source/mock tests plus separately skipped isolated root fixtures.

No native manager/container calls, installation or deployed security acceptance.
Run with python3 -B scripts/test-runtime-trust.py; never use sudo for this suite.
"""
from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

path=Path(__file__).resolve().parents[1]/'runtime-generator/podman-ops/runtime-trust.py'
spec=importlib.util.spec_from_file_location('runtime_trust_fixture',path)
trust=importlib.util.module_from_spec(spec);spec.loader.exec_module(trust)

@unittest.skipUnless(os.geteuid()==0,'isolated ownership/denial fixtures require root')
class Trust(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o755)
        self.private=self.root/'private';self.public=self.root/'public';self.target=self.root/'leaf'
        for p in (self.private,self.public,self.target):p.mkdir(mode=0o750)
        self.key=self.root/'fixture.key';self.cert=self.root/'fixture.crt'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(self.key),'-out',str(self.cert)],
            check=True,capture_output=True,timeout=20)
        self.key.chmod(0o600);self.cert.chmod(0o644)
        (self.public/'caddy-ca.crt').write_bytes(self.cert.read_bytes())
        (self.private/'root.key').write_bytes(self.key.read_bytes());(self.private/'root.key').chmod(0o600)
    def tearDown(self):self.tmp.cleanup()
    def actor(self,code):
        return subprocess.run(['setpriv','--reuid=65533','--regid=65533','--clear-groups',
            'python3','-B','-c',code],capture_output=True,timeout=10).returncode
    def test_public_certificate_only_and_private_key_denial(self):
        trust.prepare(self.private,self.public,self.target)
        self.assertEqual(self.actor(f'open({str(self.public/"caddy-ca.crt")!r}).read()'),0)
        self.assertNotEqual(self.actor(f'open({str(self.public/"caddy-ca.crt")!r},"ab").write(b"x")'),0)
        self.assertNotEqual(self.actor(f'open({str(self.private/"root.key")!r},"rb").read()'),0)
        (self.public/'caddy-ca.crt').write_bytes(self.key.read_bytes())
        with self.assertRaises(ValueError):trust.prepare(self.private,self.public,self.target)
    def test_atomic_leaf_pair_and_no_ca_private_delegation(self):
        cert,key=self.cert.read_bytes(),self.key.read_bytes()
        trust.validate_leaf(cert,key,'mail.example.test')
        with self.assertRaises(ValueError):trust.validate_leaf(cert,key,'other.example.test')
        trust.prepare(self.private,self.public,self.target)
        name=trust.publish(self.target,cert,key,65533)
        self.assertEqual(os.readlink(self.target/'current'),'generations/'+name)
        self.assertEqual((self.target/'current/key.pem').read_bytes(),key)
        self.assertEqual(self.actor(f'open({str(self.target/"current/key.pem")!r},"rb").read()'),0)
        self.assertNotEqual(self.actor(f'open({str(self.target/"current/key.pem")!r},"ab").write(b"x")'),0)
        self.assertNotEqual(self.actor(f'open({str(self.private/"root.key")!r},"rb").read()'),0)
        self.assertEqual(trust.publish(self.target,cert,key,65533),name)
        self.assertEqual(len(list((self.target/'generations').iterdir())),1)
    def test_shared_public_parent_gets_only_scoped_execute(self):
        import pwd
        from unittest.mock import patch
        helper=path.with_name('grant-rootless-volume-parent-traverse.py')
        spec=importlib.util.spec_from_file_location('trust_parent_fixture',helper)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        scope=self.root/'scope';scope.mkdir(mode=0o700)
        parent=scope/'volumes';parent.mkdir(mode=0o700)
        public=parent/'public';public.mkdir(mode=0o755)
        before=subprocess.check_output(['getfacl','-cpn',str(self.root)])
        account=pwd.getpwnam('nobody')
        expected={'domains':[{'user':account.pw_name,'uid':account.pw_uid}]}
        with patch.object(trust,'storage_binding',return_value=(module,scope,pwd.getpwuid(0),expected)):
            trust.grant_public_parents(Path('/fixture-bundle'),public)
        self.assertEqual(before,subprocess.check_output(['getfacl','-cpn',str(self.root)]))
        for folder in (scope,parent):
            acl=subprocess.check_output(['getfacl','-cpn',str(folder)]).decode()
            self.assertIn(f'user:{account.pw_uid}:--x',acl)
            self.assertNotIn(f'user:{account.pw_uid}:r',acl)

    def test_derived_public_store_revokes_inherited_creator_write_not_parent(self):
        subprocess.run(['setfacl','-m','u:65533:rwx,g::rwx',str(self.public)],check=True,capture_output=True)
        before=self.root.stat().st_mode
        self.assertTrue(self.public.stat().st_mode&0o020)
        trust.prepare(self.private,self.public,self.target)
        self.assertEqual(self.root.stat().st_mode,before)
        self.assertEqual(self.public.stat().st_mode&0o777,0o755)
        self.assertNotEqual(self.actor(f'open({str(self.public/"replacement")!r},"w").write("x")'),0)

    def test_rootful_mail_leaf_remains_root_private(self):
        cert,key=self.cert.read_bytes(),self.key.read_bytes()
        trust.publish(self.target,cert,key,0)
        self.assertEqual((self.target/'current/key.pem').stat().st_mode&0o777,0o600)
        self.assertNotEqual(self.actor(f'open({str(self.target/"current/key.pem")!r},"rb").read()'),0)

    def test_links_and_foreign_artifacts_refused(self):
        (self.public/'unexpected.key').write_bytes(b'synthetic-not-a-key')
        with self.assertRaises(ValueError):trust.prepare(self.private,self.public,self.target)
        (self.public/'unexpected.key').unlink();(self.public/'caddy-ca.crt').unlink()
        (self.public/'caddy-ca.crt').symlink_to(self.cert)
        with self.assertRaises((ValueError,OSError)):trust.prepare(self.private,self.public,self.target)
        (self.public/'caddy-ca.crt').unlink();(self.public/'caddy-ca.crt').symlink_to(self.root/'absent')
        with self.assertRaises((ValueError,OSError)):trust.prepare(self.private,self.public,self.target)
    def test_private_ca_cannot_be_published_as_leaf(self):
        ca=self.root/'ca.crt'
        subprocess.run(['openssl','req','-x509','-new','-key',str(self.key),'-days','1',
            '-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:TRUE','-out',str(ca)],check=True,capture_output=True)
        with self.assertRaises(ValueError):trust.validate_leaf(ca.read_bytes(),self.key.read_bytes(),'mail.example.test')

class RotationSource(unittest.TestCase):
    """Pure mocked orchestrator contract; no host or application operations."""
    def setUp(self):
        self.bundle=Path('/var/lib/stack-test/releases/r1')
        self.paths=[Path('/selected/private'),Path('/selected/public'),Path('/selected/mail')]
        self.cert=b'synthetic-certificate';self.key=b'synthetic-key-not-a-real-key'
        self.name=hashlib.sha256(self.cert).hexdigest();self.cas='a'*64
        self.authority={'paths':self.paths,'uid':23456,'hostname':'mail.example.test','intentSha256':self.cas}
        self.actor={'command':['selected-manager'],'unit':trust.MAIL_UNIT,'source':b'selected-quadlet'}
        self.receipt={'schemaVersion':1,'generation':self.name,'uid':23456,
            'sourceSha256':hashlib.sha256(self.actor['source']).hexdigest(),'intentSha256':self.cas}
        values={'selected_authority':self.authority,'mail_actor':self.actor,'active_mail':None,
            'certificates_only':None,'read_at':b'certificate-only-fixture','validate_publication':None,
            'current_generation':None,'reload_receipt':None,'read_leaf':(self.cert,self.key),
            'publish':self.name,'command':b'','write_reload_receipt':None}
        self.mocks={}
        for name,value in values.items():
            p=patch.object(trust,name,return_value=value);self.mocks[name]=p.start();self.addCleanup(p.stop)
        self.mocks['current_generation'].side_effect=[None,self.name]
    def run_rotation(self):return trust.rotate_mail(self.bundle)
    def no_publication(self):
        self.mocks['publish'].assert_not_called();self.mocks['command'].assert_not_called()
        self.mocks['write_reload_receipt'].assert_not_called()
    def test_changed_active_exact_reload_and_ack(self):
        result=self.run_rotation()
        self.assertTrue(result['changed']);self.assertTrue(result['reloaded']);self.assertFalse(result['deferred'])
        self.mocks['publish'].assert_called_once_with(self.paths[2],self.cert,self.key,23456)
        self.mocks['command'].assert_called_once_with(['selected-manager','--no-ask-password',
            '--job-mode=fail','reload',trust.MAIL_UNIT])
        self.mocks['write_reload_receipt'].assert_called_once_with(self.paths[2],self.receipt)
        for call in self.mocks['selected_authority'].call_args_list[1:]:self.assertEqual(call.kwargs,{'expected':self.cas})
        body=json.dumps(result)
        self.assertNotIn(self.key.decode(),body);self.assertNotIn(self.cert.decode(),body)
    def test_acknowledged_unchanged_has_no_write_or_reload(self):
        self.mocks['current_generation'].side_effect=None;self.mocks['current_generation'].return_value=self.name
        self.mocks['reload_receipt'].return_value=self.receipt
        result=self.run_rotation()
        self.assertFalse(result['changed']);self.assertFalse(result['reloaded']);self.assertFalse(result['deferred'])
        self.no_publication()
    def test_published_but_unacknowledged_retries_reload(self):
        self.mocks['current_generation'].side_effect=None;self.mocks['current_generation'].return_value=self.name
        result=self.run_rotation()
        self.assertFalse(result['changed']);self.assertTrue(result['reloaded'])
        self.mocks['command'].assert_called_once()
    def test_stopped_failed_pending_unsupported_defer_before_key_read(self):
        for reason in ('mailserver-not-active','mailserver-job-pending','mail-reload-not-configured'):
            with self.subTest(reason=reason):
                self.mocks['active_mail'].return_value=reason
                result=self.run_rotation();self.assertEqual(result['reason'],reason);self.assertTrue(result['deferred'])
                self.no_publication();self.mocks['read_leaf'].assert_not_called()
    def test_no_mail_selected_has_no_actor_or_material_access(self):
        self.authority['paths']=[self.paths[0],self.paths[1],None]
        self.assertEqual(self.run_rotation()['reason'],'mailserver-not-selected')
        self.no_publication();self.mocks['mail_actor'].assert_not_called();self.mocks['read_leaf'].assert_not_called()
    def test_pending_issuance_is_deferred_not_waited(self):
        self.mocks['read_leaf'].side_effect=FileNotFoundError()
        with patch.object(trust.time,'sleep') as sleep:
            self.assertEqual(self.run_rotation()['reason'],'mail-leaf-not-issued');sleep.assert_not_called()
        self.no_publication()
    def test_invalid_public_or_leaf_material_refuses_without_publish(self):
        self.mocks['certificates_only'].side_effect=ValueError('synthetic refusal')
        with self.assertRaises(ValueError):self.run_rotation()
        self.no_publication()
        self.mocks['certificates_only'].side_effect=None;self.mocks['read_leaf'].side_effect=ValueError('synthetic refusal')
        with self.assertRaises(ValueError):self.run_rotation()
        self.no_publication()
    def test_cas_changed_before_publication_refuses(self):
        self.mocks['selected_authority'].side_effect=[self.authority,ValueError('CAS changed')]
        with self.assertRaises(ValueError):self.run_rotation()
        self.no_publication()
    def test_cas_changed_after_publication_never_reloads_or_acks(self):
        self.mocks['selected_authority'].side_effect=[self.authority,self.authority,ValueError('CAS changed')]
        with self.assertRaises(ValueError):self.run_rotation()
        self.mocks['publish'].assert_called_once();self.mocks['command'].assert_not_called()
        self.mocks['write_reload_receipt'].assert_not_called()
    def test_stops_after_publication_defer_without_start_or_ack(self):
        self.mocks['active_mail'].side_effect=[None,'mailserver-not-active']
        result=self.run_rotation();self.assertTrue(result['changed']);self.assertTrue(result['deferred'])
        self.mocks['publish'].assert_called_once();self.mocks['command'].assert_not_called()
        self.mocks['write_reload_receipt'].assert_not_called()
    def test_reload_failure_has_changed_deferred_metadata_no_ack(self):
        for error in (ValueError('reload refused'),subprocess.TimeoutExpired('synthetic',20)):
            self.mocks['command'].side_effect=error
            result=self.run_rotation()
            self.assertEqual(result['reason'],'mail-reload-failed');self.assertTrue(result['deferred'])
            self.assertTrue(result['changed']);self.assertFalse(result['reloaded'])
            self.mocks['write_reload_receipt'].assert_not_called()
            self.mocks['current_generation'].side_effect=[None,self.name]
    def test_stop_or_cas_change_after_reload_does_not_ack(self):
        self.mocks['active_mail'].side_effect=[None,None,'mailserver-not-active']
        result=self.run_rotation();self.assertTrue(result['deferred']);self.assertFalse(result['reloaded'])
        self.mocks['write_reload_receipt'].assert_not_called()
    def test_generation_race_does_not_ack(self):
        self.mocks['current_generation'].side_effect=[None,'b'*64]
        with self.assertRaises(ValueError):self.run_rotation()
        self.mocks['write_reload_receipt'].assert_not_called()


class BindingSource(unittest.TestCase):
    def test_storage_binding_calls_existing_authority_and_exact_marker(self):
        bundle=Path('/selected/release');scope=Path('/selected/scope');operator=object();expected={'synthetic':'identity'}
        module=SimpleNamespace(authority=Mock(return_value=(scope,operator,expected)),marker=Mock())
        spec=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
        with patch.object(trust.importlib.util,'spec_from_file_location',return_value=spec), \
             patch.object(trust.importlib.util,'module_from_spec',return_value=module):
            self.assertEqual(trust.storage_binding(bundle),(module,scope,operator,expected))
        module.authority.assert_called_once_with(bundle);module.marker.assert_called_once_with(scope,expected)
    def test_binding_scope_reader_policy_and_exact_mail_actor(self):
        bundle=Path('/selected/release');scope=Path('/selected/scope');operator=object()
        helper_spec=importlib.util.spec_from_file_location('trust_path_fixture',path.with_name('grant-rootless-volume-parent-traverse.py'))
        helper=importlib.util.module_from_spec(helper_spec);helper_spec.loader.exec_module(helper)
        module=SimpleNamespace(normal_path=helper.normal_path,safe_parent=Mock())
        expected={'domains':[{'name':'mail','uid':23456}]}
        ir={'volumes':{'caddy_certs':{'hostPath':str(scope/'private')},
            'caddy_ca':{'hostPath':str(scope/'public'),'rootlessAccess':'read-only'},
            'mail_tls':{'hostPath':str(scope/'leaf'),'rootlessAccess':'read-only'}},
            'services':{'mailserver':{'placement':'rootless','rootlessDomain':'mail'}}}
        def read(root,name,**kwargs):return b'DOMAIN=example.test\n' if name=='runtime/stack.env' else json.dumps(ir).encode()
        with patch.object(trust,'storage_binding',return_value=(module,scope,operator,expected)), \
             patch.object(trust,'read_at',side_effect=read):
            paths,uid,host=trust.binding(bundle)
            self.assertEqual((uid,host),(23456,'mail.example.test'));self.assertEqual(paths,[scope/'private',scope/'public',scope/'leaf'])
            module.safe_parent.assert_called_once_with(scope,operator)
            for value in ('/outside','/selected/scope/../outside',str(scope/'private'),str(scope/'private/child')):
                ir['volumes']['mail_tls']['hostPath']=value
                with self.assertRaises(ValueError):trust.binding(bundle)
            ir['volumes']['mail_tls']['hostPath']=str(scope/'leaf')
            ir['volumes']['mail_tls']['rootlessAccess']='read-write'
            with self.assertRaises(ValueError):trust.binding(bundle)
            ir['volumes']['mail_tls']['rootlessAccess']='read-only';ir['services']['mailserver']['placement']='unknown'
            with self.assertRaises(ValueError):trust.binding(bundle)
    def test_marker_failure_prevents_binding_result(self):
        module=SimpleNamespace(authority=Mock(return_value=(Path('/scope'),object(),{})),marker=Mock(side_effect=ValueError('marker mismatch')))
        spec=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
        with patch.object(trust.importlib.util,'spec_from_file_location',return_value=spec), \
             patch.object(trust.importlib.util,'module_from_spec',return_value=module):
            with self.assertRaises(ValueError):trust.storage_binding(Path('/release'))


class AuthoritySource(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.bundle=Path('/var/lib/stack-test/releases/r1')
        jpath=path.with_name('install-journal.py')
        spec=importlib.util.spec_from_file_location('trust_journal_fixture',jpath)
        journal=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal)
        self.files={name:b'{}' for name in journal.CORE_INPUTS+journal.PINNED_INPUTS}
        for name in ('podman-domains.json','site/manifest.json'):
            self.files[name]=json.dumps({'deploymentMode':'standalone','installerStateRoot':'/var/lib/stack-test'}).encode()
        self.intent={'schemaVersion':1,'phase':'active','release':str(self.bundle),
            'steps':['preparing','units-selected','building','starting','active'],
            'previousRelease':None,'resumedFrom':None,
            'inputs':{name:hashlib.sha256(body).hexdigest() for name,body in self.files.items()}}
        self.sync()
        def read(root,name,**kwargs):
            if name not in self.files:raise FileNotFoundError()
            return self.files[name]
        self.patches=[patch.object(trust,'read_at',side_effect=read),
            patch.object(trust,'directory',side_effect=lambda p:os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)),
            patch.object(trust.os,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFLNK,st_uid=0,st_nlink=1)),
            patch.object(trust.os,'readlink',return_value=str(self.bundle)),
            patch.object(trust,'binding',return_value=([Path('/private'),Path('/public'),Path('/mail')],0,'mail.example.test'))]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def sync(self):
        body=json.dumps(self.intent).encode();self.files['.install-intent.json']=body;self.files['installation-receipt.json']=body
    def test_complete_pins_receipt_selected_pointer_and_cas(self):
        value=trust.selected_authority(self.bundle)
        self.assertEqual(value['intentSha256'],hashlib.sha256(self.files['.install-intent.json']).hexdigest())
        trust.selected_authority(self.bundle,expected=value['intentSha256'])
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle,expected='0'*64)
    def test_failed_retired_unknown_pending_journal_cannot_rotate(self):
        for phase in ('failed','retired-failed','preparing','units-selected','building','starting','unknown'):
            with self.subTest(phase=phase):
                self.intent['phase']=phase;self.sync()
                with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_existing_internal_building_only(self):
        self.intent['phase']='building';self.intent['steps']=['preparing','units-selected','building']
        self.sync();trust.selected_authority(self.bundle,internal=True)
        self.intent['phase']='active';self.sync()
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle,internal=True)
    def test_receipt_mismatch_or_missing_refuses(self):
        self.files['installation-receipt.json']=b'{}'
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
        del self.files['installation-receipt.json']
        with self.assertRaises(FileNotFoundError):trust.selected_authority(self.bundle)
    def test_missing_old_extra_changed_and_linked_pins_refuse(self):
        for name in ('site/manifest.json','podman-domains.json','bundle.json'):
            saved=self.files[name];self.files[name]=b'changed'
            with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
            self.files[name]=saved
        del self.intent['inputs']['site/manifest.json'];self.sync()
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_absent_optional_pin_is_exact_not_silently_ignored(self):
        name='site/agent-vm.json';self.intent['inputs'][name]=None;del self.files[name];self.sync()
        trust.selected_authority(self.bundle)
        self.files[name]=b'{}'
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_current_alias_or_foreign_owner_refuses(self):
        for destination in ('../releases/r1','/var/lib/stack-test/releases/r2'):
            with patch.object(trust.os,'readlink',return_value=destination):
                with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
        with patch.object(trust.os,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFLNK,st_uid=1000,st_nlink=1)):
            with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_unknown_journal_shape_steps_and_claims_refuse(self):
        original=dict(self.intent)
        for change in ({'extra':True},{'steps':['active']},{'previousRelease':'/outside/releases/r0'},
                       {'resumedFrom':'relative'},{'schemaVersion':True}):
            self.intent=dict(original,**change);self.sync()
            with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_semantically_equal_but_changed_receipt_bytes_refuse(self):
        self.files['installation-receipt.json']=json.dumps(self.intent,indent=2).encode()
        with self.assertRaises(ValueError):trust.selected_authority(self.bundle)
    def test_state_root_and_nonstandalone_mismatch_refuse(self):
        for value in ({'deploymentMode':'standalone','installerStateRoot':'/var/lib/unrelated'},
                      {'deploymentMode':'guest','installerStateRoot':'/var/lib/stack-test'}):
            body=json.dumps(value).encode();self.files['site/manifest.json']=body
            self.intent['inputs']['site/manifest.json']=hashlib.sha256(body).hexdigest();self.sync()
            with self.assertRaises(ValueError):trust.selected_authority(self.bundle)


class ActorSource(unittest.TestCase):
    def source(self,configured=True):
        return ('[Container]\nContainerName=mailserver\n[Service]\n'+
            (''.join('ExecReload='+s+'\n' for s in trust.MAIL_RELOAD) if configured else '')).encode()
    def actor(self,placement='rootful',uid=0,configured=True):
        ir={'services':{'mailserver':{'placement':placement,'rootlessDomain':'mail'}}}
        source=self.source(configured)
        with patch.object(trust,'read_at',side_effect=lambda root,name,**kw:json.dumps(ir).encode() if name=='stack.ir.json' else source):
            return trust.mail_actor(Path('/installed'),uid)
    def test_rootful_selects_only_exact_system_manager_unit(self):
        actor=self.actor()
        self.assertEqual(actor['command'],['systemctl']);self.assertEqual(actor['owner'],0)
        self.assertEqual(actor['installed'],Path('/etc/containers/systemd/webservices-mailserver.container'))
        self.assertTrue(actor['reloadConfigured'])
    def test_rootless_selects_only_bound_manager_and_home(self):
        row={'name':'mail','user':'test-mail','uid':23456}
        with patch.object(trust,'storage_binding',return_value=(None,None,None,{'domains':[row]})), \
             patch.object(trust.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=23456,pw_dir='/home/test-mail')):
            actor=self.actor('rootless',23456)
        self.assertEqual(actor['command'],['runuser','-u','test-mail','--','env','HOME=/home/test-mail',
            'XDG_RUNTIME_DIR=/run/user/23456','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/23456/bus','systemctl','--user'])
        self.assertEqual(actor['installed'],Path('/home/test-mail/.config/containers/systemd/webservices-mailserver.container'))
    def test_unknown_actor_and_rootless_identity_drift_refused(self):
        for placement,uid in (('unknown',0),('rootful',123),('rootless',0),('rootful',False)):
            with self.assertRaises(ValueError):self.actor(placement,uid)
        with patch.object(trust,'storage_binding',return_value=(None,None,None,{'domains':[]})):
            with self.assertRaises(ValueError):self.actor('rootless',23456)
    def test_missing_reload_is_not_advertised_as_supported(self):
        self.assertFalse(self.actor(configured=False)['reloadConfigured'])
    def test_active_probe_fail_closed_and_never_mutates_manager(self):
        actor=self.actor()
        props={'Id':trust.MAIL_UNIT,'LoadState':'loaded','ActiveState':'active','SubState':'running',
            'SourcePath':str(actor['installed']),'DropInPaths':'','NeedDaemonReload':'no','CanReload':'yes','Job':'',
            'PropagatesReloadTo':'','OnFailure':'','OnSuccess':''}
        def body():return ''.join(k+'='+v+'\n' for k,v in props.items()).encode()
        with patch.object(trust,'installed_source') as check,patch.object(trust,'command',side_effect=lambda args:body()) as call:
            self.assertIsNone(trust.active_mail(actor));check.assert_called_once_with(actor)
            self.assertEqual(call.call_args.args[0][2:4],['show',trust.MAIL_UNIT])
            self.assertIn('--all',call.call_args.args[0])
            props['Job']='0';self.assertIsNone(trust.active_mail(actor));props['Job']=''
            for state in ('inactive','failed','activating','deactivating','reloading'):
                props['ActiveState']=state;self.assertEqual(trust.active_mail(actor),'mailserver-not-active')
            props['ActiveState']='active';props['Job']='7'
            self.assertEqual(trust.active_mail(actor),'mailserver-job-pending');props['Job']=''
            props['CanReload']='no';self.assertEqual(trust.active_mail(actor),'mail-reload-not-configured');props['CanReload']='yes'
            for key,value in (('Id','unrelated.service'),('LoadState','not-found'),('DropInPaths','/foreign'),
                              ('NeedDaemonReload','yes'),('SourcePath','/foreign'),('SubState','dead'),('ActiveState','mystery'),
                              ('Job','unknown'),('PropagatesReloadTo','unrelated.service'),('OnFailure','unrelated.service'),
                              ('OnSuccess','unrelated.service')):
                old=props[key];props[key]=value
                with self.assertRaises(ValueError):trust.active_mail(actor)
                props[key]=old
            del props['Job']
            with self.assertRaises(ValueError):trust.active_mail(actor)


class FilesystemSource(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    @contextmanager
    def synthetic_root(self):
        # Only synthetic temp inodes: spoof UID, NOT file type/link count/modes.
        real_fstat=os.fstat
        def root_stat(fd):
            info=real_fstat(fd)
            return SimpleNamespace(**{name:(0 if name=='st_uid' else getattr(info,name)) for name in
                ('st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns','st_dev','st_ino')})
        with patch.object(trust.os,'fstat',side_effect=root_stat):yield
    def test_canonical_paths_duplicate_json_and_relative_escape_refused(self):
        for p in (Path('relative'),Path('/safe/../outside'),Path('//safe/x')):
            with self.assertRaises(ValueError):trust.canonical(p)
        with self.assertRaises(ValueError):trust.strict_json(b'{"a":1,"a":2}')
        for p in (Path('/root/current'),Path('/root/releases/..'),Path('/root/releases/-bad')):
            with self.assertRaises(ValueError):trust.installer_root(p)
        with self.synthetic_root():
            for name in ('../outside','/absolute','./file','a//b'):
                with self.assertRaises(ValueError):trust.read_at(self.root,name)
    def test_nonroot_ownership_is_not_admitted(self):
        if os.geteuid()==0:self.skipTest('nonroot denial case')
        with self.assertRaises(ValueError):trust.directory(self.root)
    def test_link_hardlink_fifo_permissions_and_size_refused(self):
        regular=self.root/'regular';regular.write_bytes(b'synthetic');regular.chmod(0o600)
        (self.root/'linked').symlink_to(regular);os.link(regular,self.root/'hardlinked')
        os.mkfifo(self.root/'fifo',0o600)
        with self.synthetic_root():
            for name in ('linked','hardlinked','regular','fifo'):
                with self.assertRaises((ValueError,OSError)):trust.read_at(self.root,name)
            (self.root/'hardlinked').unlink()
            self.assertEqual(trust.read_at(self.root,'regular',mode=0o600),b'synthetic')
            with self.assertRaises(ValueError):trust.read_at(self.root,'regular',limit=2)
            with self.assertRaises(ValueError):trust.read_at(self.root,'regular',mode=0o644)
            regular.chmod(0o622)
            with self.assertRaises(ValueError):trust.read_at(self.root,'regular')
    def test_intermediate_links_or_writable_parent_refused(self):
        child=self.root/'child';child.mkdir(mode=0o700);(child/'value').write_bytes(b'synthetic')
        (self.root/'alias').symlink_to(child,target_is_directory=True)
        with self.synthetic_root():
            with self.assertRaises(OSError):trust.read_at(self.root,'alias/value')
            child.chmod(0o777)
            with self.assertRaises(ValueError):trust.read_at(self.root,'child/value')
    def test_installed_source_exact_actor_owner_bytes_and_no_links(self):
        source=self.root/'mail.container';source.write_bytes(b'synthetic');source.chmod(0o600)
        actor={'installed':source,'owner':os.getuid(),'source':b'synthetic'}
        # Production ancestors are protected; /tmp is intentionally writable,
        # so fake only that ancestor mode in this isolated source fixture.
        real=os.fstat
        def metadata(fd):
            info=real(fd)
            return SimpleNamespace(st_uid=info.st_uid,st_mode=info.st_mode&~0o022,st_nlink=info.st_nlink,st_size=info.st_size)
        with patch.object(trust.os,'fstat',side_effect=metadata):
            trust.installed_source(actor)
            actor['source']=b'wrong'
            with self.assertRaises(ValueError):trust.installed_source(actor)
            actor['source']=b'synthetic';os.link(source,self.root/'hard')
            with self.assertRaises(ValueError):trust.installed_source(actor)
            (self.root/'hard').unlink();source.unlink();source.symlink_to(self.root/'missing')
            with self.assertRaises(OSError):trust.installed_source(actor)
    def test_external_and_internal_same_lock_busy_and_identity(self):
        lock=self.root/'.install.lock';lock.touch(mode=0o600)
        real_stat=os.stat
        def root_stat(*args,**kwargs):
            info=real_stat(*args,**kwargs)
            return SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino,st_nlink=info.st_nlink)
        with self.synthetic_root(),patch.object(trust.os,'stat',side_effect=root_stat):
            with trust.installer_lock(self.root) as held:
                self.assertTrue(held)
                with trust.installer_lock(self.root) as busy:self.assertFalse(busy)
            inherited=os.open(lock,os.O_RDWR)
            try:
                trust.fcntl.flock(inherited,trust.fcntl.LOCK_EX|trust.fcntl.LOCK_NB)
                with trust.installer_lock(self.root,inherited) as held:self.assertTrue(held)
                with trust.installer_lock(self.root) as busy:self.assertFalse(busy)
                foreign=self.root/'foreign';foreign.touch(mode=0o600);fd=os.open(foreign,os.O_RDWR)
                try:
                    with self.assertRaises(ValueError):
                        with trust.installer_lock(self.root,fd):pass
                finally:os.close(fd)
            finally:os.close(inherited)
            with trust.installer_lock(self.root) as held:self.assertTrue(held)
    def test_descriptor_only_publication_pair_rotation_and_no_unrelated_mutation(self):
        unrelated=self.root/'outside';unrelated.write_bytes(b'untouched')
        target=self.root/'target';target.mkdir(mode=0o700)
        real_stat=os.stat
        def root_link(*args,**kwargs):
            info=real_stat(*args,**kwargs)
            return SimpleNamespace(st_uid=0,st_mode=info.st_mode,st_nlink=info.st_nlink)
        with self.synthetic_root(),patch.object(trust.os,'stat',side_effect=root_link),patch.object(trust,'reader') as reader:
            first=trust.publish(target,b'synthetic-cert-one',b'synthetic-key-one',123)
            self.assertEqual(trust.current_generation(target),first)
            self.assertEqual((target/'current/key.pem').read_bytes(),b'synthetic-key-one')
            self.assertEqual(trust.publish(target,b'synthetic-cert-one',b'synthetic-key-one',123),first)
            second=trust.publish(target,b'synthetic-cert-two',b'synthetic-key-two',0)
            self.assertNotEqual(first,second);self.assertEqual(trust.current_generation(target),second)
            self.assertEqual([p.name for p in (target/'generations').iterdir()],[second])
            self.assertEqual((target/'current/key.pem').read_bytes(),b'synthetic-key-two')
            for call in reader.call_args_list:self.assertIs(type(call.args[0]),int)
        self.assertEqual(unrelated.read_bytes(),b'untouched')
    def test_unknown_generation_or_selector_never_writes_new_pair(self):
        generations=self.root/'generations';generations.mkdir(mode=0o700)
        foreign=generations/('a'*64);foreign.mkdir(mode=0o700);(foreign/'foreign').write_bytes(b'untouched')
        with self.synthetic_root(),patch.object(trust,'reader') as reader:
            with self.assertRaises(ValueError):trust.publish(self.root,b'new-cert',b'new-key',0)
            self.assertEqual([p.name for p in generations.iterdir()],['a'*64]);reader.assert_not_called()
        self.assertEqual((foreign/'foreign').read_bytes(),b'untouched')
    def test_reader_acl_operations_are_pinned_to_inherited_descriptor(self):
        item=self.root/'key';item.write_bytes(b'synthetic');fd=os.open(item,os.O_RDONLY)
        try:
            with self.synthetic_root(),patch.object(trust,'command',return_value=b'') as command:
                trust.reader(fd,123)
                self.assertEqual(command.call_args_list[0].args[0],['setfacl','-b','/proc/self/fd/'+str(fd)])
                self.assertEqual(command.call_args_list[1].args[0],['setfacl','-m','u:123:r--,m::r--','/proc/self/fd/'+str(fd)])
                for call in command.call_args_list:self.assertEqual(call.kwargs,{'pass_fds':(fd,)})
                command.reset_mock();trust.reader(fd,0);self.assertEqual(command.call_count,1)
        finally:os.close(fd)
    def test_reload_receipt_atomic_metadata_only_and_strict_schema(self):
        receipt={'schemaVersion':1,'uid':123,'generation':'a'*64,'intentSha256':'b'*64,'sourceSha256':'c'*64}
        with self.synthetic_root():
            trust.write_reload_receipt(self.root,receipt)
            self.assertEqual(trust.reload_receipt(self.root),receipt)
            body=(self.root/'.reload-receipt.json').read_bytes()
            self.assertEqual((self.root/'.reload-receipt.json').stat().st_mode&0o777,0o600)
            self.assertNotIn(b'PRIVATE KEY',body)
            (self.root/'.reload-receipt.json').write_text('{"unexpected":"field"}')
            with self.assertRaises(ValueError):trust.reload_receipt(self.root)
    def test_unknown_publication_namespace_refuses_without_deleting(self):
        foreign=self.root/'foreign';foreign.write_bytes(b'untouched')
        with self.synthetic_root():
            with self.assertRaises(ValueError):trust.validate_publication(self.root)
        self.assertEqual(foreign.read_bytes(),b'untouched')


class EntrySource(unittest.TestCase):
    def setUp(self):
        self.bundle='/var/lib/stack-test/releases/r1'
    def invoke(self,flags,locked=True):
        @contextmanager
        def lock(*args,**kwargs):yield locked
        with patch.object(sys,'argv',['runtime-trust.py','--bundle',self.bundle,*flags]), \
             patch.object(trust.os,'geteuid',return_value=0), \
             patch.object(trust,'installer_lock',side_effect=lock) as locking, \
             redirect_stdout(io.StringIO()) as output:
            trust.main()
            return locking,json.loads(output.getvalue())
    def test_external_busy_does_not_read_journal_or_leaf(self):
        with patch.object(trust,'selected_authority') as authority,patch.object(trust,'rotate_mail') as rotate:
            locking,result=self.invoke(['--rotate-mail'],False)
            locking.assert_called_once_with(Path('/var/lib/stack-test'),None)
            self.assertEqual(result['reason'],'installer-busy');self.assertTrue(result['deferred'])
            authority.assert_not_called();rotate.assert_not_called()
    def test_external_cli_forwards_optional_cas_without_internal_fd(self):
        with patch.object(trust,'rotate_mail',return_value=trust.rotation_result()) as rotate:
            locking,result=self.invoke(['--rotate-mail','--expected-intent','a'*64])
            locking.assert_called_once_with(Path('/var/lib/stack-test'),None)
            rotate.assert_called_once_with(Path(self.bundle),'a'*64)
            self.assertFalse(result['changed'])
    def test_existing_prepare_inherits_fd9_without_reload(self):
        paths=[Path('/selected/private'),Path('/selected/public'),None]
        value={'paths':paths,'uid':None,'hostname':None,'intentSha256':'a'*64}
        with patch.object(trust,'selected_authority',return_value=value) as authority, \
             patch.object(trust,'prepare') as prepare,patch.object(trust,'grant_public_parents') as grant, \
             patch.object(trust,'command') as command:
            locking,result=self.invoke(['--prepare'])
            locking.assert_called_once_with(Path('/var/lib/stack-test'),9)
            authority.assert_called_once_with(Path(self.bundle),internal=True)
            prepare.assert_called_once_with(*paths);grant.assert_called_once_with(Path(self.bundle),paths[1])
            command.assert_not_called();self.assertTrue(result['trustPrepared'])
    def test_existing_publish_inherits_fd9_without_reload_or_ack(self):
        paths=[Path('/selected/private'),Path('/selected/public'),Path('/selected/leaf')]
        value={'paths':paths,'uid':0,'hostname':'mail.example.test','intentSha256':'a'*64}
        with patch.object(trust,'selected_authority',return_value=value) as authority, \
             patch.object(trust,'read_leaf',return_value=(b'cert',b'key')), \
             patch.object(trust,'read_at',return_value=b'public'),patch.object(trust,'certificates_only'), \
             patch.object(trust,'current_generation',return_value=None),patch.object(trust,'publish',return_value='b'*64), \
             patch.object(trust,'command') as command,patch.object(trust,'write_reload_receipt') as ack:
            locking,result=self.invoke(['--publish-mail'])
            locking.assert_called_once_with(Path('/var/lib/stack-test'),9)
            self.assertTrue(result['changed']);self.assertTrue(result['mailLeafPublished']);self.assertFalse(result['reloaded'])
            authority.assert_called_with(Path(self.bundle),internal=True,expected='a'*64)
            command.assert_not_called();ack.assert_not_called()
    def test_reload_failure_cli_exits_nonzero_after_safe_metadata(self):
        with patch.object(trust,'rotate_mail',return_value=trust.rotation_result('mail-reload-failed',changed=True)):
            with self.assertRaises(SystemExit) as error:self.invoke(['--rotate-mail'])
            self.assertEqual(error.exception.code,1)
    def test_nonroot_entry_refuses_before_lock_or_bundle_access(self):
        with patch.object(sys,'argv',['runtime-trust.py','--bundle',self.bundle,'--rotate-mail']), \
             patch.object(trust.os,'geteuid',return_value=123),patch.object(trust,'installer_lock') as locking:
            with self.assertRaises(ValueError):trust.main()
            locking.assert_not_called()


class CommandSource(unittest.TestCase):
    def test_bounded_captured_command_passes_only_explicit_descriptors(self):
        with patch.object(trust.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'public-result')) as run:
            self.assertEqual(trust.command(['synthetic-command'],b'synthetic-stdin',(123,)),b'public-result')
            run.assert_called_once_with(['synthetic-command'],input=b'synthetic-stdin',capture_output=True,timeout=20,pass_fds=(123,))
    def test_native_diagnostics_are_never_in_error_message(self):
        with patch.object(trust.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout=b'private',stderr=b'private')):
            with self.assertRaises(ValueError) as error:trust.command(['synthetic-command'])
            self.assertNotIn('private',str(error.exception))
    def test_termination_waits_for_bounded_child_then_aborts_and_restores_handler(self):
        original=trust.signal.getsignal(trust.signal.SIGTERM);finished=[]
        def run(*args,**kwargs):
            trust.signal.getsignal(trust.signal.SIGTERM)(trust.signal.SIGTERM,None)
            finished.append(True)
            return SimpleNamespace(returncode=0,stdout=b'not-returned')
        with patch.object(trust.subprocess,'run',side_effect=run):
            with self.assertRaises(InterruptedError):trust.command(['synthetic-command'])
        self.assertEqual(finished,[True]);self.assertEqual(trust.signal.getsignal(trust.signal.SIGTERM),original)


class LeafSource(unittest.TestCase):
    """Real local OpenSSL checks, only disposable synthetic nonroot temp files."""
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
        cls.key=cls.root/'key';cls.cert=cls.root/'cert'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-nodes','-days','1','-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:FALSE','-keyout',str(cls.key),'-out',str(cls.cert)],
            check=True,capture_output=True,timeout=20)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_leaf_san_pair_and_certificate_only_real_local_validation(self):
        cert,key=self.cert.read_bytes(),self.key.read_bytes()
        trust.validate_leaf(cert,key,'mail.example.test')
        with self.assertRaises(ValueError):trust.validate_leaf(cert,key,'other.example.test')
        with self.assertRaises(ValueError):trust.certificates_only(cert+key)
        with self.assertRaises(ValueError):trust.validate_leaf(cert,key+key,'mail.example.test')
        with self.assertRaises(ValueError):trust.validate_leaf(cert,b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----','mail.example.test')
    def test_not_yet_valid_and_different_leaf_key_refused(self):
        cert,key=self.cert.read_bytes(),self.key.read_bytes()
        with patch.object(trust.time,'time',return_value=0):
            with self.assertRaises(ValueError):trust.validate_leaf(cert,key,'mail.example.test')
        other=self.root/'other-key'
        subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256',
            '-out',str(other)],check=True,capture_output=True,timeout=20)
        with self.assertRaises(ValueError):trust.validate_leaf(cert,other.read_bytes(),'mail.example.test')
    def test_real_ca_signing_key_refused(self):
        ca=self.root/'ca'
        subprocess.run(['openssl','req','-x509','-new','-key',str(self.key),'-days','1',
            '-subj','/CN=mail.example.test','-addext','subjectAltName=DNS:mail.example.test',
            '-addext','basicConstraints=critical,CA:TRUE','-out',str(ca)],check=True,capture_output=True,timeout=20)
        with self.assertRaises(ValueError):trust.validate_leaf(ca.read_bytes(),self.key.read_bytes(),'mail.example.test')


if __name__=='__main__':unittest.main()
