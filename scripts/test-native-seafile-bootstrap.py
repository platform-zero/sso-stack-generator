#!/usr/bin/env python3
"""Serialized SOURCE/MODEL tests only; no container/actor/Root admission.

The owning module source is supplied explicitly, never discovered from cwd.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--module-source',required=True)
args,remaining=parser.parse_known_args();sys.argv=[sys.argv[0],*remaining]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
ops=Path(__file__).parents[1]/'runtime-generator/podman-ops'
b=load('seafile_bootstrap_model',ops/'native-seafile-bootstrap.py')
p=b.load_protocol();contract=load('seafile_model_selected_contract',Path(args.module_source).resolve(strict=True))
CID='1'*64

class Models(unittest.TestCase):
 def fixture(self,temp):
  f=b.Fresh.__new__(b.Fresh);f.p=p;f.require=p.require;f.capsule=Path(temp);f.cids=[];f.cidfiles={};f.relay=None;f.fresh_raw=b'fixture-only';f.release=Path(temp)/'release'
  f.accounts={name:types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid(),pw_name='fixture-only') for name in ('apps','platform')}
  f.rows={name:dict(volumeRoot=str(Path(temp)/name)) for name in ('apps','platform')}
  f.source={
   'mariadb':dict(volumes=['mariadb_data:/var/lib/mysql','./configs/mariadb/init.sh:/init.sh:ro'],entrypoint=[],command='--fixture-option yes'),
   'valkey':dict(volumes=['redis_data:/data','valkey_acl:/etc/valkey'],entrypoint=['/bin/sh','-c','public-fixture-script']),
   'seafile':dict(volumes=['seafile_files:/shared','./configs/seafile/runtime-entrypoint.sh:/runtime-entrypoint.sh:ro','./configs/seafile-admin/authorization.json:/run/seafile-admin/authorization.json:ro'],entrypoint=['/bin/bash','/runtime-entrypoint.sh'])}
  f.images={name:'registry.invalid/'+name+'@sha256:'+'a'*64 for name in f.source}
  files={name:('public-fixture:'+name).encode() for name in p.IMPLEMENTATION_FILES};files['mariadb/init.sh']=b'fixture-only'
  f.binding=types.SimpleNamespace(files=files,receipt_sha='a'*64)
  def file(path,body,uid=0,gid=0,mode=0o600):
   path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(body);path.chmod(mode)
  f.file=file;f.environment=lambda name,sha:dict(PRIVATE_FIXTURE='model-only-secret',SEAFILE_ADMIN_AUTHORIZATION_SHA256=sha)
  f.uidmaps=lambda domain:['--uidmap','0:1000:1','--gidmap','0:1000:1']
  f.temporary_evidence=mock.Mock()
  return f
 def test_finite_commands_keep_secrets_off_argv_and_no_host_network_ports(self):
  for name in ('mariadb','valkey','seafile'):
   with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);calls=[]
    def command(arguments,**kw):
     calls.append(arguments);return types.SimpleNamespace(returncode=1 if arguments[0]=='container' else 0,stdout=CID.encode())
    f.command=command
    result=f.create(name,'b'*64,'--bootstrap-owned-admin' if name=='seafile' else None,network=None if name=='mariadb' else '2'*64)
    self.assertEqual(result,CID);creation=calls[-1]
    self.assertIn('--timeout=900',creation);self.assertIn('--log-driver=none',creation)
    self.assertIn('--security-opt=no-new-privileges',creation)
    self.assertFalse(any('publish' in arg or arg=='--network=host' for arg in creation))
    self.assertNotIn('model-only-secret',' '.join(creation))
    self.assertIn('--uidmap',creation)
    self.assertIn('--no-hosts',creation);self.assertFalse(any(arg.startswith('--add-host') for arg in creation))
    hosts=[arg for arg in creation if arg.startswith('--volume=') and arg.endswith(':/etc/hosts:ro')]
    self.assertEqual(len(hosts),1)
    host_path=Path(hosts[0][len('--volume='):].rsplit(':/etc/hosts:ro',1)[0])
    self.assertTrue(host_path.is_relative_to(f.release))
    self.assertEqual(host_path.read_bytes(),b'127.0.0.1 localhost host.containers.internal\n::1 localhost\n')
    if name=='seafile':
     script=next(arg for arg in creation if arg.startswith('--volume=') and arg.endswith(':/runtime-entrypoint.sh:ro'))
     self.assertTrue(Path(script[len('--volume='):].rsplit(':/runtime-entrypoint.sh:ro',1)[0]).is_relative_to(f.release))
     self.assertEqual(creation[-1],'--bootstrap-owned-admin')
     self.assertTrue(any(':/run/seafile-admin:ro' in arg for arg in creation))
     self.assertFalse(any('authorization.json:/run' in arg for arg in creation))
 def test_all_data_absence_preflight_before_first_creation(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp)
   for row in f.rows.values():Path(row['volumeRoot']).mkdir()
   paths=f.data_paths();paths['redis_data'].mkdir()
   with self.assertRaises(p.Refused):f.prepare_data()
   self.assertFalse(paths['mariadb_data'].exists());self.assertFalse(paths['seafile_files'].exists())
 def test_input_writer_never_overwrites_existing_or_follows_symlink(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);target=Path(temp)/'preserved';target.write_bytes(b'protected-model')
   link=Path(temp)/'link';link.symlink_to(target)
   for path in (target,link):
    with self.subTest(kind='link' if path.is_symlink() else 'file'),self.assertRaises(FileExistsError):
     b.Fresh.file(f,path,b'replacement',uid=os.getuid(),gid=os.getgid())
   self.assertEqual(target.read_bytes(),b'protected-model')
 def test_name_collision_never_creates_container(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b''))
   with self.assertRaises(p.Refused):f.create('mariadb')
   self.assertEqual(f.command.call_count,1);self.assertEqual(f.cids,[])
 def test_foreign_volume_or_missing_config_refuses_before_native_create(self):
  for volume in ('foreign_store:/shared','./configs/absent/file:/config:ro','seafile_files:/data'):
   with self.subTest(volume=volume),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);f.source['mariadb']['volumes']=[volume]
    f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=1,stdout=b''))
    with self.assertRaises(p.Refused):f.create('mariadb')
    self.assertEqual(f.command.call_count,1)
 def test_empty_or_malformed_cid_is_not_admitted(self):
  for cid in (b'',b'caller-value',b'1'*63):
   with self.subTest(cid_length=len(cid)),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp)
    f.command=mock.Mock(side_effect=[types.SimpleNamespace(returncode=1,stdout=b''),types.SimpleNamespace(returncode=0,stdout=cid)])
    with self.assertRaises(p.Refused):f.create('mariadb')
    self.assertEqual(f.cids,[])
 def test_actual_command_cleanup_works_after_reserve_failure(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.reserve=mock.Mock(side_effect=p.Refused('fixture reserve refused'))
   running=[True]
   def native(arguments,**kw):
    operation=arguments[1]
    if operation=='inspect':out=p.encoded(dict(Running=running[0],ExitCode=0))
    else:
     if operation=='stop':running[0]=False
     out=b''
    return types.SimpleNamespace(returncode=0,stdout=out)
   with mock.patch.object(b.subprocess,'run',side_effect=native) as native_run:
    self.assertTrue(f.stop_all());self.assertTrue(native_run.called)
   f.reserve.assert_not_called();self.assertEqual(f.cids,[])
 def test_normal_command_refuses_reserves_without_launch(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.reserve=mock.Mock(side_effect=p.Refused('fixture reserve refused'))
   with mock.patch.object(b.subprocess,'run') as native:
    with self.assertRaises(p.Refused):f.command(['pull','fixture'])
    native.assert_not_called()
 def test_foreign_cleanup_cannot_skip_reserves(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID]
   with mock.patch.object(b.subprocess,'run') as native:
    for command in (['rm','2'*64],['pull',CID],['stop','unowned']):
     with self.assertRaises(p.Refused):f.command(command,cleanup=True)
    native.assert_not_called()
 def test_failed_graceful_stop_forces_only_exact_cid_but_is_never_success(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.state=lambda cid,cleanup=False:dict(Running=True,ExitCode=0)
   calls=[]
   def command(arguments,**kw):
    calls.append((arguments,kw))
    if arguments[0]=='stop':raise p.Refused('fixture stop failed')
    return types.SimpleNamespace(returncode=0,stdout=b'')
   f.command=command
   self.assertFalse(f.stop_all())
   self.assertEqual([call[0] for call in calls],[['stop','--time=30',CID],['rm','--force',CID]])
   self.assertTrue(all(call[1]['cleanup'] for call in calls))
 def test_cidfile_recovers_native_identity_after_client_timeout(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);path=mock.Mock()
   path.lstat.return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=64)
   path.read_text.return_value=CID;f.cidfiles={path:'fixture-native-planned-name'}
   f.state=lambda cid,cleanup=False:dict(Running=False,ExitCode=0)
   f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b''))
   self.assertTrue(f.stop_all());f.command.assert_called_once_with(['rm',CID],cleanup=True)
 def test_foreign_or_malformed_cidfile_cannot_trigger_container_operation(self):
  for mutation in ('uid','mode','body'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);path=mock.Mock();info=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_size=64)
    if mutation=='uid':info.st_uid=1000
    if mutation=='mode':info.st_mode=stat.S_IFREG|0o666
    path.lstat.return_value=info;path.read_text.return_value='caller' if mutation=='body' else CID
    f.cidfiles={path:'fixture-planned'};f.command=mock.Mock()
    self.assertFalse(f.stop_all());f.command.assert_not_called()

class Pipeline(unittest.TestCase):
 fixture=Models.fixture
 def pipeline(self,temp,fault=None):
  f=self.fixture(temp);events=[];f.old={};f.plan={}
  identity=dict(issuer='https://keycloak.fixture.invalid/realms/webservices',subject='fixture-sub',remote_user='fixture-sub')
  database=dict(host='host.containers.internal',port=25003,user='seafile',schemas=['ccnet','files','hub'])
  f.password=b'fresh-independent-fixture-password-at-least-32-bytes'
  f.fresh_raw,f.marker=p.fresh_material(contract,'a'*64,'b'*64,'synthetic',identity,'owner@fixture.invalid',database,f.binding.files,f.password,'c'*64)
  f.contract=contract;f.environments={'seafile':dict(SEAFILE_MYSQL_DB_PORT='25003',REDIS_PORT='25004')}
  auth=p.strict(f.fresh_raw);proof={key:auth[key] for key in p.PROOF_FIELDS-{'local_user','account_sha256'}}
  proof.update(local_user=p.subject_key(identity),account_sha256='d'*64)
  def check(expected):events.append('source-check')
  f.check=check;f.prepare_data=lambda:events.append('data-init')
  f.wait_database=lambda cid:events.append('db-ready');f.wait_cache=lambda cid:events.append('cache-ready')
  f.start_relay=lambda cid:events.append('private-relay')
  def create(name,sha=None,action=None,network=None):
   events.append(action or name)
   cid={'mariadb':'2'*64,'valkey':'3'*64,'--bootstrap-owned-admin':'4'*64,'--verify-owned-admin':'5'*64}.get(action or name)
   f.cids.append(cid);return cid
  f.create=create;f.state=lambda cid:dict(Running=False,ExitCode=23 if fault=='native-exit' and cid=='4'*64 else 0)
  def command(arguments,**kwargs):
   if arguments[0]=='container':return types.SimpleNamespace(returncode=1,stdout=b'')
   if arguments[0]=='create':
    cidfile=Path(next(x.split('=',1)[1] for x in arguments if x.startswith('--cidfile=')))
    cidfile.write_text(CID);return types.SimpleNamespace(returncode=0,stdout=CID.encode())
   if arguments[:2]==['start','--attach']:
    cid=arguments[-1]
    if cid==CID:
     if fault=='upstream':raise p.Refused('fixture upstream refused')
     events.append('upstream-qualified');return types.SimpleNamespace(returncode=0,stdout=b'')
    if cid=='4'*64:return types.SimpleNamespace(returncode=0,stdout=p.PROOF_PREFIX+p.encoded(proof))
    self.assertEqual(cid,'5'*64)
    self.assertFalse((f.capsule/'seafile-admin/password').exists())
    normal=p.strict((f.capsule/'seafile-admin/authorization.json').read_bytes())
    self.assertEqual(normal['operation'],'verify-existing')
    readback=dict(proof,operation='verify-existing',account_sha256='e'*64 if fault=='cas' else 'd'*64)
    return types.SimpleNamespace(returncode=0,stdout=p.PROOF_PREFIX+p.encoded(readback))
   return types.SimpleNamespace(returncode=0,stdout=b'')
  f.command=command
  def stop():events.append('stop-all');return fault!='stop'
  f.stop_all=stop
  return f,events
 def invoke(self,f,base):
  def capsule(**kw):
   path=Path(base)/'capsule';path.mkdir();return str(path)
  with mock.patch.object(b.tempfile,'mkdtemp',side_effect=capsule):return f.run({})
 def test_complete_model_orders_gate_init_native_readback_stop_and_recheck(self):
  with tempfile.TemporaryDirectory() as temp:
   f,events=self.pipeline(temp);result=self.invoke(f,temp)
   self.assertEqual(result['status'],'completed');self.assertTrue(result['nativeTemporaryStop'])
   self.assertLess(events.index('upstream-qualified'),events.index('data-init'))
   self.assertLess(events.index('cache-ready'),events.index('--bootstrap-owned-admin'))
   self.assertLess(events.index('--bootstrap-owned-admin'),events.index('--verify-owned-admin'))
   self.assertLess(events.index('--verify-owned-admin'),events.index('stop-all'))
   self.assertEqual(events[-1],'source-check');self.assertFalse((Path(temp)/'capsule').exists())
 def test_upstream_failure_precedes_data_and_still_cleans_private_capsule(self):
  with tempfile.TemporaryDirectory() as temp:
   f,events=self.pipeline(temp,'upstream')
   with self.assertRaises(p.Refused):self.invoke(f,temp)
   self.assertNotIn('data-init',events);self.assertIn('stop-all',events)
   self.assertFalse((Path(temp)/'capsule').exists())
 def test_native_exit_cas_and_stop_failure_cannot_return_admission(self):
  for fault in ('native-exit','cas','stop'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
    f,events=self.pipeline(temp,fault)
    with self.assertRaises(p.Refused):self.invoke(f,temp)
    self.assertIn('stop-all',events);self.assertEqual(f.password,b'')
    self.assertFalse((Path(temp)/'capsule').exists())

if __name__=='__main__':unittest.main()
