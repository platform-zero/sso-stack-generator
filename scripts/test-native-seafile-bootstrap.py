#!/usr/bin/env python3
"""Serialized SOURCE/MODEL tests only; no container/actor/Root admission.

The owning module source is supplied explicitly, never discovered from cwd.
"""
import argparse
import importlib.util
import io
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
  f.start_database=lambda cid:f.command(['start',cid])
  f.finish_database_observer=mock.Mock(return_value=True)
  f.mac_name='webservices_native_'+'a'*32
  f.mac_body=b.PREPARATION_MAC_TEMPLATE.replace('@PROFILE@',f.mac_name).encode()
  f.mac_pin=None;f.mac_custody=dict(modelOnly=True)
  f.install_mac_policy=mock.Mock();f.verify_mac_policy=mock.Mock()
  return f
 def test_scoped_mac_retains_default_restrictions_and_only_scoped_peer_signalling(self):
  template=b.PREPARATION_MAC_TEMPLATE
  for rule in ('deny mount,','deny @{PROC}/* w,','deny @{PROC}/sysrq-trigger rwklx,',
               'deny @{PROC}/kcore rwklx,','deny /sys/firmware/** rwklx,',
               'deny /sys/kernel/security/** rwklx,','deny /sys/[^f]*/** wklx,',
               'deny /sys/f[^s]*/** wklx,','deny /sys/fs/[^c]*/** wklx,',
               'deny /sys/fs/c[^g]*/** wklx,','deny /sys/fs/cg[^r]*/** wklx,',
               'signal (send,receive) peer=@PROFILE@,','ptrace (trace,read) peer=@PROFILE@,'):
   self.assertIn(rule,template)
  self.assertIn('flags=(attach_disconnected,mediate_deleted)',template)
  self.assertNotIn('flags=(unconfined)',template)
  self.assertNotIn('signal (send,receive),',template)
 def test_mac_loader_creates_new_policy_without_replace_adoption_shared_cache_or_raw_output(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.reserve=mock.Mock()
   pin=dict(name=f.mac_name,kernelSha256='b'*64,device=1,inode=2)
   f.kernel_mac_policy=mock.Mock(side_effect=[None,None,pin])
   expanded=f.mac_body+b'\n# expanded model-only input\n'
   results=[types.SimpleNamespace(returncode=0,stdout=expanded,stderr=b''),
            types.SimpleNamespace(returncode=0,stdout=f.mac_name.encode()+b'\n',stderr=b''),
            types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')]
   with mock.patch.object(b.subprocess,'run',side_effect=results) as run:
    b.Fresh.install_mac_policy(f)
   self.assertEqual(f.mac_pin,pin)
   self.assertFalse(f.mac_custody['sharedDefaultModified']);self.assertFalse(f.mac_custody['confinementDisabled'])
   for call in run.call_args_list:
    argv=call.args[0]
    self.assertIn('--skip-cache',argv);self.assertIn('--skip-read-cache',argv)
    self.assertFalse(any(arg in argv for arg in ('--replace','--remove','--write-cache','--purge-cache','--Complain')))
    self.assertTrue(any(arg.startswith('--config-file='+str(f.release)) for arg in argv))
   self.assertIn('--add',run.call_args_list[-1].args[0])
   self.assertTrue((f.release/'native-seafile/mac-policy/custody.json').is_file())
   f.mac_pin=None;f.kernel_mac_policy=mock.Mock(return_value=pin)
   with mock.patch.object(b.subprocess,'run') as run,self.assertRaises(p.Refused):
    b.Fresh.install_mac_policy(f)
   run.assert_not_called()
 def test_kernel_policy_reader_follows_only_attested_securityfs_to_apparmorfs_magic_view(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp)
   link=types.SimpleNamespace(st_dev=1,st_ino=99,st_mode=stat.S_IFLNK|0o444,st_uid=0,st_gid=0,
                             st_nlink=1,st_mtime_ns=1,st_ctime_ns=1)
   def filesystem(fd,buffer):
    b.ctypes.c_long.from_buffer(buffer).value=0x73636673 if fd==14 else 0x5a3c69f0
    return 0
   library=types.SimpleNamespace(fstatfs=mock.Mock(side_effect=filesystem))
   with mock.patch.object(b.os,'open',side_effect=range(10,17)) as opened,\
        mock.patch.object(b.os,'fstat',return_value=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o555,st_dev=1,st_ino=2)),\
        mock.patch.object(b.os,'stat',return_value=link),\
        mock.patch.object(b.os,'readlink',return_value='apparmorfs:[147]'),\
        mock.patch.object(b.os,'listdir',return_value=[]),\
        mock.patch.object(b.ctypes,'CDLL',return_value=library),mock.patch.object(b.os,'close'):
    self.assertIsNone(f.kernel_mac_policy())
   self.assertEqual(opened.call_args_list[-2].args,('policy',os.O_RDONLY|os.O_DIRECTORY))
   self.assertEqual(opened.call_args_list[-1].args,('profiles',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
   with mock.patch.object(b.os,'open',side_effect=range(10,17)) as opened,\
        mock.patch.object(b.os,'fstat',return_value=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o555)),\
        mock.patch.object(b.os,'stat',return_value=link),\
        mock.patch.object(b.os,'readlink',return_value='/ordinary-untrusted-link'),\
        mock.patch.object(b.ctypes,'CDLL',return_value=library),mock.patch.object(b.os,'close'),self.assertRaises(p.Refused):
    f.kernel_mac_policy()
   self.assertFalse(any(call.args[0]=='policy' for call in opened.call_args_list))
   f.mac_name='../foreign-policy'
   with mock.patch.object(b.os,'open') as opened,self.assertRaises(p.Refused):f.kernel_mac_policy()
   opened.assert_not_called()
 def test_mac_kernel_custody_drift_refuses_without_repair_or_replacement(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.mac_pin=dict(kernelSha256='a'*64)
   f.kernel_mac_policy=mock.Mock(return_value=dict(kernelSha256='b'*64))
   with mock.patch.object(b.subprocess,'run') as run,self.assertRaises(p.Refused):b.Fresh.verify_mac_policy(f)
   run.assert_not_called()
 def test_real_writer_finalizes_declared_new_inode_modes_under_private_umask_only(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);previous=os.umask(0o077)
   try:
    for mode in (0o444,0o555,0o600):
     target=Path(temp)/('declared-mode-'+str(mode))
     with mock.patch.object(b.os,'fchmod',wraps=os.fchmod) as declared:
      b.Fresh.file(f,target,b'public-or-private-model-input',os.getuid(),os.getgid(),mode)
      self.assertEqual(stat.S_IMODE(target.stat().st_mode),mode)
      self.assertEqual(target.read_bytes(),b'public-or-private-model-input')
      with self.assertRaises(FileExistsError):
       b.Fresh.file(f,target,b'must-not-repair-existing',os.getuid(),os.getgid(),0o600)
      self.assertEqual(target.read_bytes(),b'public-or-private-model-input')
      declared.assert_called_once();self.assertEqual(declared.call_args.args[1],mode)
   finally:os.umask(previous)
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
    self.assertIn('--security-opt=apparmor='+f.mac_name,creation)
    self.assertFalse(any('publish' in arg or arg=='--network=host' for arg in creation))
    self.assertNotIn('model-only-secret',' '.join(creation))
    self.assertIn('--uidmap',creation)
    self.assertIn('--no-hosts',creation);self.assertFalse(any(arg.startswith('--add-host') for arg in creation))
    hosts=[arg for arg in creation if arg.startswith('--volume=') and arg.endswith(':/etc/hosts:ro')]
    self.assertEqual(len(hosts),1)
    host_path=Path(hosts[0][len('--volume='):].rsplit(':/etc/hosts:ro',1)[0])
    self.assertTrue(host_path.is_relative_to(f.release))
    native_name=next(arg[len('--name='):] for arg in creation if arg.startswith('--name='))
    expected='127.0.0.1 localhost host.containers.internal'+(' '+native_name if name=='mariadb' else '')+'\n::1 localhost\n'
    self.assertEqual(host_path.read_bytes(),expected.encode())
    if name=='mariadb':self.assertIn('--hostname='+native_name,creation)
    else:self.assertFalse(any(arg.startswith('--hostname=') for arg in creation))
    if name=='seafile':
     script=next(arg for arg in creation if arg.startswith('--volume=') and arg.endswith(':/runtime-entrypoint.sh:ro'))
     self.assertTrue(Path(script[len('--volume='):].rsplit(':/runtime-entrypoint.sh:ro',1)[0]).is_relative_to(f.release))
     self.assertEqual(creation[-1],'--bootstrap-owned-admin')
     self.assertTrue(any(':/run/seafile-admin:ro' in arg for arg in creation))
     self.assertFalse(any('authorization.json:/run' in arg for arg in creation))
 def test_peer_hosts_cannot_replace_database_local_hostname_binding(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);calls=[]
   def command(arguments,**kw):
    calls.append(arguments);return types.SimpleNamespace(returncode=1 if arguments[0]=='container' else 0,stdout=CID.encode())
   f.command=command;f.create('mariadb')
   db=f.release/'native-seafile/config-inputs/hosts/mariadb';before=db.read_bytes()
   f.create('valkey',network='2'*64);f.create('seafile',network='2'*64)
   self.assertEqual(db.read_bytes(),before)
   self.assertNotEqual(db.read_bytes(),(db.parent/'valkey').read_bytes())
   for creation in (row for row in calls if row[0]=='create' and '--network=container:'+'2'*64 in row):
    self.assertFalse(any(arg.startswith('--hostname=') for arg in creation))
 def test_database_probe_diagnostics_expose_only_fixed_error_classes(self):
  sentinel=b' private-fixture-user-password-sql-must-not-appear'
  for code,label in ((1045,'authentication-refused'),(1049,'service-database-absent'),
                     (2002,'database-connectivity-unavailable'),(2003,'database-connectivity-unavailable'),
                     (9999,'other-database-probe-refusal')):
   with self.subTest(code=code):
    result=types.SimpleNamespace(returncode=1,stdout=sentinel,stderr=b'ERROR '+str(code).encode()+b' (HY000):'+sentinel)
    self.assertEqual(b.Fresh.database_probe_observation(result),label)
  # A discarded or merged stderr stream is None, not an absent attribute.
  # Never let diagnostic stream handling replace the original readiness guard.
  merged=types.SimpleNamespace(returncode=1,stdout=b'ERROR 2002 (HY000):'+sentinel,stderr=None)
  self.assertEqual(b.Fresh.database_probe_observation(merged),'database-connectivity-unavailable')
  for code,label in ((125,'native-exec-engine-refused'),(126,'native-exec-permission-refused'),(127,'native-exec-command-unavailable')):
   self.assertEqual(b.Fresh.database_probe_observation(types.SimpleNamespace(returncode=code,stdout=sentinel,stderr=sentinel)),label)
  self.assertEqual(b.Fresh.database_probe_observation(types.SimpleNamespace(returncode=0,stdout=b'1\n')),'service-database-ready')
  self.assertEqual(b.Fresh.database_probe_observation(types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'private ERROR 1045 '+sentinel)),'other-database-probe-refusal')
 def test_installer_defaults_observation_is_exact_own_cid_and_closed_flags_only(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.database_cid=CID
   f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b'--verbose\n--password=private-fixture-secret\n'))
   self.assertEqual(f.observe_installer_defaults(),'installer-verbose-enabled')
   self.assertEqual(f.command.call_args.args[0],['exec',CID,'my_print_defaults','--mariadbd','mysql_install_db','mariadb-install-db'])
   f.cids=[]
   self.assertEqual(f.observe_installer_defaults(),'installer-defaults-unavailable')
   self.assertEqual(f.command.call_count,1)
 def test_dedicated_own_exec_helper_signals_only_itself_not_server_or_host_pid(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.database_cid=CID
   f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=143,stdout=b'private-fixture-secret'))
   self.assertEqual(f.observe_database_self_signal(),'own-helper-self-signal-permitted')
   self.assertEqual(f.command.call_args.args[0],['exec',CID,'/bin/sh','-c','test "$$" -gt 1 || exit 41; kill -TERM "$$" || exit 43; exit 42'])
   f.command.return_value.returncode=42
   self.assertEqual(f.observe_database_self_signal(),'own-helper-self-signal-ignored')
   f.command.return_value.returncode=43
   self.assertEqual(f.observe_database_self_signal(),'own-helper-self-signal-refused')
   f.cids=[]
   self.assertEqual(f.observe_database_self_signal(),'own-helper-self-signal-unavailable')
   self.assertEqual(f.command.call_count,3)
 def test_mac_assignment_observation_never_emits_profile_labels_or_uses_foreign_cid(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.database_cid=CID
   f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b'"private-fixture-label"'))
   self.assertEqual(f.observe_database_mac_assignment(),'engine-other-assigned-profile')
   self.assertEqual(f.command.call_args.args[0],['inspect','--format={{json .AppArmorProfile}}',CID])
   f.command.return_value.stdout=b'""'
   self.assertEqual(f.observe_database_mac_assignment(),'engine-unassigned')
   f.cids=[]
   self.assertEqual(f.observe_database_mac_assignment(),'own-mac-assignment-unavailable')
   self.assertEqual(f.command.call_count,2)
 def test_actual_oci_policy_classification_is_closed_and_distinguishes_conditions_and_denials(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp)
   policy=dict(defaultAction='SCMP_ACT_ERRNO',architectures=['SCMP_ARCH_X86_64'],
     syscalls=[dict(names=['kill','tgkill'],action='SCMP_ACT_ALLOW')])
   document=dict(linux=dict(seccomp=policy),process=dict(env=['PRIVATE=model-secret']))
   with mock.patch.object(b.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')):
    result=f.classify_runtime_policy(document)
   self.assertEqual(result,dict(status='exact-own-oci-observed',seccomp='declared',
     kill='unconditional-allow',tgkill='unconditional-allow',nativeArchitectureDeclared=True))
   self.assertNotIn('model-secret',json.dumps(result))
   policy['syscalls'][0]['args']=[dict(index=0,value=0,op='SCMP_CMP_EQ')]
   self.assertEqual(f.classify_runtime_policy(document)['kill'],'conditional-or-conflicting')
   policy['syscalls'].append(dict(names=['kill'],action='SCMP_ACT_ERRNO'))
   self.assertEqual(f.classify_runtime_policy(document)['kill'],'conditional-or-conflicting')
   policy['syscalls']=[]
   self.assertEqual(f.classify_runtime_policy(document)['kill'],'not-allowed')
   policy['defaultAction']='SCMP_ACT_ALLOW'
   self.assertEqual(f.classify_runtime_policy(document)['kill'],'default-allow')
   self.assertEqual(f.classify_runtime_policy({})['seccomp'],'not-declared')
   policy['syscalls']=[{}]*4097
   with self.assertRaises(p.Refused):f.classify_runtime_policy(document)
 def test_runtime_policy_never_opens_foreign_cid_or_engine_selected_foreign_path(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.database_cid=CID;f.state=mock.Mock(return_value=dict(Running=True,Pid=12001))
   f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b'"/private-fixture-secret/config.json"'))
   with mock.patch.object(b.os,'open') as opened:
    self.assertEqual(f.observe_database_runtime_policy(),dict(status='own-runtime-policy-unavailable'))
    f.command.assert_not_called();opened.assert_not_called()
    f.cids=[CID]
    self.assertEqual(f.observe_database_runtime_policy(),dict(status='own-runtime-policy-unavailable'))
    f.command.assert_called_once_with(['inspect','--format={{json .OCIConfigPath}}',CID],cleanup=True,allow_failure=True,timeout=10)
    opened.assert_not_called()
 def test_own_mac_signal_query_is_securityfs_transaction_only_and_emits_closed_classes(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);label=b':model-private-namespace://containers-default-model (enforce)'
   def filesystem(fd,buffer):
    b.ctypes.c_long.from_buffer(buffer).value=0x73636673
    return 0
   library=types.SimpleNamespace(fstatfs=mock.Mock(side_effect=filesystem))
   reply=b'allow 0x00000006\ndeny 0x00000000\naudit 0x00000000\nquiet 0x00000000\n'
   with mock.patch.object(b.os,'open',return_value=42) as opened,\
        mock.patch.object(b.os,'fstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)),\
        mock.patch.object(b.ctypes,'CDLL',return_value=library),\
        mock.patch.object(b.os,'write',side_effect=lambda fd,body:len(body)) as written,\
        mock.patch.object(b.os,'read',return_value=reply) as read,\
        mock.patch.object(b.os,'close') as closed:
    self.assertEqual(f.query_own_self_signal_policy(label),'own-mac-self-term-send-and-receive-allowed')
    opened.assert_called_once_with('/sys/kernel/security/apparmor/.access',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
    self.assertEqual(written.call_args.args,(42,b'labelall\x00:model-private-namespace://containers-default-model\x00\x0a\x0fcontainers-default-model'))
    closed.assert_called_once_with(42)
    read.return_value=reply.replace(b'00000006',b'00000002')
    self.assertEqual(f.query_own_self_signal_policy(label),'own-mac-self-term-receive-denied')
    read.return_value=b'malformed-private-fixture-label'
    self.assertEqual(f.query_own_self_signal_policy(label),'own-mac-signal-query-unavailable')
    library.fstatfs.side_effect=lambda fd,buffer:0
    prior=written.call_count
    self.assertEqual(f.query_own_self_signal_policy(label),'own-mac-signal-query-unavailable')
    self.assertEqual(written.call_count,prior)
   with mock.patch.object(b.os,'open') as opened:
    self.assertEqual(f.query_own_self_signal_policy(b'outer//&inner (enforce)'),
                     'own-mac-signal-query-unsupported-label')
    opened.assert_not_called()
 def cgroup_fixture(self,temp,membership=None,contents=b'12001\n'):
  root=Path(temp);f=self.fixture(temp);f.cids=[CID];f.database_cid=CID
  f.query_own_self_signal_policy=mock.Mock(return_value='own-mac-signal-query-unavailable')
  f.state=mock.Mock(return_value=dict(Running=True,Pid=12001))
  proc=root/'model-proc';group=root/'model-cgroups';(proc/'12001').mkdir(parents=True)
  relative='machine.slice/libpod-'+CID+'.scope';leaf=group/relative;leaf.mkdir(parents=True)
  (leaf/'cgroup.procs').write_bytes(contents)
  (leaf/'cgroup.threads').write_bytes(contents)
  for name,body in (('pids.current',b'4\n'),('pids.max',b'256\n'),('pids.events',b'max 0\n')):(leaf/name).write_bytes(body)
  (proc/'12001/cgroup').write_text(membership or '0::/'+relative+'\n')
  (proc/'12001/stat').write_text('12001 (mariadbd) D '+' '.join(['0']*18+['123']+['0']*3)+'\n')
  (proc/'12001/wchan').write_text('io_schedule\n')
  (proc/'12001/syscall').write_bytes(b'202 0xdeadbeef private-fixture-secret\n')
  (proc/'12001/status').write_bytes(b'SigIgn:\t0\nSigBlk:\t4000\nSigPnd:\t0\nShdPnd:\t0\nSeccomp_filters:\t2\n')
  (proc/'12001/attr').mkdir();(proc/'12001/attr/current').write_bytes(b':model-namespace://containers-default-model (enforce)\x00\n')
  (root/'model-pidfd').touch()
  return f,proc,group,root/'model-pidfd'
 def test_process_observation_is_exact_own_nonempty_cgroup_and_fixed_roles_only(self):
  with tempfile.TemporaryDirectory() as temp:
   f,proc,group,pidfile=self.cgroup_fixture(temp)
   with mock.patch.object(b,'PROC',proc),mock.patch.object(b,'CGROUP',group),\
        mock.patch.object(b.os,'pidfd_open',side_effect=lambda pid:os.open(pidfile,os.O_RDONLY)),\
        mock.patch.object(b.select,'select',return_value=([],[],[])),\
        mock.patch.object(b.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')),\
        mock.patch.object(b.os,'listdir',side_effect=AssertionError('global process enumeration forbidden')):
    result=f.observe_database_processes()
   self.assertEqual(result,dict(status='exact-own-cgroup-observed',processCount=1,threadCount=1,bounded=False,
      taskBudgets=[dict(taskCount=4,taskLimit=256,taskLimitEvents=0)]*2,
      selfSignalMacQuery='own-mac-signal-query-unavailable',
      threads=[dict(role='database-server',state='disk-wait',wait='io-wait',syscall='futex',
         terminationIgnored=False,terminationBlocked=True,terminationPending=False,seccompFilters=2,
         macClass='default-container-enforced')]))
   self.assertNotIn('12001',str(result));self.assertNotIn(CID,str(result))
   self.assertNotIn('0xdeadbeef',str(result));self.assertNotIn('private-fixture-secret',str(result))
   self.assertNotIn('model-namespace',str(result))
 def test_exact_own_container_leaf_is_allowed_without_parent_or_global_fallback(self):
  with tempfile.TemporaryDirectory() as temp:
   f,proc,group,pidfile=self.cgroup_fixture(temp)
   parent=group/'machine.slice'/('libpod-'+CID+'.scope');leaf=parent/'container';leaf.mkdir()
   (parent/'cgroup.procs').rename(leaf/'cgroup.procs')
   (parent/'cgroup.threads').rename(leaf/'cgroup.threads')
   for name in ('pids.current','pids.max','pids.events'):(leaf/name).write_bytes((parent/name).read_bytes())
   (proc/'12001/cgroup').write_text('0::/machine.slice/libpod-'+CID+'.scope/container\n')
   with mock.patch.object(b,'PROC',proc),mock.patch.object(b,'CGROUP',group),\
        mock.patch.object(b.os,'pidfd_open',side_effect=lambda pid:os.open(pidfile,os.O_RDONLY)),\
        mock.patch.object(b.select,'select',return_value=([],[],[])):
    self.assertEqual(f.observe_database_processes()['status'],'exact-own-cgroup-observed')
 def test_empty_or_global_cgroup_has_no_process_fallback(self):
  for membership,contents in (('0::/\n',b'12001\n'),(None,b'')):
   with self.subTest(membership=membership,contents=contents),tempfile.TemporaryDirectory() as temp:
    f,proc,group,pidfile=self.cgroup_fixture(temp,membership,contents)
    with mock.patch.object(b,'PROC',proc),mock.patch.object(b,'CGROUP',group),\
         mock.patch.object(b.os,'pidfd_open',side_effect=lambda pid:os.open(pidfile,os.O_RDONLY)),\
         mock.patch.object(b.os,'listdir',side_effect=AssertionError('global process enumeration forbidden')):
     self.assertEqual(f.observe_database_processes(),{'status':'own-cgroup-observation-unavailable',
        'phase':'cgroup-membership' if membership else 'cgroup-processes'})
 def test_live_database_console_retains_only_predefined_codes(self):
  observer=b.DatabaseConsoleObservations()
  private=b'private-fixture-password-sql-source-must-not-appear'
  observer.consume(io.BytesIO(b'Initializing database files\n'+private+b'\nPermission denied\n'))
  self.assertEqual(observer.snapshot(),['database-files-initializing','filesystem-permission-refused'])
  self.assertNotIn(private.decode(),str(observer.__dict__))
 def test_database_console_patterns_survive_chunk_boundary_without_retaining_tail(self):
  observer=b.DatabaseConsoleObservations()
  observer.consume(io.BytesIO(b'x'*(4096-10)+b'Initializing database files\n'))
  self.assertEqual(observer.snapshot(),['database-files-initializing'])
 def test_console_classification_bound_does_not_retain_or_classify_late_payloads(self):
  observer=b.DatabaseConsoleObservations()
  observer.consume(io.BytesIO(b'x'*(8*1024*1024)+b'Permission denied private-fixture-secret'))
  self.assertEqual(observer.snapshot(),['database-console-output-bound-exceeded'])
 def test_innodb_shutdown_console_remains_fixed_classifications_not_service_log_text(self):
  observer=b.DatabaseConsoleObservations()
  observer.consume(io.BytesIO(b'InnoDB: Starting shutdown private-fixture-secret\nInnoDB: Shutdown completed\n'))
  self.assertEqual(observer.snapshot(),['innodb-log-observed','innodb-shutdown-completed','innodb-shutdown-starting'])
  self.assertNotIn('private-fixture-secret',repr(observer.snapshot()))
 def test_forced_observer_helper_cleanup_is_not_clean_stop_proof(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.database_console=b.DatabaseConsoleObservations()
   f.database_start=types.SimpleNamespace(stdout=io.BytesIO(),wait=mock.Mock(side_effect=[subprocess.TimeoutExpired('model-helper',10),0]),
       terminate=mock.Mock(),kill=mock.Mock())
   f.database_reader=mock.Mock();f.database_reader.is_alive.return_value=False
   self.assertFalse(b.Fresh.finish_database_observer(f))
   f.database_start.terminate.assert_called_once();f.database_start.kill.assert_not_called()
   self.assertIn('database-observer-helper-not-clean',f.database_console.snapshot())
 def test_attached_database_start_uses_exact_own_cid_no_signal_proxy_or_raw_log(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.reserve=mock.Mock();f.state=mock.Mock(return_value=dict(Running=True))
   process=types.SimpleNamespace(stdout=io.BytesIO(b'Initializing database files\nprivate-fixture-secret\n'),
       poll=mock.Mock(return_value=None),wait=mock.Mock(return_value=0))
   with mock.patch.object(b.subprocess,'Popen',return_value=process) as popen:
    b.Fresh.start_database(f,CID)
    self.assertEqual(popen.call_args.args[0],['/usr/bin/podman','start','--attach','--sig-proxy=false',CID])
    self.assertEqual(popen.call_args.kwargs['stderr'],subprocess.STDOUT)
    f.database_reader.join(timeout=1)
    self.assertEqual(f.database_console.snapshot(),['database-files-initializing'])
    self.assertTrue(b.Fresh.finish_database_observer(f))
    with self.assertRaises(p.Refused):b.Fresh.start_database(f,'2'*64)
    self.assertEqual(popen.call_count,1)
 def database_fixture(self,temp):
  f=self.fixture(temp);f.cids=[CID]
  f.environments={'seafile':dict(SEAFILE_MYSQL_DB_USER='fixture-service',SEAFILE_MYSQL_DB_PASSWORD='fixture-service-password',
     SEAFILE_MYSQL_DB_SEAHUB_DB_NAME='fixture_db'),'mariadb':dict(MYSQL_ROOT_PASSWORD='fixture-root-password')}
  f.state=mock.Mock(return_value=dict(Running=True));return f
 def test_database_can_finish_after_start_period_without_bypassing_service_gate(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.database_fixture(temp);calls=[]
   def command(arguments,**kwargs):
    calls.append((arguments,kwargs));ready=len(calls)==66
    self.assertNotIn('fixture-service-password',' '.join(arguments))
    return types.SimpleNamespace(returncode=0 if ready else 1,stdout=b'1\n' if ready else b'',stderr=b'ERROR 2002 (HY000): fixture')
   f.command=command
   with mock.patch.object(b.time,'sleep'),mock.patch.object(b.time,'monotonic',return_value=0):f.wait_database(CID)
   self.assertEqual(len(calls),66);self.assertEqual(f.database_observation,'service-database-ready')
   self.assertFalse(any('--protocol=socket' in args for args,kwargs in calls))
 def test_initialization_socket_ready_is_diagnostic_not_service_readiness(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.database_fixture(temp);f.command=mock.Mock(return_value=types.SimpleNamespace(returncode=0,stdout=b'1\n',stderr=b''))
   with mock.patch.object(b.time,'monotonic',side_effect=[0,181]),self.assertRaises(p.Refused):f.wait_database(CID)
   self.assertEqual(f.database_initialization_observation,'initialization-socket-ready')
   args=f.command.call_args.args[0];kwargs=f.command.call_args.kwargs
   self.assertIn('--protocol=socket',args);self.assertNotIn('fixture-root-password',' '.join(args))
   self.assertEqual(kwargs['environment'],{'MYSQL_PWD':'fixture-root-password'})
   self.assertIs(kwargs['diagnostic_stderr'],True)
 def test_only_own_database_probe_can_capture_stderr_privately(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID];f.reserve=mock.Mock()
   result=types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'ERROR 1045 (HY000): private-fixture-secret')
   with mock.patch.object(b.subprocess,'run',return_value=result) as run:
    value=b.Fresh.command(f,['exec','--env=MYSQL_PWD',CID,'mariadb','--execute=SELECT 1'],
                         allow_failure=True,diagnostic_stderr=True)
    self.assertEqual(run.call_args.kwargs['stderr'],subprocess.PIPE)
    self.assertEqual(b.Fresh.database_probe_observation(value),'authentication-refused')
    with self.assertRaises(p.Refused):b.Fresh.command(f,['exec','--env=MYSQL_PWD','2'*64,'mariadb'],diagnostic_stderr=True)
    with self.assertRaises(p.Refused):b.Fresh.command(f,['exec','--env=MYSQL_PWD',CID,'other'],diagnostic_stderr=True)
    self.assertEqual(run.call_count,1)
 def test_declared_numeric_container_user_matches_eventual_service_user(self):
  for user in ('0:0','999:999','65536:65536'):
   with self.subTest(user=user),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);f.source['mariadb']['user']=user;calls=[]
    def command(arguments,**kw):
     calls.append(arguments);return types.SimpleNamespace(returncode=1 if arguments[0]=='container' else 0,stdout=CID.encode())
    f.command=command;f.create('mariadb')
    self.assertIn('--user='+user,calls[-1])
    self.assertTrue(any(value.endswith(':/var/lib/mysql:U') for value in calls[-1]))
 def test_container_user_cannot_escape_exact_numeric_maps_or_expand_host_values(self):
  for user in ('mysql','999','999:999\n','65537:0','0:65537','-1:0','${PRIVATE_FIXTURE}:0',999):
   with self.subTest(user=user),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);f.source['mariadb']['user']=user;calls=[]
    def command(arguments,**kw):
     calls.append(arguments);return types.SimpleNamespace(returncode=1,stdout=CID.encode())
    f.command=command
    with self.assertRaises(p.Refused):f.create('mariadb')
    self.assertFalse(any(row[0]=='create' for row in calls))
 def test_failure_observations_are_fixed_states_not_error_env_or_service_contents(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID]
   f.state=mock.Mock(return_value=dict(Running=False,ExitCode=137,OOMKilled=True,
       Error='private-fixture-must-not-appear',env='private-fixture-must-not-appear'))
   directory=f.release/'native-seafile';directory.mkdir(parents=True,mode=0o700)
   original=Path.lstat
   def metadata(path,*a,**kw):
    if path==directory:return types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0)
    return original(path,*a,**kw)
   with mock.patch.object(Path,'lstat',new=metadata):
    b.Fresh.temporary_evidence(f,'preparation-failed')
    body=(directory/'failure-observations.json').read_bytes();value=json.loads(body)
    self.assertEqual(value['observedStates'],[dict(cid=CID,running=False,exitCode=137,oomKilled=True)])
    self.assertNotIn(b'private-fixture',body)
    f.cids=[];b.Fresh.temporary_evidence(f,'temporary-stopped')
    self.assertEqual((directory/'failure-observations.json').read_bytes(),body)
 def test_actual_shell_gets_one_compose_dollar_unescape_not_pid_as_password(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);calls=[]
   script='printf "%s|%s|%s" "$${VALKEY_PASSWORD}" "$$$$" "50%"'
   f.source['valkey']['entrypoint']=['/bin/sh','-c',script]
   def command(arguments,**kw):
    calls.append(arguments);return types.SimpleNamespace(returncode=1 if arguments[0]=='container' else 0,stdout=CID.encode())
   f.command=command;f.create('valkey');creation=calls[-1]
   child=creation[-1];self.assertEqual(child,script.replace('$$','$'))
   self.assertNotIn('synthetic-shell-fixture-only',' '.join(creation))
   result=subprocess.run(['/bin/sh','-c',child],env={'VALKEY_PASSWORD':'synthetic-shell-fixture-only'},capture_output=True,check=True)
   value,pid,percent=result.stdout.split(b'|')
   self.assertEqual(value,b'synthetic-shell-fixture-only');self.assertTrue(pid.isdigit());self.assertEqual(percent,b'50%')
 def test_direct_command_unescape_never_expands_host_variables_or_systemd_percent(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);calls=[];f.source['mariadb']['command']='--literal=$${CHILD_ONLY} --pid=$$$$ --percent=50%'
   def command(arguments,**kw):
    calls.append(arguments);return types.SimpleNamespace(returncode=1 if arguments[0]=='container' else 0,stdout=CID.encode())
   f.command=command
   with mock.patch.dict(os.environ,{'CHILD_ONLY':'host-only-sentinel'}):f.create('mariadb')
   self.assertEqual(calls[-1][-3:],['--literal=${CHILD_ONLY}','--pid=$$','--percent=50%'])
   self.assertNotIn('host-only-sentinel',' '.join(calls[-1]))
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
 def test_host_network_namespace_is_refused_before_any_relay_exec(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.cids=[CID]
   f.environments={'seafile':{'SEAFILE_MYSQL_DB_PORT':'25003','REDIS_PORT':'25004'}}
   f.command=mock.Mock(return_value=types.SimpleNamespace(stdout=json.dumps({'Running':True,'Pid':os.getpid()}).encode()))
   with mock.patch.object(b.subprocess,'Popen') as opening:
    with self.assertRaises(p.Refused):f.start_relay(CID)
    opening.assert_not_called()
 def test_relay_exec_receives_only_held_namespace_fd_and_closes_parent_copy(self):
  with tempfile.TemporaryDirectory() as temp:
   f=self.fixture(temp);f.environments={'seafile':{'SEAFILE_MYSQL_DB_PORT':'25003','REDIS_PORT':'25004'}}
   path=Path(temp)/'public-model-only';path.write_bytes(b'not-a-namespace; subprocess mocked')
   fd=os.open(path,os.O_RDONLY);f.relay_namespace=mock.Mock(return_value=fd)
   process=mock.Mock();process.stdout=mock.Mock();process.stdout.readline.return_value=b'SEAFILE_PRIVATE_LOOPBACK_READY\n'
   with mock.patch.object(b.subprocess,'Popen',return_value=process) as opening,mock.patch.object(b.select,'select',return_value=([process.stdout],[],[])):
    f.start_relay(CID)
   argv=opening.call_args.args[0];kwargs=opening.call_args.kwargs
   self.assertIn('--net=/proc/self/fd/'+str(fd),argv)
   self.assertFalse(any(arg.startswith('--target') for arg in argv))
   self.assertEqual(kwargs['pass_fds'],(fd,));self.assertTrue(kwargs['close_fds'])
   with self.assertRaises(OSError):os.fstat(fd)
 def test_qualifier_success_accepts_native_auto_removed_or_retained_own_cidfile(self):
  for auto_removed in (False,True):
   with self.subTest(auto_removed=auto_removed),tempfile.TemporaryDirectory() as temp:
    f=self.fixture(temp);capsule=Path(temp)/'capsule';capsule.mkdir();files=[]
    f.check=mock.Mock();f.state=lambda cid:dict(Running=False,ExitCode=0)
    f.prepare_data=mock.Mock(side_effect=p.Refused('model-stop-after-qualifier-cleanup'))
    f.stop_all=mock.Mock(return_value=True)
    def command(arguments,**kw):
     if arguments[0]=='container':return types.SimpleNamespace(returncode=1,stdout=b'')
     if arguments[0]=='create':
      path=Path(next(arg.split('=',1)[1] for arg in arguments if arg.startswith('--cidfile=')));path.write_text(CID);files.append(path)
      return types.SimpleNamespace(returncode=0,stdout=CID.encode())
     if arguments[0]=='rm' and auto_removed:files[-1].unlink()
     return types.SimpleNamespace(returncode=0,stdout=b'')
    f.command=command
    with mock.patch.object(b.tempfile,'mkdtemp',return_value=str(capsule)):
     with self.assertRaises(p.Refused):f.run({})
    f.prepare_data.assert_called_once();f.stop_all.assert_called_once()
    self.assertEqual(f.cidfiles,{});self.assertEqual(f.cids,[])
    self.assertFalse(capsule.exists())
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
    return types.SimpleNamespace(returncode=0,stdout=out,stderr=None)
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
