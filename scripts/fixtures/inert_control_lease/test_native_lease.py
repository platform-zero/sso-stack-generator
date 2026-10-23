"""REAL implementation branches, explicit INTERNAL kernel/FS/NSS/source/sysd fakes.
No root, proc, selected/native code, policy, service or target access occurs.
"""
import copy,json,os,stat,types,unittest
from pathlib import Path,PurePosixPath as P
from unittest.mock import patch
import inert_control_lease_native as m
REAL_PROCESS=m._processes_quiescent

class Node:
 def __init__(self,name,ino,mode,data=b''):
  self.name=name;self.ino=ino;self.mode=mode;self.data=data;self.linked=True;self.uid=0;self.gid=0;self.clock=1

class FS:
 def __init__(self):self.nodes={};self.children_map={};self.generation=0;self.directory_cache={};self.fds={};self.nextfd=10;self.nextino=10;self.events=[];self.uid=0;self.callback=None;self.opens=[];self.put('/',stat.S_IFDIR|0o755)
 def __getattr__(self,n):
  if n.isupper():return getattr(os,n)
  if n=='fspath':return os.fspath
  raise AttributeError(n)
 def put(self,name,mode=stat.S_IFREG|0o644,data=b''):
  name=str(name)
  if name!='/':
   parent=str(P(name).parent)
   if parent not in self.nodes:self.put(parent,stat.S_IFDIR|0o755)
  self.generation+=1
  self.nextino+=1;node=Node(name,self.nextino,mode,data);self.nodes[name]=node
  if name!='/':self.children_map.setdefault(str(P(name).parent),set()).add(P(name).name)
  return node
 def directory(self,p,mode=0o755):return self.put(p,stat.S_IFDIR|mode)
 def resolve(self,p,fd=None):return str(P(self.fds[fd][0].name)/str(p)) if fd is not None and not str(p).startswith('/') else str(p)
 def children(self,p):return sorted(n for n in self.children_map.get(p,set()) if str(P(p)/n) in self.nodes)
 def meta(self,node):
  directory=stat.S_ISDIR(node.mode)
  key=(node.ino,self.generation,node.linked)
  if directory and key in self.directory_cache:return self.directory_cache[key]
  links=(2+sum(stat.S_ISDIR(self.nodes[str(P(node.name)/n)].mode) for n in self.children(node.name))) if directory else 1
  result=types.SimpleNamespace(st_dev=1,st_ino=node.ino,st_uid=node.uid,st_gid=node.gid,st_mode=node.mode,
   st_nlink=links if node.linked else 0,st_size=len(node.data) if not directory else 40+20*len(self.children(node.name)),st_mtime_ns=node.clock,st_ctime_ns=node.clock)
  if directory:self.directory_cache[key]=result
  return result
 def lstat(self,p):
  if str(p) not in self.nodes:raise FileNotFoundError()
  return self.meta(self.nodes[str(p)])
 def stat(self,p,dir_fd=None,follow_symlinks=True):
  name=self.resolve(p,dir_fd)
  if name in ('/proc/self/ns/user','/proc/1/ns/user'):return types.SimpleNamespace(st_dev=9,st_ino=99)
  return self.lstat(name)
 def fstat(self,fd):return self.meta(self.fds[fd][0])
 def open(self,p,flags,mode=0o777,dir_fd=None):
  name=self.resolve(p,dir_fd);self.opens.append((name,flags))
  if flags&os.O_CREAT:
   if name in self.nodes:raise FileExistsError()
   self.put(name,stat.S_IFREG|mode)
  if name not in self.nodes:raise FileNotFoundError()
  n=self.nodes[name]
  if stat.S_ISLNK(n.mode) and flags&os.O_NOFOLLOW:raise OSError('PUBLIC fake symlink')
  if flags&os.O_DIRECTORY and not stat.S_ISDIR(n.mode):raise NotADirectoryError()
  self.nextfd+=1;self.fds[self.nextfd]=[n,0];return self.nextfd
 def read(self,fd,size):
  n,offset=self.fds[fd];out=n.data[offset:offset+size];self.fds[fd][1]+=len(out);return out
 def write(self,fd,body):
  n,offset=self.fds[fd];n.data=n.data[:offset]+body;n.clock+=1;self.fds[fd][1]+=len(body);return len(body)
 def lseek(self,fd,offset,whence):self.fds[fd][1]=offset
 def close(self,fd):
  n=self.fds.pop(fd)[0];self.events.append(('close',n.name))
 def listdir(self,p):return self.children(self.fds[p][0].name if type(p) is int else str(p))
 def walk(self,root,followlinks=False):
  def walk(p):
   names=self.children(p);dirs=[n for n in names if stat.S_ISDIR(self.nodes[str(P(p)/n)].mode)];files=[n for n in names if n not in dirs]
   yield p,dirs,files
   for n in dirs:yield from walk(str(P(p)/n))
  yield from walk(str(root))
 def readlink(self,p):return self.nodes[str(p)].data.decode()
 def emit(self,event):
  self.events.append(event)
  if self.callback:self.callback(event)
 def fsync(self,fd):self.emit(('fsync',self.fds[fd][0].name))
 def unlink(self,name,dir_fd=None):
  p=self.resolve(name,dir_fd);node=self.nodes.pop(p);node.linked=False;self.generation+=1;self.emit(('unlink',p))
 def rmdir(self,name,dir_fd=None):
  p=self.resolve(name,dir_fd)
  if self.children(p):raise OSError('PUBLIC nonempty')
  self.nodes.pop(p).linked=False;self.generation+=1;self.emit(('rmdir',p))
 def replace(self,src,dst,src_dir_fd=None,dst_dir_fd=None):
  a=self.resolve(src,src_dir_fd);b=self.resolve(dst,dst_dir_fd)
  if b in self.nodes:self.nodes[b].linked=False
  n=self.nodes.pop(a);n.name=b;self.nodes[b]=n;self.generation+=1;self.emit(('replace',b))
 def geteuid(self):return self.uid
 def getpid(self):return 777

class NativeTests(unittest.TestCase):
 def setUp(self):
  self.fs=FS();f=self.fs;self.ns='p0test-unit';self.flat='/flat';self.bundle='/bundle';self.slot='/usr/local/libexec/'+self.ns+'-control/agent-service-releases/slot1';self.runtime='/run/'+self.ns+'-control';self.ledger='/audit/ledger.json'
  for fixed in ('/etc/sudoers.d','/etc/tmpfiles.d','/etc/systemd/system'):f.directory(fixed)
  f.directory('/audit',0o700);f.directory(self.runtime,0o700);f.put(self.runtime+'/lifecycle.lock',stat.S_IFREG|0o600)
  f.put('/proc/self/uid_map',data=b'0 0 4294967295\n')
  source=json.loads((Path(__file__).parent/'SOURCE-LOCK.json').read_text())
  pins={}
  for name in source['ops']:
   body=('PUBLIC SOURCE FIXTURE '+name).encode();pins[name]=m.digest(body)
   f.put(self.flat+'/'+name,data=body);f.put(self.bundle+'/ops/'+name,data=body)
  ec4body=b'PUBLIC ec4 fake';self.ec4=m.digest(ec4body)
  for name,body in [('retire-failed-venue-registry-image.py',ec4body),('policy_fence.py',b'PUBLIC native policy helper'),('inert_control_lease_native.py',b'PUBLIC native lease operation')]:f.put(self.flat+'/'+name,data=body)
  f.put(self.flat+'/SOURCE-LOCK.json',data=m.encoded({'ops':pins,'ec4':self.ec4,'generatorCommit':'PUBLIC_SOURCE_FIXTURE'}))
  self.policy=m.digest(f.nodes[self.flat+'/policy_fence.py'].data)
  self.plan={'prefix':self.ns,'sourceCommit':'g'*40,'selectorSha256':'a'*64,'quadletTreeSha256':'b'*64,
    'accounts':[{'name':self.ns+'-a'+str(i),'uid':4000+i} for i in range(7)],
    'roots':{'r'+str(i):'/gone/'+self.ns+'/d'+str(i) for i in range(38)},'configs':{}}
  self.plan_sha=m.digest(m.canonical(self.plan));self.provenance=m.digest(b'PUBLIC provenance')
  for n,b in [('source-provenance.json',b'PUBLIC provenance'),('podman-domains.json',b'{}'),('stack.ir.json',b'{}'),('site/agent-vm.json',b'{}')]:f.put(self.bundle+'/'+n,data=b)
  f.put('/selector.json',data=b'PUBLIC selector')
  f.put(self.bundle+'/site/global.settings/registry-image-ids.json',data=b'PUBLIC source identity fixture')
  self.manifest={'/etc/containers/systemd/'+self.ns+'-u'+str(i)+'.container':{} for i in range(190)}
  for i in range(190):f.put(self.bundle+'/quadlet/rootful/u'+str(i)+'.container',data=b'PUBLIC quadlet')
  manifest={}
  for n in m.HOST_NAMES:
   b=('PUBLIC unit '+n).encode();f.put(self.slot+'/units/'+n,data=b);manifest['units/'+n]=m.digest(b)
  f.put(self.slot+'/p0_host_context.py',data=b'PUBLIC host context code')
  f.put(self.slot+'/manifest.json',data=m.encoded({'files':manifest}))
  base='/usr/local/libexec/'+self.ns+'-control';f.put(base+'/agent-services-current-host',stat.S_IFLNK|0o777,self.slot.encode())
  self.context=types.SimpleNamespace(namespace=self.ns,source=P(base),runtime=P(self.runtime),digest='c'*64,unit=lambda n:self.ns+'-'+n)
  # Reproduce S2's currently documented exact canonical closure wire.
  treehash=lambda root:{n[len(root)+1:]:m.digest(v.data) for n,v in f.nodes.items() if n.startswith(root+'/') and not stat.S_ISDIR(v.mode)}
  closure={'ops':m.digest(m.encoded(treehash(self.bundle+'/ops'))),'slot':m.digest(m.encoded(treehash(self.slot))),
    'quadlet':m.digest(m.encoded(treehash(self.bundle+'/quadlet'))),'slotPath':self.slot,'manifest':{'files':manifest}}
  closure_sha=m.digest(m.canonical(closure));names=[a['name'] for a in self.plan['accounts']];paths=list(self.plan['roots'].values())
  units=[{'path':p,'dev':1,'ino':100+i} for i,p in enumerate(self.manifest)]
  hostpaths=[str(P('/etc/systemd/system')/self.context.unit(n)) for n in m.HOST_NAMES]
  self.images={names[0]+'|localhost/model:pending':'sha256:'+'1'*64,names[1]+'|localhost/model:verified':'sha256:'+'2'*64}
  self.state={'plan':self.plan,'venueInstallerVersion':1,'venueInstallerPhase':'retired-inert','status':'retired-empty','activationAuthorized':False,
   'installedUnits':units,'retiredUnits':list(self.manifest),'graphCleared':['root']+names,'managerStopped':names,
   'createPaths':paths,'createdPaths':paths,'pathIdentities':{p:{'dev':1,'ino':200+i,'uid':0,'mode':0o700} for i,p in enumerate(paths)},
   'venueHostUnitsRetirement':{'phase':'retired','contextSha256':self.context.digest,'neverStartedInstallerVersion':1,'units':[{'path':p,'sha256':'d'*64} for p in hostpaths],'removed':hostpaths},
   m.FENCE:{'schemaVersion':1,'phase':'fenced','namespace':self.ns,'hostContextSha256':self.context.digest,'provenanceSha256':self.provenance,
    'planSha256':self.plan_sha,'operationSha256':self.policy,'sourceClosureSha256':closure_sha}}
  for k in ('venueCompositeMode','venueRuntimeEnvPhase','venueDomainRuntimePhase','venueReleasePhase','venueRegistryPhase','venueBuildBasePhase'):self.state[k]='retired-inert'
  f.put(self.ledger,stat.S_IFREG|0o600,m.encoded(self.state))
  stage=types.SimpleNamespace(owned_plan=lambda *args:copy.deepcopy(self.plan))
  authority=dict(generatorCommit=self.plan['sourceCommit'],selectorSha256=self.plan['selectorSha256'],quadletTreeSha256=self.plan['quadletTreeSha256'],imageIds=self.images)
  self.lifecycle=types.SimpleNamespace(host_context=lambda *args:self.context)
  self.registry=types.SimpleNamespace(stage=stage,authority=types.SimpleNamespace(pinned_images=types.SimpleNamespace(selected_image_ids=lambda *args:self.images)),
   composite=types.SimpleNamespace(units=types.SimpleNamespace(manifest=lambda *args:self.manifest)),load=self.load_lifecycle)
  self.loaded=[];self.jobs=False;self.process_bad=False;self.nss_bad=False;self.process_hook=None
  patches=[patch.object(m,'_os',f),patch.object(m,'_SELF',self.flat+'/inert_control_lease_native.py'),
   patch.object(m,'sys',types.SimpleNamespace(flags=types.SimpleNamespace(isolated=True,no_site=True),dont_write_bytecode=True,pycache_prefix=None)),
   patch.object(m,'_load',self.load),patch.object(m,'_command',self.command),patch.object(m,'_processes_quiescent',self.processes),
   patch.object(m,'pwd',types.SimpleNamespace(getpwnam=self.nss,getpwuid=self.nss)),patch.object(m,'grp',types.SimpleNamespace(getgrnam=self.nss,getgrgid=self.nss)),
   patch.object(m.fcntl,'flock',lambda fd,flags:f.emit(('flock',f.fds[fd][0].name)))]
  for p in patches:p.start();self.addCleanup(p.stop)
 def nss(self,*args):
  if self.nss_bad:return object()
  raise KeyError()
 def load(self,p,name):
  self.loaded.append(str(p));self.assertTrue(all(any(x[0]==self.flat+'/'+n for x in self.fs.opens) for n in json.loads(self.fs.nodes[self.flat+'/SOURCE-LOCK.json'].data)['ops']))
  return self.registry
 def load_lifecycle(self,*args):
  self.assertTrue(any(x[0]==self.slot+'/p0_host_context.py' for x in self.fs.opens));return self.lifecycle
 def processes(self,*args):
  if self.process_hook:self.process_hook()
  if self.process_bad:raise m.Refused('root-controller-active')
 def command(self,argv):
  if 'list-jobs' in argv:return 'PUBLIC pending job' if self.jobs else ''
  props=argv[-1].split('=',1)[1].split(',');unit=argv[2]
  values={'LoadState':'not-found','ActiveState':'inactive','SubState':'dead','FragmentPath':'','DropInPaths':''}
  return '\n'.join(k+'='+values[k] for k in props)+'\n'
 def data(self):return json.loads(self.fs.nodes[self.ledger].data)
 def mutate(self,fn):
  state=self.data();fn(state);self.fs.nodes[self.ledger].data=m.encoded(state)
 def run_api(self,epoch=None):return m.retire_inert_control_lease(self.bundle,'/selector.json',self.ledger,epoch or m.digest(self.fs.nodes[self.ledger].data),self.provenance,self.plan_sha)
 def events(self,n):return [x for x in self.fs.events if x[0]==n]
 def crash_phase(self,phase):
  def callback(event):
   if event==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')==phase:raise OSError('PUBLIC injected crash')
  self.fs.callback=callback
  with self.assertRaises(m.Refused):self.run_api()
  self.fs.callback=None
 def history(self):
  verified={list(self.images)[1]:list(self.images.values())[1]}
  return {'schemaVersion':1,'pending':list(self.images)[0],'selectedImageId':list(self.images.values())[0],'retiredImageId':'sha256:'+'3'*64,
   'verifiedSha256':m.digest(m.canonical(verified)),'sourceProvenanceSha256':self.provenance,'operationSourceSha256':self.ec4,'ledgerSha256Before':'d'*64,'phase':'retired-drifted-pending'},verified
 def test_positive_full_native_default_branches_with_explicit_internal_fakes(self):
  result=self.run_api();self.assertEqual(result['status'],'retired-inert-control-lease');self.assertEqual(result['acceptedIntegratedInstalls'],0)
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1);self.assertNotIn(self.runtime,self.fs.nodes)
  self.assertEqual(self.data()[m.KEY]['phase'],'retired');self.assertFalse(result['nativeRecoveryAuthorized'])
  for p,flags in self.fs.opens:
   if p.endswith('lifecycle.lock'):self.assertFalse(flags&os.O_CREAT)
  self.assertLess(self.fs.events.index(('rmdir',self.runtime)),self.fs.events.index(('close',self.runtime+'/lifecycle.lock')))
 def test_unprivileged_refuses_before_kernel_or_private_source_reads(self):
  self.fs.uid=1000
  with self.assertRaisesRegex(m.Refused,'root-admission'):self.run_api()
  self.assertEqual(self.fs.opens,[]);self.assertEqual(self.loaded,[])
 def test_nonisolated_refuses_before_reads(self):
  m.sys.flags.isolated=False
  with self.assertRaisesRegex(m.Refused,'root-admission'):self.run_api()
  self.assertEqual(self.fs.opens,[])
 def test_wrong_cas_no_writes(self):
  with self.assertRaisesRegex(m.Refused,'ledger-cas'):self.run_api('a'*64)
  self.assertEqual(self.events('replace'),[])
 def test_marker_without_actual_policy_absence_refuses(self):
  self.fs.put('/etc/tmpfiles.d/'+self.ns+'-control.conf',data=b'PUBLIC policy')
  with self.assertRaisesRegex(m.Refused,'policy-present'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_three_host_units_must_actually_be_absent(self):
  self.fs.put('/etc/systemd/system/'+self.context.unit(m.HOST_NAMES[0]),data=b'PUBLIC unit')
  with self.assertRaisesRegex(m.Refused,'retired-path-present'):self.run_api()
 def test_missing_policy_binding_refuses(self):
  self.mutate(lambda s:s.pop(m.FENCE))
  with self.assertRaisesRegex(m.Refused,'policy-fence-binding'):self.run_api()
 def test_policy_code_mismatch_refuses(self):
  self.mutate(lambda s:s[m.FENCE].update(operationSha256='e'*64))
  with self.assertRaisesRegex(m.Refused,'policy-fence-binding'):self.run_api()
 def test_full_normal_retirement_required(self):
  self.mutate(lambda s:s['retiredUnits'].pop())
  with self.assertRaisesRegex(m.Refused,'units-scope'):self.run_api()
 def test_nss_uid_group_reuse_refuses(self):
  self.nss_bad=True
  with self.assertRaisesRegex(m.Refused,'account-or-group-present'):self.run_api()
 def test_unknown_pending_refuses(self):
  self.mutate(lambda s:s.update(unknownPending=False))
  with self.assertRaisesRegex(m.Refused,'pending-state'):self.run_api()
 def test_ec4_completed_nine_field_history_preserved(self):
  history,verified=self.history()
  self.mutate(lambda s:s.update(venueRegistryFailedPendingRetirement=history,venueRegistryPlan=self.images,venueRegistryVerified=verified,venueRegistryPreparationAbandoned=True))
  self.run_api();self.assertEqual(self.data()['venueRegistryFailedPendingRetirement'],history)
 def test_six_field_illustration_is_not_real_history(self):
  self.mutate(lambda s:s.update(venueRegistryFailedPendingRetirement={'phase':'retired-drifted-pending'}))
  with self.assertRaisesRegex(m.Refused,'pending-history'):self.run_api()
 def test_history_source_map_mismatch_refuses(self):
  h,v=self.history();h['selectedImageId']='sha256:'+'4'*64
  self.mutate(lambda s:s.update(venueRegistryFailedPendingRetirement=h,venueRegistryPlan=self.images,venueRegistryVerified=v,venueRegistryPreparationAbandoned=True))
  with self.assertRaisesRegex(m.Refused,'history-binding'):self.run_api()
 def test_nonfinite_numeric_overflow_fixed_enum(self):
  body=self.fs.nodes[self.ledger].data.rstrip();self.fs.nodes[self.ledger].data=body[:-1]+b',"public":1e999}\n'
  with self.assertRaisesRegex(m.Refused,'json-nonfinite'):self.run_api()
 def test_malformed_installed_observation_fixed_enum(self):
  self.mutate(lambda s:s['installedUnits'][0].update(ino='PUBLIC wrong type'))
  with self.assertRaisesRegex(m.Refused,'units-schema'):self.run_api()
 def test_new_missing_runtime_cannot_be_adopted(self):
  self.fs.nodes.pop(self.runtime+'/lifecycle.lock');self.fs.nodes.pop(self.runtime)
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('replace'),[])
 def test_source_cache_before_load_refuses(self):
  self.fs.put(self.bundle+'/ops/__pycache__/bad.pyc',data=b'PUBLIC cache')
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.loaded,[])
 def test_external_slot_cache_refuses_before_host_context_load(self):
  self.fs.put(self.slot+'/__pycache__/bad.pyc',data=b'PUBLIC cache')
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('replace'),[])
 def test_intended_resume_existing_lock_only(self):
  self.crash_phase('intended');self.run_api();self.assertEqual(len(self.events('unlink')),1)
 def test_issued_present_lease_never_second_delete(self):
  self.crash_phase('lease-delete-issued')
  with self.assertRaisesRegex(m.Refused,'issued-lease-present'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_issued_present_directory_never_rmdir(self):
  self.crash_phase('directory-delete-issued')
  with self.assertRaisesRegex(m.Refused,'issued-directory-present'):self.run_api()
  self.assertEqual(self.events('rmdir'),[])
 def test_absent_lease_continuation_no_second_unlink(self):
  self.fs.callback=lambda e:(_ for _ in ()).throw(OSError('PUBLIC crash')) if e[0]=='unlink' else None
  with self.assertRaises(m.Refused):self.run_api()
  self.fs.callback=None;self.run_api();self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
 def test_absent_directory_continuation_and_repeat_no_second_delete(self):
  self.fs.callback=lambda e:(_ for _ in ()).throw(OSError('PUBLIC crash')) if e[0]=='rmdir' else None
  with self.assertRaises(m.Refused):self.run_api()
  self.fs.callback=None;self.run_api();self.run_api();self.assertEqual(len(self.events('unlink')),1);self.assertEqual(len(self.events('rmdir')),1)
 def test_recreated_lease_after_issued_refuses(self):
  self.crash_phase('lease-delete-issued');self.fs.put(self.runtime+'/lifecycle.lock',stat.S_IFREG|0o600)
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_recreated_directory_after_issued_refuses(self):
  self.crash_phase('directory-delete-issued');self.fs.nodes.pop(self.runtime);self.fs.directory(self.runtime,0o700)
  with self.assertRaisesRegex(m.Refused,'issued-directory-present'):self.run_api()
 def test_late_jobs_after_issued_refuse_before_unlink(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.jobs=True
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'jobs-present'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_late_root_process_after_issued_refuses(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.process_bad=True
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'root-controller-active'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_late_source_bytes_refuse(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.nodes[self.flat+'/venue-owned-stage.py'].data=b'PUBLIC foreign'
  self.fs.callback=callback
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_late_cache_addition_refuses(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.put(self.slot+'/bad.pyc',data=b'PUBLIC cache')
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'source-entries-race'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_late_cas_foreign_epoch_not_adopted(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.nodes[self.ledger].data=b'PUBLIC foreign epoch'
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'ledger-cas'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_late_lease_identity_refuses(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.fs.put(self.runtime+'/lifecycle.lock',stat.S_IFREG|0o600)
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'held-lease-race'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_private_exception_not_emitted(self):
  with patch.object(m,'_command',side_effect=OSError('PUBLIC-SYNTHETIC-PRIVATE-BODY')):
   with self.assertRaises(m.Refused) as e:self.run_api()
  self.assertEqual(str(e.exception),'native-observation-refused');self.assertTrue(e.exception.__suppress_context__)
 def proc_record(self,argv=b'/usr/bin/public-idle\0',uid=0,start=100,flags=0):
  tail=['S','1','0','0','0','0',str(flags)]+['0']*12+[str(start)]
  self.fs.put('/proc/100/stat',data=('100 (PUBLIC fixture) '+' '.join(tail)).encode())
  self.fs.put('/proc/100/status',data=('Uid:\t'+'\t'.join([str(uid)]*4)+'\n').encode())
  self.fs.put('/proc/100/cmdline',data=argv)
 def test_real_process_observer_branch_with_synthetic_proc_records(self):
  self.proc_record()
  REAL_PROCESS(self.ns,[a['uid'] for a in self.plan['accounts']])
  self.assertFalse(any(p.endswith('/environ') for p,flags in self.fs.opens))
 def test_real_process_observer_rejects_root_controller(self):
  self.proc_record(b'/usr/bin/python3\0/flat/venue-start-quarantine.py\0--selector\0/public-fixture.json\0')
  with self.assertRaisesRegex(m.Refused,'root-controller-active'):REAL_PROCESS(self.ns,[])
 def test_real_process_observer_rejects_tmpfiles_create(self):
  self.proc_record(b'/usr/bin/systemd-tmpfiles\0--create\0')
  with self.assertRaisesRegex(m.Refused,'tmpfiles-create-active'):REAL_PROCESS(self.ns,[])
 def test_real_process_observer_rejects_retired_uid_process(self):
  self.proc_record(uid=4000)
  with self.assertRaisesRegex(m.Refused,'retired-uid-process'):REAL_PROCESS(self.ns,[4000])
 def test_real_process_observer_rejects_pid_reuse(self):
  self.proc_record();original=self.fs.open;count=0
  def opening(p,*args,**kwargs):
   nonlocal count
   if str(p)=='/proc/100/stat':
    count+=1
    if count==2:self.proc_record(start=200)
   return original(p,*args,**kwargs)
  with patch.object(self.fs,'open',opening),self.assertRaisesRegex(m.Refused,'process-reused'):REAL_PROCESS(self.ns,[])
 def test_real_process_observer_unknown_empty_root_argv_refuses(self):
  self.proc_record(argv=b'')
  with self.assertRaisesRegex(m.Refused,'process-unknown'):REAL_PROCESS(self.ns,[])
 def test_real_process_observer_known_kernel_thread_not_controller(self):
  self.proc_record(argv=b'',flags=0x00200000)
  REAL_PROCESS(self.ns,[])
 def test_real_process_malformed_observation_public_fixed_refusal(self):
  self.proc_record();self.fs.nodes['/proc/100/stat'].data=b'PUBLIC malformed'
  with patch.object(m,'_processes_quiescent',REAL_PROCESS):
   with self.assertRaisesRegex(m.Refused,'native-observation-refused'):self.run_api()
 def test_late_uid_reuse_prevents_rmdir_but_no_second_unlink(self):
  def callback(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='directory-delete-issued':self.nss_bad=True
  self.fs.callback=callback
  with self.assertRaisesRegex(m.Refused,'account-or-group-present'):self.run_api()
  self.assertEqual(len(self.events('unlink')),1);self.assertEqual(self.events('rmdir'),[])
 def test_policy_parent_symlink_is_not_an_absence_proof(self):
  self.fs.put('/etc/tmpfiles.d',stat.S_IFLNK|0o777,b'/PUBLIC-other')
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def test_default_api_has_only_six_args_no_injected_host(self):
  import inspect
  self.assertEqual(tuple(inspect.signature(m.retire_inert_control_lease).parameters),('bundle','selector','ledger','reviewed_sha','provenance_sha','plan_sha'))

if __name__=='__main__':unittest.main(verbosity=2)
