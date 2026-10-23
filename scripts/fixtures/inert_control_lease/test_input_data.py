"""Own USER files/real FDs; explicit INTERNAL Root-metadata projections only.
No proc/Root/private target access, no descriptor-limit changes, no public seam.
"""
import copy,hashlib,importlib.util,json,os,resource,stat,tempfile,types,unittest
from contextlib import ExitStack,contextmanager
from pathlib import Path,PurePosixPath as P
from unittest.mock import patch
import inert_control_lease_native as m
import fixture_correction as fixture
import test_native_lease as original
R=Path(__file__).resolve().parent
class OwnOS:
 def __init__(self,root):
  self.root=Path(root);self.fds={};self.peak=0;self.bytes=0;self.uid={};self.fixed={};self.hook=None;self.scans=0;self.peak_resources=0
  self.path=types.SimpleNamespace(realpath=lambda p:str(p))
 def __getattr__(self,n):return getattr(os,n)
 def name(self,p,dir_fd=None):
  result=Path(self.fds[dir_fd])/str(p) if dir_fd is not None and not str(p).startswith('/') else Path(p)
  if result!=self.root and self.root not in result.parents:raise AssertionError('outside own synthetic tree')
  return result
 def project(self,info,p):
  values={n:getattr(info,n) for n in dir(info) if n.startswith('st_')};values.update(st_uid=self.uid.get(str(p),0),st_gid=0)
  values.update(self.fixed.get(str(p),{}));return types.SimpleNamespace(**values)
 def lstat(self,p):
  p=Path(p)
  if p!=self.root and self.root not in p.parents:
   assert p in self.root.parents
   return types.SimpleNamespace(st_dev=1,st_ino=1,st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0,st_nlink=2,st_size=0,st_mtime_ns=0,st_ctime_ns=0)
  return self.project(os.lstat(p),p)
 def stat(self,p,dir_fd=None,follow_symlinks=True):
  p=self.name(p,dir_fd);return self.project(os.stat(p,follow_symlinks=follow_symlinks),p)
 def fstat(self,fd):return self.project(os.fstat(fd),self.fds[fd])
 def open(self,p,flags,mode=0o777,dir_fd=None):
  name=self.name(p,dir_fd);fd=os.open(name,flags,mode);self.fds[fd]=name;self.peak=max(self.peak,len(self.fds));self.peak_resources=max(self.peak_resources,len(self.fds)+self.scans);return fd
 def close(self,fd):os.close(fd);self.fds.pop(fd)
 def read(self,fd,size):
  part=os.read(fd,size);self.bytes+=len(part)
  if self.hook:self.hook(fd,part)
  return part
 def listdir(self,p):return os.listdir(p if type(p) is int else self.name(p))
 @contextmanager
 def scandir(self,p):
  self.scans+=1;self.peak_resources=max(self.peak_resources,len(self.fds)+self.scans)
  try:
   with os.scandir(p if type(p) is int else self.name(p)) as iterator:yield iterator
  finally:self.scans-=1
 def walk(self,root,followlinks=False,onerror=None):
  pending=[self.name(root)]
  while pending:
   directory=pending.pop();dirs=[];names=[];self.scans+=1;self.peak_resources=max(self.peak_resources,len(self.fds)+self.scans)
   try:
    with os.scandir(directory) as entries:
     for entry in entries:(dirs if entry.is_dir(follow_symlinks=False) else names).append(entry.name)
   except OSError as error:
    if onerror:onerror(error)
    else:raise
   finally:self.scans-=1
   yield str(directory),dirs,names
   pending.extend(directory/n for n in reversed(dirs))
class ProjectedPath(type(Path())):
 proxy=None
 def lstat(self):return self.proxy.lstat(self)
def policy_module():
 spec=importlib.util.spec_from_file_location('selected_input_policy',R/'policy_fence.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
@contextmanager
def projected_policy(module,proxy):
 ProjectedPath.proxy=proxy
 with patch.object(module,'os',proxy),patch.object(module,'Path',ProjectedPath),patch.object(module,'_fd_stat',proxy.fstat),patch.object(module,'_path_stat',proxy.lstat),patch.object(module,'_entry_stat',lambda fd,name:proxy.stat(name,dir_fd=fd,follow_symlinks=False)):
  yield

def make_scale(root):
 target=root/'legacy/node_modules';target.mkdir(parents=True)
 count=12077;zero=18;maximum=25409160;total=165832391
 (target/'large.jar').write_bytes(b'J'*maximum)
 for i in range(zero):(target/('empty-%02d'%i)).write_bytes(b'')
 n=count-zero-1;q,remainder=divmod(total-maximum,n);bodies=(b'd'*q,b'd'*(q+1))
 for i in range(n):(target/('input-%05d'%i)).write_bytes(bodies[i<remainder])
 return {'files':count,'bytes':total,'maximum':maximum,'empty':zero}
class RealData(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=R/'USER_TMP');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)/'build';self.root.mkdir();self.proxy=OwnOS(self.root);self.limits=resource.getrlimit(resource.RLIMIT_NOFILE)
 def tearDown(self):
  self.assertEqual(self.proxy.fds,{});self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE),self.limits)
 def scan(self,action=None):
  with patch.object(m,'_os',self.proxy),ExitStack() as stack:
   files,guards=m._data_tree(P(str(self.root)),stack)
   if action:action(files,guards)
   return files
 def file(self,name='input',body=b'public input'):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);return p
 def d_empty_tree(self):self.assertEqual(self.scan(),{})
 def d_zero_file(self):self.file(body=b'');self.assertEqual(self.scan(),{'input':hashlib.sha256(b'').hexdigest()})
 def d_no_filter_legacy_modules(self):self.file('legacy/node_modules/retained',b'public');self.assertIn('legacy/node_modules/retained',self.scan())
 def d_real32769_entry_bound(self):
  for i in range(32769):(self.root/str(i)).touch()
  with self.assertRaisesRegex(m.Refused,'data-entry-bound'):self.scan()
  self.assertEqual(self.proxy.bytes,0)
 def d_file64mib_plus_one(self):
  with (self.root/'large').open('wb') as f:f.truncate(64*1024*1024+1)
  with self.assertRaisesRegex(m.Refused,'protected-data-file'):self.scan()
  self.assertEqual(self.proxy.bytes,0)
 def d_aggregate512mib_bound(self):
  for i in range(9):
   with (self.root/str(i)).open('wb') as f:f.truncate(64*1024*1024)
  with self.assertRaisesRegex(m.Refused,'data-total-bound'):self.scan()
  self.assertEqual(self.proxy.bytes,512*1024*1024)
 def d_deadline60(self):
  self.file()
  with patch.object(m.time,'monotonic',side_effect=[0,61]),self.assertRaisesRegex(m.Refused,'data-timeout'):self.scan()
 def d_symlink_file(self):
  self.file();(self.root/'alias').symlink_to('input')
  with self.assertRaises(m.Refused):self.scan()
 def d_symlink_directory(self):
  (self.root/'directory').mkdir();(self.root/'alias').symlink_to('directory',target_is_directory=True)
  with self.assertRaises(m.Refused):self.scan()
 def d_cache_directory(self):
  self.file('__pycache__/bad',b'x')
  with self.assertRaisesRegex(m.Refused,'source-cache'):self.scan()
 def d_cache_file(self):
  self.file('bad.pyc',b'x')
  with self.assertRaisesRegex(m.Refused,'source-cache'):self.scan()
 def d_uid(self):
  p=self.file();self.proxy.uid[str(p)]=1000
  with self.assertRaisesRegex(m.Refused,'protected-data-file'):self.scan()
 def d_mode(self):
  p=self.file();p.chmod(0o666)
  with self.assertRaisesRegex(m.Refused,'protected-data-file'):self.scan()
 def d_nlink(self):
  p=self.file();os.link(p,self.root/'hardlink')
  with self.assertRaisesRegex(m.Refused,'protected-data-file'):self.scan()
 def d_late_full_hash_even_stale_metadata(self):
  p=self.file(body=b'aaaa');info=os.stat(p);self.proxy.fixed[str(p)]={'st_mtime_ns':info.st_mtime_ns,'st_ctime_ns':info.st_ctime_ns}
  def action(files,guards):
   before=self.proxy.bytes;p.write_bytes(b'bbbb')
   with self.assertRaisesRegex(m.Refused,'data-closure-race'):guards[0].check()
   self.assertEqual(self.proxy.bytes-before,4)
  self.scan(action)
 def d_late_foreign_entry(self):
  self.file()
  def action(files,guards):
   self.file('foreign')
   with self.assertRaises(m.Refused):guards[0].check()
  self.scan(action)
 def d_late_cache(self):
  self.file()
  def action(files,guards):
   self.file('bad.pyc')
   with self.assertRaises(m.Refused):guards[0].check()
  self.scan(action)
 def d_original_real_fd_vs_named_replacement(self):
  p=self.file();replacement=Path(self.tmp.name)/'replacement';replacement.write_bytes(b'foreign');fired=[]
  def hook(fd,part):
   if not fired and self.proxy.fds[fd]==p:
    old=os.fstat(fd);os.replace(replacement,p);fired.append((old.st_ino,os.lstat(p).st_ino));self.assertNotEqual(*fired[0])
  self.proxy.hook=hook
  with self.assertRaisesRegex(m.Refused,'data-file-race'):self.scan()
  self.assertEqual(len(fired),1)
 def d_real12077_scale_all_hashes_default_fd_limits(self):
  scale=make_scale(self.root)
  files=self.scan(lambda files,guards:guards[0].check())
  sizes=[p.stat().st_size for p in self.root.rglob('*') if p.is_file()]
  self.assertEqual((len(files),sum(sizes),max(sizes),sizes.count(0)),(12077,165832391,25409160,18))
  expected={}
  for p in self.root.rglob('*'):
   if p.is_file():
    h=hashlib.sha256()
    with p.open('rb') as f:
     while chunk:=f.read(65536):h.update(chunk)
    expected[str(p.relative_to(self.root))]=h.hexdigest()
  self.assertEqual(files,expected);self.assertLessEqual(self.proxy.peak,3);self.assertLessEqual(self.proxy.peak_resources,4)
  policy=policy_module()
  with projected_policy(policy,self.proxy):s2=policy.protected_input_tree(self.root)
  native=hashlib.sha256(m.encoded(files)).hexdigest();self.assertEqual(s2,native)
  proof={**scale,'nativeDataHash':native,'actualS2DataHash':s2,'trackedRealFdPeak':self.proxy.peak,'trackedFdPlusScandirPeak':self.proxy.peak_resources,'rlimitUnchanged':True,'scope':'own USER files + explicit Root metadata projection, NOT original target bytes'}
  (R/'DATA-SCALE-PROOF.json').write_text(json.dumps(proof,indent=2)+'\n')

class Tmpfiles(original.NativeTests):
 def reject(self,key,value):
  self.tmp_overrides[key]=value
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def d_tmp_exact_successful_exited(self):self.run_api();self.assertEqual(len(self.events('unlink')),1)
 def d_tmp_running(self):self.reject('SubState','running')
 def d_tmp_nononeshot(self):self.reject('Type','simple')
 def d_tmp_remain(self):self.reject('RemainAfterExit','no')
 def d_tmp_mainpid(self):self.reject('MainPID','123')
 def d_tmp_controlpid(self):self.reject('ControlPID','123')
 def d_tmp_failed_result(self):self.reject('Result','exit-code')
 def d_tmp_failed_status(self):self.reject('ExecMainStatus','1')
 def d_tmp_cgroup_present(self):
  self.fs.directory('/sys/fs/cgroup/system.slice/'+m.TMPFILES[0]);self.reject('ControlGroup','/system.slice/'+m.TMPFILES[0]);self.reject('ControlGroup','')
 def d_tmp_jobs(self):
  self.jobs=True
  with self.assertRaisesRegex(m.Refused,'jobs-present'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def d_tmp_process(self):
  self.process_bad=True
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def d_tmp_dropins(self):self.reject('DropInPaths','/synthetic/foreign.conf')
 def d_tmp_foreign_fragment(self):self.reject('FragmentPath','/foreign/'+m.TMPFILES[0])
 def d_tmp_foreign_group(self):self.reject('ControlGroup','/system.slice/foreign.service')
 def d_tmp_noncanonical_pid(self):self.reject('MainPID','00')
 def edit_cfg(self,fn):
  node=self.fs.nodes[self.flat+'/SOURCE-LOCK.json'];cfg=json.loads(node.data);fn(cfg['targetAuthority']['inputConfiguration']);node.data=m.encoded(cfg)
 def d_target_67_complete_positive(self):
  cfg=json.loads(self.fs.nodes[self.flat+'/SOURCE-LOCK.json'].data)['targetAuthority']
  self.assertEqual(len(cfg['ops']),57);self.assertEqual(len(cfg['inputConfiguration']['ops']),67)
  self.assertEqual(set(cfg['inputConfiguration']['ops'])-set(cfg['ops']),m.GENERATED_OPS)
  self.run_api();self.assertTrue(all(p.startswith(self.flat+'/') for p in self.loaded))
 def d_target_missing_generated_pin(self):
  self.edit_cfg(lambda c:c['ops'].pop(next(iter(m.GENERATED_OPS))))
  with self.assertRaisesRegex(m.Refused,'target-input-members'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_unconfigured_extra(self):
  self.fs.put(self.bundle+'/ops/unknown-generated',data=b'SYNTHETIC unknown')
  with self.assertRaisesRegex(m.Refused,'original-target-ops-pins'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_generated_mode(self):
  self.fs.nodes[self.bundle+'/ops/'+next(iter(m.GENERATED_OPS))].mode|=0o100
  with self.assertRaisesRegex(m.Refused,'original-target-ops-mode'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_generated_bytes(self):
  self.fs.nodes[self.bundle+'/ops/'+next(iter(m.GENERATED_OPS))].data=b'SYNTHETIC foreign generated body'
  with self.assertRaisesRegex(m.Refused,'original-target-ops-pins'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_receipt_sha(self):
  self.edit_cfg(lambda c:c.update(historicalArtifactReceiptSha256='f'*64))
  with self.assertRaisesRegex(m.Refused,'historical-artifact-receipt'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_wrong_path_tuple(self):
  self.edit_cfg(lambda c:c.update(bundlePath='/synthetic-foreign-target'))
  with self.assertRaisesRegex(m.Refused,'target-input-binding'):self.run_api()
  self.assertEqual(self.loaded,[])
 def d_target_initial_ledger(self):
  self.edit_cfg(lambda c:c.update(initialReviewedLedgerSha256='f'*64))
  with self.assertRaisesRegex(m.Refused,'target-input-initial-ledger'):self.run_api()
  self.assertEqual(self.events('unlink'),[])
 def d_tmp_late_writer_before_unlink(self):
  def changed(e):
   if e==('fsync','/audit') and self.data().get(m.KEY,{}).get('phase')=='lease-delete-issued':self.tmp_overrides['ControlPID']='123'
  self.fs.callback=changed
  with self.assertRaises(m.Refused):self.run_api()
  self.assertEqual(self.events('unlink'),[])

class FullContext(original.NativeTests):
 def d_actual_s2_context_full12077_build(self):
  with tempfile.TemporaryDirectory(dir=R/'USER_TMP') as temp:
   root=Path(temp)/'build';root.mkdir();make_scale(root);proxy=OwnOS(root);data=policy_module()
   with patch.object(m,'_os',proxy),ExitStack() as stack:files,guards=m._data_tree(P(str(root)),stack)
   expected=copy.deepcopy(self.closure);expected['build']=hashlib.sha256(m.encoded(files)).hexdigest()
   policy=policy_module();self.registry.stage.safe_parents=lambda *a:copy.deepcopy(self.state['createPaths'])
   def loaded(path,name):
    file=P(str(path)).name
    return {'venue-owned-stage.py':self.registry.stage,'venue-start-quarantine.py':self.lifecycle,
     'venue-unit-stage.py':self.registry.composite.units,'venue-image-authority.py':self.registry.authority}[file]
   def build_hash(path):
    self.assertEqual(str(path),self.bundle+'/build')
    with projected_policy(data,proxy):return data.protected_input_tree(root)
   with patch.object(policy,'Path',fixture.SlotPath),patch.object(policy,'os',self.fs),patch.object(policy,'protected_tree',m.protected_tree),patch.object(policy,'_fd_stat',self.fs.fstat),patch.object(policy,'_path_stat',self.fs.lstat),patch.object(policy,'_entry_stat',lambda fd,name:self.fs.stat(name,dir_fd=fd,follow_symlinks=False)),patch.object(policy,'load_closed',loaded),patch.object(policy,'protected_input_tree',build_hash):
    plan,context,manifest,created,closure=policy.actual_context(fixture.SlotPath(self.bundle),fixture.SlotPath('/selector.json'))
   self.assertEqual(closure,expected);self.assertEqual(hashlib.sha256(m.canonical(closure)).hexdigest(),hashlib.sha256(m.canonical(expected)).hexdigest())
   self.assertEqual(proxy.fds,{});self.assertLessEqual(proxy.peak,3)
   (R/'ACTUAL-S2-CONTEXT-SCALE-PROOF.json').write_text(json.dumps({'files':len(files),'buildHash':expected['build'],'closureHash':hashlib.sha256(m.canonical(closure)).hexdigest(),'actualContextExecuted':True,'realDataFdPeak':proxy.peak,'scope':'source code/context fakes + real own USER scale data; NOT target proof'},indent=2)+'\n')
