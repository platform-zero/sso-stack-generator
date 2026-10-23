"""C33 independent boundary tests: own USER tree/FDs, internal privileged fakes.
No actual Root/proc/cgroup/unit/target reads. Fakes never authenticate authority.
"""
from contextlib import ExitStack
import hashlib,json,os,resource,stat,unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a
from test_tmpfiles_quiescence import boot,text,SEARCH

class Watch:
 def __init__(self):self.live=set();self.peak=0;self.requests=[];self.stack=ExitStack()
 def __enter__(self):
  op=p.os.open;di=p._directory_fd;cl=p.os.close;rd=p.os.read
  def add(fd):self.live.add(fd);self.peak=max(self.peak,len(self.live));return fd
  def opened(*args,**kw):return add(op(*args,**kw))
  def directory(*args,**kw):return add(di(*args,**kw))
  def closed(fd):self.live.discard(fd);return cl(fd)
  def read(fd,n):self.requests.append(n);return rd(fd,n)
  for c in (patch.object(p.os,'open',opened),patch.object(p,'_directory_fd',directory),patch.object(p.os,'close',closed),patch.object(p.os,'read',read)):self.stack.enter_context(c)
  return self
 def __exit__(self,*args):self.stack.close()

class FreshTests(unittest.TestCase):
 def build(self,w):
  root=w.root/'data';root.mkdir(mode=0o700);return root
 def leaf(self,root,name,data=b'abc'):
  path=root/name;path.write_bytes(data);path.chmod(0o600);return path
 def test_faithful_data_exact_full_hash_nonzero_bodies_under_64_fd_limit(self):
  with a.World() as w:
   root=self.build(w);base=root/'node_modules';base.mkdir(mode=0o700)
   buckets=[base/str(i) for i in range(48)]
   for d in buckets:d.mkdir(mode=0o700)
   q,r=divmod(165832391-25409160,12077-19);expected={};cache={};sizes=[]
   for i in range(12077):
    size=0 if i<18 else 25409160 if i==18 else q+int(i-19<r)
    path=buckets[i%48]/(str(i)+('.jar' if i==18 else '.data'));head=i%251;tail=i*11%251
    with path.open('wb') as out:
     out.truncate(size)
     if size:out.seek(0);out.write(bytes([head]));out.seek(size-1);out.write(bytes([tail]))
    path.chmod(0o600);key=(size,head,tail)
    if key not in cache:
     digest=hashlib.sha256()
     if size:
      digest.update(bytes([head]));remaining=size-2
      while remaining:n=min(65536,remaining);digest.update(b'\0'*n);remaining-=n
      digest.update(bytes([tail]))
     cache[key]=digest.hexdigest()
    expected[str(path.relative_to(root))]=cache[key];sizes.append(size)
   self.assertEqual((len(sizes),sum(sizes),max(sizes),sizes.count(0)),(12077,165832391,25409160,18))
   before=resource.getrlimit(resource.RLIMIT_NOFILE)
   try:
    resource.setrlimit(resource.RLIMIT_NOFILE,(min(64,before[0]),before[1]))
    with Watch() as watch:actual=p.protected_input_tree(root)
   finally:resource.setrlimit(resource.RLIMIT_NOFILE,before)
   self.assertEqual(actual,p.sha(p.encode(expected)));self.assertEqual(watch.live,set())
   self.assertLessEqual(watch.peak,2);self.assertTrue(watch.requests);self.assertLessEqual(max(watch.requests),65536)
   (p.Path(__file__).parent/'faithful-metrics.json').write_text(json.dumps({'files':len(sizes),'total':sum(sizes),'maximum':max(sizes),'empty':sizes.count(0),'defaultNoFile':before,'testSoftLimit':min(64,before[0]),'trackedPeakFDs':watch.peak,'maximumReadRequest':max(watch.requests),'actualHash':actual,'expectedHash':p.sha(p.encode(expected))},indent=2)+'\n')

 def test_directory_entries_not_just_files_count_toward_bound(self):
  with a.World() as w:
   root=self.build(w);(root/'d').mkdir(mode=0o700);self.leaf(root/'d','file',b'')
   with patch.object(p,'INPUT_MAX_ENTRIES',2):self.assertEqual(p.protected_input_tree(root),p.sha(p.encode({'d/file':p.sha(b'')})))
   with Watch() as watch,patch.object(p,'INPUT_MAX_ENTRIES',1),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertEqual(watch.live,set())

 def test_stream_shrink_special_file_and_final_leaf_replacement_refuse(self):
  for kind in ('shrink','fifo','final-replace'):
   with self.subTest(kind=kind),a.World() as w:
    root=self.build(w);file=self.leaf(root,'data',b'a'*100000);s=a.REAL_LSTAT(file);identity=(s.st_dev,s.st_ino)
    if kind=='fifo':file.unlink();os.mkfifo(file,0o600)
    oldread=p.os.read;oldpath=p._path_stat;fired=[]
    def read(fd,n):
     data=oldread(fd,n);s=a.REAL_FSTAT(fd)
     if kind=='shrink' and not fired and (s.st_dev,s.st_ino)==identity:
      fired.append(True)
      with file.open('r+b') as out:out.truncate(2)
     return data
    def path(path):
     if kind=='final-replace' and p.Path(path)==file and not fired:
      file.rename(root/'original');self.leaf(root,'data',b'a'*100000);fired.append(True)
     return oldpath(path)
    with Watch() as watch,patch.object(p.os,'read',read),patch.object(p,'_path_stat',path),self.assertRaises(p.Refused):p.protected_input_tree(root)
    if kind!='fifo':self.assertEqual(fired,[True])
    self.assertEqual(watch.live,set())

 def test_mount_device_substitution_at_final_directory_observation_refuses(self):
  with a.World() as w:
   root=self.build(w);self.leaf(root,'data');oldpath=p._path_stat;calls=[]
   class DifferentDevice:
    def __init__(self,meta):self.meta=meta
    def __getattr__(self,key):return self.meta.st_dev+1 if key=='st_dev' else getattr(self.meta,key)
   def path(path):
    meta=oldpath(path)
    if p.Path(path)==root:
     calls.append(True)
     if len(calls)>=3:return DifferentDevice(meta)
    return meta
   with Watch() as watch,patch.object(p,'_path_stat',path),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertGreaterEqual(len(calls),3);self.assertEqual(watch.live,set())

 def test_deadline_crossing_after_final_serialization_refuses(self):
  with a.World() as w:
   root=self.build(w);self.leaf(root,'data');oldencode=p.encode;expired=[]
   def encode(value):out=oldencode(value);expired.append(True);return out
   with Watch() as watch,patch.object(p.time,'monotonic',side_effect=lambda:61 if expired else 0),patch.object(p,'encode',encode),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertEqual(expired,[True]);self.assertEqual(watch.live,set())

 def test_saved_plan_bool_float_and_saved_wire_type_drift_refuse(self):
  for value in (True,1.0):
   with self.subTest(value=value),a.World() as w:
    state=w.read();state['plan']['schemaVersion']=value;w.save(state)
    with self.assertRaises(p.Refused):w.run()
    self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
  for field,value in (('schemaVersion',True),('ledgerParent',None),('policies',{}),('intendedEpochs',{})):
   with self.subTest(field=field),a.World() as w:
    w.run();state=w.read();state[p.KEY][field]=value;w.save(state)
    with self.assertRaises(p.Refused):w.run()
    self.assertEqual(len(w.unlinks),2)

 def test_tmpfiles_duplicate_missing_fields_return_status_and_exact_pid0_required(self):
  name=p.TMPFILES[0];base=boot(name)
  cases=[(0,text(base)+'MainPID=0\n'),(0,text({k:v for k,v in base.items() if k!='ControlPID'})),
         (1,text(base)),(4,text(base)),(0,text(boot(name,ExecMainStatus='00'))),(0,text(boot(name,MainPID='-0'))),
         (0,text(boot(name,ControlPID='0\t'))),(0,text(boot(name,Result='success\nForeign=x')))]
  for code,raw in cases:
   with self.subTest(code=code,raw=raw),a.World() as w,patch.object(p,'_systemctl',return_value=(code,raw)),self.assertRaises(p.Refused):p._tmpfiles_quiescent(name,SEARCH)

 def test_tmpfiles_all_literals_strict_inactive_positive_and_permission_refusal(self):
  for name in p.TMPFILES:
   with self.subTest(name=name),a.World() as w:
    row=boot(name,ActiveState='inactive',SubState='dead',Type='simple',RemainAfterExit='no',Result='exit-code',ExecMainStatus='9')
    with patch.object(p,'_systemctl',return_value=(0,text(row))):p._tmpfiles_quiescent(name,SEARCH)
    path=p._path_stat;fired=[]
    def denied(value):
     if str(value).startswith('/sys/fs/cgroup/'):
      fired.append(True);raise PermissionError('own synthetic inaccessible cgroup observation')
     return path(value)
    with patch.object(p,'_systemctl',return_value=(0,text(boot(name)))),patch.object(p,'_path_stat',denied),self.assertRaises(PermissionError):p._tmpfiles_quiescent(name,SEARCH)
    self.assertEqual(fired,[True])

 def test_tmpfiles_job_root_writer_and_cgroup_late_barriers_refuse_without_unlink(self):
  for kind in ('job','writer','cgroup'):
   with self.subTest(kind=kind),a.World() as w:
    previous=w.sysd;replace=p.os.replace;fired=[]
    def query(args):
     if args[0]=='show' and args[1] in p.TMPFILES:return 0,text(boot(args[1]))
     if kind=='job' and fired and args[0]=='list-jobs':return 0,'1 '+p.TMPFILES[0]+' start waiting\n'
     return previous(args)
    def issue(*args,**kw):
     replace(*args,**kw)
     if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':
      fired.append(True)
      if kind=='writer':w.block_process=True
      if kind=='cgroup':w.mapped('/sys/fs/cgroup/system.slice/'+p.TMPFILES[0]).mkdir(parents=True,mode=0o700)
    with patch.object(p,'_systemctl',side_effect=query),patch.object(p.os,'replace',issue),self.assertRaises(p.Refused):w.run()
    self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[]);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')

 def test_host_and_user_manager_do_not_inherit_tmpfiles_active_exited_allowance(self):
  for selected in ('host','user'):
   with self.subTest(selected=selected),a.World() as w:
    previous=w.sysd
    def query(args):
     if args[0]=='show' and args[1] in p.TMPFILES:return 0,text(boot(args[1]))
     if args[0]=='show' and args[1]!='--property=UnitPath' and ((selected=='host' and args[1]==w.context.unit(p.HOST_UNITS[0])) or (selected=='user' and args[1].startswith('user@'))):
      return 0,text({'LoadState':'loaded','ActiveState':'active','SubState':'exited','FragmentPath':'','DropInPaths':''})
     return previous(args)
    with patch.object(p,'_systemctl',side_effect=query),self.assertRaises(p.Refused):w.run()
    self.assertEqual(w.unlinks,[])

 def test_entire_operation_deadline_must_still_hold_after_late_context_scan_before_unlink(self):
  with a.World() as w:
   selected=w.selected;elapsed=[0];calls=[]
   def context(*args):
    result=selected(*args)
    if w.read().get(p.KEY,{}).get('phase')=='sudo-issued':elapsed[0]+=46;calls.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p,'actual_context',side_effect=context),self.assertRaises(p.Refused):w.run()
   self.assertEqual(calls,[True,True]);self.assertGreaterEqual(elapsed[0],90)
   self.assertEqual(w.unlinks,[],'whole-operation deadline expired during late scans but a policy was nevertheless unlinked')

 def test_expired_final_context_scan_must_not_report_successful_completion(self):
  with a.World() as w:
   selected=w.selected;elapsed=[0];calls=[]
   def context(*args):
    result=selected(*args)
    if w.read().get(p.KEY,{}).get('phase')=='fenced':elapsed[0]+=46;calls.append(True)
    return result
   with patch.object(p.time,'monotonic',side_effect=lambda:elapsed[0]),patch.object(p,'actual_context',side_effect=context):
    try:result=w.run()
    except p.Refused:result=None
   self.assertEqual(calls,[True,True]);self.assertGreaterEqual(elapsed[0],90)
   self.assertEqual(w.read()[p.KEY]['phase'],'fenced');self.assertEqual(len(w.unlinks),2)
   self.assertIsNone(result,'full late scans exceeded operation deadline but callable nevertheless returned success')

 def test_data_reader_does_not_weaken_strict_code_empty_large_and_cache_controls(self):
  for kind in ('empty','large','cache'):
   with self.subTest(kind=kind),a.World() as w:
    root=self.build(w)
    if kind=='cache':self.leaf(root,'foreign.pyc',b'x')
    else:
     path=self.leaf(root,'data',b'')
     if kind=='large':
      with path.open('wb') as out:out.truncate(1024*1024+1)
    with self.assertRaises(p.Refused):p.closed_code_tree(root)
    if kind=='cache':
     with self.assertRaises(p.Refused):p.protected_input_tree(root)
    else:self.assertEqual(len(p.protected_input_tree(root)),64)
