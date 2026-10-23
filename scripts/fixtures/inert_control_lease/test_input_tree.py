"""Bounded real own-USER data trees; explicit internal Root metadata fakes only."""
import hashlib,json,os,stat,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as author

class InputTests(unittest.TestCase):
 def build(self,w):
  root=w.root/'build';root.mkdir(mode=0o700);return root
 def leaf(self,root,name,size=3):
  path=root/name
  with path.open('wb') as f:f.truncate(size)
  path.chmod(0o600);return path
 def test_faithful_12077_files_18_empty_25mb_max_165832391_bytes(self):
  with author.World() as w:
   root=self.build(w);base=root/'node_modules';base.mkdir(mode=0o700)
   buckets=[base/str(i) for i in range(48)]
   for d in buckets:d.mkdir(mode=0o700)
   q,r=divmod(165832391-25409160,12077-19)
   sizes=[]
   for i in range(12077):
    size=0 if i<18 else (25409160 if i==18 else q+int(i-19<r))
    self.leaf(buckets[i%48],str(i)+('.jar' if i==18 else '.data'),size);sizes.append(size)
   self.assertEqual((len(sizes),sum(sizes),max(sizes),sizes.count(0)),(12077,165832391,25409160,18))
   # The old epoch intentionally runs THIS positive requirement against its old
   # code reader: an ordinary retained red, not a production fallback.
   reader=getattr(p,'protected_input_tree',p.closed_code_tree)
   try:result=reader(root)
   except p.Refused:result='REFUSED'
   self.assertEqual(len(result),64,'valid data cohort refused by '+reader.__name__)
 def test_small_nonempty_hash_identical_to_strict_code_reader(self):
  with author.World() as w:
   root=self.build(w);(root/'nested').mkdir(mode=0o700)
   self.leaf(root,'alpha',5);self.leaf(root/'nested','beta.jar',3000)
   self.assertEqual(p.protected_input_tree(root),p.closed_code_tree(root))
 def test_empty_data_hash_uses_same_complete_fingerprint_map(self):
  with author.World() as w:
   root=self.build(w);self.leaf(root,'empty',0)
   self.assertEqual(p.protected_input_tree(root),p.sha(p.encode({'empty':p.sha(b'')})))
   with self.assertRaises(p.Refused):p.closed_code_tree(root)
 def test_inclusive_64mib_leaf_streamed_but_oversize_refuses_before_body(self):
  with author.World() as w:
   root=self.build(w);file=self.leaf(root,'large.jar',64*1024*1024)
   self.assertEqual(len(p.protected_input_tree(root)),64)
   with file.open('r+b') as f:f.truncate(64*1024*1024+1)
   original=p.os.read;body_reads=[];target=author.REAL_LSTAT(file).st_ino
   def read(fd,n):
    if author.REAL_FSTAT(fd).st_ino==target:body_reads.append(True)
    return original(fd,n)
   with patch.object(p.os,'read',read),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertEqual(body_reads,[])
 def test_aggregate_512mib_inclusive_then_extra_empty_ok_extra_byte_refuses(self):
  with author.World() as w:
   root=self.build(w)
   for i in range(8):self.leaf(root,str(i)+'.jar',64*1024*1024)
   extra=self.leaf(root,'extra',0)
   self.assertEqual(len(p.protected_input_tree(root)),64)
   with extra.open('r+b') as f:f.truncate(1)
   with self.assertRaises(p.Refused):p.protected_input_tree(root)
 def test_32768_entries_inclusive_and_32769_refuses(self):
  with author.World() as w:
   root=self.build(w)
   for i in range(32768):self.leaf(root,str(i),0)
   self.assertEqual(len(p.protected_input_tree(root)),64)
   self.leaf(root,'overflow',0)
   with self.assertRaises(p.Refused):p.protected_input_tree(root)
 def test_deadline_during_stream_refuses_and_closes_leaf(self):
  with author.World() as w:
   root=self.build(w);file=self.leaf(root,'data',200000);oldread=p.os.read;oldclose=p.os.close
   started=time.monotonic();expired=[];opened=[];closed=[];oldopen=p.os.open
   def read(fd,n):
    result=oldread(fd,n)
    if author.REAL_FSTAT(fd).st_ino==author.REAL_LSTAT(file).st_ino:expired.append(True)
    return result
   def opening(*a,**kw):
    fd=oldopen(*a,**kw)
    if author.REAL_FSTAT(fd).st_ino==author.REAL_LSTAT(file).st_ino:opened.append(fd)
    return fd
   def closing(fd):closed.append(fd);return oldclose(fd)
   with patch.object(p.time,'monotonic',side_effect=lambda:started+(61 if expired else 0)),patch.object(p.os,'open',opening),patch.object(p.os,'close',closing),patch.object(p.os,'read',read),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertTrue(expired);self.assertTrue(opened);self.assertTrue(all(fd in closed for fd in opened))
 def test_mode_uid_and_hardlink_refuse(self):
  for kind in ('mode','uid','link'):
   with self.subTest(kind=kind),author.World() as w:
    root=self.build(w);file=self.leaf(root,'data')
    if kind=='mode':file.chmod(0o666)
    if kind=='link':os.link(file,root/'alias')
    old=p._entry_stat
    class Foreign:
     def __init__(self,s):self.s=s
     def __getattr__(self,k):return 1000 if k=='st_uid' else getattr(self.s,k)
    def entry(fd,name):
     s=old(fd,name);return Foreign(s) if kind=='uid' else s
    with patch.object(p,'_entry_stat',entry),self.assertRaises(p.Refused):p.protected_input_tree(root)
 def test_symlink_nested_cache_and_alternate_prefix_refuse(self):
  for kind in ('symlink','dirlink','pyc','pyo','cache','prefix'):
   with self.subTest(kind=kind),author.World() as w:
    root=self.build(w);nested=root/'nested';nested.mkdir(mode=0o700);file=self.leaf(nested,'data')
    if kind=='symlink':(root/'alias').symlink_to(file)
    if kind=='dirlink':(root/'alias').symlink_to(nested,target_is_directory=True)
    if kind in ('pyc','pyo'):self.leaf(nested,'bad.'+kind)
    if kind=='cache':(nested/'__pycache__').mkdir(mode=0o700)
    with patch.object(p.sys,'pycache_prefix','/own-not-used' if kind=='prefix' else None),self.assertRaises(p.Refused):p.protected_input_tree(root)
 def test_body_growth_during_stream_and_named_replacement_refuse(self):
  for kind in ('growth','replacement'):
   with self.subTest(kind=kind),author.World() as w:
    root=self.build(w);file=self.leaf(root,'data',100000);oldread=p.os.read;fired=[];inode=author.REAL_LSTAT(file).st_ino
    def read(fd,n):
     result=oldread(fd,n)
     if not fired and author.REAL_FSTAT(fd).st_ino==inode:
      fired.append(True)
      if kind=='growth':
       with file.open('ab') as out:out.write(b'x')
      else:file.rename(root/'original');self.leaf(root,'data',100000)
     return result
    with patch.object(p.os,'read',read),self.assertRaises(p.Refused):p.protected_input_tree(root)
    self.assertEqual(fired,[True])
 def test_directory_entry_drift_refuses(self):
  with author.World() as w:
   root=self.build(w);file=self.leaf(root,'data',100000);oldread=p.os.read;fired=[]
   def read(fd,n):
    result=oldread(fd,n)
    if not fired:fired.append(True);self.leaf(root,'late-extra',0)
    return result
   with patch.object(p.os,'read',read),self.assertRaises(p.Refused):p.protected_input_tree(root)
   self.assertEqual(fired,[True])
 def test_actual_context_data_reader_finishes_before_first_load_and_failure_never_loads(self):
  actual=author.ACTUAL_CONTEXT
  for bad in (False,True):
   with self.subTest(bad=bad),author.World() as w:
    root=self.build(w);self.leaf(root,'empty',0)
    if bad:(root/'cache.pyc').write_bytes(b'not executed')
    events=[];real=p.protected_input_tree
    def data(path):
     self.assertEqual(str(path),str(w.bundle/'build'));events.append('data-start')
     value=real(root);events.append('data-complete');return value
    def load(*a):events.append('load');raise p.Refused('own-stop-before-code')
    with patch.object(p,'closed_code_tree',return_value='a'*64),patch.object(p,'protected_file',return_value=b'{}'),patch.object(p,'protected_input_tree',data),patch.object(p,'load_closed',load),self.assertRaises(p.Refused):actual(w.bundle,w.selector)
    if bad:self.assertNotIn('load',events)
    else:self.assertEqual(events,['data-start','data-complete','load'])

if __name__=='__main__':unittest.main(verbosity=2)
