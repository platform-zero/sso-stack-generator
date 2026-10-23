"""Own ordinary USER files and real FDs/unlink/fsync; internal Root facts are fake.
Assertions after callable return/refusal are outside its catch-all.
"""
from contextlib import ExitStack
import os
import stat
import unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as author

class Trace:
 def __init__(self,w):
  self.w=w;self.live={};self.opened=[];self.before=[];self.synced=[];self.closed=[];self.stack=ExitStack()
  self.names=[x[0].name for x in w.specs]
  self.ids=[];self.parents=[]
  for i,name in enumerate(self.names):
   parent=w.sudo if i==0 else w.tmpfiles
   try:
    s=author.REAL_LSTAT(parent/name);self.ids.append((s.st_dev,s.st_ino))
   except FileNotFoundError:self.ids.append(None)
   s=author.REAL_LSTAT(parent);self.parents.append((s.st_dev,s.st_ino))
 def state(self):
  values=[]
  for identity in self.ids:
   matching=[author.REAL_FSTAT(fd).st_nlink for fd,row in self.live.items() if row[1:]==identity]
   values.append(matching)
  return values
 def leases(self):return sum(row[0]=='lifecycle.lock' for row in self.live.values())
 def __enter__(self):
  oldopen=p.os.open;oldclose=p.os.close;oldunlink=p.os.unlink;oldsync=p.os.fsync
  def opened(name,*a,**kw):
   fd=oldopen(name,*a,**kw)
   if os.fspath(name) in self.names+['lifecycle.lock']:
    s=author.REAL_FSTAT(fd);self.live[fd]=(os.fspath(name),s.st_dev,s.st_ino);self.opened.append(os.fspath(name))
   return fd
  def closed(fd):
   if fd in self.live:self.closed.append(self.live.pop(fd))
   return oldclose(fd)
  def unlink(name,*a,**kw):
   if name in self.names:self.before.append((name,self.state(),self.leases()))
   return oldunlink(name,*a,**kw)
  def sync(fd):
   s=author.REAL_FSTAT(fd)
   if (s.st_dev,s.st_ino) in self.parents:
    self.synced.append((self.parents.index((s.st_dev,s.st_ino)),self.state(),self.leases()))
   return oldsync(fd)
  for change in (patch.object(p.os,'open',opened),patch.object(p.os,'close',closed),patch.object(p.os,'unlink',unlink),patch.object(p.os,'fsync',sync)):
   self.stack.enter_context(change)
  return self
 def __exit__(self,*args):self.stack.close()

class HeldPolicyTests(unittest.TestCase):
 def test_both_actual_original_policy_fds_and_lease_held_at_both_unlinks_and_fsync(self):
  with author.World() as w,Trace(w) as t:
   result=w.run()
   self.assertEqual(result['policiesAbsent'],2)
   self.assertEqual([x[1] for x in t.before],[[[1],[1]],[[0],[1]]])
   self.assertTrue(all(x[2]>=1 for x in t.before))
   self.assertEqual([x[1] for x in t.synced],[[[0],[1]],[[0],[0]]])
   self.assertTrue(all(x[2]>=1 for x in t.synced))
   self.assertEqual([t.opened.count(n) for n in t.names],[1,1])
   self.assertEqual(t.live,{})
 def test_constructor_second_policy_refusal_closes_first_and_second_policy_fd(self):
  with author.World() as w,Trace(w) as t:
   (w.tmpfiles/w.specs[1][0].name).chmod(0o640)
   with self.assertRaises(p.Refused):w.run()
   self.assertEqual(w.unlinks,[]);self.assertEqual(t.live,{})
   self.assertEqual([t.opened.count(n) for n in t.names],[1,1])
 def test_refusal_after_issue_before_unlink_closes_all_fds_and_never_retries_present(self):
  with author.World() as w,Trace(w) as t:
   w.fault='before-sudo-issued'
   with self.assertRaises(p.Refused):w.run()
   self.assertEqual(t.live,{})
   count=len(w.unlinks);w.fault=None
   with self.assertRaises(p.Refused):w.run()
   self.assertEqual(len(w.unlinks),count);self.assertEqual(t.live,{})
 def test_after_first_unlink_recovery_never_reopens_deleted_policy(self):
  with author.World() as w:
   w.fault='after-sudo-issued'
   with Trace(w) as first:
    with self.assertRaises(p.Refused):w.run()
    self.assertEqual(first.live,{})
   w.fault=None
   with Trace(w) as resumed:
    result=w.run()
    self.assertEqual(result['policiesAbsent'],2)
    self.assertNotIn(w.specs[0][0].name,resumed.opened)
    self.assertEqual(resumed.opened.count(w.specs[1][0].name),1)
    self.assertEqual(resumed.live,{})
   self.assertEqual(w.unlinks,[s[0].name for s in w.specs])
 def test_after_second_unlink_and_fenced_recovery_never_reopens_either_policy(self):
  with author.World() as w:
   w.fault='after-tmpfiles-issued'
   with self.assertRaises(p.Refused):w.run()
   w.fault=None
   with Trace(w) as t:
    w.run();w.run()
    self.assertTrue(all(n not in t.opened for n in t.names))
    self.assertEqual(t.live,{})
   self.assertEqual(len(w.unlinks),2)
 def test_late_second_named_replacement_is_not_adopted_and_foreign_preserved(self):
  with author.World() as w,Trace(w) as t:
   old=p.os.replace;fired=[];target=w.tmpfiles/w.specs[1][0].name
   def replace(*a,**kw):
    old(*a,**kw)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-done':
     target.rename(w.tmpfiles/'original-held-policy')
     target.write_bytes(w.specs[1][2]);target.chmod(w.specs[1][1]);fired.append(True)
   with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[w.specs[0][0].name])
   self.assertEqual(target.read_bytes(),w.specs[1][2]);self.assertEqual(t.live,{})
 def test_late_second_body_drift_refuses_before_own_second_unlink(self):
  with author.World() as w,Trace(w) as t:
   old=p.os.replace;fired=[]
   def replace(*a,**kw):
    old(*a,**kw)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-done':
     (w.tmpfiles/w.specs[1][0].name).write_bytes(b'own synthetic changed body\n');fired.append(True)
   with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[w.specs[0][0].name]);self.assertEqual(t.live,{})
 def test_unlinked_held_first_policy_metadata_drift_refuses_before_second_unlink(self):
  with author.World() as w,Trace(w) as t:
   old=p.os.replace;fired=[]
   def replace(*a,**kw):
    old(*a,**kw)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-done':
     fd=next(fd for fd,row in t.live.items() if row[1:]==t.ids[0])
     self.assertEqual(author.REAL_FSTAT(fd).st_nlink,0)
     os.fchmod(fd,0o600);fired.append(True)
   with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[w.specs[0][0].name]);self.assertEqual(t.live,{})
 def test_policy_parent_fsync_fault_keeps_issued_then_absence_only_closes_every_fd(self):
  for index in (0,1):
   with self.subTest(index=index),author.World() as w,Trace(w) as t:
    old=p.os.fsync;fired=[];parent=w.sudo if index==0 else w.tmpfiles;name=w.specs[index][0].name
    def sync(fd):
     s=author.REAL_FSTAT(fd)
     if not fired and (s.st_dev,s.st_ino)==t.parents[index] and not (parent/name).exists():
      fired.append(True);raise OSError('own synthetic fsync fault')
     return old(fd)
    with patch.object(p.os,'fsync',sync),self.assertRaises(p.Refused):w.run()
    self.assertEqual(fired,[True]);self.assertEqual(t.live,{})
    count=len(w.unlinks);w.run()
    self.assertEqual(count,index+1);self.assertEqual(len(w.unlinks),2);self.assertEqual(t.live,{})
 def test_saved_identity_resume_mismatch_cannot_adopt_current_policy_fd(self):
  with author.World() as w:
   w.fault='after-sudo-issued'
   with self.assertRaises(p.Refused):w.run()
   w.fault=None
   target=w.tmpfiles/w.specs[1][0].name
   target.rename(w.tmpfiles/'original');target.write_bytes(w.specs[1][2]);target.chmod(w.specs[1][1])
   with Trace(w) as t,self.assertRaises(p.Refused):w.run()
   self.assertEqual(t.live,{});self.assertEqual(w.unlinks,[w.specs[0][0].name])
   self.assertEqual(target.read_bytes(),w.specs[1][2])

 def test_ten_key_closure_and_complete_six_epoch_wire_unchanged(self):
  with author.World() as w:
   w.closure.update(site='6'*64,build='7'*64)
   self.assertEqual(set(w.closure),{'ops','slot','quadlet','slotPath','manifest','site','build','imageIds','frozenRegistrySha256','provenanceSha256'})
   w.run();record=w.read()[p.KEY]
   self.assertEqual(set(record),{'schemaVersion','namespace','hostContextSha256','provenanceSha256','planSha256','operationSha256','sourceClosureSha256','ledgerPath','ledgerParent','leaseIdentity','phase','ledgerSha256Before','policies','intendedEpochs'})
   self.assertEqual(record['sourceClosureSha256'],p.sha(p.canonical(w.closure)))
   self.assertEqual(record['operationSha256'],p.sha(author.Path(p.__file__).read_bytes()))
   self.assertEqual(len(set(record['intendedEpochs'])),6)
   self.assertEqual(record['ledgerSha256Before'],record['intendedEpochs'][0])
   self.assertEqual(len(record['policies']),2)
   for saved in record['policies']:
    self.assertEqual(set(saved),{'path','mode','bodySha256','parent','file'})
    self.assertEqual(saved['file']['nlink'],1)
 def test_held_body_is_reread_even_under_explicitly_stale_timestamp_observations(self):
  with author.World() as w,Trace(w) as t:
   target=w.tmpfiles/w.specs[1][0].name;before=author.REAL_LSTAT(target)
   previous_stat=p._fd_stat;previous_entry=p._entry_stat;previous_replace=p.os.replace;previous_read=p.os.read
   fired=[];body_reads=[]
   class FrozenTimes:
    def __init__(self,meta):self.meta=meta
    def __getattr__(self,key):
     if key in ('st_mtime_ns','st_ctime_ns'):return getattr(before,key)
     return getattr(self.meta,key)
   def masked(meta):
    return FrozenTimes(meta) if (meta.st_dev,meta.st_ino)==t.ids[1] else meta
   def replace(*a,**kw):
    previous_replace(*a,**kw)
    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-done':
     body=w.specs[1][2];target.write_bytes(bytes([body[0]^1])+body[1:]);fired.append(True)
   def read(fd,count):
    s=author.REAL_FSTAT(fd)
    if fired and (s.st_dev,s.st_ino)==t.ids[1]:body_reads.append(fd)
    return previous_read(fd,count)
   with patch.object(p,'_fd_stat',side_effect=lambda fd:masked(previous_stat(fd))), \
        patch.object(p,'_entry_stat',side_effect=lambda fd,name:masked(previous_entry(fd,name))), \
        patch.object(p.os,'replace',replace),patch.object(p.os,'read',read),self.assertRaises(p.Refused):w.run()
   self.assertEqual(fired,[True]);self.assertTrue(body_reads)
   self.assertEqual(w.unlinks,[w.specs[0][0].name]);self.assertEqual(t.live,{})

if __name__=='__main__':unittest.main(verbosity=2)
