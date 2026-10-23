"""Independent C30 tests. Real OWN USER IO; internal Root facts remain fakes.
No actual /proc, Root, policies, controller, NSS or systemd reads permitted.
"""
from contextlib import ExitStack
import inspect
import fcntl
import os
import stat
import unittest
from unittest.mock import patch
import policy_fence as p
import test_complete_policy_fence as a

class Monitor:
    def __init__(self,w):
        self.w=w;self.live={};self.policy={};self.opens=[];self.closed=[];self.stack=ExitStack()
        self.names=[s[0].name for s in w.specs]
        self.paths=[w.sudo/self.names[0],w.tmpfiles/self.names[1]]
        self.original=[]
        for path in self.paths:
            try:
                s=a.REAL_LSTAT(path);self.original.append((s.st_dev,s.st_ino))
            except FileNotFoundError:self.original.append(None)
    def observe(self,fd,name,flags):
        s=a.REAL_FSTAT(fd);identity=(s.st_dev,s.st_ino)
        self.live[fd]=(str(name),identity)
        # An old unlinked inode number may be reused by a later journal temp.
        # Policy classification requires BOTH original identity and policy name.
        if identity in self.original and p.Path(os.fspath(name)).name in self.names:
            self.policy[fd]=self.original.index(identity)
            self.opens.append((self.policy[fd],fd,flags))
        return fd
    def snapshot(self):
        result=[]
        for index in (0,1):
            rows=[(a.REAL_FSTAT(fd).st_dev,a.REAL_FSTAT(fd).st_ino,a.REAL_FSTAT(fd).st_nlink)
                  for fd,i in self.policy.items() if i==index]
            result.append(rows)
        return result
    def __enter__(self):
        oldopen=p.os.open;olddir=p._directory_fd;oldclose=p.os.close
        def opened(name,flags,*args,**kw):return self.observe(oldopen(name,flags,*args,**kw),name,flags)
        def directory(path):return self.observe(olddir(path),path,None)
        def closed(fd):
            self.closed.append(self.live.pop(fd,None));self.policy.pop(fd,None)
            return oldclose(fd)
        for c in (patch.object(p.os,'open',opened),patch.object(p,'_directory_fd',directory),patch.object(p.os,'close',closed)):
            self.stack.enter_context(c)
        return self
    def __exit__(self,*args):self.stack.close()

class FreshTests(unittest.TestCase):
    def test_original_acquisition_flags_and_lifetime_through_all_six_publications(self):
        with a.World() as w,Monitor(w) as m:
            publications=[];parent_syncs=[];unlinks=[]
            oldreplace=p.os.replace;oldsync=p.os.fsync;oldunlink=p.os.unlink
            parentids=[]
            for path in (w.sudo,w.tmpfiles):
                s=a.REAL_LSTAT(path);parentids.append((s.st_dev,s.st_ino))
            def replace(*args,**kw):
                oldreplace(*args,**kw)
                record=w.read()[p.KEY];snap=m.snapshot()
                publications.append((record['phase'],snap))
                self.assertEqual([len(rows) for rows in snap],[1,1])
                for i,rows in enumerate(snap):self.assertEqual(rows[0][:2],m.original[i])
                for fd in m.policy:
                    self.assertFalse(os.get_inheritable(fd))
                    self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE,os.O_RDONLY)
                if record['phase']=='intended':
                    self.assertEqual([rows[0][2] for rows in snap],[1,1])
                    for fd,index in m.policy.items():
                        self.assertEqual(record['policies'][index]['file'],p.file_identity(p._fd_stat(fd)))
                if record['phase']=='fenced':self.assertEqual([rows[0][2] for rows in snap],[0,0])
            def sync(fd):
                s=a.REAL_FSTAT(fd)
                if (s.st_dev,s.st_ino) in parentids:parent_syncs.append(m.snapshot())
                return oldsync(fd)
            def unlink(name,*args,**kw):
                if name in m.names:unlinks.append(m.snapshot())
                return oldunlink(name,*args,**kw)
            with patch.object(p.os,'replace',replace),patch.object(p.os,'fsync',sync),patch.object(p.os,'unlink',unlink):result=w.run()
            self.assertEqual(result['policiesAbsent'],2)
            self.assertEqual([phase for phase,_ in publications],list(p.PHASES))
            self.assertEqual([[rows[0][2] for rows in snap] for snap in unlinks],[[1,1],[0,1]])
            self.assertEqual([[rows[0][2] for rows in snap] for snap in parent_syncs],[[0,1],[0,0]])
            self.assertEqual([i for i,fd,flags in m.opens],[0,1])
            for _,fd,flags in m.opens:
                self.assertEqual(flags&os.O_ACCMODE,os.O_RDONLY)
                self.assertEqual(flags&(os.O_CREAT|os.O_TRUNC),0)
                for flag in (os.O_NOFOLLOW,os.O_CLOEXEC,os.O_NONBLOCK):self.assertTrue(flags&flag)
            self.assertEqual(m.live,{})
            self.assertEqual(list(inspect.signature(p.fence_host_transport_policies).parameters),['bundle','selector','ledger','reviewed_sha','provenance_sha'])

    def test_constructor_io_errors_and_error_during_constructor_close_attempt_all_cleanup(self):
        for index in (0,1):
            for point in ('read','seek','stat','read-and-close'):
                with self.subTest(index=index,point=point),a.World() as w,Monitor(w) as m:
                    fired=[];close_fired=[];oldread=p.os.read;oldseek=p.os.lseek;oldstat=p._fd_stat;oldclose=p.os.close
                    def target(fd):
                        s=a.REAL_FSTAT(fd);return (s.st_dev,s.st_ino)==m.original[index]
                    def read(fd,count):
                        if point in ('read','read-and-close') and not fired and target(fd):fired.append(True);raise OSError('own synthetic read error')
                        return oldread(fd,count)
                    def seek(fd,*args):
                        if point=='seek' and not fired and target(fd):fired.append(True);raise OSError('own synthetic seek error')
                        return oldseek(fd,*args)
                    def fstat(fd):
                        if point=='stat' and not fired and target(fd):fired.append(True);raise OSError('own synthetic stat error')
                        return oldstat(fd)
                    def close(fd):
                        selected=point=='read-and-close' and target(fd)
                        oldclose(fd)
                        if selected and not close_fired:close_fired.append(True);raise OSError('own close reports error after releasing fd')
                    with patch.object(p.os,'read',read),patch.object(p.os,'lseek',seek),patch.object(p,'_fd_stat',fstat),patch.object(p.os,'close',close):
                        with self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):w.run()
                    self.assertEqual(fired,[True]);self.assertEqual(m.live,{})
                    self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
                    if point=='read-and-close':self.assertEqual(close_fired,[True])

    def test_final_publication_holds_original_zero_link_files_and_rereads_unlinked_body(self):
        with a.World() as w:
            target=w.sudo/w.specs[0][0].name
            target.chmod(0o600);writer=target.open('r+b',buffering=0);target.chmod(0o440)
            try:
                with Monitor(w) as m:
                    fired=[];reads=[];frozen=[];oldreplace=p.os.replace;oldstat=p._fd_stat;oldread=p.os.read
                    def replace(*args,**kw):
                        oldreplace(*args,**kw)
                        if not fired and w.read()[p.KEY]['phase']=='fenced':
                            fd=next(fd for fd,index in m.policy.items() if index==0)
                            frozen.append((fd,oldstat(fd)))
                            self.assertEqual(a.REAL_FSTAT(fd).st_nlink,0)
                            self.assertEqual([len(x) for x in m.snapshot()],[1,1])
                            writer.seek(0);first=writer.read(1);writer.seek(0);writer.write(bytes([first[0]^1]));fired.append(True)
                    def fstat(fd):return frozen[0][1] if frozen and fd==frozen[0][0] else oldstat(fd)
                    def read(fd,count):
                        if fired and fd==frozen[0][0]:reads.append(True)
                        return oldread(fd,count)
                    with patch.object(p.os,'replace',replace),patch.object(p,'_fd_stat',fstat),patch.object(p.os,'read',read):
                        with self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):w.run()
                    self.assertEqual(fired,[True]);self.assertTrue(reads)
                    self.assertEqual(w.read()[p.KEY]['phase'],'fenced')
                    self.assertEqual(len(w.unlinks),2);self.assertEqual(m.live,{})
            finally:writer.close()

    def test_own_unlink_only_allows_nlink_zero_and_nondecreasing_ctime_other_fields_fixed(self):
        cases={'st_nlink':1,'st_ctime_ns':-1,'st_uid':1,'st_mode':stat.S_IFREG|0o600,'st_size':-1,'st_mtime_ns':-1,'st_ino':0,'st_dev':-1}
        for field,value in cases.items():
            with self.subTest(field=field),a.World() as w,Monitor(w) as m:
                oldstat=p._fd_stat;fired=[]
                class Changed:
                    def __init__(self,meta):self.meta=meta
                    def __getattr__(self,key):return value if key==field else getattr(self.meta,key)
                def fstat(fd):
                    meta=oldstat(fd)
                    if (meta.st_dev,meta.st_ino)==m.original[0] and meta.st_nlink==0:
                        fired.append(True);return Changed(meta)
                    return meta
                with patch.object(p,'_fd_stat',fstat),self.assertRaises(p.Refused):w.run()
                self.assertTrue(fired);self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')
                self.assertEqual(w.unlinks,[w.specs[0][0].name]);self.assertEqual(m.live,{})
                before=len(m.opens);w.run()
                self.assertEqual([i for i,fd,flags in m.opens[before:]],[1])
                self.assertEqual(len(w.unlinks),2);self.assertEqual(m.live,{})

    def test_each_phase_commit_interruption_resume_never_reopens_an_absent_policy(self):
        for phase in p.PHASES:
            with self.subTest(phase=phase),a.World() as w,Monitor(w) as m:
                old=p.os.replace;fired=[]
                def replace(*args,**kw):
                    old(*args,**kw)
                    if not fired and w.read()[p.KEY]['phase']==phase:fired.append(True);raise OSError('own synthetic post-replace interruption')
                with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
                self.assertEqual(fired,[True]);self.assertEqual(w.read()[p.KEY]['phase'],phase)
                self.assertEqual(m.live,{})
                count=len(w.unlinks);before=len(m.opens)
                if phase.endswith('issued'):
                    with self.assertRaises(p.Refused):w.run()
                    self.assertEqual(len(w.unlinks),count);self.assertEqual(m.opens[before:],[])
                else:
                    w.run();self.assertEqual(len(w.unlinks),2)
                    expected=[0,1] if phase=='intended' else [1] if phase=='sudo-done' else []
                    self.assertEqual([i for i,fd,flags in m.opens[before:]],expected)
                self.assertEqual(m.live,{})

    def test_cleanup_close_error_still_attempts_every_remaining_source_parent_and_policy_fd(self):
        with a.World() as w,Monitor(w) as m:
            oldclose=p.os.close;fired=[]
            def close(fd):
                selected=m.policy.get(fd)==1
                oldclose(fd)
                if selected and not fired:fired.append(True);raise OSError('own close returned error after fd release')
            with patch.object(p.os,'close',close),self.assertRaises(p.Refused):w.run()
            self.assertEqual(fired,[True]);self.assertEqual(m.live,{})
            self.assertEqual(w.read()[p.KEY]['phase'],'fenced');self.assertEqual(len(w.unlinks),2)
            before=len(m.opens);w.run();self.assertEqual(m.opens[before:],[]);self.assertEqual(m.live,{})

    def test_policy_empty_and_16kib_bound_refuse_before_policy_body_read(self):
        for index in (0,1):
            for size in (0,16385):
                with self.subTest(index=index,size=size),a.World() as w,Monitor(w) as m:
                    target=m.paths[index];target.chmod(0o600);target.write_bytes(b'x'*size);target.chmod(w.specs[index][1])
                    oldread=p.os.read;reads=[]
                    def read(fd,count):
                        s=a.REAL_FSTAT(fd)
                        if (s.st_dev,s.st_ino)==m.original[index]:reads.append(True)
                        return oldread(fd,count)
                    with patch.object(p.os,'read',read),self.assertRaises(p.Refused):w.run()
                    self.assertEqual(reads,[]);self.assertEqual(w.unlinks,[])
                    self.assertNotIn(p.KEY,w.read());self.assertEqual(m.live,{})

    def test_initial_read_named_replacement_never_adopted_before_intent(self):
        for index in (0,1):
            with self.subTest(index=index),a.World() as w,Monitor(w) as m:
                target=m.paths[index];oldread=p.os.read;fired=[];foreign=target.parent/'saved-original'
                def read(fd,count):
                    s=a.REAL_FSTAT(fd)
                    if not fired and (s.st_dev,s.st_ino)==m.original[index]:
                        target.rename(foreign);target.write_bytes(w.specs[index][2]);target.chmod(w.specs[index][1]);fired.append(True)
                    return oldread(fd,count)
                with patch.object(p.os,'read',read),self.assertRaises(p.Refused):w.run()
                self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[]);self.assertNotIn(p.KEY,w.read())
                self.assertEqual(target.read_bytes(),w.specs[index][2]);self.assertTrue(foreign.exists())
                self.assertEqual(m.live,{})
