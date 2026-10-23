"""C27 R2 concrete implementation, own files/FDs with explicit internal fakes.
No root, actual proc/manager/private policy/slot/ledger/target is touched.
"""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import os
import stat
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'cohort-r2'))
import policy_fence as p
import test_complete_policy_fence as author

class Independent(unittest.TestCase):
    def test_default_unprivileged_does_not_coerce_paths_or_read_private_kernel(self):
        touched=[]
        class PrivatePath:
            def __fspath__(self):touched.append('path');raise AssertionError('private path must stay unread')
        def read(*args):touched.append('read');raise AssertionError('private read must not happen')
        with patch.object(p.os,'geteuid',return_value=1000),patch.object(p.Path,'read_bytes',read):
            with self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):
                p.fence_host_transport_policies(PrivatePath(),PrivatePath(),PrivatePath(),'a'*64,'b'*64)
        self.assertEqual(touched,[])

    def test_concrete_systemctl_client_uses_bounded_private_readonly_transport(self):
        read,write=os.pipe2(os.O_CLOEXEC)
        os.write(write,b'opaque synthetic response\n');os.close(write)
        class Child:
            stdout=os.fdopen(read,'rb',buffering=0)
            def wait(self,timeout):return 0
            def poll(self):return 0
            def kill(self):raise AssertionError('no live child in this fake')
        child=Child()
        with patch.object(p.subprocess,'Popen',return_value=child) as spawn:
            code,text=p._systemctl(['show','synthetic.service','--property=ActiveState'])
        self.assertEqual((code,text),(0,'opaque synthetic response\n'))
        args,kw=spawn.call_args.args[0],spawn.call_args.kwargs
        self.assertEqual(args[0],'/usr/bin/systemctl')
        self.assertEqual(kw['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        self.assertFalse(kw['shell']);self.assertTrue(kw['close_fds'])
        self.assertEqual(kw['stderr'],p.subprocess.DEVNULL)
        self.assertTrue(child.stdout.closed)

    def test_required_policy_file_descriptors_remain_held_at_unlink(self):
        with author.World() as w:
            identities={}
            for i,spec in enumerate(w.specs):
                path=(w.sudo if i==0 else w.tmpfiles)/spec[0].name
                s=author.REAL_LSTAT(path);identities[spec[0].name]=(s.st_dev,s.st_ino)
            live={};observed=[];lease_observed=[]
            oldopen=p.os.open;oldclose=p.os.close;oldunlink=p.os.unlink
            def opened(path,*args,**kwargs):
                fd=oldopen(path,*args,**kwargs)
                name=os.fspath(path)
                if name in identities or name=='lifecycle.lock':
                    s=author.REAL_FSTAT(fd);live[fd]=(name,s.st_dev,s.st_ino)
                return fd
            def closed(fd):
                live.pop(fd,None);return oldclose(fd)
            def unlink(name,*args,**kwargs):
                if name in identities:
                    observed.append(sum(1 for fd,row in live.items() if row[0]==name and row[1:]==identities[name]))
                    lease_observed.append(sum(1 for row in live.values() if row[0]=='lifecycle.lock'))
                return oldunlink(name,*args,**kwargs)
            with patch.object(p.os,'open',opened),patch.object(p.os,'close',closed),patch.object(p.os,'unlink',unlink):
                result=w.run()
            self.assertEqual(result['policiesAbsent'],2)
            self.assertEqual(len(observed),2)
            self.assertTrue(all(n>=1 for n in lease_observed),'tracker must observe the genuinely held lease FD')
            self.assertTrue(all(n>=1 for n in observed),
                'required policy file FDs are closed before both unlink calls; identity snapshots are not held files')

    def test_root_gate_requires_all_initial_namespace_flags_before_private_source(self):
        def scenario(map_value=b'0 0 4294967295\n',different=None,isolated=True):
            seen=[]
            def read(path):
                self.assertEqual(str(path),'/proc/self/uid_map');seen.append('uid-map');return map_value
            def ns(path,*args,**kw):
                text=str(path)
                self.assertTrue(text.startswith('/proc/self/ns/') or text.startswith('/proc/1/ns/'))
                return SimpleNamespace(st_ino=2 if different and text=='/proc/1/ns/'+different else 1)
            with patch.object(p.os,'geteuid',return_value=0),patch.object(p.os,'getegid',return_value=0), \
                 patch.object(p.sys,'flags',SimpleNamespace(isolated=isolated,no_site=True)), \
                 patch.object(p.sys,'dont_write_bytecode',True),patch.object(p.Path,'read_bytes',read), \
                 patch.object(p.os,'stat',side_effect=ns),patch.object(p,'protected_tree') as tree, \
                 patch.object(p,'protected_file',return_value=b'opaque public source') as source:
                if isolated and map_value==b'0 0 4294967295\n' and different is None:
                    p.root_admission();source.assert_called_once();return
                with self.assertRaises(p.Refused):p.root_admission()
                source.assert_not_called();tree.assert_not_called()
        scenario()
        scenario(map_value=b'0 1000 1\n')
        for namespace in ('user','pid','mnt'):scenario(different=namespace)
        scenario(isolated=False)

    def test_native_closed_tree_rejects_nested_registry_and_controller_caches(self):
        with author.World() as w:
            for name in ('registry','controller'):
                root=w.root/name;root.mkdir(mode=0o700)
                (root/'main.py').write_bytes(b'# opaque synthetic source\n')
                self.assertEqual(len(p.closed_code_tree(root)),64)
                nested=root/'nested';nested.mkdir(mode=0o700)
                (nested/'cached.pyc').write_bytes(b'opaque-not-executed')
                with self.assertRaises(p.Refused):p.closed_code_tree(root)
                author.REAL_UNLINK(nested/'cached.pyc')
                (nested/'__pycache__').mkdir(mode=0o700)
                with self.assertRaises(p.Refused):p.closed_code_tree(root)

    def test_native_closed_tree_rejects_foreign_alias_before_any_code_load(self):
        with author.World() as w:
            root=w.root/'code';root.mkdir(mode=0o700)
            (root/'original.py').write_bytes(b'# opaque\n')
            (root/'alias.py').symlink_to(root/'original.py')
            with patch.object(p,'load_closed') as load,self.assertRaises(p.Refused):p.closed_code_tree(root)
            load.assert_not_called()

    def test_existing_lease_contention_never_creates_or_deletes_policy(self):
        with author.World() as w,patch.object(p.fcntl,'flock',side_effect=BlockingIOError):
            with self.assertRaises(p.Refused):w.run()
            self.assertEqual(w.unlinks,[])
            self.assertEqual(set(os.listdir(w.runtime)),{'lifecycle.lock'})

    def test_late_named_lease_inode_replacement_refuses_while_original_fd_held(self):
        with author.World() as w:
            old=p.os.replace;changed=[]
            def replace(source,target,*args,**kw):
                old(source,target,*args,**kw)
                if not changed and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':
                    (w.runtime/'lifecycle.lock').rename(w.runtime/'old.lock')
                    (w.runtime/'lifecycle.lock').touch(mode=0o600);changed.append(True)
            with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
            self.assertEqual(changed,[True]);self.assertEqual(w.unlinks,[])

    def test_late_policy_parent_replacement_refuses(self):
        with author.World() as w:
            old=p.os.replace;changed=[]
            def replace(source,target,*args,**kw):
                old(source,target,*args,**kw)
                if not changed and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':
                    w.sudo.rename(w.root/'held-old-sudo');w.sudo.mkdir(mode=0o700);changed.append(True)
            with patch.object(p.os,'replace',replace),self.assertRaises(p.Refused):w.run()
            self.assertEqual(changed,[True]);self.assertEqual(w.unlinks,[])
            self.assertTrue((w.root/'held-old-sudo'/w.specs[0][0].name).is_file())

    def test_real_unlink_then_policy_parent_fsync_failure_resumes_absence_only(self):
        for index,issued in ((0,'sudo-issued'),(1,'tmpfiles-issued')):
            with self.subTest(index=index),author.World() as w:
                parent=w.sudo if index==0 else w.tmpfiles
                st=author.REAL_LSTAT(parent);expected=(st.st_dev,st.st_ino)
                old=p.os.fsync;fired=[]
                def fsync(fd):
                    s=author.REAL_FSTAT(fd)
                    if not fired and (s.st_dev,s.st_ino)==expected and not (parent/w.specs[index][0].name).exists():
                        fired.append(True);raise OSError('synthetic directory fsync fault')
                    return old(fd)
                with patch.object(p.os,'fsync',fsync),self.assertRaises(p.Refused):w.run()
                self.assertEqual(fired,[True]);self.assertEqual(w.read()[p.KEY]['phase'],issued)
                count=len(w.unlinks);w.run()
                self.assertEqual(len(w.unlinks),2);self.assertEqual(count,index+1)

    def test_own_regular_parent_metadata_changes_and_ledger_replacement_do_not_strand_resume(self):
        with author.World() as w:
            # Hold the original fixture ledger: without this, legitimate inode
            # recycling across multiple atomic replacements invalidates != tests.
            with w.ledger.open('rb') as original:
                before=author.REAL_FSTAT(original.fileno()).st_ino
                w.fault='after-sudo-issued'
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(author.REAL_FSTAT(original.fileno()).st_nlink,0)
                self.assertNotEqual(author.REAL_LSTAT(w.ledger).st_ino,before)
                (w.sudo/'unrelated-synthetic-file').write_bytes(b'opaque')
                (w.root/'unrelated-synthetic-file').write_bytes(b'opaque')
                w.fault=None;w.run()
                self.assertEqual(len(w.unlinks),2)
                self.assertEqual(w.read()[p.KEY]['phase'],'fenced')

    def test_actual_nss_reuse_inside_full_engine_refuses_without_any_unlink(self):
        for name in ('getpwnam','getpwuid','getgrnam','getgrgid'):
            with self.subTest(name=name),author.World() as w,ExitStack() as stack:
                # Disable only World's broad NSS fake; exercise concrete NSS checker.
                stack.enter_context(patch.object(p,'_accounts_absent',NSS_CHECK))
                for lookup in ('getpwnam','getpwuid','getgrnam','getgrgid'):
                    module=p.pwd if lookup.startswith('getpw') else p.grp
                    stack.enter_context(patch.object(module,lookup,side_effect=None if lookup==name else KeyError,
                                                    return_value=object()))
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_independent_late_root_jobs_process_and_source_at_issued_barrier(self):
        for kind in ('jobs','process','source'):
            with self.subTest(kind=kind),author.World() as w:
                replace=p.os.replace;fired=[]
                def issue(source,target,*args,**kw):
                    replace(source,target,*args,**kw)
                    if not fired and w.read().get(p.KEY,{}).get('phase')=='sudo-issued':
                        fired.append(True)
                        if kind=='jobs':w.block_job=True
                        if kind=='process':w.block_process=True
                        if kind=='source':w.closure['ops']='0'*64
                with patch.object(p.os,'replace',issue),self.assertRaises(p.Refused):w.run()
                self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[])
                self.assertEqual(w.read()[p.KEY]['phase'],'sudo-issued')

    def test_late_cas_change_at_temporary_file_fsync_is_not_overwritten(self):
        with author.World() as w:
            original=p.os.fsync;fired=[]
            def fsync(fd):
                if not fired and stat.S_ISREG(author.REAL_FSTAT(fd).st_mode):
                    fired.append(True);w.ledger.write_bytes(b'opaque synthetic foreign during fsync')
                return original(fd)
            with patch.object(p.os,'fsync',fsync),self.assertRaises(p.Refused):w.run()
            self.assertEqual(fired,[True]);self.assertEqual(w.unlinks,[])
            self.assertEqual(w.ledger.read_bytes(),b'opaque synthetic foreign during fsync')

    def test_native_journal_handles_actual_short_writes(self):
        with author.World() as w:
            original=p.os.write;short=[]
            def write(fd,data):
                if len(data)>1024:short.append(True)
                return original(fd,data[:1024])
            with patch.object(p.os,'write',write):result=w.run()
            self.assertTrue(short);self.assertEqual(result['policiesAbsent'],2)
            self.assertEqual(w.read()[p.KEY]['phase'],'fenced')

    def test_native_64mib_bound_refuses_sparse_own_ledger_before_reading_body(self):
        with author.World() as w:
            with w.ledger.open('wb') as output:output.truncate(p.MAX_LEDGER+1)
            s=author.REAL_LSTAT(w.ledger);target=(s.st_dev,s.st_ino)
            original=p.os.read;reads=[]
            def read(fd,count):
                info=author.REAL_FSTAT(fd)
                if (info.st_dev,info.st_ino)==target:reads.append(True)
                return original(fd,count)
            with patch.object(p.os,'read',read),self.assertRaises(p.Refused):
                p.fence_host_transport_policies(str(w.bundle),str(w.selector),str(w.ledger),'0'*64,p.sha(w.provenance))
            self.assertEqual(reads,[]);self.assertEqual(w.unlinks,[])

    def test_final_observations_late_epoch_not_adopted(self):
        with author.World() as w:
            original=p.native_observations;fired=[]
            def observe(*args):
                original(*args)
                if w.read().get(p.KEY,{}).get('phase')=='tmpfiles-done' and not fired:
                    w.ledger.write_bytes(b'opaque synthetic foreign epoch');fired.append(True)
            with patch.object(p,'native_observations',observe),self.assertRaises(p.Refused):w.run()
            self.assertEqual(fired,[True]);self.assertEqual(len(w.unlinks),2)
            self.assertEqual(w.ledger.read_bytes(),b'opaque synthetic foreign epoch')

NSS_CHECK=p._accounts_absent
if __name__=='__main__':unittest.main(verbosity=2)
