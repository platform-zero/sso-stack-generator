"""Real implementation branches over own USER files + explicitly fake kernel facts.
No actual Root, /proc, /etc, manager, selected controller or target is accessed.
"""
from contextlib import ExitStack
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import policy_fence as p

HERE=Path(__file__).resolve().parent
REAL_FSTAT=os.fstat;REAL_STAT=os.stat;REAL_LSTAT=os.lstat;REAL_OPEN=os.open
REAL_UNLINK=os.unlink;REAL_REPLACE=os.replace
ACTUAL_CONTEXT=p.actual_context

class Meta:
    def __init__(self,s):self.s=s
    def __getattr__(self,key):
        if key in ('st_uid','st_gid'):return 0 # EXPLICIT synthetic Root metadata, not authority
        return getattr(self.s,key)

class World:
    def __init__(self):
        self.tmp=tempfile.TemporaryDirectory(dir=HERE/'USER_TMP');self.root=Path(self.tmp.name)
        self.ns='p0test-example';self.source=Path('/usr/local/libexec/'+self.ns+'-control')
        self.context=SimpleNamespace(namespace=self.ns,digest='a'*64,source=self.source,runtime=Path('/run/'+self.ns+'-control'),
            unit=lambda n:self.ns+'-'+n.removeprefix('p0-'))
        self.bundle=self.root/'bundle';self.bundle.mkdir();self.selector=self.root/'selector';self.selector.write_bytes(b'{}')
        self.provenance=b'public synthetic provenance';(self.bundle/'source-provenance.json').write_bytes(self.provenance)
        self.sudo=self.root/'sudo';self.tmpfiles=self.root/'tmpfiles';self.runtime=self.root/'runtime'
        for x in (self.sudo,self.tmpfiles,self.runtime):x.mkdir(mode=0o700)
        (self.runtime/'lifecycle.lock').touch(mode=0o600)
        self.specs=p.policy_spec(self.context)
        for path,mode,body in self.specs:
            target=(self.sudo if mode==0o440 else self.tmpfiles)/path.name;target.write_bytes(body);target.chmod(mode)
        self.accounts=[]
        for i,name in enumerate(('core','ai','apps','ci-runner','postgres','vector','obs')):
            user=self.ns+'-'+name
            self.accounts.append(dict(name=user,uid=4000+i,subuid=200000+i*65536,home='/home/'+user,
                state='/var/lib/'+user,graph='/var/lib/'+user+'/graph',volume='/var/lib/'+user+'/volumes'))
        roots={k:'/synthetic/'+k for k in ('rootful-state','rootful-graph','rootful-network','rootful-run',
                   'rootful-volume','rootful-runtime','postgres','vectors','log')}
        for a in self.accounts:
            for key in ('home','state','graph','volume'):roots[a['name']+'-'+key]=a[key]
        roots['ci-runner-ssh']='/var/lib/'+self.ns+'-ci-runner/forgejo-runner-ssh'
        configs={'/synthetic/rootful-state/containers.conf':'public synthetic config'}
        for a in self.accounts:configs[a['home']+'/.config/containers/storage.conf']='public synthetic config'
        self.plan=dict(schemaVersion=1,prefix=self.ns,accounts=self.accounts,roots=roots,configs=configs,
                       selectorSha256=p.sha(b'{}'),quadletTreeSha256='b'*64,bundleIrSha256='c'*64,sourceCommit='d'*40,activationAuthorized=False)
        self.created=sorted(set(roots.values())|{str(Path(n).parent) for n in configs})
        self.units={str(Path('/etc/containers/systemd')/(self.ns+'-unit'+str(i)+'.container')):
                    dict(source='/synthetic/quadlet/'+str(i),sha256='e'*64,uid=0) for i in range(190)}
        self.closure={'ops':'f'*64,'slot':'1'*64,'quadlet':'2'*64,'slotPath':str(self.source/'agent-service-releases/host-fake'),
                      'manifest':{'files':{'units/'+name:'3'*64 for name in p.HOST_UNITS}}}
        hostpaths=[str(Path('/etc/systemd/system')/self.context.unit(n)) for n in p.HOST_UNITS]
        self.closure.update(imageIds={'root|synthetic/image:1':'sha256:'+'4'*64},frozenRegistrySha256='4'*64,
                            provenanceSha256=p.sha(self.provenance))
        self.history=dict(schemaVersion=1,pending='root|synthetic/image:1',selectedImageId='sha256:'+'4'*64,
             retiredImageId='sha256:'+'5'*64,verifiedSha256=p.sha(p.canonical({})),sourceProvenanceSha256=p.sha(self.provenance),
             operationSourceSha256=p.C17_SOURCE_SHA,phase='retired-drifted-pending',ledgerSha256Before='9'*64)
        self.state=dict(schemaVersion=1,venueInstallerVersion=1,status='retired-empty',venueInstallerPhase='retired-inert',
             activationAuthorized=False,plan=self.plan,installedUnits=[dict(dev=1,ino=i+1,path=n) for i,n in enumerate(self.units)],
             retiredUnits=list(self.units),graphCleared=['root']+[a['name'] for a in self.accounts],
             managerStopped=[a['name'] for a in self.accounts],createPaths=self.created,createdPaths=self.created,
             pathIdentities={n:dict(dev=1,ino=i+1,uid=0,mode=0o700) for i,n in enumerate(self.created)},
             venueHostUnitsRetirement=dict(phase='retired',contextSha256=self.context.digest,neverStartedInstallerVersion=1,
                 units=[dict(path=n,sha256='3'*64) for n in hostpaths],removed=hostpaths),
             venueRegistryFailedPendingRetirement=self.history,venueRegistryPreparationAbandoned=True,
             venueRegistryPlan=self.closure['imageIds'],venueRegistryVerified={},venueRegistryFrozenSha256='4'*64)
        for key in ('venueCompositeMode','venueRuntimeEnvPhase','venueDomainRuntimePhase','venueReleasePhase','venueRegistryPhase','venueBuildBasePhase'):
            self.state[key]='retired-inert'
        self.ledger=self.root/'ledger';self.save(self.state)
        self.events=[];self.unlinks=[];self.fault=None;self.block_job=False;self.block_process=False;self.stack=ExitStack()
    def save(self,value):self.ledger.write_bytes(p.encode(value));self.ledger.chmod(0o600)
    def read(self):return json.loads(self.ledger.read_bytes())
    def mapped(self,path):
        path=Path(path)
        if path.is_relative_to(HERE):return path
        if path==Path('/etc/sudoers.d'):return self.sudo
        if path==Path('/etc/tmpfiles.d'):return self.tmpfiles
        if path==self.context.runtime:return self.runtime
        if path.parent==Path('/etc/sudoers.d'):return self.sudo/path.name
        if path.parent==Path('/etc/tmpfiles.d'):return self.tmpfiles/path.name
        # All other native absence paths are synthetic missing USER paths.
        return self.root/'absent'/str(path).lstrip('/')
    def selected(self,*args):return copy.deepcopy((self.plan,self.context,self.units,self.created,self.closure))
    def protected(self,path):
        path=self.mapped(path)
        if not path.is_relative_to(HERE):raise AssertionError('not own fixture')
    def sysd(self,args):
        self.events.append('jobs')
        if args==['show','--property=UnitPath','--value']:return 0,'/etc/systemd/system /run/systemd/system /usr/lib/systemd/system\n'
        if args[0]=='list-jobs':return 0,('1 '+self.ns+'-web.service start waiting\n' if self.block_job else '')
        if args[0]=='list-units':return 0,''
        name=args[1];missing=name.startswith(self.ns)
        return 0,'LoadState='+('not-found' if missing else 'loaded')+'\nActiveState=inactive\nSubState=dead\nFragmentPath=\nDropInPaths=\n'
    def proc(self,pid,name,limit):
        self.events.append('processes')
        if name=='stat':return b'100 (synthetic) S '+b'0 '*18+b'123 0\n'
        if name=='status':return b'Uid:\t0\t0\t0\t0\n'
        if name=='cmdline':
            if self.fault in ('scan-ledger','scan-source') and self.read().get(p.KEY,{}).get('phase')=='sudo-issued':
                if self.fault=='scan-ledger':self.ledger.write_bytes(b'PRIVATE late foreign epoch')
                else:self.closure['ops']='0'*64
                self.fault=None
            return (str(self.source/'agent-identity-host.py').encode() if self.block_process else b'/synthetic/idle')+b'\0'
        raise AssertionError('unreviewed proc field')
    def unlink(self,name,*args,**kwargs):
        if name in (x[0].name for x in self.specs):
            self.events.append('unlink:'+name);self.unlinks.append(name)
            phase=self.read()[p.KEY]['phase']
            if phase not in ('sudo-issued','tmpfiles-issued'):raise AssertionError('not issued durably')
            if self.fault=='before-'+phase:raise RuntimeError('PRIVATE fake interrupted before unlink')
            REAL_UNLINK(name,*args,**kwargs)
            if self.fault=='after-'+phase:raise RuntimeError('PRIVATE fake interrupted after unlink')
            return
        return REAL_UNLINK(name,*args,**kwargs)
    def replace(self,source,target,*args,**kwargs):
        REAL_REPLACE(source,target,*args,**kwargs)
        phase=self.read().get(p.KEY,{}).get('phase');self.events.append('commit:'+str(phase))
        if self.fault=='postwrite':self.ledger.write_bytes(b'PRIVATE foreign bytes')
        if self.fault=='source-'+str(phase):self.closure['ops']='0'*64
        if self.fault=='jobs-'+str(phase):self.block_job=True
        if self.fault=='process-'+str(phase):self.block_process=True
        if phase=='sudo-issued' and self.fault in ('late-inode','late-mode','late-link'):
            target=self.sudo/self.specs[0][0].name
            if self.fault=='late-inode':target.rename(self.sudo/'original');target.write_bytes(self.specs[0][2]);target.chmod(0o440)
            if self.fault=='late-mode':target.chmod(0o640)
            if self.fault=='late-link':os.link(target,self.sudo/'alias')
    def __enter__(self):
        changes=[patch.object(p,'root_admission'),patch.object(p,'protected_tree',side_effect=self.protected),
            patch.object(p,'actual_context',side_effect=self.selected),
            patch.object(p,'_directory_fd',side_effect=lambda path:REAL_OPEN(self.mapped(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)),
            patch.object(p,'_fd_stat',side_effect=lambda fd:Meta(REAL_FSTAT(fd))),
            patch.object(p,'_path_stat',side_effect=lambda path:Meta(REAL_LSTAT(self.mapped(path)))),
            patch.object(p,'_entry_stat',side_effect=lambda fd,name:Meta(REAL_STAT(name,dir_fd=fd,follow_symlinks=False))),
            patch.object(p,'_accounts_absent'),patch.object(p,'_systemctl',side_effect=self.sysd),
            patch.object(p,'_proc_ids',return_value=[100]),patch.object(p,'_proc_bytes',side_effect=self.proc),
            patch.object(p.os,'unlink',side_effect=self.unlink),patch.object(p.os,'replace',side_effect=self.replace)]
        for change in changes:self.stack.enter_context(change)
        return self
    def run(self):
        return p.fence_host_transport_policies(str(self.bundle),str(self.selector),str(self.ledger),p.sha(self.ledger.read_bytes()),p.sha(self.provenance))
    def __exit__(self,*args):self.stack.close();self.tmp.cleanup()

class CompleteTests(unittest.TestCase):
    def test_default_unprivileged_refuses_before_private_reads(self):
        self.assertNotEqual(os.geteuid(),0)
        with patch.object(p,'protected_file',side_effect=AssertionError('private read forbidden')):
            with self.assertRaisesRegex(p.Refused,'^policy-fence-refused$'):
                p.fence_host_transport_policies('/unread','/unread','/unread','a'*64,'b'*64)

    def test_full_positive_real_engine_preserves_terminal_history(self):
        with World() as w:
            before=p.canonical(w.read()['venueRegistryFailedPendingRetirement'])
            result=w.run();record=w.read()[p.KEY]
            self.assertEqual(result['policiesAbsent'],2);self.assertEqual(record['phase'],'fenced')
            self.assertEqual(record['schemaVersion'],1);self.assertEqual(record['namespace'],w.ns)
            self.assertEqual(record['planSha256'],p.sha(p.canonical(w.plan)))
            self.assertEqual(p.canonical(w.read()['venueRegistryFailedPendingRetirement']),before)
            self.assertEqual(w.unlinks,[x[0].name for x in w.specs])
            between=w.events[w.events.index('unlink:'+w.specs[0][0].name)+1:w.events.index('unlink:'+w.specs[1][0].name)]
            self.assertIn('jobs',between);self.assertIn('processes',between)
            self.assertEqual(len(record['intendedEpochs']),6)
            w.run();self.assertEqual(len(w.unlinks),2)

    def test_no_public_context_adapter_boolean_or_delete_path(self):
        self.assertEqual(list(inspect.signature(p.fence_host_transport_policies).parameters),
            ['bundle','selector','ledger','reviewed_sha','provenance_sha'])

    def test_both_crash_after_unlink_resume_absence_only(self):
        for issued in ('sudo-issued','tmpfiles-issued'):
            with self.subTest(phase=issued),World() as w:
                w.fault='after-'+issued
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.read()[p.KEY]['phase'],issued)
                w.fault=None;w.run();self.assertEqual(len(w.unlinks),2)

    def test_issued_present_never_retries_even_original(self):
        for issued in ('sudo-issued','tmpfiles-issued'):
            with self.subTest(phase=issued),World() as w:
                w.fault='before-'+issued
                with self.assertRaises(p.Refused):w.run()
                count=len(w.unlinks);w.fault=None
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(len(w.unlinks),count)

    def test_unowned_missing_either_file_refuses_before_any_delete(self):
        for index in (0,1):
            with self.subTest(index=index),World() as w:
                target=(w.sudo if index==0 else w.tmpfiles)/w.specs[index][0].name
                REAL_UNLINK(target)
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_recreated_file_after_done_or_fenced_refuses_without_delete(self):
        with World() as w:
            w.run();target=w.sudo/w.specs[0][0].name;target.write_bytes(w.specs[0][2]);target.chmod(0o440)
            with self.assertRaises(p.Refused):w.run()
            self.assertEqual(len(w.unlinks),2)

    def test_late_source_jobs_process_changes_stop_before_unlink(self):
        for fault in ('source-sudo-issued','jobs-sudo-issued','process-sudo-issued'):
            with self.subTest(fault=fault),World() as w:
                w.fault=fault
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_late_jobs_after_sudo_done_preserve_partial_fence(self):
        with World() as w:
            w.fault='jobs-sudo-done'
            with self.assertRaises(p.Refused):w.run()
            self.assertEqual(w.read()[p.KEY]['phase'],'sudo-done')
            self.assertEqual(w.unlinks,[w.specs[0][0].name])
            self.assertTrue((w.tmpfiles/w.specs[1][0].name).exists())
            w.fault=None;w.block_job=False;w.run();self.assertEqual(len(w.unlinks),2)

    def test_foreign_postwrite_epoch_is_not_adopted(self):
        with World() as w:
            w.fault='postwrite'
            with self.assertRaises(p.Refused):w.run()
            self.assertEqual(w.ledger.read_bytes(),b'PRIVATE foreign bytes');self.assertEqual(w.unlinks,[])

    def test_policy_alias_symlink_hardlink_wrong_mode_body_refuse(self):
        for variant in ('symlink','hardlink','mode','body'):
            with self.subTest(variant=variant),World() as w:
                target=w.sudo/w.specs[0][0].name
                if variant=='symlink':
                    target.rename(w.sudo/'foreign');target.symlink_to(w.sudo/'foreign')
                if variant=='hardlink':os.link(target,w.sudo/'alias')
                if variant=='mode':target.chmod(0o640)
                if variant=='body':target.chmod(0o600);target.write_bytes(b'PRIVATE foreign policy');target.chmod(0o440)
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_lease_missing_or_foreign_runtime_never_created_or_adopted(self):
        for kind in ('missing','foreign','authority'):
            with self.subTest(kind=kind),World() as w:
                if kind=='missing':REAL_UNLINK(w.runtime/'lifecycle.lock')
                else:(w.runtime/('runtime-authority.json' if kind=='authority' else 'foreign')).write_text('{}')
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])
                if kind=='missing':self.assertFalse((w.runtime/'lifecycle.lock').exists())

    def test_live_unknown_pending_and_start_history_refuse_but_terminal_passes(self):
        for kind in ('unknownPending','venueRegistryPending','pending','venueStartPhase','venueRuntimeAuthorityFoo'):
            with self.subTest(kind=kind),World() as w:
                value=w.read();value[kind]=False;w.save(value)
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])
        with World() as w:
            value=w.read();value['venueRegistryFailedPendingRetirement']['phase']='delete-issued';w.save(value)
            with self.assertRaises(p.Refused):w.run()

    def test_json_overflow_duplicate_nonfinite_refusal_privacy(self):
        for raw in (b'{"a":1e999}',b'{"a":NaN}',b'{"a":1,"a":2}',b'{"PRIVATE":'):
            with self.subTest(raw=raw),World() as w:
                w.ledger.write_bytes(raw)
                with self.assertRaises(p.Refused) as caught:w.run()
                self.assertEqual(str(caught.exception),'policy-fence-refused')
                self.assertTrue(caught.exception.__suppress_context__);self.assertEqual(w.unlinks,[])

    def test_source_selected_190_created_paths_host_disposition_and_typed_facts(self):
        for kind in ('units','created','host','boolVersion','manager'):
            with self.subTest(kind=kind),World() as w:
                value=w.read()
                if kind=='units':value['installedUnits'][0]['path']='/foreign'
                if kind=='created':value['createdPaths']=[]
                if kind=='host':value['venueHostUnitsRetirement']['units'][0]['sha256']='0'*64
                if kind=='boolVersion':value['venueInstallerVersion']=True
                if kind=='manager':value['managerStopped']=[]
                w.save(value)
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_native_account_name_uid_group_absence_and_uid_reuse(self):
        for which in ('getpwnam','getpwuid','getgrnam','getgrgid'):
            with ExitStack() as stack:
                lookups={name:stack.enter_context(patch.object(p.pwd if name.startswith('getpw') else p.grp,name,side_effect=KeyError))
                         for name in ('getpwnam','getpwuid','getgrnam','getgrgid')}
                account={'name':'p0test-example-core','uid':4000}
                p._accounts_absent([account]);lookups[which].side_effect=None;lookups[which].return_value=object()
                with self.assertRaises(p.Refused):p._accounts_absent([account])

    def test_process_gone_and_pid_reuse_are_distinguished(self):
        ctx=SimpleNamespace(source=Path('/synthetic/source'),runtime=Path('/synthetic/runtime'))
        with patch.object(p,'_proc_bytes',side_effect=FileNotFoundError):self.assertIsNone(p._process_row(123,ctx))
        statraw=b'123 (synthetic) S '+b'0 '*18+b'123 0\n'
        with patch.object(p,'_proc_bytes',side_effect=[FileNotFoundError,statraw]):
            with self.assertRaises(p.Refused):p._process_row(123,ctx)
        with patch.object(p,'_proc_bytes',side_effect=[statraw,b'Uid: 0 0 0 0\n',b'/synthetic/idle\0',statraw.replace(b'123 0\n',b'124 0\n')]):
            with self.assertRaises(p.Refused):p._process_row(123,ctx)

    def test_unrelated_process_gone_can_converge_on_fresh_snapshot(self):
        with patch.object(p,'_proc_ids',side_effect=[[100],[100],[]]),patch.object(p,'_process_row',return_value=None):
            p._check_processes(SimpleNamespace())

    def test_tmpfiles_active_overrides_bad_jobs_refuse(self):
        with World() as w:
            base=w.sysd
            for mode in ('active','overrides','malformed'):
                def bad(args):
                    code,text=base(args)
                    if mode=='malformed' and args[0]=='list-jobs':return 0,'PRIVATE unparseable\n'
                    if args[0]=='show' and args[1] in p.TMPFILES:
                        if mode=='active':text=text.replace('ActiveState=inactive','ActiveState=active')
                        if mode=='overrides':text=text.replace('DropInPaths=','DropInPaths=/PRIVATE')
                    return code,text
                with patch.object(p,'_systemctl',side_effect=bad),self.assertRaises(p.Refused):w.run()
            self.assertEqual(w.unlinks,[])

    def test_late_policy_identity_and_during_scan_cas_source_refuse(self):
        for fault in ('late-inode','late-mode','late-link','scan-ledger','scan-source'):
            with self.subTest(fault=fault),World() as w:
                w.fault=fault
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_exact_nine_field_history_source_verified_provenance_c17_bindings(self):
        for field in ('pending','selectedImageId','retiredImageId','verifiedSha256','sourceProvenanceSha256','operationSourceSha256'):
            with self.subTest(field=field),World() as w:
                value=w.read();history=value['venueRegistryFailedPendingRetirement']
                history[field]=(history['selectedImageId'] if field=='retiredImageId' else
                    ('root|foreign/image:1' if field=='pending' else ('sha256:' if field.endswith('ImageId') else '')+'0'*64))
                w.save(value)
                with self.assertRaises(p.Refused):w.run()
                self.assertEqual(w.unlinks,[])

    def test_actual_context_executes_closure_order_and_cache_refusal_branch(self):
        with World() as w:
            class KernelPath(type(Path())):
                def lstat(self):return SimpleNamespace(st_uid=0,st_mode=stat.S_IFLNK|0o777)
                def resolve(self,strict=False):return KernelPath(str(w.source/'agent-service-releases/host-fake'))
            for fail_external in (False,True):
                events=[]
                def close(root):
                    events.append('close:'+str(root))
                    if fail_external and str(root).endswith('host-fake'):raise p.Refused('fake-code-cache-refusal')
                    return 'f'*64
                def read(path,maximum):
                    if str(path).endswith('/manifest.json'):return p.encode({'files':{'p0_host_context.py':p.sha(b'closed')}})
                    if str(path).endswith('/p0_host_context.py'):return b'closed'
                    return b'{}'
                def load(path,name):
                    events.append('load:'+Path(path).name)
                    if Path(path).name=='venue-owned-stage.py':return SimpleNamespace(owned_plan=lambda *a:w.plan,safe_parents=lambda a:w.created)
                    if Path(path).name=='venue-start-quarantine.py':return SimpleNamespace(host_context=lambda *a:w.context)
                    if Path(path).name=='venue-unit-stage.py':return SimpleNamespace(manifest=lambda *a:w.units)
                    if Path(path).name=='venue-image-authority.py':return SimpleNamespace(authority=lambda *a:w.closure)
                    raise AssertionError('unknown own source fake')
                # Bypass World's selection fake ONLY here to exercise authentic
                # selection implementation over explicit source/kernel fakes.
                actual=p.actual_context._mock_wraps if getattr(p.actual_context,'_mock_wraps',None) else ACTUAL_CONTEXT
                with patch.object(p,'Path',KernelPath),patch.object(p,'closed_code_tree',side_effect=close),\
                     patch.object(p,'protected_file',side_effect=read),patch.object(p,'load_closed',side_effect=load):
                    if fail_external:
                        with self.assertRaises(p.Refused):actual(KernelPath('/synthetic/bundle'),KernelPath('/synthetic/selector'))
                        self.assertNotIn('load:venue-start-quarantine.py',events)
                    else:
                        actual(KernelPath('/synthetic/bundle'),KernelPath('/synthetic/selector'))
                        self.assertLess(events.index('close:'+str(w.source/'agent-service-releases/host-fake')),
                                        events.index('load:venue-start-quarantine.py'))

    def test_circular_selection_and_foreign_observation_refuse_privately(self):
        with World() as w:
            w.closure['cycle']=w.closure
            with self.assertRaises(p.Refused) as caught:w.run()
            self.assertEqual(str(caught.exception),'policy-fence-refused');self.assertEqual(w.unlinks,[])
        with World() as w,patch.object(p,'_systemctl',return_value=(0,{'PRIVATE':'foreign'})):
            with self.assertRaises(p.Refused) as caught:w.run()
            self.assertEqual(str(caught.exception),'policy-fence-refused');self.assertEqual(w.unlinks,[])

    def test_deleted_account_with_lingering_selected_uid_process_refuses(self):
        with World() as w:
            def kernel(pid,name,limit):
                if name=='status':return b'Uid: 4000 4000 4000 4000\n'
                return w.proc(pid,name,limit)
            with patch.object(p,'_proc_bytes',side_effect=kernel),self.assertRaises(p.Refused):w.run()
            self.assertEqual(w.unlinks,[])

    def test_source_closure_ordering_is_before_external_exec(self):
        text=inspect.getsource(p.actual_context)
        self.assertLess(text.index('slot_sha=closed_code_tree(slot)'),text.index("lifecycle=load_closed"))
        self.assertLess(text.index("require(sha(protected_file(slot/member"),text.index("lifecycle=load_closed"))

if __name__=='__main__':unittest.main(verbosity=2)
