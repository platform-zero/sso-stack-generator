#!/usr/bin/env python3
"""Fail-closed isolated typed apply queue/worker; no production or data rollback.

A lane may request an exact already-root-approved plan; the worker rechecks the
machine, final inputs and approval before a single supported native installer.
No automatic restart, retry, data restore, old-release promotion or pruning.
"""
import argparse
import fcntl
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import pwd
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time

PLANS = Path('/var/lib/platform-zero/maintenance-plans')
APPROVALS = Path('/var/lib/platform-zero/maintenance-approvals')
INCOMING = Path('/var/lib/platform-zero/incoming')
OPERATIONS = Path('/var/lib/platform-zero/maintenance-operations')
INPUTS = Path('/etc/platform-zero/maintenance-install.json')
APPROVER = Path('/usr/local/sbin/p0-host-approve')
TEST_APPROVER = Path('/usr/local/sbin/p0-host-test-approve')
ROLLBACK_APPROVER = Path('/usr/local/sbin/p0-host-rollback-approve')
BINDER = Path('/usr/local/libexec/p0-host-install-inputs.py')
BROKER = Path('/usr/local/libexec/p0-host-broker')
NATIVE_ROOT = Path('/var/lib/webservices')
PIN_FILES = ('bundle.json','stack.ir.json','source-provenance.json','podman-domains.json',
             'site/agent-vm.json','site/agent-vm.provenance.json','site/manifest.json',
             'site/components.lock.json','site/global.settings/registry-image-ids.json')


def load(path,name):
    loader=SourceFileLoader(name,str(path))
    spec=importlib.util.spec_from_loader(name,loader)
    if not spec or not spec.loader:raise ValueError('Trusted typed operation source missing')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def protected_directory(path,create=False):
    if create and not path.exists()and not path.is_symlink():path.mkdir(mode=0o700,parents=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode)or path.is_symlink()or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('Unsafe typed operation directory')


def read_private(path,maximum=8192):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or info.st_size>maximum):
            raise ValueError('Unsafe typed operation authority file')
        body=os.read(fd,maximum+1)
        if len(body)>maximum:raise ValueError('Oversized typed operation authority')
    finally:os.close(fd)
    def pairs(rows):
        value={}
        for k,v in rows:
            if k in value:raise ValueError('Duplicate typed operation authority')
            value[k]=v
        return value
    value=json.loads(body,object_pairs_hook=pairs)
    if not isinstance(value,dict):raise ValueError('Typed operation authority is not an object')
    return value


def atomic_private(path,value):
    protected_directory(path.parent)
    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
    fd,tmp=tempfile.mkstemp(prefix='.operation-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        sync=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(sync)
        finally:os.close(sync)
    finally:Path(tmp).unlink(missing_ok=True)


class operation_lock:
    def __enter__(self):
        protected_directory(OPERATIONS,create=True)
        self.fd=os.open(OPERATIONS/'.queue.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1):
            os.close(self.fd);raise ValueError('Unsafe typed operation lock')
        fcntl.flock(self.fd,fcntl.LOCK_EX)
        return self

    def __exit__(self,*_):os.close(self.fd)


def approved_inputs(plan_id):
    if os.geteuid()!=0 or not re.fullmatch('[a-f0-9]{32}',plan_id):
        raise ValueError('Exact root operation identity required')
    protected_directory(PLANS);protected_directory(APPROVALS);protected_directory(INCOMING)
    approver=load(APPROVER,'p0_typed_root_approver')
    approver.PLANS=PLANS;approver.APPROVALS=APPROVALS
    plan=approver.strict(PLANS/(plan_id+'.json'),maximum=4096)
    if not isinstance(plan,dict)or plan.get('planId')!=plan_id:
        raise ValueError('Unbound typed maintenance proposal')
    release=plan.get('release')
    if not isinstance(release,str)or not re.fullmatch('[a-f0-9]{64}',release):
        raise ValueError('Invalid selected typed release')
    bound=approver.review(plan_id,release)
    if bound['context']!='isolated':
        # Production apply needs data recovery + notice + undo and its own
        # installed runner proof. An approval is necessary, never sufficient.
        raise ValueError('Production typed apply remains unavailable')
    binder=load(BINDER,'p0_typed_inputs_binder')
    broker=load(BROKER,'p0_typed_trusted_broker')
    bundle=INCOMING/release
    binder.root_controlled_parents(bundle)
    binder.protected(bundle,directory=True)
    if broker.tree_sha256(bundle)!=release:
        raise ValueError('Approved immutable release changed')
    broker.validate_bundle(bundle)
    data=read_private(INPUTS)
    if (set(data)!={'schemaVersion','scope','machineUuid','release','controlCommit',
                    'controlCheckout','siteSpecSha256','imageInputs','imageInputsSha256'}
            or data.get('schemaVersion')!=1 or data.get('scope')!='isolated-synthetic'
            or data.get('machineUuid')!=bound['machineUuid'] or data.get('release')!=release):
        raise ValueError('Root-maintained installer inputs unbound')
    if not isinstance(data['controlCheckout'],str)or not isinstance(data['imageInputs'],str):
        raise ValueError('Invalid root-maintained installer paths')
    binder.OUTPUT=INPUTS
    checked=binder.prepare(bundle,Path(data['controlCheckout']),Path(data['imageInputs']),release)
    if not checked['unchanged']:
        raise ValueError('A worker cannot create its own installer authority')
    if read_private(INPUTS)!=data:
        raise ValueError('Installer authority changed during validation')
    return release,bundle,data,approver


def materialize_approved_worktree(plan_id,release,bundle):
    """Run the native renderer on a private copy, never on sealed approval input.

    Native rendering writes decrypted runtime files into its --bundle directory.
    Mutating INCOMING/<sha> would invalidate future exact-release review after a
    successful apply or failed-intent recovery. No copy is an experiment backup:
    this is the selected one-operation installer input, retained only on error.
    """
    binder=load(BINDER,'p0_typed_worktree_binder')
    broker=load(BROKER,'p0_typed_worktree_broker')
    parent=INCOMING.parent/'maintenance-install-worktrees'
    binder.root_controlled_parents(parent)
    protected_directory(parent,create=True)
    destination=parent/plan_id
    if destination.exists()or destination.is_symlink():
        raise ValueError('Approved installer worktree already exists')
    temporary=Path(tempfile.mkdtemp(prefix='.approved-'+plan_id+'-',dir=parent))
    try:
        shutil.copytree(bundle,temporary,symlinks=True,dirs_exist_ok=True)
        temporary.chmod(0o700)
        if broker.tree_sha256(temporary)!=release or broker.tree_sha256(bundle)!=release:
            raise ValueError('Approved release changed during private installer staging')
        broker.validate_bundle(temporary)
        if destination.exists()or destination.is_symlink():
            raise ValueError('Approved installer worktree raced')
        os.rename(temporary,destination)
        return destination
    finally:
        if temporary.exists():shutil.rmtree(temporary)


def status(plan_id):
    if not re.fullmatch('[a-f0-9]{32}',plan_id):raise ValueError('Exact typed operation ID required')
    protected_directory(OPERATIONS)
    row=read_private(OPERATIONS/(plan_id+'.json'))
    if row.get('schemaVersion')!=1 or row.get('operationId')!=plan_id:
        raise ValueError('Unbound typed operation receipt')
    # Do not export proof paths, installer logs, argv, account names or secrets.
    return {key:row[key]for key in ('operationId','kind','release','state','startedAt','finishedAt')if key in row}


def queue_apply(plan_id):
    release,_,_,_=approved_inputs(plan_id)
    with operation_lock():
        marker=OPERATIONS/'.active.json'
        if marker.exists()or marker.is_symlink():
            raise ValueError('Another typed host operation remains active or needs root review')
        receipt=OPERATIONS/(plan_id+'.json')
        if receipt.exists()or receipt.is_symlink():raise ValueError('Typed operation already queued')
        row={'schemaVersion':1,'operationId':plan_id,'kind':'apply','release':release,
             'state':'queued','startedAt':int(time.time()),'finishedAt':None}
        atomic_private(receipt,row)
        atomic_private(marker,{'schemaVersion':1,'operationId':plan_id})
        command=['systemd-run','--collect','--unit=p0-typed-apply-'+plan_id,
                 '--property=Type=oneshot','--property=TimeoutStartSec=3h',
                 '/usr/bin/python3',str(Path(__file__).resolve()),
                 '--execute-apply',plan_id]
        started=subprocess.run(command,capture_output=True,text=True,timeout=30,cwd='/')
        if started.returncode:
            row['state']='failed-unstarted';row['finishedAt']=int(time.time())
            atomic_private(receipt,row)
            marker.unlink();raise ValueError('Typed host worker could not start')
    return {'operation_id':plan_id,'release':release,'state':'queued','applied':False}


def approved_test(suite,claimed_operation=None):
    if os.geteuid()!=0 or suite!='ts-unit':raise ValueError('Unsupported isolated test suite')
    approver=load(TEST_APPROVER,'p0_typed_test_approver')
    bound=approver.review(suite,claimed_operation=claimed_operation)
    runner=Path(bound['release'])/'build/stack.containers/test-runner/run-tests.sh'
    return bound,runner,approver


def queue_test(suite):
    bound,_,_=approved_test(suite)
    with operation_lock():
        marker=OPERATIONS/'.active.json'
        if marker.exists()or marker.is_symlink():
            raise ValueError('Another typed operation requires settlement/root review')
        operation_id=secrets.token_hex(16)
        receipt=OPERATIONS/(operation_id+'.json')
        if receipt.exists()or receipt.is_symlink():raise ValueError('Typed operation ID collision')
        row={'schemaVersion':1,'operationId':operation_id,'kind':'test','suite':suite,
             'release':bound['journalSha256'],'state':'queued','startedAt':int(time.time()),'finishedAt':None}
        atomic_private(receipt,row)
        atomic_private(marker,{'schemaVersion':1,'operationId':operation_id})
        command=['systemd-run','--collect','--unit=p0-typed-test-'+operation_id,
                 '--property=Type=oneshot','--property=TimeoutStartSec=2h',
                 '/usr/bin/python3',str(Path(__file__).resolve()),'--execute-test',operation_id]
        started=subprocess.run(command,capture_output=True,text=True,timeout=30,cwd='/')
        if started.returncode:
            row['state']='failed-unstarted';row['finishedAt']=int(time.time())
            atomic_private(receipt,row)
            marker.unlink();raise ValueError('Typed synthetic test worker could not start')
    return {'operation_id':operation_id,'suite':suite,'state':'queued','testPassed':False}


def guard_test_capacity():
    available=next((int(line.split()[1])for line in Path('/proc/meminfo').read_text().splitlines()
                    if line.startswith('MemAvailable:')),0)
    if available<10*1024*1024 or shutil.disk_usage('/').free<55*2**30:
        raise ValueError('Insufficient measured memory/disk reserve for synthetic suite')


def selected_test_runner_account(release):
    # The installed test entrypoint refuses root. Use only the exact native
    # release's signed domain owner, not a lane-provided user or environment.
    journal=read_private(NATIVE_ROOT/'.install-intent.json')
    manifest=release/'podman-domains.json'
    expected=journal.get('inputs',{}).get('podman-domains.json')
    if (journal.get('phase')!='active' or journal.get('release')!=str(release)
            or not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected)
            or manifest.is_symlink() or manifest.stat().st_uid!=0
            or manifest.stat().st_mode&0o022):
        raise ValueError('Selected test-runner identity differs from native journal')
    source=manifest.read_bytes()
    if hashlib.sha256(source).hexdigest()!=expected:
        raise ValueError('Selected test-runner identity differs from native journal')
    selected=json.loads(source)
    if not isinstance(selected,dict) or not isinstance(selected.get('domains'),list):
        raise ValueError('Invalid selected domain manifest')
    owners=[row for row in selected['domains'] if isinstance(row,dict) and row.get('name')=='test-runners']
    if len(owners)!=1 or owners[0].get('user')!='webservices-test-runners':
        raise ValueError('Selected test-runner domain is missing or changed')
    account=pwd.getpwnam('webservices-test-runners')
    if (account.pw_uid!=owners[0].get('uid') or account.pw_dir!='/home/webservices-test-runners'
            or not Path('/run/user/'+str(account.pw_uid)+'/bus').is_socket()):
        raise ValueError('Selected rootless test-runner account is unavailable')
    state_root=Path(owners[0].get('stateRoot',''))
    graph_root=Path(owners[0].get('graphRoot',''))
    if (not state_root.is_absolute() or state_root.name!='state'
            or state_root.parent.name!='test-runners'
            or state_root.parent!=graph_root.parent
            or state_root.parent.is_symlink() or state_root.parent.stat().st_uid!=0
            or state_root.parent.stat().st_mode&0o022
            or state_root.is_symlink() or not state_root.is_dir()
            or state_root.stat().st_uid!=account.pw_uid
            or state_root.stat().st_mode&0o022):
        raise ValueError('Selected rootless test results parent is not owned')
    return account,state_root


def execute_test(operation_id):
    with operation_lock():
        row=read_private(OPERATIONS/(operation_id+'.json'))
        marker=read_private(OPERATIONS/'.active.json')
        if (marker!={'schemaVersion':1,'operationId':operation_id} or row.get('state')!='queued'
                or row.get('kind')!='test' or row.get('suite')!='ts-unit'):
            raise ValueError('Unqueued or unsupported synthetic test refused')
        row['state']='validating';atomic_private(OPERATIONS/(operation_id+'.json'),row)
    claimed=False
    try:
        bound,runner,approver=approved_test('ts-unit')
        guard_test_capacity()
        approver.consume('ts-unit',operation_id)
        claimed=True
        refreshed,runner,_=approved_test('ts-unit',claimed_operation=operation_id)
        if refreshed!=bound or row['release']!=bound['journalSha256']:
            raise ValueError('Selected synthetic test authority changed')
        with operation_lock():
            row['state']='running';atomic_private(OPERATIONS/(operation_id+'.json'),row)
        log=OPERATIONS/(operation_id+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as output:
            account,state_root=selected_test_runner_account(Path(bound['release']))
            uid=str(account.pw_uid)
            results=state_root/('typed-ts-unit-'+operation_id)
            if results.exists() or results.is_symlink():
                raise ValueError('Synthetic test results already exist')
            rc=subprocess.run(['runuser','-u',account.pw_name,'--','env',
                               'HOME='+account.pw_dir,'XDG_RUNTIME_DIR=/run/user/'+uid,
                               'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+uid+'/bus',
                               'TEST_RESULTS_HOST_DIR='+str(results),
                               str(runner),'ts-unit'],stdout=output,stderr=subprocess.STDOUT,
                              cwd='/',timeout=6900).returncode
            output.flush();os.fsync(output.fileno())
        if rc:raise ValueError('Synthetic unit test runner refused')
        after,_,_=approved_test('ts-unit',claimed_operation=operation_id)
        if after!=bound:raise ValueError('Selected native test release changed during run')
        result='synthetic-test-passed'
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        result='failed-after-approval' if claimed else 'failed-before-approval'
    with operation_lock():
        row=read_private(OPERATIONS/(operation_id+'.json'))
        row['state']=result;row['finishedAt']=int(time.time())
        atomic_private(OPERATIONS/(operation_id+'.json'),row)
        if read_private(OPERATIONS/'.active.json')!={'schemaVersion':1,'operationId':operation_id}:
            raise ValueError('Synthetic test operation lease changed')
        (OPERATIONS/'.active.json').unlink()
    return result=='synthetic-test-passed'


def approved_rollback(apply_id,claimed_operation=None):
    if os.geteuid()!=0 or not re.fullmatch('[a-f0-9]{32}',apply_id):
        raise ValueError('Exact approved isolated apply required')
    approver=load(ROLLBACK_APPROVER,'p0_typed_rollback_approver')
    bound=approver.review(apply_id,claimed_operation=claimed_operation)
    data=read_private(INPUTS)
    if (set(data)!={'schemaVersion','scope','machineUuid','release','controlCommit',
                    'controlCheckout','siteSpecSha256','imageInputs','imageInputsSha256'}
            or data['schemaVersion']!=1 or data['scope']!='isolated-synthetic'
            or data['machineUuid']!=bound['machineUuid']
            or data['release']!=bound['applyRelease']):
        raise ValueError('Isolated native installer inputs changed after approved apply')
    binder=load(BINDER,'p0_rollback_trusted_input_binder')
    binder.OUTPUT=INPUTS
    incoming=INCOMING/data['release']
    binder.root_controlled_parents(incoming)
    binder.protected(incoming,directory=True)
    checked=binder.prepare(incoming,Path(data['controlCheckout']),
                           Path(data['imageInputs']),data['release'])
    if not checked['unchanged']or read_private(INPUTS)!=data:
        raise ValueError('Rollback worker cannot create a new installer authority')
    return bound,data,approver


def queue_rollback(apply_id):
    bound,_,_=approved_rollback(apply_id)
    with operation_lock():
        marker=OPERATIONS/'.active.json'
        if marker.exists()or marker.is_symlink():
            raise ValueError('Another typed operation requires settlement/root review')
        operation_id=secrets.token_hex(16)
        receipt=OPERATIONS/(operation_id+'.json')
        if receipt.exists()or receipt.is_symlink():raise ValueError('Typed operation ID collision')
        row={'schemaVersion':1,'operationId':operation_id,'kind':'rollback',
             'applyOperationId':apply_id,'release':bound['currentJournalSha256'],
             'state':'queued','startedAt':int(time.time()),'finishedAt':None}
        atomic_private(receipt,row)
        atomic_private(marker,{'schemaVersion':1,'operationId':operation_id})
        command=['systemd-run','--collect','--unit=p0-typed-rollback-'+operation_id,
                 '--property=Type=oneshot','--property=TimeoutStartSec=3h',
                 '/usr/bin/python3',str(Path(__file__).resolve()),'--execute-rollback',operation_id]
        started=subprocess.run(command,capture_output=True,text=True,timeout=30,cwd='/')
        if started.returncode:
            row['state']='failed-unstarted';row['finishedAt']=int(time.time())
            atomic_private(receipt,row)
            marker.unlink();raise ValueError('Typed rollback worker could not start')
    return {'operation_id':operation_id,'state':'queued','rolledBack':False}


def execute_rollback(operation_id):
    with operation_lock():
        row=read_private(OPERATIONS/(operation_id+'.json'))
        marker=read_private(OPERATIONS/'.active.json')
        if (marker!={'schemaVersion':1,'operationId':operation_id} or row.get('state')!='queued'
                or row.get('kind')!='rollback' or not isinstance(row.get('applyOperationId'),str)):
            raise ValueError('Unqueued or unsupported synthetic rollback refused')
        row['state']='validating';atomic_private(OPERATIONS/(operation_id+'.json'),row)
    claimed=False
    try:
        bound,data,approver=approved_rollback(row['applyOperationId'])
        guard_test_capacity()
        approver.consume(row['applyOperationId'],operation_id)
        claimed=True
        reviewed,again,_=approved_rollback(row['applyOperationId'],claimed_operation=operation_id)
        if reviewed!=bound or again!=data or row['release']!=bound['currentJournalSha256']:
            raise ValueError('Native predecessor or root installer inputs changed')
        previous=Path(bound['previousRelease']);selected=Path(bound['selectedRelease'])
        native_installer=selected/'ops/install-podman-bundle.sh'
        with operation_lock():
            row['state']='running';atomic_private(OPERATIONS/(operation_id+'.json'),row)
        log=OPERATIONS/(operation_id+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as output:
            rc=subprocess.run([str(native_installer),'--bundle',str(previous),
                '--control-checkout',data['controlCheckout'],'--image-inputs',data['imageInputs'],
                '--activate'],stdout=output,stderr=subprocess.STDOUT,cwd='/',timeout=None,
                env=dict(os.environ,WEBSERVICES_ACTIVATION_ROLLBACK='0')).returncode
            output.flush();os.fsync(output.fileno())
        if rc:raise ValueError('Native predecessor reinstallation refused; never restart automatically')
        native=read_private(NATIVE_ROOT/'.install-intent.json')
        now=Path(native.get('release',''))
        expected=read_private(previous/'installation-receipt.json')['inputs']
        if (native.get('schemaVersion')!=1 or native.get('phase')!='active'
                or native.get('inputs')!=expected
                or native.get('previousRelease')!=str(selected)
                or now.parent!=NATIVE_ROOT/'releases' or now==selected or now==previous
                or (NATIVE_ROOT/'current').resolve()!=now):
            raise ValueError('Native rollback release selection could not be proved')
        result='native-predecessor-reinstalled'
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        result='failed-after-approval' if claimed else 'failed-before-approval'
    with operation_lock():
        row=read_private(OPERATIONS/(operation_id+'.json'))
        row['state']=result;row['finishedAt']=int(time.time())
        atomic_private(OPERATIONS/(operation_id+'.json'),row)
        if read_private(OPERATIONS/'.active.json')!={'schemaVersion':1,'operationId':operation_id}:
            raise ValueError('Synthetic rollback lease changed; root review required')
        (OPERATIONS/'.active.json').unlink()
    return result=='native-predecessor-reinstalled'


def execute_apply(plan_id):
    # The transient unit is root-only; it rechecks, then consumes, before any
    # installer code. Errors preserve source data/intent and never restart.
    with operation_lock():
        row=read_private(OPERATIONS/(plan_id+'.json'))
        marker=read_private(OPERATIONS/'.active.json')
        if marker!={'schemaVersion':1,'operationId':plan_id} or row.get('state')!='queued':
            raise ValueError('Unqueued typed operation refused')
        row['state']='validating';atomic_private(OPERATIONS/(plan_id+'.json'),row)
    claimed=False
    worktree=None
    try:
        release,bundle,data,approver=approved_inputs(plan_id)
        approver.consume(plan_id,release)
        claimed=True
        worktree=materialize_approved_worktree(plan_id,release,bundle)
        with operation_lock():
            row['state']='running';row['installWorktree']=str(worktree)
            atomic_private(OPERATIONS/(plan_id+'.json'),row)
        log=OPERATIONS/(plan_id+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as output:
            rc=subprocess.run([str(worktree/'ops/install-podman-bundle.sh'),'--bundle',str(worktree),
                '--control-checkout',data['controlCheckout'],'--image-inputs',data['imageInputs'],
                '--activate'],stdout=output,stderr=subprocess.STDOUT,cwd='/',timeout=None,
                env=dict(os.environ,WEBSERVICES_ACTIVATION_ROLLBACK='0')).returncode
            output.flush();os.fsync(output.fileno())
        if rc:raise ValueError('Native selected installer refused; inspect protected journal')
        current=NATIVE_ROOT/'.install-intent.json'
        native=read_private(current)
        selected=Path(native.get('release',''))
        if (native.get('schemaVersion')!=1 or native.get('phase')!='active'
                or selected.parent!=NATIVE_ROOT/'releases'
                or (NATIVE_ROOT/'current').resolve()!=selected):
            raise ValueError('Native installer did not select an active exact release')
        expected={}
        for name in PIN_FILES:
            pinned=bundle/name
            expected[name]=hashlib.sha256(pinned.read_bytes()).hexdigest() if pinned.is_file() else None
        if native.get('inputs')!=expected:
            raise ValueError('Native selected journal differs from approved final pins')
        selected_release=str(selected)
        selected_journal_sha=hashlib.sha256(current.read_bytes()).hexdigest()
        if load(BROKER,'p0_typed_post_install_broker').tree_sha256(bundle)!=release:
            raise ValueError('Approved sealed release changed after native installation')
        # The selected native release has its own independent copy. Do not
        # remove a failed install's private worktree or any data/intent.
        shutil.rmtree(worktree)
        result='native-installed'
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        result='failed-after-approval' if claimed else 'failed-before-approval'
    with operation_lock():
        row=read_private(OPERATIONS/(plan_id+'.json'))
        row['state']=result;row['finishedAt']=int(time.time())
        if result=='native-installed':
            row.pop('installWorktree',None)
            row['selectedRelease']=selected_release
            row['selectedJournalSha256']=selected_journal_sha
        atomic_private(OPERATIONS/(plan_id+'.json'),row)
        marker=read_private(OPERATIONS/'.active.json')
        if marker!={'schemaVersion':1,'operationId':plan_id}:
            raise ValueError('Typed operation lease changed; root review required')
        (OPERATIONS/'.active.json').unlink()
    return result=='native-installed'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    kind=p.add_mutually_exclusive_group(required=True)
    kind.add_argument('--execute-apply')
    kind.add_argument('--execute-test')
    kind.add_argument('--execute-rollback')
    a=p.parse_args()
    try:
        if a.execute_apply:success=execute_apply(a.execute_apply)
        elif a.execute_test:success=execute_test(a.execute_test)
        else:success=execute_rollback(a.execute_rollback)
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):success=False
    raise SystemExit(0 if success else 1)


if __name__=='__main__':main()
