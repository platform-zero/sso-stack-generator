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
from pathlib import Path
import re
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
    try:
        release,bundle,data,approver=approved_inputs(plan_id)
        approver.consume(plan_id,release)
        claimed=True
        with operation_lock():
            row['state']='running';atomic_private(OPERATIONS/(plan_id+'.json'),row)
        log=OPERATIONS/(plan_id+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as output:
            rc=subprocess.run([str(bundle/'ops/install-podman-bundle.sh'),'--bundle',str(bundle),
                '--control-checkout',data['controlCheckout'],'--image-inputs',data['imageInputs'],
                '--activate'],stdout=output,stderr=subprocess.STDOUT,cwd='/',timeout=None).returncode
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
        result='native-installed'
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        result='failed-after-approval' if claimed else 'failed-before-approval'
    with operation_lock():
        row=read_private(OPERATIONS/(plan_id+'.json'))
        row['state']=result;row['finishedAt']=int(time.time())
        atomic_private(OPERATIONS/(plan_id+'.json'),row)
        marker=read_private(OPERATIONS/'.active.json')
        if marker!={'schemaVersion':1,'operationId':plan_id}:
            raise ValueError('Typed operation lease changed; root review required')
        (OPERATIONS/'.active.json').unlink()
    return result=='native-installed'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute-apply',required=True)
    a=p.parse_args()
    try:success=execute_apply(a.execute_apply)
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):success=False
    raise SystemExit(0 if success else 1)


if __name__=='__main__':main()
