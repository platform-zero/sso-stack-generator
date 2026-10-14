#!/usr/bin/env python3
"""Independent root-only, exact isolated synthetic suite approval.

Only the reviewed ts-unit suite is supported here. This is an authority receipt,
not a test run; a worker must consume it once after rechecking live selection.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

APPROVALS=Path('/var/lib/platform-zero/maintenance-test-approvals')
MARKER=Path('/etc/platform-zero/isolated-fixture.json')
DMI=Path('/sys/class/dmi/id/product_uuid')
NATIVE=Path('/var/lib/webservices')
SUITES={'ts-unit'}


def strict(path,maximum=16384):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or info.st_size>maximum):raise ValueError('Unmanaged test approval authority')
        body=os.read(fd,maximum+1)
        if len(body)>maximum:raise ValueError('Oversized test approval authority')
    finally:os.close(fd)
    def pairs(rows):
        result={}
        for key,value in rows:
            if key in result:raise ValueError('Duplicate test approval authority')
            result[key]=value
        return result
    value=json.loads(body,object_pairs_hook=pairs)
    if not isinstance(value,dict):raise ValueError('Invalid test approval authority')
    return value,hashlib.sha256(body).hexdigest()


def selected(suite):
    if os.geteuid()!=0 or suite not in SUITES:raise ValueError('Unsupported synthetic suite')
    machine=DMI.read_text().strip().lower()
    if str(uuid.UUID(machine))!=machine or strict(MARKER,maximum=4096)[0]!={
            'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':machine}:
        raise ValueError('Actual synthetic machine proof required')
    journal,digest=strict(NATIVE/'.install-intent.json')
    if journal.get('schemaVersion')!=1 or journal.get('phase')!='active':
        raise ValueError('No active selected native release')
    release=Path(journal.get('release',''))
    if (release.parent!=NATIVE/'releases' or not release.is_dir()or release.is_symlink()
            or release.stat().st_uid!=0 or (NATIVE/'current').resolve()!=release):
        raise ValueError('Selected test release changed')
    script=release/'build/stack.containers/test-runner/run-tests.sh'
    info=script.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('Selected test runner is untrusted')
    return {'machineUuid':machine,'journalSha256':digest,'release':str(release),
            'runnerSha256':hashlib.sha256(script.read_bytes()).hexdigest()}


def protected_dir(path,create=False):
    if create and not path.exists()and not path.is_symlink():path.mkdir(mode=0o700,parents=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode)or path.is_symlink()or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('Unmanaged test approval directory')


def approve(suite,now=None):
    if suite not in SUITES:raise ValueError('Unsupported synthetic suite')
    bound=selected(suite)
    current=int(time.time()if now is None else now)
    protected_dir(APPROVALS,create=True)
    data={'schemaVersion':1,'suite':suite,'scope':'isolated-synthetic',**bound,
          'approvedAt':current,'expiresAt':current+600,'singleUse':True}
    dest=APPROVALS/(suite+'.json')
    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as out:json.dump(data,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
    sync=os.open(APPROVALS,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(sync)
    finally:os.close(sync)
    return {'suite':suite,'expiresAt':current+600,'applied':False}


def review(suite,now=None,claimed_operation=None):
    if suite not in SUITES or os.geteuid()!=0:raise ValueError('Unsupported root synthetic suite')
    protected_dir(APPROVALS)
    path=APPROVALS/(suite+'.json')
    if claimed_operation is not None:
        if not isinstance(claimed_operation,str)or not re.fullmatch('[a-f0-9]{32}',claimed_operation):
            raise ValueError('Invalid claimed synthetic test operation')
        protected_dir(APPROVALS/'consumed')
        path=APPROVALS/'consumed'/(claimed_operation+'.json')
    value,_=strict(path,maximum=4096)
    current=int(time.time()if now is None else now)
    if (set(value)!={'schemaVersion','suite','scope','machineUuid','journalSha256',
                     'release','runnerSha256','approvedAt','expiresAt','singleUse'}
            or type(value['schemaVersion'])is not int or value['schemaVersion']!=1
            or value['suite']!=suite or value['scope']!='isolated-synthetic'
            or value['singleUse'] is not True
            or type(value['approvedAt'])is not int or type(value['expiresAt'])is not int
            or not value['approvedAt']<=current<=value['expiresAt']
            or value['expiresAt']!=value['approvedAt']+600):
        raise ValueError('Stale or changed test approval')
    for key,item in selected(suite).items():
        if value[key]!=item:raise ValueError('Synthetic test selection changed after approval')
    return {'suite':suite,'release':value['release'],'machineUuid':value['machineUuid'],
            'journalSha256':value['journalSha256']}


def consume(suite,operation_id,now=None):
    if not isinstance(operation_id,str)or not re.fullmatch('[a-f0-9]{32}',operation_id):
        raise ValueError('Exact synthetic test operation required')
    protected_dir(APPROVALS)
    fd=os.open(APPROVALS/'.claim.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
            raise ValueError('Unsafe synthetic test approval claim')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        bound=review(suite,now)
        target_dir=APPROVALS/'consumed';protected_dir(target_dir,create=True)
        target=target_dir/(operation_id+'.json')
        if target.exists()or target.is_symlink():raise ValueError('Synthetic test approval already claimed')
        os.replace(APPROVALS/(suite+'.json'),target)
        for directory in (APPROVALS,target_dir):
            sync=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(sync)
            finally:os.close(sync)
        return bound
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite',required=True)
    args=parser.parse_args()
    try:print(json.dumps(approve(args.suite)))
    except (ValueError,OSError,TypeError,KeyError):parser.exit(1,'independent synthetic test approval refused\n')

if __name__=='__main__':main()
