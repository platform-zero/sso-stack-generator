#!/usr/bin/env python3
"""Independent root-only approval of an exact typed host-broker proposal.

Approval is not application. No lane socket can create this receipt. Production
requires three separate root-reviewed, release-bound recovery/announcement/undo
receipts; an isolated approval binds the actual local DMI UUID instead.
"""
import argparse,fcntl,hashlib,json,os,re,stat,time,uuid
from pathlib import Path

PLANS=Path(os.environ.get('P0_PLANS','/var/lib/platform-zero/maintenance-plans'))
APPROVALS=Path(os.environ.get('P0_APPROVALS','/var/lib/platform-zero/maintenance-approvals'))
DMI=Path(os.environ.get('P0_MACHINE_UUID_PATH','/sys/class/dmi/id/product_uuid'))
ISOLATED_MARKER=Path(os.environ.get('P0_ISOLATED_MARKER','/etc/platform-zero/isolated-fixture.json'))


def strict(path: Path, maximum=65536,with_bytes=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077
                or info.st_nlink!=1 or info.st_size>maximum):
            raise ValueError('Unmanaged approval authority file')
        body=os.read(fd,maximum+1)
        if len(body)>maximum:raise ValueError('Oversized approval authority file')
    finally:os.close(fd)
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise ValueError('Duplicate approval authority key')
            value[key]=item
        return value
    value=json.loads(body,object_pairs_hook=pairs)
    return (value,body)if with_bytes else value


def protected_directory(path: Path,create=False):
    if create and not path.exists()and not path.is_symlink():path.mkdir(mode=0o700,parents=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode)or path.is_symlink()or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('Unsafe root approval directory')


def approve(plan_id,release,context,machine_uuid,evidence=None,now=None):
    if os.geteuid()!=0:raise ValueError('Independent root approval required')
    if not re.fullmatch(r'[a-f0-9]{32}',plan_id)or not re.fullmatch(r'[a-f0-9]{64}',release):
        raise ValueError('Exact plan and release required')
    if str(uuid.UUID(machine_uuid))!=machine_uuid or DMI.read_text().strip().lower()!=machine_uuid:
        raise ValueError('Current machine identity mismatch')
    if context not in ('isolated','production'):raise ValueError('Unknown approval context')
    if context=='isolated':
        marker=strict(ISOLATED_MARKER,maximum=4096)
        if marker!={'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':machine_uuid}:
            raise ValueError('Isolated approval requires exact root-owned synthetic machine marker')
    protected_directory(PLANS)
    plan=strict(PLANS/(plan_id+'.json'),maximum=4096)
    current=int(time.time()if now is None else now)
    if (set(plan)!={'schemaVersion','planId','release','createdAt','state'}
            or type(plan['schemaVersion'])is not int or plan['schemaVersion']!=1
            or plan['planId']!=plan_id or plan['release']!=release
            or plan['state']!='awaiting-independent-root-approval'
            or type(plan['createdAt'])is not int or not 0<=current-plan['createdAt']<=900):
        raise ValueError('Stale or changed maintenance proposal')
    evidence=evidence or {}
    if context=='production' and set(evidence)!={'recovery','announcement','rollback'}:
        raise ValueError('Production recovery, announcement and undo proof required')
    if context=='isolated' and evidence:
        raise ValueError('Synthetic approval must not claim production proof')
    evidence_hashes={}
    if len({path.resolve(strict=True)for path in evidence.values()})!=len(evidence):
        raise ValueError('Production proof purposes require distinct receipts')
    for name,path in evidence.items():
        receipt,body=strict(path,with_bytes=True)
        if (not isinstance(receipt,dict)or type(receipt.get('schemaVersion'))is not int
                or receipt.get('schemaVersion')!=1 or receipt.get('planId')!=plan_id or receipt.get('release')!=release
                or receipt.get('scope')!='production' or receipt.get('purpose')!=name
                or receipt.get('verified')is not True):
            raise ValueError('Production receipt is not exact/reviewed')
        evidence_hashes[name]=hashlib.sha256(body).hexdigest()
    protected_directory(APPROVALS,create=True)
    consumed=APPROVALS/'consumed'
    if consumed.exists() or consumed.is_symlink():
        protected_directory(consumed)
        if (consumed/(plan_id+'.json')).exists() or (consumed/(plan_id+'.json')).is_symlink():
            raise ValueError('Maintenance approval was already consumed')
    output=APPROVALS/(plan_id+'.json')
    data={'schemaVersion':1,'planId':plan_id,'release':release,'context':context,
          'machineUuid':machine_uuid,'approvedAt':current,'expiresAt':current+600,
          'evidenceSha256':evidence_hashes,
          'evidencePaths':{name:str(path.resolve(strict=True))for name,path in evidence.items()},
          'singleUse':True}
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as target:
        json.dump(data,target,sort_keys=True);target.write('\n');target.flush();os.fsync(target.fileno())
    directory=os.open(APPROVALS,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
    return {'planId':plan_id,'release':release,'context':context,'expiresAt':current+600,'applied':False}


def review(plan_id,release,now=None):
    """Read an independent root receipt without granting application authority."""
    if os.geteuid()!=0 or not re.fullmatch(r'[a-f0-9]{32}',plan_id) or not re.fullmatch(r'[a-f0-9]{64}',release):
        raise ValueError('Exact root approval identity required')
    protected_directory(PLANS)
    protected_directory(APPROVALS)
    current=int(time.time()if now is None else now)
    plan=strict(PLANS/(plan_id+'.json'),maximum=4096)
    receipt=strict(APPROVALS/(plan_id+'.json'),maximum=8192)
    if (set(plan)!={'schemaVersion','planId','release','createdAt','state'}
            or type(plan.get('schemaVersion'))is not int or plan.get('schemaVersion')!=1
            or plan.get('planId')!=plan_id
            or plan.get('release')!=release or plan.get('state')!='awaiting-independent-root-approval'
            or type(plan.get('createdAt'))is not int or not 0<=current-plan['createdAt']<=900):
        raise ValueError('Stale or changed maintenance proposal')
    if (not isinstance(receipt,dict)
            or set(receipt)!={'schemaVersion','planId','release','context','machineUuid',
                              'approvedAt','expiresAt','evidenceSha256','evidencePaths','singleUse'}
            or type(receipt.get('schemaVersion'))is not int or receipt.get('schemaVersion')!=1
            or receipt.get('planId')!=plan_id
            or receipt.get('release')!=release or receipt.get('singleUse') is not True
            or type(receipt.get('approvedAt'))is not int or type(receipt.get('expiresAt'))is not int
            or not plan['createdAt']<=receipt['approvedAt']<=current<=receipt['expiresAt']
            or receipt['expiresAt']!=receipt['approvedAt']+600):
        raise ValueError('Stale or unbound root approval')
    machine=receipt['machineUuid']
    if not isinstance(machine,str) or str(uuid.UUID(machine))!=machine or DMI.read_text().strip().lower()!=machine:
        raise ValueError('Approval machine identity changed')
    context=receipt['context'];paths=receipt['evidencePaths'];hashes=receipt['evidenceSha256']
    if not isinstance(paths,dict)or not isinstance(hashes,dict):
        raise ValueError('Invalid approval evidence authority')
    if context=='isolated':
        if paths or hashes or strict(ISOLATED_MARKER,maximum=4096)!={
                'schemaVersion':1,'scope':'isolated-synthetic','machineUuid':machine}:
            raise ValueError('Synthetic approval identity or scope changed')
    elif context=='production':
        purposes={'recovery','announcement','rollback'}
        if set(paths)!=purposes or set(hashes)!=purposes:
            raise ValueError('Production proof purposes missing')
        checked=set()
        for purpose in sorted(purposes):
            if not isinstance(paths[purpose],str):raise ValueError('Invalid production evidence path')
            path=Path(paths[purpose])
            if not path.is_absolute() or str(path.resolve(strict=True))!=paths[purpose] or path in checked:
                raise ValueError('Linked or reused production evidence')
            checked.add(path)
            value,body=strict(path,with_bytes=True)
            if (not isinstance(value,dict)or type(value.get('schemaVersion'))is not int
                    or value.get('schemaVersion')!=1 or value.get('planId')!=plan_id or value.get('release')!=release
                    or value.get('scope')!='production' or value.get('purpose')!=purpose
                    or value.get('verified') is not True
                    or hashlib.sha256(body).hexdigest()!=hashes[purpose]):
                raise ValueError('Production evidence changed since independent review')
    else:
        raise ValueError('Unknown approval context')
    return {'planId':plan_id,'release':release,'context':context,'machineUuid':machine}


def consume(plan_id,release,now=None):
    """Single-use claim, never an apply: caller must independently verify inputs."""
    if os.geteuid()!=0:raise ValueError('Root operation required')
    protected_directory(APPROVALS)
    lock=APPROVALS/'.consume.lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
            raise ValueError('Unsafe root approval claim lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        bound=review(plan_id,release,now)
        claimed=APPROVALS/'consumed'
        protected_directory(claimed,create=True)
        target=claimed/(plan_id+'.json')
        if target.exists() or target.is_symlink():raise ValueError('Root approval was already consumed')
        os.replace(APPROVALS/(plan_id+'.json'),target)
        for directory in (APPROVALS,claimed):
            sync=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(sync)
            finally:os.close(sync)
        return bound
    finally:
        os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-id',required=True)
    parser.add_argument('--release',required=True)
    parser.add_argument('--context',choices=('isolated','production'),required=True)
    parser.add_argument('--machine-uuid',required=True)
    for name in ('recovery','announcement','rollback'):
        parser.add_argument('--'+name+'-receipt',type=Path)
    args=parser.parse_args()
    evidence={name:value for name in ('recovery','announcement','rollback')if(value:=getattr(args,name+'_receipt'))is not None}
    try:print(json.dumps(approve(args.plan_id,args.release,args.context,args.machine_uuid,evidence)))
    except (ValueError,OSError,KeyError,TypeError):parser.exit(1,'independent maintenance approval refused\n')

if __name__=='__main__':main()
