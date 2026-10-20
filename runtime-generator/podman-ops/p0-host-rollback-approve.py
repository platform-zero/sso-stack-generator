#!/usr/bin/env python3
"""Root-only narrow synthetic same-composition native predecessor review.

This only issues/validates one-use authority. It does not restart, switch,
stop or restore any stack. Production and mismatched pinned releases fail shut.
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
import time

ROOT=Path('/var/lib/webservices')
OPERATIONS=Path('/var/lib/platform-zero/maintenance-operations')
APPROVALS=Path('/var/lib/platform-zero/maintenance-rollback-approvals')
TEST_APPROVER=Path('/usr/local/sbin/p0-host-test-approve')
INSTALLED_CONTROL={
    'p0-host-test-approve.py':Path('/usr/local/sbin/p0-host-test-approve'),
    'p0-host-rollback-approve.py':Path('/usr/local/sbin/p0-host-rollback-approve'),
    'p0-host-operations.py':Path('/usr/local/libexec/p0-host-operations.py'),
    'p0-host-broker.py':Path('/usr/local/libexec/p0-host-broker'),
}
PINNED=('bundle.json','stack.ir.json','source-provenance.json','podman-domains.json',
        'site/agent-vm.json','site/agent-vm.provenance.json','site/manifest.json',
        'site/components.lock.json','site/global.settings/registry-image-ids.json')
SAME_COMPOSITION=('stack.ir.json','podman-domains.json','site/agent-vm.json',
                  'site/agent-vm.provenance.json','site/manifest.json',
                  'site/components.lock.json','site/global.settings/registry-image-ids.json',
                  'site/global.settings/webservices.sops.json')


def trust():
    info=TEST_APPROVER.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('Unmanaged synthetic predecessor authority')
    loader=SourceFileLoader('p0_rollback_synthetic_machine',str(TEST_APPROVER))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def file_sha(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022 or info.st_nlink!=1:
        raise ValueError('Changed immutable rollback source file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review_selection(apply_id):
    if os.geteuid()!=0 or not isinstance(apply_id,str)or not re.fullmatch('[a-f0-9]{32}',apply_id):
        raise ValueError('Exact root isolated apply operation required')
    marker=trust();selected=marker.selected('ts-unit')
    marker.protected_dir(OPERATIONS)
    apply,_=marker.strict(OPERATIONS/(apply_id+'.json'),maximum=4096)
    if (apply.get('schemaVersion')!=1 or apply.get('kind')!='apply'
            or apply.get('operationId')!=apply_id or apply.get('state')!='native-installed'
            or not isinstance(apply.get('release'),str)or not re.fullmatch('[a-f0-9]{64}',apply['release'])
            or not isinstance(apply.get('selectedJournalSha256'),str)
            or not re.fullmatch('[a-f0-9]{64}',apply['selectedJournalSha256'])):
        raise ValueError('No successful independently approved apply operation')
    current,journal_sha=marker.strict(ROOT/'.install-intent.json')
    current_release=Path(current.get('release',''))
    prior=Path(current.get('previousRelease',''))
    if (current.get('schemaVersion')!=1 or current.get('phase')!='active'
            or selected['journalSha256']!=journal_sha
            or apply['selectedJournalSha256']!=journal_sha
            or apply.get('selectedRelease')!=str(current_release)
            or selected['release']!=str(current_release)
            or current_release.parent!=ROOT/'releases' or prior.parent!=ROOT/'releases'
            or prior==current_release or not prior.is_dir()or prior.is_symlink()
            or prior.stat().st_uid!=0 or prior.stat().st_mode&0o022):
        raise ValueError('Selected active release has no pinned predecessor')
    old,old_sha=marker.strict(prior/'installation-receipt.json')
    current_receipt,_=marker.strict(current_release/'installation-receipt.json')
    if (old.get('schemaVersion')!=1 or old.get('phase')!='active'
            or old.get('release')!=str(prior)or set(old.get('inputs',{}))!=set(PINNED)
            or set(current.get('inputs',{}))!=set(PINNED)
            or current_receipt!=current):
        raise ValueError('Predecessor or current receipt is untrusted')
    for release,receipt in ((prior,old),(current_release,current)):
        for name in PINNED:
            path=release/name
            expected=receipt['inputs'][name]
            actual=file_sha(path)if path.exists()or path.is_symlink()else None
            if actual!=expected:raise ValueError('Native selected release pins changed')
    for name in SAME_COMPOSITION:
        if file_sha(prior/name)!=file_sha(current_release/name):
            raise ValueError('Changed service/site/secret pins require separate recovery review')
    previous_source=json.loads((prior/'source-provenance.json').read_text())
    current_source=json.loads((current_release/'source-provenance.json').read_text())
    if (not isinstance(previous_source.get('siteCommit'),str)
            or not re.fullmatch('[a-f0-9]{40}',previous_source['siteCommit'])
            or previous_source['siteCommit']!=current_source.get('siteCommit')
            or previous_source.get('siteDirty') is not False
            or current_source.get('siteDirty') is not False
            or previous_source.get('generatorDirty') is not False
            or current_source.get('generatorDirty') is not False):
        raise ValueError('Only clean exact-site pinned predecessor is eligible')
    service_ir=json.loads((current_release/'stack.ir.json').read_text())
    manifest=json.loads((current_release/'site/manifest.json').read_text())
    if len(service_ir.get('services',{}))!=94 or len(manifest.get('modules',[]))!=58:
        raise ValueError('Only same 58/94 native composition rollback reviewed')
    # A stack-source upgrade is not a controller upgrade by implication. Do
    # not let a stale installed broker/worker silently authorize rollback of
    # a newer selected source; it must be adopted via the reviewed installer.
    for source,target in INSTALLED_CONTROL.items():
        if file_sha(current_release/'ops'/source)!=file_sha(target):
            raise ValueError('Installed typed control is not the selected release')
    installer=current_release/'ops/install-podman-bundle.sh'
    installer_hash=file_sha(installer)
    if not(installer.stat().st_mode&stat.S_IXUSR):raise ValueError('Native rollback installer is not executable')
    return {'machineUuid':selected['machineUuid'],'applyOperationId':apply_id,
            'currentJournalSha256':journal_sha,'selectedRelease':str(current_release),
            'previousRelease':str(prior),'previousReceiptSha256':old_sha,
            'installerSha256':installer_hash,'applyRelease':apply['release']}


def approve(apply_id,reviewed,now=None):
    if not reviewed:raise ValueError('Explicit synthetic data compatibility review required')
    bound=review_selection(apply_id)
    marker=trust();marker.protected_dir(APPROVALS,create=True)
    current=int(time.time()if now is None else now)
    row={'schemaVersion':1,'scope':'isolated-synthetic','reviewedDataState':True,
         'approvedAt':current,'expiresAt':current+600,'singleUse':True,**bound}
    dest=APPROVALS/(apply_id+'.json')
    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as out:json.dump(row,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
    sync=os.open(APPROVALS,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(sync)
    finally:os.close(sync)
    return {'applyOperationId':apply_id,'expiresAt':row['expiresAt'],'rolledBack':False}


def review(apply_id,now=None,claimed_operation=None):
    marker=trust();marker.protected_dir(APPROVALS)
    path=APPROVALS/(apply_id+'.json')
    if claimed_operation is not None:
        if not isinstance(claimed_operation,str)or not re.fullmatch('[a-f0-9]{32}',claimed_operation):
            raise ValueError('Invalid synthetic rollback claim')
        marker.protected_dir(APPROVALS/'consumed')
        path=APPROVALS/'consumed'/(claimed_operation+'.json')
    value,_=marker.strict(path,maximum=4096)
    current=int(time.time()if now is None else now)
    bound=review_selection(apply_id)
    expected={'schemaVersion':1,'scope':'isolated-synthetic','reviewedDataState':True,
              'approvedAt':value.get('approvedAt'),'expiresAt':value.get('expiresAt'),
              'singleUse':True,**bound}
    if (value!=expected or type(value.get('approvedAt'))is not int
            or type(value.get('expiresAt'))is not int
            or value['expiresAt']!=value['approvedAt']+600
            or not value['approvedAt']<=current<=value['expiresAt']):
        raise ValueError('Changed or expired native predecessor approval')
    return bound


def consume(apply_id,operation_id,now=None):
    if not isinstance(operation_id,str)or not re.fullmatch('[a-f0-9]{32}',operation_id):
        raise ValueError('Exact rollback worker claim required')
    marker=trust();marker.protected_dir(APPROVALS)
    fd=os.open(APPROVALS/'.claim.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
            raise ValueError('Unmanaged rollback claim lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        bound=review(apply_id,now)
        destdir=APPROVALS/'consumed';marker.protected_dir(destdir,create=True)
        dest=destdir/(operation_id+'.json')
        if dest.exists()or dest.is_symlink():raise ValueError('Rollback claim reused')
        os.replace(APPROVALS/(apply_id+'.json'),dest)
        for directory in (APPROVALS,destdir):
            sync=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(sync)
            finally:os.close(sync)
        return bound
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply-operation-id',required=True)
    parser.add_argument('--reviewed-data-state',action='store_true')
    args=parser.parse_args()
    try:print(json.dumps(approve(args.apply_operation_id,args.reviewed_data_state)))
    except (ValueError,OSError,TypeError,KeyError,json.JSONDecodeError):
        parser.exit(1,'synthetic native rollback approval refused\n')

if __name__=='__main__':main()
