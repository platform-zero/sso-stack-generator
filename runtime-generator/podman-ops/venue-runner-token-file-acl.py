#!/usr/bin/env python3
"""Post-publisher Forgejo runner token FILE ACL reconciler (installed-only).

The Forgejo publisher replaces token and finally chmods it 0400, which
nullifies an earlier named ACL mask. An installed host controller must run
this *after* each publication and before the CI runner. No inert stage,
selector label or directory ACL grants authority to mutate a real token.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def acl(path):
    result=subprocess.run(['getfacl','-cpn',str(path)],capture_output=True,text=True,timeout=12,cwd='/')
    if result.returncode:raise Refusal('selected token file ACL unavailable')
    return [line.strip().split('#',1)[0].strip() for line in result.stdout.splitlines() if line and not line.startswith('#')]

def token_inode(path,allowed_owners):
    path=Path(path);st=path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or
            st.st_uid not in allowed_owners or st.st_size<12 or st.st_size>4096 or
            stat.S_IMODE(st.st_mode) not in (0o400,0o440)):
        raise Refusal('Forgejo runner token file ownership/mode/size changed')
    return (st.st_dev,st.st_ino,st.st_uid,st.st_size,hashlib.sha256(path.read_bytes()).hexdigest())

def narrow(path,publisher,consumer):
    """Apply exact user ACL, never lift a mask over foreign named entries."""
    before=token_inode(path,publisher)
    previous=acl(path)
    named=[x for x in previous if x.startswith(('user:','group:')) and x.split(':')[1]]
    if (any(x!=f'user:{consumer}:r--' for x in named) or
            'user::r--' not in previous or 'group::---' not in previous or 'other::---' not in previous):
        raise Refusal('token file has foreign access ACL entry')
    expected=['user::r--',f'user:{consumer}:r--','group::---','mask::r--','other::---']
    if previous!=expected:
        # Narrowly replace only the access ACL after checking ALL named
        # principals. Never merely set mask r: that could unmask an
        # inherited, unrelated user or group.
        result=subprocess.run(['setfacl','--set',','.join(expected),str(path)],capture_output=True,timeout=12,cwd='/')
        if result.returncode:raise Refusal('token file ACL mutation refused')
    after=token_inode(path,publisher)
    if after!=before or acl(path)!=expected:raise Refusal('token inode/bytes or exact narrow ACL changed')
    return {'fileDev':after[0],'fileIno':after[1],'publisherUID':after[2],
            'consumerUID':consumer,'tokenSha256':after[4], 'aclExactlyNarrow':True,
            'tokenValueDisclosed':False}

def reconcile(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root-only installed publisher ACL')
    p=Path(ledger);st=p.lstat()
    if p.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600:
        raise Refusal('protected installed-release journal required')
    data=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or data.get('status')!='installed-running' or
            data.get('activationAuthorized') is not True or data.get('venueInstallerVersion',0)<2 or
            data.get('crossDomainAclStatus')!='granted' or data.get('venueReleasePhase')!='installed'):
        raise Refusal('only reviewed, running exact-CAS installed release may reconcile token')
    rows=[x for x in data.get('venueDataBindDirs',[]) if x.get('label')=='forgejo_runner_token']
    if len(rows)!=1 or rows[0]['consumers']!=['rootless-apps','rootless-ci-runner']:
        raise Refusal('actual shared token bind authority differs')
    root=Path(rows[0]['path']);s=root.lstat()
    if (root.is_symlink() or not stat.S_ISDIR(s.st_mode) or
            (s.st_dev,s.st_ino,s.st_uid)!=(rows[0]['dev'],rows[0]['ino'],0) or
            root!=Path(json.loads(Path(selector).read_text())['volumes']['forgejo_runner_token'])):
        raise Refusal('selected token directory inode/selector differs')
    apps=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-apps')
    ci=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-ci-runner')
    # Rootless apps' container root maps to the apps host UID; other
    # container IDs map to only that app's reviewed subordinate range.
    owners={apps['uid'],*range(apps['subuid'],apps['subuid']+65536)}
    file=root/'token'
    result=narrow(file,owners,ci['uid'])
    data['venueRunnerTokenFileAcl']={**result,'status':'granted'}
    stage.write_ledger(p,data)
    return {'status':'granted','aclExactlyNarrow':True,'tokenValueDisclosed':False,
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    try:print(json.dumps(reconcile(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue runner token file ACL refused: '+str(exc)) from exc
if __name__=='__main__':main()
