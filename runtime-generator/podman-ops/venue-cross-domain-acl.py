#!/usr/bin/env python3
"""Exact temporary ACLs for the two cross-domain fresh test-only binds.

Does not grant old data or issue the venue volume-init readiness marker.
Requires all 61 actual empty data binds; snapshot/restore original inherited
ACLs byte-exactly. This is NOT the populated installation/reset lifecycle.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
stage=load('venue_owned_stage','venue-owned-stage.py')
binds=load('venue_bind_dirs','venue-bind-dirs.py')
Refusal=stage.Refusal

def call(command,*,input=None):
    r=subprocess.run(command,input=input,capture_output=True,text=True,timeout=15,cwd='/')
    if r.returncode:raise Refusal('selected ACL operation failed')
    return r.stdout

def acl(path):return call(['getfacl','-p',str(path)])

def policy(plan,paths):
    accounts={a['name'].removeprefix(plan['prefix']+'-'):a['uid'] for a in plan['accounts']}
    root=Path(plan['roots']['rootful-volume'])
    ca=root/'caddy_ca';token=root/'forgejo_runner_token'
    if (paths.get(str(ca),{}).get('consumers')!=['rootful','rootless-apps','rootless-platform','rootless-vaultwarden'] or
            paths.get(str(token),{}).get('consumers')!=['rootless-apps','rootless-ci-runner']):
        raise Refusal('cross-domain consumers differ from reviewed Caddy CA and Forgejo token')
    if set(accounts)!=set(('platform','apps','homeassistant','vaultwarden','ci-runner','workloads','test-runners')):
        raise Refusal('seven selected accounts missing')
    parent={accounts[d]:'--x' for d in ('platform','apps','vaultwarden','ci-runner','test-runners')}
    ca_users={accounts[d]:'r-x' for d in ('platform','apps','vaultwarden','test-runners')}
    token_users={accounts['apps']:'rwx',accounts['ci-runner']:'r-x'}
    return [(root,parent),(ca,ca_users),(token,token_users)]

def permission_rows(path):
    rows=[]
    for line in call(['getfacl','-cn',str(path)]).splitlines():
        line=line.split('\t',1)[0]
        if line.startswith(('user:','group:','mask:','other:','default:')):rows.append(line)
    return rows

def granted_rows(users):
    return ['user::rwx',*(f'user:{uid}:{mode}' for uid,mode in sorted(users.items())),
            'group::---','mask::'+('rwx' if 'rwx' in users.values() else 'r-x' if 'r-x' in users.values() else '--x'),
            'other::---']

def context(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root required for isolated cross-domain ACLs')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('protected data-bind stage ledger required')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if data.get('plan')!=plan or data.get('status')!='data-binds-inert' or len(data.get('venueDataBindDirs',[]))!=61:
        raise Refusal('61 fresh, inert, selected data binds required')
    paths=binds.inventory(bundle,selector,plan)
    if Path(plan['roots']['rootful-state'],'volume-ready-r1.txt').exists():
        raise Refusal('installed volume readiness marker must remain absent')
    rules=policy(plan,paths)
    root=str(rules[0][0])
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:lines=(process/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        if any((mp:=line.split()[4].replace('\\040',' '))==root or mp.startswith(root+'/')
               for line in lines if len(line.split())>=5):
            raise Refusal('selected rootful volume parent or child is mounted in a process namespace')
    record={row['path']:row for row in data['venueDataBindDirs']}
    parent=rules[0][0]
    expected={Path(row['path']).name for row in data['venueDataBindDirs'] if row['parent']==str(parent)}
    if len(expected)!=13 or {child.name for child in parent.iterdir()}!=expected:
        raise Refusal('unreviewed content under selected rootful volume parent')
    for child in parent.iterdir():
        row=record.get(str(child));info=child.lstat()
        if (not row or child.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid)!=(row['dev'],row['ino'],0)):
            raise Refusal('selected rootful child inode changed')
    for p,_ in rules:
        st=p.lstat()
        if p.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid!=0:
            raise Refusal('cross-domain ACL target is not fresh root-owned directory')
        if str(p)!=plan['roots']['rootful-volume']:
            row=record.get(str(p))
            if not row or (st.st_dev,st.st_ino)!=(row['dev'],row['ino']):
                raise Refusal('cross-domain data inode changed')
        else:
            row=data['pathIdentities'].get(str(p))
            if not row or (st.st_dev,st.st_ino)!=(row['dev'],row['ino']):
                raise Refusal('rootful volume parent inode changed')
    return path,data,rules

def grant(bundle,selector,ledger):
    path,data,rules=context(bundle,selector,ledger)
    if data.get('crossDomainAclStatus'):raise Refusal('cross-domain ACL already journaled')
    if any(stat.S_IMODE(p.lstat().st_mode)!=0o700 or (p!=rules[0][0] and any(p.iterdir())) for p,_ in rules):
        raise Refusal('only three empty 0700 test-owned paths may receive initial ACL')
    snapshots={str(p):acl(p) for p,_ in rules}
    data['crossDomainAclOriginal']=snapshots;data['crossDomainAclStatus']='granting';stage.write_ledger(path,data)
    for p,users in rules:
        call(['setfacl','-b',str(p)])
        changes=','.join('u:'+str(uid)+':'+mode for uid,mode in sorted(users.items()))
        call(['setfacl','-m',changes,str(p)])
        if permission_rows(p)!=granted_rows(users):raise Refusal('granted ACL differs from exact reviewed matrix')
    data['crossDomainAclStatus']='granted';stage.write_ledger(path,data)
    return {'status':'granted','crossDomainPaths':3,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def restore(bundle,selector,ledger):
    path,data,rules=context(bundle,selector,ledger)
    if data.get('crossDomainAclStatus') not in ('granting','granted','restoring'):
        raise Refusal('no exact selected ACL journal to restore')
    snapshots=data.get('crossDomainAclOriginal',{})
    if set(snapshots)!={str(p) for p,_ in rules}:raise Refusal('incomplete original ACL snapshots')
    for p,users in rules:
        if p!=rules[0][0] and any(p.iterdir()):
            raise Refusal('cross-domain data now populated; empty-stage restore refused')
        current=acl(p)
        if current!=snapshots[str(p)] and permission_rows(p)!=granted_rows(users):
            # A crash between -b and -m can leave base-only ACL; permit only
            # that exact transient shape when the journal says granting.
            if data['crossDomainAclStatus']!='granting' or permission_rows(p)!=['user::rwx','group::---','other::---']:
                raise Refusal('cross-domain ACL changed outside selected lifecycle')
    data['crossDomainAclStatus']='restoring';stage.write_ledger(path,data)
    for p,_ in reversed(rules):
        call(['setfacl','--restore=-'],input=snapshots[str(p)])
        if acl(p)!=snapshots[str(p)] or stat.S_IMODE(p.stat().st_mode)!=0o700:
            raise Refusal('original inherited ACL was not restored exactly')
    data['crossDomainAclStatus']='retired';stage.write_ledger(path,data)
    return {'status':'retired','crossDomainPaths':3,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('bundle','selector','ledger'):p.add_argument('--'+k,required=True)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--grant-empty',action='store_true');group.add_argument('--restore-empty',action='store_true')
    a=p.parse_args()
    try:print(json.dumps((grant if a.grant_empty else restore)(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue cross-domain ACL lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
