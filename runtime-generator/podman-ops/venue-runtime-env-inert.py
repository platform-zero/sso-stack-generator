#!/usr/bin/env python3
"""Materialize exactly 75 sealed per-service env files, inactive only.

Keep plaintext in the root-owned rootful runtime or one selected rootless
UID's private /run/user subtree. No broad /run/webservices or shared user
store, no unit start/marker, and no completed-installed-data reset authority.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_release',HERE/'venue-release-inert.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
stage=release.stage;Refusal=release.Refusal
PATTERN=re.compile(r'\$\{([A-Z_][A-Z0-9_]*)(?:(:-|:\?)([^}]*))?\}')
# Forgejo uses lowercase sections; Elastic/OpenSearch intentionally pass
# dotted/hyphenated process-environment settings (not shell assignments).
NAME=re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*\Z')

def sha(value):return hashlib.sha256(value).hexdigest()
def identity(path):
    s=Path(path).lstat()
    if Path(path).is_symlink() or not stat.S_ISDIR(s.st_mode):raise Refusal('selected runtime directory class differs')
    return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}

def env_values(path):
    source=Path(path);s=source.lstat()
    if source.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:
        raise Refusal('aggregate rendered environment is not root0600')
    values={}
    for line in source.read_text().splitlines():
        if not line or line.startswith('#'):continue
        key,sep,val=line.partition('=')
        if not sep or not NAME.fullmatch(key) or key in values:raise Refusal('ambiguous aggregate environment variable')
        values[key]=val.replace('$$','$')
    return values

def expand(value,values):
    def replacement(match):
        key,op,fallback=match.group(1),match.group(2),match.group(3) or ''
        actual=values.get(key,'')
        if op==':-':return actual or fallback
        if op==':?':
            if not actual:raise Refusal('required sealed runtime environment key absent: '+key)
            return actual
        return actual
    for _ in range(8):
        updated=PATTERN.sub(replacement,value)
        if updated==value:break
        value=updated
    value=value.replace('$$','$')
    if PATTERN.search(value) or '\n' in value or '\r' in value or '\x00' in value:
        raise Refusal('unresolved or multiline selected runtime environment value')
    return value

def source(bundle,selector,ledger):
    b,p,data,plan,state=release.context(bundle,selector,ledger)
    if (data.get('status')!='managers-ready' or
            data.get('managerStarted')!=[a['name'] for a in plan['accounts']] or data.get('managerStopped') or
            data.get('venueReleasePhase')!='inert-ready' or data.get('venueDomainRuntimePhase')!='inert-ready' or
            data.get('activationAuthorized') is not False):
        raise Refusal('exact seven-manager, two-release pre-unit venue required')
    aggregate=Path(data.get('venueReleaseRoot') or '')
    if (aggregate!=Path(data.get('releaseRoot') or '') or
            data.get('venueReleaseManifest')!=release.inventory(aggregate)):
        raise Refusal('rootful rendered source CAS changed')
    values=env_values(aggregate/'runtime/stack.env')
    templates={x.name.removesuffix('.env.template'):x for x in (aggregate/'runtime-env').glob('*.env.template')}
    if len(templates)!=75 or len(set(templates))!=75:raise Refusal('75 distinct selected env templates required')
    owners={}
    for q in (b/'quadlet').glob('*/*.container'):
        lines=[x.split('=',1)[1] for x in q.read_text().splitlines() if x.startswith('EnvironmentFile=')]
        if not lines:continue
        if len(lines)!=1:raise Refusal('multi-env selected unit')
        if not q.name.startswith(plan['prefix']+'-'):raise Refusal('selected unit prefix differs')
        name=q.name.removesuffix('.container').removeprefix(plan['prefix']+'-');line=lines[0]
        if name in owners or name not in templates:raise Refusal('environment service source mismatched')
        if q.parent.name=='rootful':
            if line!='/run/'+plan['prefix']+'/'+name+'.env':raise Refusal('rootful unit env path differs')
            owners[name]={'uid':0,'directory':plan['roots']['rootful-runtime']}
        else:
            domain=q.parent.name.removeprefix('rootless-');a=next((a for a in plan['accounts'] if a['name']==plan['prefix']+'-'+domain),None)
            if a is None or line!='%t/'+plan['prefix']+'/'+name+'.env':
                raise Refusal('rootless unit/env identity differs')
            owners[name]={'uid':a['uid'],'directory':'/run/user/'+str(a['uid'])+'/'+plan['prefix']}
    if set(owners)!=set(templates):raise Refusal('env templates differ from exactly 75 Quadlet consumers')
    entries={}
    for name,template in sorted(templates.items()):
        lines=[];seen=set()
        for raw in template.read_text().splitlines():
            if not raw or raw.startswith('#'):continue
            key,sep,value=raw.partition('=')
            if not sep or not NAME.fullmatch(key) or key in seen:raise Refusal('unsafe duplicate/invalid env template key')
            seen.add(key);lines.append(key+'='+expand(value,values))
        payload=('\n'.join(lines)+'\n').encode()
        owner=owners[name];path=Path(owner['directory'])/(name+'.env')
        entries[name]={'path':str(path),'uid':owner['uid'],'sha256':sha(payload),'bytes':payload}
    return b,p,data,plan,entries

def prepare(bundle,selector,ledger):
    b,p,data,plan,entries=source(bundle,selector,ledger)
    if (data.get('venueRuntimeEnvPhase') or data.get('unitFiles') or
            data.get('venueDataBindDirs') or data.get('venueHulyVolumes')):
        raise Refusal('private runtime environment requires pre-data, pre-unit managers')
    directories={Path(v['path']).parent:v['uid'] for v in entries.values()}
    if len(directories)!=8:raise Refusal('one root and seven selected user runtime dirs required')
    for directory,uid in directories.items():
        if uid==0:
            row=data['pathIdentities'].get(str(directory),{})
            if identity(directory)!={'dev':row.get('dev'),'ino':row.get('ino'),'uid':0,'mode':0o700}:
                raise Refusal('rootful staged runtime directory changed')
        else:
            base=directory.parent;s=base.lstat()
            if (base.is_symlink() or s.st_uid!=uid or not stat.S_ISDIR(s.st_mode) or
                    stat.S_IMODE(s.st_mode)&0o077 or not (base/'bus').is_socket()):
                raise Refusal('selected user manager runtime/DBus differs')
            if os.path.lexists(directory):raise Refusal('user env runtime directory already occupied')
    if any(os.path.lexists(v['path']) for v in entries.values()):raise Refusal('selected env file already occupied')
    data['venueRuntimeEnvPlan']={k:{key:value for key,value in v.items() if key!='bytes'} for k,v in entries.items()}
    data['venueRuntimeEnvPhase']='preparing';stage.write_ledger(p,data)
    for directory,uid in directories.items():
        if uid:
            directory.mkdir(mode=0o700);os.chown(directory,uid,uid);directory.chmod(0o700)
        data.setdefault('venueRuntimeEnvDirs',{})[str(directory)]=identity(directory)
        stage.write_ledger(p,data)
    for name,v in entries.items():
        path=Path(v['path']);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchown(fd,v['uid'],v['uid']);os.write(fd,v['bytes']);os.fsync(fd)
        finally:os.close(fd)
        st=path.lstat()
        data.setdefault('venueRuntimeEnvFiles',{})[str(path)]={'dev':st.st_dev,'ino':st.st_ino,
             'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode),'sha256':v['sha256']}
        stage.write_ledger(p,data)
    data['venueRuntimeEnvPhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':'inert-ready','privateEnvFiles':len(entries),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    b,p,data,plan,entries=source(bundle,selector,ledger)
    if data.get('venueRuntimeEnvPhase')!='inert-ready' or len(data.get('venueRuntimeEnvFiles',{}))!=75:
        raise Refusal('only fully recorded inactive environment may retire')
    if data.get('venueCompositeVersion') and (data.get('venueCompositeMode')!='retired-inert' or
            len(data.get('retiredUnits',[]))!=194):
        raise Refusal('co-staged units must retire before private environments')
    directories=data.get('venueRuntimeEnvDirs',{})
    if len(directories)!=8 or set(data['venueRuntimeEnvPlan'])!=set(entries):
        raise Refusal('runtime directory or template identities differ')
    for name,v in entries.items():
        row=data['venueRuntimeEnvFiles'].get(v['path'],{});path=Path(v['path']);s=path.lstat()
        if (data['venueRuntimeEnvPlan'].get(name)!={k:val for k,val in v.items() if k!='bytes'} or
                path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or
                (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=
                (row.get('dev'),row.get('ino'),v['uid'],0o600) or release.sha(path)!=v['sha256']):
            raise Refusal('private runtime env file or selected bytes changed')
    for name,row in directories.items():
        directory=Path(name);uid=row['uid'];contents={Path(v['path']).name for v in entries.values() if Path(v['path']).parent==directory}
        if identity(directory)!=row or {x.name for x in directory.iterdir()}!=contents:
            raise Refusal('foreign private runtime env entry')
    data['venueRuntimeEnvPhase']='retiring';stage.write_ledger(p,data)
    for v in entries.values():Path(v['path']).unlink()
    for name,row in directories.items():
        if row['uid']:Path(name).rmdir()
    data['venueRuntimeEnvPhase']='retired-inert';stage.write_ledger(p,data)
    return {'status':'retired-inert','privateEnvFiles':len(entries),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):a.add_argument('--'+name,required=True)
    mode=a.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true');mode.add_argument('--retire',action='store_true')
    args=a.parse_args()
    try:print(json.dumps(prepare(args.bundle,args.selector,args.ledger) if args.prepare else retire(args.bundle,args.selector,args.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,TypeError) as exc:
        raise SystemExit('venue private runtime environment refused: '+str(exc)) from exc
if __name__=='__main__':main()
