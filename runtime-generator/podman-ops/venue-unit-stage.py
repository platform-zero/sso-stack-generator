#!/usr/bin/env python3
"""Install/remove ONLY inert exact-name isolated Quadlets and target files.

No enable/start/image/network/control/guest action. Every file is inventoried in
the root-private empty-stage ledger before installation. This is not a full
installer or a reset of a running stack.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def run(*args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=50,cwd='/')

def manifest(bundle,plan):
    bundle=Path(bundle);root=bundle/'quadlet'
    if not root.is_dir() or root.is_symlink():raise Refusal('missing staged Quadlet source')
    accounts={a['name'].removeprefix(plan['prefix']+'-'):a for a in plan['accounts']}
    result={}
    count=0
    for source_dir in sorted(root.iterdir()):
        domain=source_dir.name
        account=None if domain=='rootful' else accounts.get(domain.removeprefix('rootless-'))
        if (domain!='rootful' and (not domain.startswith('rootless-') or account is None)) or source_dir.is_symlink():
            raise Refusal('unknown Quadlet domain')
        for p in sorted(source_dir.iterdir()):
            count+=1
            if p.is_symlink() or not p.is_file() or p.suffix not in ('.container','.network','.build','.target'):
                raise Refusal('unclassified Quadlet source')
            if not p.name.startswith(plan['prefix']+'-') and p.name!=plan['prefix']+'.target':
                raise Refusal('Quadlet source escaped exact namespace')
            if p.suffix=='.target':
                dest=(Path('/etc/systemd/system')/p.name if account is None else
                      Path(account['home'])/'.config/systemd/user'/p.name)
            else:
                dest=(Path('/etc/containers/systemd')/p.name if account is None else
                      Path(account['home'])/'.config/containers/systemd'/p.name)
            if str(dest) in result:raise Refusal('duplicate installed unit path')
            result[str(dest)]={'source':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                               'uid':0 if account is None else account['uid']}
    if count!=194 or len(result)!=194:
        raise Refusal('incomplete 194-member venue Quadlet inventory')
    return result

def verified(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('only root can manage isolated unit stage')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('missing protected empty-stage ledger')
    state=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if state.get('plan')!=plan or state.get('managerStarted')!=[a['name'] for a in plan['accounts']] or state.get('managerStopped'):
        raise Refusal('unit stage requires exact seven running selected managers')
    for a in plan['accounts']:
        if pwd.getpwnam(a['name']).pw_uid!=a['uid'] or run('systemctl','is-active','--quiet','user@'+str(a['uid'])+'.service',check=False).returncode:
            raise Refusal('isolated rootless manager is not active')
        for name in (a['home'],a['home']+'/.config',a['home']+'/.config/containers'):
            p=Path(name);record=state.get('pathIdentities',{}).get(name)
            if not record or p.is_symlink():raise Refusal('linked or missing staged home authority')
            info=p.lstat()
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino,info.st_uid)!=(record['dev'],record['ino'],record['uid']):
                raise Refusal('rootless unit parent inode/owner drift')
    return path,state,plan

def reload(plan):
    run('systemctl','daemon-reload')
    for a in plan['accounts']:
        uid=a['uid'];user=a['name']
        run('runuser','-u',user,'--','env','HOME='+a['home'],'XDG_RUNTIME_DIR=/run/user/'+str(uid),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(uid)+'/bus','systemctl','--user','daemon-reload')

def units_idle(plan):
    patterns=(plan['prefix']+'-*.service',plan['prefix']+'*.target')
    for authority in [None,*plan['accounts']]:
        if authority is None:
            cmd=['systemctl']
        else:
            uid=authority['uid'];cmd=['runuser','-u',authority['name'],'--','env',
                'HOME='+authority['home'],'XDG_RUNTIME_DIR=/run/user/'+str(uid),
                'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(uid)+'/bus','systemctl','--user']
        for pattern in patterns:
            listed=run(*cmd,'list-units','--all','--plain','--no-legend',pattern,check=False)
            if listed.returncode not in (0,1):raise Refusal('isolated unit activity unavailable')
            if any(' active ' in line or ' activating ' in line for line in listed.stdout.splitlines()):
                raise Refusal('selected venue service or target became active')
        jobs=run(*cmd,'list-jobs','--no-legend','--no-pager',check=False)
        if jobs.returncode not in (0,1):raise Refusal('isolated unit jobs unavailable')
        if any(plan['prefix'] in line for line in jobs.stdout.splitlines()):
            raise Refusal('selected venue has an unexpected systemd job')

def install(bundle,selector,ledger):
    path,state,plan=verified(bundle,selector,ledger)
    if state['status']!='managers-ready' or state.get('unitFiles'):
        raise Refusal('unit stage already selected or has ambiguous progress')
    files=manifest(bundle,plan)
    for dest,row in files.items():
        p=Path(dest)
        if os.path.lexists(p) or p.parent.is_symlink() or p.parent.parent.is_symlink():
            raise Refusal('existing or linked systemd/Quadlet unit destination')
        if row['uid']:
            if not str(p).startswith('/home/'+plan['prefix']+'-'):
                raise Refusal('rootless unit escaped selected test home')
        elif not (str(p).startswith('/etc/containers/systemd/'+plan['prefix']) or
                  str(p).startswith('/etc/systemd/system/'+plan['prefix'])):
            raise Refusal('rootful unit escaped selected test namespace')
    dirs=sorted({str(Path(p).parent) for p in files if not Path(p).parent.exists()},key=lambda p:(len(Path(p).parts),p))
    all_dirs=[]
    for name in dirs:
        for parent in reversed((Path(name),*Path(name).parents)):
            if str(parent).startswith('/home/'+plan['prefix']+'-') and not parent.exists() and str(parent) not in all_dirs:
                all_dirs.append(str(parent))
    all_dirs=sorted(all_dirs,key=lambda p:(len(Path(p).parts),p))
    state['unitFiles']=files;state['unitDirs']=all_dirs;state['installedUnits']=[];state['installedUnitDirs']=[]
    state['status']='units-installing';stage.write_ledger(path,state)
    for name in all_dirs:
        p=Path(name);owner=next(a for a in plan['accounts'] if name.startswith(a['home']+'/'))
        state['pendingUnitDir']=name;stage.write_ledger(path,state)
        p.mkdir(mode=0o700);os.chown(p,owner['uid'],owner['uid']);os.chmod(p,0o700)
        st=p.lstat()
        state['installedUnitDirs'].append({'path':name,'dev':st.st_dev,'ino':st.st_ino,'uid':owner['uid']})
        state.pop('pendingUnitDir');stage.write_ledger(path,state)
    for dest,row in files.items():
        p=Path(dest);source=Path(row['source'])
        state['pendingUnit']=dest;stage.write_ledger(path,state)
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'wb') as output:
            output.write(source.read_bytes());output.flush();os.fsync(output.fileno())
        os.chown(p,row['uid'],row['uid']);os.chmod(p,0o644)
        st=p.lstat();state['installedUnits'].append({'path':dest,'dev':st.st_dev,'ino':st.st_ino})
        state.pop('pendingUnit');stage.write_ledger(path,state)
    reload(plan)
    units_idle(plan)
    state['status']='units-staged';stage.write_ledger(path,state)
    return state

def retire(bundle,selector,ledger):
    path,state,plan=verified(bundle,selector,ledger)
    if state['status'] not in ('units-staged','units-installing','units-retiring'):
        raise Refusal('no exact selected unit stage to retire')
    files=manifest(bundle,plan)
    if state.get('unitFiles')!=files or len(state.get('installedUnits',[]))>194:
        raise Refusal('unit source/ledger CAS drift')
    units_idle(plan)
    # No untracked destination is removed. Pending install is recognized only
    # because every destination was proved absent before this exact journal.
    entries=list(state.get('installedUnits',[]))
    pending=state.get('pendingUnit')
    if pending and pending not in {e['path'] for e in entries} and os.path.lexists(pending):
        p=Path(pending);entries.append({'path':pending,'dev':p.lstat().st_dev,'ino':p.lstat().st_ino})
    removed=set(state.get('retiredUnits',[]))
    for row in entries:
        name=row['path']
        if name in removed:continue
        p=Path(name);expect=files[name];st=p.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or (st.st_dev,st.st_ino,st.st_uid)!=(row['dev'],row['ino'],expect['uid']) or stat.S_IMODE(st.st_mode)!=0o644 or hashlib.sha256(p.read_bytes()).hexdigest()!=expect['sha256']:
            raise Refusal('selected installed unit drift; do not delete')
    # Directory preflight before even one file deletion.
    directory_rows=list(state.get('installedUnitDirs',[]));pending_dir=state.get('pendingUnitDir')
    mountpoints=[row.split()[4].replace('\\040',' ') for row in Path('/proc/self/mountinfo').read_text().splitlines()]
    if any(mp==name or mp.startswith(name.rstrip('/')+'/') for mp in mountpoints for name in state.get('unitDirs',[])):
        raise Refusal('mounted unit directory cannot be retired')
    if pending_dir and pending_dir not in {e['path'] for e in directory_rows} and os.path.lexists(pending_dir):
        st=Path(pending_dir).lstat();directory_rows.append({'path':pending_dir,'dev':st.st_dev,'ino':st.st_ino,
             'uid':next(a['uid'] for a in plan['accounts'] if pending_dir.startswith(a['home']+'/'))})
    for row in directory_rows:
        if row['path'] in state.get('retiredUnitDirs',[]):continue
        p=Path(row['path']);st=p.lstat()
        if not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino,st.st_uid)!=(row['dev'],row['ino'],row['uid']):
            raise Refusal('selected unit parent drift')
        descendants={Path(e['path']).name for e in entries if Path(e['path']).parent==p and e['path'] not in removed}
        descendants|={Path(e['path']).name for e in directory_rows if Path(e['path']).parent==p and e['path'] not in state.get('retiredUnitDirs',[])}
        if {x.name for x in p.iterdir()}!=descendants:raise Refusal('unreviewed content in unit directory')
    state['status']='units-retiring';stage.write_ledger(path,state)
    for row in reversed(entries):
        name=row['path']
        if name in state.get('retiredUnits',[]):continue
        Path(name).unlink();state.setdefault('retiredUnits',[]).append(name);stage.write_ledger(path,state)
    for row in reversed(directory_rows):
        name=row['path']
        if name in state.get('retiredUnitDirs',[]):continue
        Path(name).rmdir();state.setdefault('retiredUnitDirs',[]).append(name);stage.write_ledger(path,state)
    reload(plan)
    state['status']='managers-ready';stage.write_ledger(path,state)
    return state

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('bundle','selector','ledger'):p.add_argument('--'+arg,required=True)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--install-inert-units',action='store_true')
    modes.add_argument('--retire-inert-units',action='store_true')
    a=p.parse_args()
    try:
        state=install(a.bundle,a.selector,a.ledger) if a.install_inert_units else retire(a.bundle,a.selector,a.ledger)
        print(json.dumps({'status':state['status'],'unitFiles':len(state.get('unitFiles',{})),
                          'activationAuthorized':False,'acceptedIntegratedInstalls':0},sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue inert-unit lifecycle refused: '+str(exc)) from exc

if __name__=='__main__':main()
