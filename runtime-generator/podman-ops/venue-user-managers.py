#!/usr/bin/env python3
"""Stage/retire seven NEW rootless user managers for an empty isolated venue.

This never installs Quadlets, loads images or starts the 95 services. Only
accounts named by an exact root0600 empty-stage ledger can be affected.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_owned_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def run(*args,check=True):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=30,cwd='/')

def read_stage(bundle,selector,ledger):
    path=Path(ledger)
    if os.geteuid()!=0 or not path.is_file() or path.is_symlink():
        raise Refusal('root and exact existing empty-stage ledger required')
    meta=path.stat()
    if meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o600:
        raise Refusal('unsafe empty-stage ledger')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or data.get('createdAccounts')!=[a['name'] for a in plan['accounts']]
            or data.get('createdGroups')!=data.get('createdAccounts')
            or data.get('createdPaths')!=data.get('createPaths')
            or len(data.get('pathIdentities',{}))!=len(data.get('createPaths',[]))
            or set(data.get('createdConfigs',[]))!=set(plan['configs'])
            or data.get('retiredConfigs') or data.get('retiredPaths') or data.get('retiredAccounts')):
        raise Refusal('incomplete or changed empty-stage identity authority')
    for account in plan['accounts']:
        user=pwd.getpwnam(account['name'])
        if user.pw_uid!=account['uid'] or user.pw_gid!=account['uid'] or user.pw_dir!=account['home']:
            raise Refusal('selected rootless account drift')
        home=Path(account['home'])
        for name in ('state','graph','volume'):
            p=Path(account[name]);info=p.lstat()
            record=data['pathIdentities'].get(str(p))
            if not record or not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino,info.st_uid)!=(record['dev'],record['ino'],record['uid']):
                raise Refusal('selected graph/state/volume inode drift')
        for c in (home/'.config/containers/storage.conf',home/'.config/containers/containers.conf'):
            if c.is_symlink() or not c.is_file() or c.read_text()!=plan['configs'][str(c)]:
                raise Refusal('rootless store config differs from selected stage')
    for parent in (Path('/etc/containers/systemd'),Path('/etc/systemd/system'),Path('/run/systemd/system')):
        if parent.exists() and any(x.name.startswith(plan['prefix']) for x in parent.iterdir()):
            raise Refusal('venue Quadlet or host unit installed; not empty stage')
    return path,data,plan

def act(bundle,selector,ledger,*,stop=False):
    path,data,plan=read_stage(bundle,selector,ledger)
    accounts=plan['accounts']
    if stop:
        if data.get('venueRuntimeEnvPhase') not in (None,'retired-inert'):
            raise Refusal('retire all private selected service environments before manager shutdown')
        if data['status'] not in ('managers-ready','managers-stopping','managers-starting'):
            raise Refusal('unreviewed manager stop authority')
        started=data.get('managerStarted',[])
        names=[a['name'] for a in accounts]
        if started!=names[:len(started)] or (data['status']=='managers-ready' and started!=names):
            raise Refusal('manager start ledger differs from ordered account authority')
        pending=data.get('pendingManager')
        if pending is not None and (len(started)>=len(names) or pending!=names[len(started)]):
            raise Refusal('pending manager is not the next selected account')
        selected=started+([pending] if pending else [])
        # Do not stop any manager hosting installed units or nonempty graph data.
        for a in accounts:
            if any(any(Path(a[k]).iterdir()) for k in ('graph','volume')):
                raise Refusal('test graph/volume contains data; exact empty-manager stop refused')
            linger=Path('/var/lib/systemd/linger')/a['name']
            if linger.is_symlink():raise Refusal('linger identity changed')
            if a['name'] in started and a['name'] not in data.get('managerStopped',[]) and not linger.is_file() and data['status']!='managers-stopping':
                raise Refusal('recorded manager has no selected linger')
            if a['name'] not in selected and linger.exists():raise Refusal('unrecorded account linger exists')
        data['status']='managers-stopping';stage.write_ledger(path,data)
        for a in reversed(accounts):
            name=a['name'];unit='user@'+str(a['uid'])+'.service'
            if name not in selected or name in data.get('managerStopped',[]):continue
            if run('systemctl','is-active','--quiet',unit,check=False).returncode==0:
                run('systemctl','stop',unit)
            if run('systemctl','is-active','--quiet',unit,check=False).returncode==0:
                raise Refusal('selected manager remains active')
            if (Path('/var/lib/systemd/linger')/name).exists():
                run('loginctl','disable-linger',name)
            if (Path('/var/lib/systemd/linger')/name).exists():raise Refusal('selected linger remains enabled')
            data.setdefault('managerStopped',[]).append(name);stage.write_ledger(path,data)
        data['status']='staged-empty';stage.write_ledger(path,data)
        return data
    if data['status']!='staged-empty' or data.get('managerStarted'):
        raise Refusal('empty manager start requires a fresh stage')
    for a in accounts:
        name=a['name'];unit='user@'+str(a['uid'])+'.service'
        if run('systemctl','is-active','--quiet',unit,check=False).returncode==0 or (Path('/var/lib/systemd/linger')/name).exists():
            raise Refusal('selected user manager/linger already active without ownership')
        if any(any(Path(a[k]).iterdir()) for k in ('graph','volume')):
            raise Refusal('rootless image/volume store is not empty')
    data['status']='managers-starting';data['managerStarted']=[];stage.write_ledger(path,data)
    for a in accounts:
        name=a['name'];uid=a['uid'];unit='user@'+str(uid)+'.service'
        data['pendingManager']=name;stage.write_ledger(path,data)
        run('loginctl','enable-linger',name)
        run('systemctl','start',unit)
        if run('systemctl','is-active','--quiet',unit,check=False).returncode!=0:
            raise Refusal('user manager failed after enable-linger')
        runtime=Path('/run/user')/str(uid)
        info=runtime.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)&0o077 or not (runtime/'bus').is_socket():
            raise Refusal('selected runtime/user bus did not start in private UID scope')
        data['managerStarted'].append(name);data.pop('pendingManager');stage.write_ledger(path,data)
    data['status']='managers-ready';stage.write_ledger(path,data)
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('bundle','selector','ledger'):p.add_argument('--'+k,required=True)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--start-empty-managers',action='store_true')
    modes.add_argument('--stop-empty-managers',action='store_true')
    a=p.parse_args()
    try:
        data=act(a.bundle,a.selector,a.ledger,stop=a.stop_empty_managers)
        print(json.dumps({'status':data['status'],'managerStarted':len(data.get('managerStarted',[])),
                          'managerStopped':len(data.get('managerStopped',[])),
                          'activationAuthorized':False,'acceptedIntegratedInstalls':0},sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue manager lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
