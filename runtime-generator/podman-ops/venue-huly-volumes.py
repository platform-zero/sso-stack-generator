#!/usr/bin/env python3
"""Create/retire ONLY FOUR empty, new-graph Huly named Podman volumes.

This preparation probe is NOT installed-data reset. It refuses any nonempty
_data directory and cannot touch the preserved original apps graph.
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
NAMES=('huly_cockroach','huly_elastic','huly_minio','huly_redpanda')

def command(account,*args):
    uid=account['uid']
    return ['runuser','-u',account['name'],'--','env','-u','CONTAINERS_STORAGE_CONF','-u','CONTAINERS_CONF',
            'HOME='+account['home'],'XDG_RUNTIME_DIR=/run/user/'+str(uid),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(uid)+'/bus',
            'podman',*args]

def run(account,*args):
    result=subprocess.run(command(account,*args),capture_output=True,text=True,timeout=45,cwd='/')
    if result.returncode:raise Refusal('selected apps Podman volume operation refused')
    return result.stdout.strip()

def check_apps(data,plan,apps):
    graph=Path(apps['graph']);info=graph.lstat();record=data['pathIdentities'].get(str(graph))
    if not record or graph.is_symlink() or (info.st_dev,info.st_ino,info.st_uid)!=(record['dev'],record['ino'],apps['uid']):
        raise Refusal('apps graph is not the exclusive staged inode')
    if pwd.getpwnam(apps['name']).pw_uid!=apps['uid']:
        raise Refusal('selected apps account identity changed')
    home=Path(apps['home']);config=home/'.config/containers/storage.conf'
    config_info=config.lstat()
    if (any(p.is_symlink() for p in (home,home/'.config',home/'.config/containers',config)) or
            not stat.S_ISREG(config_info.st_mode) or config_info.st_uid!=apps['uid'] or
            stat.S_IMODE(config_info.st_mode)!=0o600 or
            config.read_text()!=plan['configs'].get(str(config))):
        raise Refusal('apps Podman storage config cannot select shared graph')
    active=subprocess.run(['systemctl','is-active','--quiet','user@'+str(apps['uid'])+'.service'],
                          capture_output=True,timeout=15,cwd='/')
    if active.returncode:raise Refusal('selected apps user manager is not active')

def context(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root required for exclusive volume lifecycle')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('protected stage ledger required')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or
            data.get('status') not in (('managers-ready','data-binds-inert','units-staged') if data.get('venueCompositeVersion')==2 else ('managers-ready',)) or
            data.get('managerStarted')!=[a['name'] for a in plan['accounts']] or data.get('managerStopped')):
        raise Refusal('seven selected active managers and empty-stage authority required')
    apps=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-apps')
    check_apps(data,plan,apps)
    actual=set()
    for unit in (Path(bundle)/'quadlet/rootless-apps').glob('*.container'):
        for line in unit.read_text().splitlines():
            if line.startswith('Volume=huly_'):actual.add(line[7:].split(':',1)[0])
    if actual!=set(NAMES):raise Refusal('four Huly named-volume source identities changed')
    return path,data,plan,apps

def inventory(apps):
    entries=run(apps,'volume','ls','--quiet').splitlines()
    return set(entries)

def mountpoint(apps,name):
    result=json.loads(run(apps,'volume','inspect',name,'--format','json'))
    if not isinstance(result,list) or len(result)!=1 or result[0].get('Name')!=name:
        raise Refusal('selected Huly named-volume metadata differs')
    path=Path(result[0].get('Mountpoint',''))
    graph=Path(apps['graph'])
    if not path.is_absolute() or graph not in path.parents or path.name!='_data' or path.is_symlink():
        raise Refusal('Huly volume mountpoint escaped isolated apps graph')
    return path

def create(bundle,selector,ledger):
    path,data,plan,apps=context(bundle,selector,ledger)
    if data.get('venueHulyVolumes') or data.get('pendingVenueHulyVolume'):
        raise Refusal('named volumes already selected or interrupted')
    if inventory(apps):raise Refusal('unexpected existing volume in exclusive fresh apps graph')
    data['venueHulyVolumes']=[]
    if data.get('venueCompositeVersion')==2:data['preVenueHulyStatus']=data['status']
    data['status']='huly-volumes-creating';stage.write_ledger(path,data)
    for name in NAMES:
        data['pendingVenueHulyVolume']=name;stage.write_ledger(path,data)
        if run(apps,'volume','create',name)!=name:raise Refusal('selected volume create returned wrong identity')
        dest=mountpoint(apps,name)
        if any(dest.iterdir()):raise Refusal('new Huly volume has unexpected data')
        st=dest.lstat();data['venueHulyVolumes'].append({'name':name,'mountpoint':str(dest),'dev':st.st_dev,'ino':st.st_ino})
        data.pop('pendingVenueHulyVolume');stage.write_ledger(path,data)
    if inventory(apps)!=set(NAMES):raise Refusal('selected Huly volume inventory differs')
    data['status']='huly-volumes-inert';stage.write_ledger(path,data)
    return {'status':data['status'],'count':4,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    # Accept a partial creation journal, but never silently remove an unknown
    # volume or nonempty data. This is not the installed-stack reset path.
    if os.geteuid()!=0:raise Refusal('root required')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('protected stage ledger required')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if data.get('plan')!=plan or data.get('status') not in ('huly-volumes-creating','huly-volumes-inert','huly-volumes-retiring'):
        raise Refusal('no selected Huly volume preparation to retire')
    apps=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-apps')
    check_apps(data,plan,apps)
    if data.get('venueCompositeVersion')==2 and data.get('preVenueHulyStatus') not in ('managers-ready','data-binds-inert','units-staged'):
        raise Refusal('composite named-volume parent phase differs')
    rows=data.get('venueHulyVolumes',[]);pending=data.get('pendingVenueHulyVolume')
    expected={row['name'] for row in rows}
    if pending and pending not in expected:expected.add(pending)
    if len(rows)>4 or expected-set(NAMES) or inventory(apps)!=expected-set(data.get('retiredHulyVolumes',[])):
        raise Refusal('foreign or missing named volume in exclusive apps graph')
    approved=[]
    for name in sorted(expected-set(data.get('retiredHulyVolumes',[]))):
        dest=mountpoint(apps,name)
        if name!=pending:
            recorded=next(row for row in rows if row['name']==name);st=dest.lstat()
            if str(dest)!=recorded['mountpoint'] or (st.st_dev,st.st_ino)!=(recorded['dev'],recorded['ino']):
                raise Refusal('selected Huly volume mountpoint replaced')
        if any(dest.iterdir()):raise Refusal('Huly volume contains data; empty-stage retire refused')
        approved.append(name)
    data['status']='huly-volumes-retiring';stage.write_ledger(path,data)
    for name in reversed(approved):
        run(apps,'volume','rm',name)
        data.setdefault('retiredHulyVolumes',[]).append(name);stage.write_ledger(path,data)
    if inventory(apps):raise Refusal('named Huly volumes remained')
    data.pop('pendingVenueHulyVolume',None)
    data['status']=data.pop('preVenueHulyStatus','managers-ready');stage.write_ledger(path,data)
    return {'status':data['status'],'retired':len(data['retiredHulyVolumes']),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','ledger'):p.add_argument('--'+key,required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--create-empty',action='store_true');mode.add_argument('--retire-empty',action='store_true')
    a=p.parse_args()
    try:print(json.dumps((create if a.create_empty else retire)(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue named-volume lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
