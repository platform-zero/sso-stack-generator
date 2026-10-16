#!/usr/bin/env python3
"""CAS-bound combined INERT preparation of 61 binds, 4 volumes, 194 units.

This is not a service installer, image import, volume-init marker issuer or
populated-data reset. All selected assets coexist before return. A failed
phase keeps the durable journal for exact inspected recovery; no implicit
cleanup of unknown data or foreign objects is permitted.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
stage=load('venue_stage','venue-owned-stage.py')
binds=load('venue_binds','venue-bind-dirs.py')
acl=load('venue_acl','venue-cross-domain-acl.py')
huly=load('venue_huly','venue-huly-volumes.py')
units=load('venue_units','venue-unit-stage.py')
graph=load('venue_graph','venue-graph-clear.py')
managers=load('venue_managers','venue-user-managers.py')
Refusal=stage.Refusal

def context(bundle,selector,ledger):
    p=Path(ledger)
    if os.geteuid()!=0 or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('root-owned 0600 stage ledger required')
    data=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or data.get('managerStarted')!=[a['name'] for a in plan['accounts']] or
            data.get('managerStopped')):
        raise Refusal('seven dedicated running managers and exact source CAS required')
    if Path(plan['roots']['rootful-state'],'volume-ready-r1.txt').exists():
        raise Refusal('protected readiness marker is not permitted in inert composition')
    return p,data,plan

def prepare(bundle,selector,ledger):
    path,data,plan=context(bundle,selector,ledger)
    if data['status']!='managers-ready' or data.get('venueCompositeVersion') or any(
            data.get(key) for key in ('venueDataBindDirs','venueHulyVolumes','unitFiles','crossDomainAclStatus')):
        raise Refusal('composite preparation requires fresh staged managers and zero assets')
    data['venueCompositeVersion']=2;data['venueCompositeMode']='preparing';stage.write_ledger(path,data)
    binds.create(bundle,selector,ledger)
    acl.grant(bundle,selector,ledger)
    huly.create(bundle,selector,ledger)
    units.install(bundle,selector,ledger)
    path,data,_=context(bundle,selector,ledger)
    if (data['status']!='units-staged' or data.get('preVenueUnitStatus')!='huly-volumes-inert' or
            data.get('preVenueHulyStatus')!='data-binds-inert' or
            data.get('preVenueDataStatus')!='managers-ready' or
            data.get('crossDomainAclStatus')!='granted' or len(data.get('venueDataBindDirs',[]))!=61 or
            len(data.get('venueHulyVolumes',[]))!=4 or len(data.get('installedUnits',[]))!=194):
        raise Refusal('composite assets failed same-CAS coexistence check')
    data['venueCompositeMode']='inert-ready';stage.write_ledger(path,data)
    return {'status':'inert-ready','actualBindDirectories':61,'namedVolumes':4,'installedInactiveUnits':194,
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    path,data,plan=context(bundle,selector,ledger)
    if (data.get('venueCompositeVersion')!=2 or data.get('venueCompositeMode') not in ('inert-ready','retiring') or
            data.get('status') not in ('units-staged','units-retiring')):
        raise Refusal('only a fully journaled inert composition may be retired here')
    # All data, named volumes and unit sources must pass BEFORE the first
    # unlink. This deliberately refuses a populated installed stack.
    rows=data['venueDataBindDirs']
    paths=binds.inventory(bundle,selector,plan)
    if len(rows)!=61 or set(paths)!={row['path'] for row in rows}:
        raise Refusal('all 61 generated data binds must remain selected')
    for row in rows:
        p=Path(row['path']);info=p.lstat()
        if (p.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid)!=(row['dev'],row['ino'],paths[row['path']]['owner']) or
                any(p.iterdir())):
            raise Refusal('nonempty or changed data bind; no inert composition retirement')
    _,_,rules=acl.context(bundle,selector,ledger) if data['status']=='data-binds-inert' else (None,None,acl.policy(plan,paths))
    if data.get('crossDomainAclStatus')!='granted' or any(acl.permission_rows(p)!=acl.granted_rows(users) for p,users in rules):
        raise Refusal('cross-domain ACL changed before composition retirement')
    apps=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-apps')
    huly.check_apps(data,plan,apps)
    if huly.inventory(apps)!=set(huly.NAMES) or len(data.get('venueHulyVolumes',[]))!=4:
        raise Refusal('four selected named volumes changed')
    for row in data['venueHulyVolumes']:
        dest=huly.mountpoint(apps,row['name']);info=dest.lstat()
        if str(dest)!=row['mountpoint'] or (info.st_dev,info.st_ino)!=(row['dev'],row['ino']) or any(dest.iterdir()):
            raise Refusal('named volume now contains data or changed inode')
    selected=units.manifest(bundle,plan)
    if selected!=data.get('unitFiles') or len(data.get('installedUnits',[]))!=194:
        raise Refusal('unit source/journal differed before retirement')
    units.units_idle(plan)
    for row in data['installedUnits']:
        p=Path(row['path']);info=p.lstat();expected=selected.get(str(p))
        if (not expected or p.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or
                (info.st_dev,info.st_ino,info.st_uid)!=(row['dev'],row['ino'],expected['uid']) or
                units.hashlib.sha256(p.read_bytes()).hexdigest()!=expected['sha256']):
            raise Refusal('installed inert unit changed before any retirement')
    data['venueCompositeMode']='retiring';stage.write_ledger(path,data)
    units.retire(bundle,selector,ledger)
    huly.retire(bundle,selector,ledger)
    acl.restore(bundle,selector,ledger)
    binds.retire(bundle,selector,ledger)
    path,data,_=context(bundle,selector,ledger)
    if data['status']!='managers-ready':raise Refusal('composite phase stack did not unwind exactly')
    data['venueCompositeMode']='retired-inert';stage.write_ledger(path,data)
    return {'status':'retired-inert','activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('bundle','selector','ledger'):p.add_argument('--'+k,required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true');mode.add_argument('--retire',action='store_true')
    a=p.parse_args()
    try:print(json.dumps((prepare if a.prepare else retire)(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,IndexError) as exc:
        raise SystemExit('inert composite venue refused: '+str(exc)) from exc
if __name__=='__main__':main()
