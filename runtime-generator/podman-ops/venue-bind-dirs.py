#!/usr/bin/env python3
"""Materialize/retire ONLY 61 EMPTY actual-Quadlet data bind directories.

No ACL, chown recursion, volume-init service, populated-data reset, image or
service activation. Cross-domain consumers are recorded, not granted access.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent

def load(name,source):
    spec=importlib.util.spec_from_file_location(name,HERE/source)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod
stage=load('venue_owned_stage','venue-owned-stage.py')
volmap=load('actual_volume_authority','inspect-venue-volume-authority.py')
Refusal=stage.Refusal

def inventory(bundle,selector,plan):
    checked=volmap.inspect(bundle,selector)
    if checked['actualDataBindSources']!=61 or checked['selectedVolumeLabels']!=65:
        raise Refusal('actual volume source count differs')
    roots=[(Path(plan['roots']['rootful-volume']),0)]
    roots.extend((Path(a['volume']),a['uid']) for a in plan['accounts'])
    paths={}
    for label,sources in checked['dataSources'].items():
        if label in volmap.NAMED:continue
        for value,consumers in sources.items():
            target=Path(value)
            matches=[(str(parent),uid) for parent,uid in roots if target.parent==parent]
            if len(matches)!=1:raise Refusal('actual data source not immediate exclusive staged volume root')
            paths[value]={'owner':matches[0][1],'parent':matches[0][0],
                          'label':label,'consumers':consumers}
    if len(paths)!=61:raise Refusal('duplicate or incomplete actual data sources')
    return paths

def checked_stage(bundle,selector,ledger,accepted):
    if os.geteuid()!=0:raise Refusal('root required to manage isolated data binds')
    ledger=Path(ledger)
    if ledger.is_symlink() or not ledger.is_file() or ledger.stat().st_uid!=0 or stat.S_IMODE(ledger.stat().st_mode)!=0o600:
        raise Refusal('missing root-private selected stage ledger')
    data=json.loads(ledger.read_text());plan=stage.owned_plan(bundle,selector)
    if data.get('plan')!=plan or data.get('status') not in accepted or data.get('managerStarted')!=[a['name'] for a in plan['accounts']] or data.get('managerStopped'):
        raise Refusal('seven selected running managers and exact stage required')
    paths=inventory(bundle,selector,plan)
    for info in paths.values():
        parent=Path(info['parent']);record=data['pathIdentities'].get(str(parent));st=parent.lstat()
        if not record or parent.is_symlink() or (st.st_dev,st.st_ino,st.st_uid)!=(record['dev'],record['ino'],info['owner']):
            raise Refusal('selected actual volume parent identity changed')
    return ledger,data,paths

def create(bundle,selector,ledger):
    path,data,paths=checked_stage(bundle,selector,ledger,('managers-ready','huly-volumes-inert','units-staged'))
    if data['status']!='managers-ready' and data.get('venueCompositeVersion')!=2:
        raise Refusal('composite data-bind phase requires versioned installer')
    if data.get('venueDataBindDirs') or data.get('pendingVenueDataDir'):
        raise Refusal('data bind stage already selected')
    if any(os.path.lexists(name) for name in paths):raise Refusal('actual data bind path already exists')
    data['venueDataBindDirs']=[]
    if data.get('venueCompositeVersion')==2:data['preVenueDataStatus']=data['status']
    data['status']='data-binds-creating';stage.write_ledger(path,data)
    for name,info in sorted(paths.items()):
        data['pendingVenueDataDir']=name;stage.write_ledger(path,data)
        p=Path(name);p.mkdir(mode=0o700);os.chown(p,info['owner'],info['owner']);os.chmod(p,0o700)
        st=p.lstat();data['venueDataBindDirs'].append({'path':name,'dev':st.st_dev,'ino':st.st_ino,
              'uid':st.st_uid,'parent':info['parent'],'label':info['label'],'consumers':info['consumers']})
        data.pop('pendingVenueDataDir');stage.write_ledger(path,data)
    data['status']='data-binds-inert';stage.write_ledger(path,data)
    return {'status':data['status'],'actualDataBindDirectories':len(paths),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    path,data,paths=checked_stage(bundle,selector,ledger,('data-binds-creating','data-binds-inert','data-binds-retiring'))
    if data.get('crossDomainAclStatus') not in (None,'retired'):
        raise Refusal('cross-domain ACL must be exactly restored before empty data-bind retirement')
    if data.get('venueCompositeVersion')==2 and data.get('preVenueDataStatus') not in ('managers-ready','huly-volumes-inert','units-staged'):
        raise Refusal('composite data-bind parent phase differs')
    rows=list(data.get('venueDataBindDirs',[]));pending=data.get('pendingVenueDataDir')
    if pending and pending not in {x['path'] for x in rows} and os.path.lexists(pending):
        st=Path(pending).lstat();info=paths[pending]
        rows.append({'path':pending,'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,
                     'parent':info['parent'],'label':info['label'],'consumers':info['consumers']})
    if len(rows)>61 or any(row['path'] not in paths or row['parent']!=paths[row['path']]['parent'] or
                            row['label']!=paths[row['path']]['label'] or row['consumers']!=paths[row['path']]['consumers']
                            for row in rows):
        raise Refusal('actual bind/selector journal changed')
    mountpoints=[line.split()[4].replace('\\040',' ') for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    retired=set(data.get('retiredDataBindDirs',[]))
    for row in rows:
        if row['path'] in retired:continue
        p=Path(row['path']);st=p.lstat()
        if (p.is_symlink() or not stat.S_ISDIR(st.st_mode) or
                (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))!=(row['dev'],row['ino'],paths[row['path']]['owner'],0o700) or
                any(p.iterdir()) or any(mp==str(p) or mp.startswith(str(p)+'/') for mp in mountpoints)):
            raise Refusal('nonempty, mounted or altered data bind; not an installed-data reset')
    data['status']='data-binds-retiring';stage.write_ledger(path,data)
    for row in reversed(rows):
        if row['path'] in retired:continue
        Path(row['path']).rmdir()
        data.setdefault('retiredDataBindDirs',[]).append(row['path']);stage.write_ledger(path,data)
    data.pop('pendingVenueDataDir',None)
    data['status']=data.pop('preVenueDataStatus','managers-ready');stage.write_ledger(path,data)
    return {'status':data['status'],'retiredEmptyDataBindDirs':len(rows),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','ledger'):p.add_argument('--'+key,required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--create-empty',action='store_true');mode.add_argument('--retire-empty',action='store_true')
    a=p.parse_args()
    try:print(json.dumps((create if a.create_empty else retire)(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('venue empty data-bind lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
