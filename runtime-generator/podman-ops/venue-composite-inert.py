#!/usr/bin/env python3
"""CAS-bound combined INERT preparation of 61 binds, 4 volumes, 194 units.

This is not a service installer, image import, volume-init marker issuer or
populated-data reset. All selected assets coexist before return. A failed
phase keeps the durable journal for exact inspected recovery; no implicit
cleanup of unknown data or foreign objects is permitted.
"""
import argparse
import hashlib
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
images=load('venue_images','install-pinned-images.py')
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

def offline_plan(bundle,plan,rows):
    """Single legacy offline image, or the exact complete frozen input set."""
    if any(not isinstance(row,dict) or set(row)!={'image','authorities'} or
           not isinstance(row['image'],str) or not isinstance(row['authorities'],list) or
           not row['authorities'] or any(not isinstance(user,str) for user in row['authorities']) for row in rows):
        raise Refusal('offline image plan fields differ')
    local=images.frozen_image_ids(Path(bundle))
    if local:
        ir=json.loads((Path(bundle)/'stack.ir.json').read_text())
        required={s['image'] for s in ir['services'].values() if s.get('image','').startswith('sha256:')}
        selected={row.get('image') for row in rows if isinstance(row,dict)}
        direct=[row for row in rows if row.get('image') not in set(local.values())]
        if (len(rows)!=len(required) or selected!=required or len(direct)!=1 or
                direct[0].get('authorities')!=[plan['prefix']+'-apps']):
            raise Refusal('complete exact frozen inputs plus selected apps offline image required')
    elif len(rows)!=1 or rows[0].get('authorities')!=[plan['prefix']+'-apps']:
        raise Refusal('one exact selected offline image and apps authority required')
    return rows


def prepare(bundle,selector,ledger,image_inputs=None):
    path,data,plan=context(bundle,selector,ledger)
    rows=images.validate(Path(bundle),Path(image_inputs)) if image_inputs is not None else []
    if image_inputs is not None:
        offline_plan(bundle,plan,[{'image':image,'authorities':users} for image,_,users in rows])
    elif images.frozen_image_ids(Path(bundle)):
        raise Refusal('frozen composition requires its complete offline input manifest')
    if data['status']!='managers-ready' or data.get('venueCompositeVersion') or any(
            data.get(key) for key in ('venueDataBindDirs','venueHulyVolumes','unitFiles','crossDomainAclStatus')):
        raise Refusal('composite preparation requires fresh staged managers and zero assets')
    data['venueCompositeVersion']=2;data['venueCompositeMode']='preparing';stage.write_ledger(path,data)
    binds.create(bundle,selector,ledger)
    acl.grant(bundle,selector,ledger)
    huly.create(bundle,selector,ledger)
    units.install(bundle,selector,ledger)
    if rows:
        path,data,_=context(bundle,selector,ledger)
        data['venueCompositeImageInputSha256']=hashlib.sha256(Path(image_inputs).read_bytes()).hexdigest()
        data['venueCompositeOfflineImages']=[{'image':image,'authorities':authorities} for image,_,authorities in rows]
        data['venueCompositeMode']='images-importing';stage.write_ledger(path,data)
        images.install(rows,Path(bundle))
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

def recover_failed_import(bundle,selector,ledger):
    """Recover only an interrupted one-image import, never unknown content."""
    path,data,plan=context(bundle,selector,ledger)
    proposed=data.get('venueCompositeOfflineImages',[])
    if (data.get('venueCompositeVersion')!=2 or data.get('venueCompositeMode')!='images-importing' or
            data.get('status')!='units-staged' or len(proposed)!=1 or
            not data.get('venueCompositeImageInputSha256')):
        raise Refusal('no exact single-image interrupted import authority')
    row=proposed[0]
    selected=graph.selected_images(bundle)
    if (not isinstance(row,dict) or row.get('authorities')!=[plan['prefix']+'-apps'] or
            row.get('image') not in selected.get(row['authorities'][0],set())):
        raise Refusal('interrupted import does not match selected apps image')
    observed={}
    for user,_,command in graph.stores(bundle,plan):
        def listing(args):
            result=graph.run(command+args)
            if result.returncode:raise Refusal('interrupted import graph cannot be inventoried')
            return set(result.stdout.splitlines())
        if listing(['ps','-aq']) or listing(['pod','ps','--quiet']):
            raise Refusal('interrupted import graph contains container or pod')
        if listing(['volume','ls','-q'])!=(set(huly.NAMES) if user==row['authorities'][0] else set()):
            raise Refusal('interrupted import graph has foreign named volume')
        if listing(['network','ls','--format','{{.Name}}'])-{'podman'}:
            raise Refusal('interrupted import graph has foreign network')
        found={('sha256:'+v.removeprefix('sha256:')) for v in listing(['image','ls','-a','--no-trunc','--format','{{.ID}}'])}
        if found-(set([row['image']]) if user==row['authorities'][0] else set()):
            raise Refusal('interrupted import graph has unjournaled image')
        observed[user]=found
    if not observed[row['authorities'][0]]:
        data['venueCompositeFailedImagePlan']=proposed
        data['venueCompositeOfflineImages']=[]
    data['venueCompositeMode']='inert-ready';stage.write_ledger(path,data)
    return retire(bundle,selector,ledger)

def finish_graph_retirement(bundle,selector,ledger):
    graph.clear(bundle,selector,ledger)
    path,data,_=context(bundle,selector,ledger)
    if not data.get('podmanImageCacheRetired'):
        graph.retire_image_cache(bundle,selector,ledger)
    path,data,_=context(bundle,selector,ledger)
    if data['status']!='managers-ready' or len(data.get('graphCleared',[]))!=8:
        raise Refusal('composite graph stack did not unwind exactly')
    if data.get('venueRegistryPhase') in ('preparing','inert-ready'):
        data['venueRegistryPhase']='retired-inert';stage.write_ledger(path,data)
    if data.get('venueBuildBasePhase') in ('preparing','inert-ready'):
        data['venueBuildBasePhase']='retired-inert';stage.write_ledger(path,data)
    if data.get('venueLocalBuildPhase') in ('preparing','inert-ready','abandoned-inert'):
        data['venueLocalBuildPhase']='retired-inert';stage.write_ledger(path,data)
    data['venueCompositeMode']='retired-inert';stage.write_ledger(path,data)
    return {'status':'retired-inert','activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    path,data,plan=context(bundle,selector,ledger)
    if (data.get('venueCompositeVersion')==2 and data.get('venueCompositeMode')=='retiring' and
            data.get('status') in ('managers-ready','graphs-clearing') and
            len(data.get('retiredUnits',[]))==194 and
            not data.get('podmanImageCacheRetired')):
        # Only graph metadata remains. Re-check the full exact 8-store image
        # inventory inside graph.clear before removing ANY image; never rerun
        # earlier bind/volume/unit deletion against a partially unwound stage.
        return finish_graph_retirement(bundle,selector,ledger)
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
    # Never delete a selected unit while a foreign graph object remains.
    offline=data.get('venueCompositeOfflineImages',[])
    selected_images=graph.selected_images(bundle)
    expected={a['name']:set() for a in plan['accounts']};expected['root']=set()
    frozen_profile=json.loads((Path(bundle)/'stack.ir.json').read_text()).get('quadletBuildImagesFrozen') is True
    maximum=len(set().union(*selected_images.values())) if frozen_profile else 1
    if not isinstance(offline,list) or len(offline)>maximum:
        raise Refusal('journaled offline images exceed selected frozen/legacy authority')
    for row in offline:
        if (not isinstance(row,dict) or not isinstance(row.get('authorities'),list) or
                not row['authorities'] or not isinstance(row.get('image'),str)):
            raise Refusal('journaled offline image authority malformed')
        for user in row['authorities']:
            if user not in expected or row['image'] not in selected_images.get(user,set()):
                raise Refusal('offline image/authority differs from selected site')
            expected[user].add(row['image'])
    registry_mode=data.get('venueRegistryPhase')
    if registry_mode is not None:
        source=graph.selected_images(bundle)
        frozen=images.selected_image_ids(Path(bundle))
        progress=data.get('venueRegistryVerified')
        if (registry_mode not in ('preparing','inert-ready') or data.get('venueRegistryPending') or
                data.get('venueRegistryPlan')!=frozen or not isinstance(progress,dict) or
                any(key not in frozen or frozen[key]!=value for key,value in progress.items()) or
                (registry_mode=='inert-ready' and progress!=frozen)):
            raise Refusal('registry image progress differs from selected site')
        for key,value in progress.items():
            user,sep,_=key.partition('|')
            if not sep or user not in expected or value not in source.get(user,set()):
                raise Refusal('registry image not selected for exact graph authority')
            expected[user].add(value)
    for observed in (graph.journaled_build_base_ids(bundle,selector,data),
                     graph.journaled_local_output_ids(bundle,selector,data)):
        for user,values in observed.items():
            if user not in expected:raise Refusal('build graph authority unknown')
            expected[user].update(values)
    for user,_,command in graph.stores(bundle,plan):
        def listing(args):
            result=graph.run(command+args)
            if result.returncode:raise Refusal('isolated graph object inventory unavailable')
            return set(result.stdout.splitlines())
        if listing(['ps','-aq']) or listing(['pod','ps','--quiet']):
            raise Refusal('running or stopped container/pod in inert venue graph')
        volumes=listing(['volume','ls','-q'])
        if volumes!=(set(huly.NAMES) if user==apps['name'] else set()):
            raise Refusal('foreign or missing named volume in inert venue graph')
        if listing(['network','ls','--format','{{.Name}}'])-{'podman'}:
            raise Refusal('foreign network in inert venue graph')
        found={('sha256:'+value.removeprefix('sha256:')) for value in listing(['image','ls','-a','--no-trunc','--format','{{.ID}}'])}
        if found!=expected[user]:
            raise Refusal('missing or unjournaled image in inert venue graph')
    data['venueCompositeMode']='retiring';stage.write_ledger(path,data)
    units.retire(bundle,selector,ledger)
    huly.retire(bundle,selector,ledger)
    acl.restore(bundle,selector,ledger)
    binds.retire(bundle,selector,ledger)
    return finish_graph_retirement(bundle,selector,ledger)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('bundle','selector','ledger'):p.add_argument('--'+k,required=True)
    p.add_argument('--image-inputs')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true');mode.add_argument('--retire',action='store_true')
    mode.add_argument('--recover-failed-import',action='store_true')
    a=p.parse_args()
    try:
        if not a.prepare and a.image_inputs:raise Refusal('retirement takes image authority only from durable journal')
        result=(prepare(a.bundle,a.selector,a.ledger,a.image_inputs) if a.prepare else
                recover_failed_import(a.bundle,a.selector,a.ledger) if a.recover_failed_import else
                retire(a.bundle,a.selector,a.ledger))
        print(json.dumps(result,sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,IndexError) as exc:
        raise SystemExit('inert composite venue refused: '+str(exc)) from exc
if __name__=='__main__':main()
