#!/usr/bin/env python3
"""Versioned exact-CAS FULL INERT venue preparation and reverse retirement.

One release journal coordinates source, selected accounts, rendered aggregate
and seven private domain releases, 75 env files, seven managers, 61 binds,
three ACLs, four Huly volumes, 194 INACTIVE units and exact offline inputs.
Version-1 preparation/retirement MUST NOT activate anything. Only explicit
--activate-isolated upgrades a fresh exact frozen stage to a version-2 intent,
issues current-boot authority under the controller lifecycle lock, and queues
native startup. Failed starts fence/cancel/stop exact units, retaining data.
No populated reset or guest mutation is implied; running is not acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
stage=load('venue_stage','venue-owned-stage.py')
release=load('venue_release','venue-release-inert.py')
domains=load('venue_domains','venue-domain-runtime-inert.py')
managers=load('venue_managers','venue-user-managers.py')
envs=load('venue_envs','venue-runtime-env-inert.py')
composite=load('venue_composite','venue-composite-inert.py')
graph=load('venue_graph','venue-graph-clear.py')
Refusal=stage.Refusal

def receipt(ledger):
    p=Path(ledger);s=p.lstat()
    if p.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:
        raise Refusal('exact root0600 release journal required')
    return json.loads(p.read_text())

def context(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root-only isolated venue installer')
    b=Path(bundle);p=Path(ledger)
    if not b.is_dir() or b.is_symlink() or p.parent.is_symlink() or not p.parent.is_dir() or p.parent.stat().st_uid!=0 or stat.S_IMODE(p.parent.stat().st_mode)!=0o700:
        raise Refusal('private clean source and root0700 journal parent required')
    plan=stage.owned_plan(b,selector)
    if plan['prefix']!='p0test-r1' or plan.get('activationAuthorized') is not False:
        raise Refusal('isolated source CAS does not match selected venue')
    return b,p,plan

def prepare(bundle,selector,inventory,ledger,age_key,image_inputs):
    b,p,plan=context(bundle,selector,ledger)
    if os.path.lexists(p):raise Refusal('release journal already exists; no reuse or overwrite')
    key=Path(age_key);st=key.lstat()
    if key.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o077:
        raise Refusal('root-owned private SOPS key input required')
    input_manifest=Path(image_inputs);i=input_manifest.lstat()
    if input_manifest.is_symlink() or not stat.S_ISREG(i.st_mode) or i.st_uid!=0:
        raise Refusal('selected image manifest changed')
    rows=composite.images.validate(b,input_manifest)
    offline=composite.offline_plan(b,plan,[{'image':image,'authorities':users} for image,_,users in rows])
    # Baseline stage itself validates protected host preflight/inventory and
    # journals every newly created account, config and directory BEFORE use.
    stage.stage(b,selector,inventory,p,mutate=True)
    data=receipt(p)
    if data['plan']!=plan or data['status']!='staged-empty':raise Refusal('selected stage CAS differs')
    data['venueInstallerVersion']=1;data['venueInstallerPhase']='preparing';stage.write_ledger(p,data)
    release.prepare(b,selector,p,key)
    domains.prepare(b,selector,p)
    managers.act(b,selector,p)
    envs.prepare(b,selector,p)
    composite.prepare(b,selector,p,input_manifest)
    composite.binds.prepare_logs(b,selector,p)
    data=receipt(p)
    marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
    if (data.get('venueReleasePhase')!='inert-ready' or data.get('venueDomainRuntimePhase')!='inert-ready' or
            data.get('venueRuntimeEnvPhase')!='inert-ready' or data.get('venueCompositeMode')!='inert-ready' or
            data.get('status')!='units-staged' or marker.exists() or
            len(data.get('venueRuntimeEnvFiles',{}))!=75 or len(data.get('installedUnits',[]))!=194 or
            len(data.get('venueDataBindDirs',[]))!=61 or len(data.get('venueHulyVolumes',[]))!=4 or
            data.get('venueCompositeOfflineImages')!=offline):
        raise Refusal('inert installer co-presence invariants not met')
    data['venueInstallerPhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':'inert-ready','rootlessCurrentTrees':7,'privateEnvFiles':75,
            'actualBindDirectories':61,'namedVolumes':4,'installedInactiveUnits':194,
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,inventory,ledger):
    b,p,plan=context(bundle,selector,ledger);data=receipt(p)
    if (data.get('plan')!=plan or data.get('venueInstallerVersion')!=1 or
            data.get('venueInstallerPhase') not in ('inert-ready','retiring') or
            data.get('activationAuthorized') is not False):
        raise Refusal('inert installed-release journal differs or is not retireable')
    if data['venueInstallerPhase']=='inert-ready':
        if any(data.get(k)!='inert-ready' for k in ('venueReleasePhase','venueDomainRuntimePhase',
                    'venueRuntimeEnvPhase')):
            raise Refusal('private inputs must coexist before initial retirement')
        if data.get('venueCompositeMode')=='inert-ready' and data.get('status')=='units-staged':
            pass
        elif data.get('venueCompositeMode')=='retired-inert' and data.get('status')=='managers-ready':
            # A caller may have already retired the exact composite to inspect
            # build-output graph rollback. Adopt ONLY that completed ledger,
            # never a partly cleared graph or active installed unit.
            if (data.get('graphCleared')!=['root']+[a['name'] for a in plan['accounts']] or
                    data.get('managerStopped') or len(data.get('installedUnits',[]))!=194 or
                    len(data.get('retiredUnits',[]))!=194 or
                    any(data.get(k)!='retired-inert' for k in
                        ('venueRegistryPhase','venueBuildBasePhase')) or
                    not data.get('podmanImageCacheRetired') or
                    (Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt').exists()):
                raise Refusal('external selected composite retirement is incomplete')
        else:
            raise Refusal('all 194 units and private inputs must coexist before initial retirement')
        data['venueInstallerPhase']='retiring';stage.write_ledger(p,data)
    if receipt(p).get('venueLogBindDirs'):composite.binds.retire_logs(b,selector,p)
    if receipt(p).get('venueCompositeMode')!='retired-inert':composite.retire(b,selector,p)
    if receipt(p).get('venueRuntimeEnvPhase')!='retired-inert':envs.retire(b,selector,p)
    if receipt(p).get('status')!='staged-empty':managers.act(b,selector,p,stop=True)
    if receipt(p).get('venueCompositeVersion') and not receipt(p).get('podmanRunrootRetired'):
        graph.retire_empty_runroot(b,selector,p)
    if receipt(p).get('venueDomainRuntimePhase')!='retired-inert':domains.retire(b,selector,p)
    if receipt(p).get('venueReleasePhase')!='retired-inert':release.retire(b,selector,p)
    if receipt(p).get('status')!='retired-empty':stage.retire_empty(b,selector,p)
    data=receipt(p)
    if data['status']!='retired-empty':raise Refusal('exact release retirement incomplete')
    data['venueInstallerPhase']='retired-inert';stage.write_ledger(p,data)
    return {'status':'retired-inert','activationAuthorized':False,'acceptedIntegratedInstalls':0}

def activate(bundle,selector,ledger,*,reviewed_failed_sha=None):
    lifecycle=load('venue_lifecycle','venue-start-quarantine.py')
    try:return lifecycle.start(bundle,selector,ledger,**({'reviewed_failed_sha':reviewed_failed_sha} if reviewed_failed_sha is not None else {}))
    except Exception as failure:
        state=receipt(ledger)
        if state.get('venueInstallerVersion')==2 and state.get('venueStartPhase') in ('starting','running','failed-quarantining'):
            try:lifecycle.quarantine(bundle,selector,ledger)
            except Exception as stop_failure:
                raise Refusal('activation failed: '+str(failure)+'; exact quarantine incomplete: '+str(stop_failure)) from stop_failure
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','protected-inventory','ledger'):p.add_argument('--'+key,required=True)
    p.add_argument('--sops-age-key-file');p.add_argument('--image-inputs')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare-inactive',action='store_true')
    mode.add_argument('--retire-inactive',action='store_true')
    mode.add_argument('--activate-isolated',action='store_true')
    mode.add_argument('--quarantine-start',action='store_true')
    mode.add_argument('--retry-reviewed-failed-sha',metavar='SHA256')
    a=p.parse_args()
    try:
        if a.prepare_inactive:
            if not a.sops_age_key_file or not a.image_inputs:raise Refusal('exact SOPS/image inputs required')
            result=prepare(a.bundle,a.selector,a.protected_inventory,a.ledger,a.sops_age_key_file,a.image_inputs)
        else:
            if a.sops_age_key_file or a.image_inputs:raise Refusal('lifecycle actions must not accept new secret/image inputs')
            if a.activate_isolated:result=activate(a.bundle,a.selector,a.ledger)
            elif a.retry_reviewed_failed_sha is not None:
                result=activate(a.bundle,a.selector,a.ledger,reviewed_failed_sha=a.retry_reviewed_failed_sha)
            elif a.quarantine_start:
                result=load('venue_lifecycle','venue-start-quarantine.py').quarantine(a.bundle,a.selector,a.ledger)
            else:result=retire(a.bundle,a.selector,a.protected_inventory,a.ledger)
        print(json.dumps(result,sort_keys=True))
    except (Refusal,KeyError,TypeError,ValueError,OSError) as exc:
        raise SystemExit('venue versioned installer refused: '+str(exc)) from exc
if __name__=='__main__':main()
