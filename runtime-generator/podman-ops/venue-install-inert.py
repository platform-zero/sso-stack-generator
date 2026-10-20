#!/usr/bin/env python3
"""Versioned exact-CAS FULL INERT venue preparation and reverse retirement.

One release journal coordinates source, selected accounts, rendered aggregate
and seven private domain releases, 75 env files, seven managers, 54 binds,
three ACLs, four Huly volumes, 190 INACTIVE units and exact offline inputs.
Version-1 preparation/retirement MUST NOT activate anything. Only explicit
--activate-isolated upgrades a fresh exact frozen stage to a version-2 intent,
issues current-boot authority under the controller lifecycle lock, and queues
native startup. Failed starts fence/cancel/stop exact units, retaining data.
Only explicit --reset-experimental-owned-sha permits exact owned experimental
content deletion after quarantine. No production reset or guest mutation is
implied; running is not acceptance.
"""
import argparse
import importlib.util
import json
import os
import shutil
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode=True
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
ingress=load('venue_private_ingress','venue-private-ingress.py')
root_health=load('venue_root_health','venue-root-health.py')
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
    composite.binds.prepare_fixtures(b,selector,p)
    ingress.prepare(b,selector,p)
    root_health.prepare(b,selector,p)
    data=receipt(p)
    marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
    if (data.get('venueReleasePhase')!='inert-ready' or data.get('venueDomainRuntimePhase')!='inert-ready' or
            data.get('venueRuntimeEnvPhase')!='inert-ready' or data.get('venueCompositeMode')!='inert-ready' or
            data.get('status')!='units-staged' or data.get('venueIngressPhase')!='inert-ready' or data.get('venueRootHealthPhase')!='inert-ready' or marker.exists() or
            len(data.get('venueRuntimeEnvFiles',{}))!=75 or len(data.get('installedUnits',[]))!=190 or
            len(data.get('venueDataBindDirs',[]))!=54 or len(data.get('venueHulyVolumes',[]))!=4 or
            data.get('venueCompositeOfflineImages')!=offline):
        raise Refusal('inert installer co-presence invariants not met')
    data['venueInstallerPhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':'inert-ready','rootlessCurrentTrees':7,'privateEnvFiles':75,
            'actualBindDirectories':54,'namedVolumes':4,'installedInactiveUnits':190,'privateInactiveRelayUnits':8,'privateInactiveHealthUnits':2,
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,inventory,ledger):
    b,p,plan=context(bundle,selector,ledger);data=receipt(p)
    reset=data.get('venueOwnedReset',{})
    reset_complete=(reset.get('phase')=='empty-owned' and reset.get('quadletTreeSha256')==plan['quadletTreeSha256'] and
                    reset.get('contextSha256')==data.get('venueStartHostContextSha256') and
                    set(reset.get('emptied',[]))=={row['path'] for row in reset.get('directories',[])} and
                    len(reset.get('directories',[]))>=54+4 and
                    set(reset.get('retiredNetworks',[]))=={row['id'] for row in reset.get('networks',{}).values()})
    version_ok=data.get('venueInstallerVersion')==1 or (data.get('venueInstallerVersion')==2 and reset_complete)
    if (data.get('plan')!=plan or not version_ok or
            data.get('venueInstallerPhase') not in ('inert-ready','reset-complete','retiring') or
            data.get('activationAuthorized') is not False):
        raise Refusal('inert installed-release journal differs or is not retireable')
    if data['venueInstallerPhase'] in ('inert-ready','reset-complete'):
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
                    data.get('managerStopped') or len(data.get('installedUnits',[]))!=190 or
                    len(data.get('retiredUnits',[]))!=190 or
                    any(data.get(k)!='retired-inert' for k in
                        ('venueRegistryPhase','venueBuildBasePhase')) or
                    not data.get('podmanImageCacheRetired') or
                    (Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt').exists()):
                raise Refusal('external selected composite retirement is incomplete')
        else:
            raise Refusal('all 190 units and private inputs must coexist before initial retirement')
        data['venueInstallerPhase']='retiring';stage.write_ledger(p,data)
    current=receipt(p)
    if current.get('venueRootHealthPhase') and current['venueRootHealthPhase']!='retired-inert':root_health.retire(b,selector,p)
    if current.get('venueIngressPhase') and current['venueIngressPhase']!='retired-inert':ingress.retire(b,selector,p)
    current=receipt(p)
    if current.get('venueFixtureBindDirs') and {r['path'] for r in current['venueFixtureBindDirs']}!=set(current.get('retiredFixtureBindDirs',[])):
        composite.binds.retire_fixtures(b,selector,p)
    if receipt(p).get('venueLogBindDirs'):composite.binds.retire_logs(b,selector,p)
    if receipt(p).get('venueCompositeMode')!='retired-inert':composite.retire(b,selector,p)
    if receipt(p).get('venueRuntimeEnvPhase')!='retired-inert':envs.retire(b,selector,p)
    current=receipt(p)
    if current.get('status')!='staged-empty':
        # A native run installed three separately receipted host control units.
        # Retire them only after graph/unit/env retirement, before the unchanged
        # manager empty-unit gate. Never make that gate ignore installed units.
        if (current.get('venueInstallerVersion')==2 and
                current.get('venueHostUnitsRetirement',{}).get('phase')!='retired'):
            lifecycle=load('venue_retire_lifecycle','venue-start-quarantine.py')
            lifecycle.retire_host_units(b,selector,p,stage.sha(p))
        managers.act(b,selector,p,stop=True)
    if receipt(p).get('venueCompositeVersion') and not receipt(p).get('podmanRunrootRetired'):
        graph.retire_empty_runroot(b,selector,p)
    if receipt(p).get('venueDomainRuntimePhase')!='retired-inert':domains.retire(b,selector,p)
    if receipt(p).get('venueReleasePhase')!='retired-inert':release.retire(b,selector,p)
    if receipt(p).get('status')!='retired-empty':stage.retire_empty(b,selector,p)
    data=receipt(p)
    if data['status']!='retired-empty':raise Refusal('exact release retirement incomplete')
    data['venueInstallerPhase']='retired-inert';stage.write_ledger(p,data)
    return {'status':'retired-inert','activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire_interrupted_import(bundle,selector,inventory,ledger,expected_sha):
    """Explicit CAS abort of a full190-unit, never-activated offline import.

    This is retirement of actual partial preparation, NOT inert-ready promotion,
    successful preparation, populated reset or a retry of the failed import.
    """
    b,p,plan=context(bundle,selector,ledger);data=receipt(p)
    if (not isinstance(expected_sha,str) or len(expected_sha)!=64 or
            any(c not in '0123456789abcdef' for c in expected_sha) or stage.sha(p)!=expected_sha):
        raise Refusal('interrupted import retirement ledger CAS changed')
    intent=data.get('venueInterruptedImportRetirement')
    image_sha=data.get('venueCompositeImageInputSha256')
    if (not isinstance(image_sha,str) or len(image_sha)!=64 or any(c not in '0123456789abcdef' for c in image_sha) or
            (intent is not None and (not isinstance(intent,dict) or
                set(intent)!={'originalLedgerSha256','imageInputSha256','phase'} or
                intent.get('phase')!='retiring-incomplete' or intent.get('imageInputSha256')!=image_sha or
                not isinstance(intent.get('originalLedgerSha256'),str) or len(intent['originalLedgerSha256'])!=64 or
                any(c not in '0123456789abcdef' for c in intent['originalLedgerSha256'])))):
        raise Refusal('interrupted import authority/retirement intent malformed')
    if (data.get('plan')!=plan or data.get('venueInstallerVersion')!=1 or
            data.get('venueInstallerPhase') not in ('preparing','retiring') or
            (data.get('venueInstallerPhase')=='retiring' and not intent) or data.get('activationAuthorized') is not False or
            len(data.get('installedUnits',[]))!=190 or data.get('venueStartPhase') or
            any(data.get(k)!='inert-ready' for k in ('venueReleasePhase','venueDomainRuntimePhase','venueRuntimeEnvPhase')) or
            any(k in data for k in ('venueIngressPhase','venueRootHealthPhase','venueRegistryPhase','venueBuildBasePhase','venueLocalBuildPhase')) or
            (not intent and (data.get('venueCompositeMode')!='images-importing' or data.get('status')!='units-staged'))):
        raise Refusal('only exact full-unit never-activated interrupted offline preparation may be aborted')
    if not intent:
        data['venueInterruptedImportRetirement']={'originalLedgerSha256':expected_sha,
            'imageInputSha256':data.get('venueCompositeImageInputSha256'),'phase':'retiring-incomplete'}
    # Enter actual retirement intent BEFORE composite graph removal. Frozen
    # multi-alias removal must see the strict never-activated retiring state;
    # leaving this as preparing would wrongly select legacy build-base logic.
    data['venueInstallerPhase']='retiring';stage.write_ledger(p,data)
    mode=receipt(p).get('venueCompositeMode')
    if mode=='images-importing':composite.recover_failed_import(b,selector,p)
    elif mode in ('interrupted-import-retiring','retiring'):composite.retire(b,selector,p)
    elif mode!='retired-inert':raise Refusal('interrupted composite retirement phase changed')
    data=receipt(p)
    if (data.get('venueCompositeMode')!='retired-inert' or data.get('status')!='managers-ready' or
            len(data.get('retiredUnits',[]))!=190 or
            data.get('graphCleared')!=['root']+[a['name'] for a in plan['accounts']] or
            not data.get('podmanImageCacheRetired') or data.get('managerStopped')):
        raise Refusal('interrupted composite did not finish exact unit/store retirement')
    data['venueInstallerPhase']='retiring';stage.write_ledger(p,data)
    result=retire(b,selector,inventory,p)
    data=receipt(p);data['venueInterruptedImportRetirement']['phase']='retired-incomplete';stage.write_ledger(p,data)
    return dict(result,retiredIncompletePreparation=True,servicesStarted=False)


def empty_owned_directory(row):
    """Keep the receipted top inode; remove only its children using dir-fds."""
    if not shutil.rmtree.avoids_symlink_attacks:raise Refusal('fd-safe recursive deletion required')
    path=Path(row['path']);info=path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino)!=(row['dev'],row['ino']):
        raise Refusal('owned reset directory inode changed')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(row['dev'],row['ino']):raise Refusal('reset directory open CAS changed')
        for name in os.listdir(fd):
            child=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                if child.st_dev!=opened.st_dev:raise Refusal('nested filesystem in selected reset directory')
                shutil.rmtree(name,dir_fd=fd)
            else:os.unlink(name,dir_fd=fd)
        os.fchown(fd,row['restoreUid'],row.get('restoreGid',row['restoreUid']));os.fchmod(fd,row.get('restoreMode',0o700))
        if os.listdir(fd):raise Refusal('selected reset directory repopulated')
        os.fsync(fd)
    finally:os.close(fd)

def no_data_mounts(rows):
    def fields(line):return [value.replace('\\040',' ').replace('\\134','\\') for value in line.split()]
    own=[fields(line) for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    selected=[]
    for row in rows:
        path=Path(row['path']);dev=f"{os.major(row['dev'])}:{os.minor(row['dev'])}"
        parents=[entry for entry in own if len(entry)>=5 and entry[2]==dev and
                 (str(path)==entry[4] or str(path).startswith(entry[4].rstrip('/')+'/'))]
        if not parents:raise Refusal('selected data filesystem root unavailable')
        parent=max(parents,key=lambda entry:len(entry[4]))
        if str(path)==parent[4]:raise Refusal('never reset a whole mounted filesystem')
        root=str(Path(parent[3])/path.relative_to(parent[4])).rstrip('/')
        if root in ('','/'):raise Refusal('never reset a whole filesystem')
        selected.append((dev,root))
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:lines=(process/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,ProcessLookupError):continue
        except OSError as exc:raise Refusal('cannot establish absence of selected data mounts') from exc
        for line in lines:
            entry=fields(line)
            if len(entry)>=5 and any(entry[2]==dev and (entry[3]==root or entry[3].startswith(root+'/')) for dev,root in selected):
                raise Refusal('selected owned data remains mounted in a process namespace')

def reset_owned(bundle,selector,inventory,ledger,reviewed_sha):
    """Explicit experimental deletion, never a production/owner-data reset RPC."""
    b,p,plan=context(bundle,selector,ledger);lifecycle=load('owned_reset_lifecycle','venue-start-quarantine.py')
    controller=lifecycle.host_context(b,plan);registry=load('owned_reset_registry','venue-registry-images.py')
    with lifecycle.lifecycle(controller):
        if stage.sha(p)!=reviewed_sha:raise Refusal('experimental reset ledger SHA CAS changed')
        data=receipt(p);lifecycle.reviewed_retry(data,plan,controller,require_repair=False)
        lifecycle.targets(b,plan,data,selector=selector,ledger=ledger);lifecycle.units.units_idle(plan)
        vm=json.loads((b/'site/agent-vm.json').read_text())
        listed=graph.run(['virsh','-c','qemu:///system','list','--all','--name'],timeout=30)
        if listed.returncode or vm['name'] in listed.stdout.splitlines():
            raise Refusal('selected guest requires separate exact owned retirement before stack reset')
        for account,command in lifecycle.selected_commands(plan):
            if account and account['name'] in data.get('venueStartApiSockets',[]):
                result=graph.run(command+['show','podman.socket','podman.service','-p','ActiveState'],timeout=30)
                if result.returncode or any(line not in ('ActiveState=inactive','ActiveState=failed','') for line in result.stdout.splitlines()):
                    raise Refusal('selected API not fully fenced before owned reset')
        for name,record in data['pathIdentities'].items():
            path=Path(name);info=path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino,info.st_uid)!=(record['dev'],record['ino'],record['uid']):
                raise Refusal('reset ancestor/source identity changed')
        authority=registry.authority.authority(b,selector)
        roots,_=registry.probe(b,plan,data,authority['imageIds'],recovering=True)
        if data.get('venueRecoveryContainers'):raise Refusal('exact stopped-native cleanup required before data reset')
        sources=composite.binds.inventory(b,selector,plan);rows=[]
        if set(sources)!={row['path'] for row in data.get('venueDataBindDirs',[])} or len(sources)!=54:
            raise Refusal('all 54 original selected data binds required for reset')
        for row in data['venueDataBindDirs']:rows.append({**row,'restoreUid':sources[row['path']]['owner'],'restoreGid':sources[row['path']]['owner']})
        logs=composite.binds.log_sources(b,plan)
        if logs!={row['path']:row['consumers'] for row in data.get('venueLogBindDirs',[])}:raise Refusal('actual owned log set differs')
        rows.extend({**row,'restoreUid':0,'restoreGid':0} for row in data.get('venueLogBindDirs',[]))
        fixtures=composite.binds.checked_fixtures(b,plan,data)
        rows.extend({**row,'restoreUid':row['uid'],'restoreGid':row['uid'],'restoreMode':row['mode']} for row in fixtures if row['kind']=='fixture')
        apps=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-apps')
        if composite.huly.inventory(apps)!=set(composite.huly.NAMES) or len(data.get('venueHulyVolumes',[]))!=4:
            raise Refusal('four exact original named volumes required')
        for row in data['venueHulyVolumes']:
            path=composite.huly.mountpoint(apps,row['name'])
            if str(path)!=row['mountpoint']:raise Refusal('named reset volume mountpoint drift')
            rows.append({**row,'path':str(path),'restoreUid':path.lstat().st_uid,'restoreGid':path.lstat().st_gid})
        paths=[Path(row['path']) for row in rows]
        if len(set(paths))!=len(paths) or any(a in b.parents for a in paths for b in paths if a!=b):
            raise Refusal('owned reset roots duplicate or overlap')
        for row in rows:
            path=Path(row['path']);info=path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino)!=(row['dev'],row['ino']):
                raise Refusal('selected populated directory is not original created inode')
        no_data_mounts(rows)
        marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
        prior_reset=data.get('venueOwnedReset',{})
        marker_removed=(not os.path.lexists(marker) and data.get('venueOwnedResetPending')=={'marker':str(marker)} and
                        prior_reset.get('phase')=='intent' and len(prior_reset.get('emptied',[]))==len(rows))
        if not marker_removed:
            info=marker.lstat()
            if (marker.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or
                    stat.S_IMODE(info.st_mode)!=0o600 or marker.read_text()!=plan['prefix']+'-volume-ready-v1\n'):
                raise Refusal('owned reset readiness marker changed')
        reset=data.setdefault('venueOwnedReset',{'phase':'intent','contextSha256':controller.digest,
            'quadletTreeSha256':plan['quadletTreeSha256'],'sourceSha256':stage.sha(__file__),
            'directories':rows,'networks':data['venueRecoveryNetworks'],'emptied':[],'retiredNetworks':[]})
        if reset['contextSha256']!=controller.digest or reset['directories']!=rows:raise Refusal('interrupted reset identity differs')
        stage.write_ledger(p,data)
        for key,proof in reset['networks'].items():
            if proof['id'] in reset['retiredNetworks']:continue
            user=key.split('|',1)[0];data['venueOwnedResetPending']={'network':proof['id']};stage.write_ledger(p,data)
            if graph.run(roots[user][1]+['network','rm',proof['id']],timeout=60).returncode:
                raise Refusal('exact native network removal failed; reset intent retained')
            reset['retiredNetworks'].append(proof['id']);stage.write_ledger(p,data)
        registry.probe(b,plan,data,authority['imageIds'])
        for row in rows:
            if row['path'] in reset['emptied']:continue
            data['venueOwnedResetPending']={'directory':row['path']};stage.write_ledger(p,data)
            empty_owned_directory(row);reset['emptied'].append(row['path']);stage.write_ledger(p,data)
        for path,users in composite.acl.policy(plan,sources):
            composite.acl.call(['setfacl','-b','-k',str(path)])
            composite.acl.call(['setfacl','--set='+','.join(composite.acl.granted_rows(users)),str(path)])
            if composite.acl.permission_rows(path)!=composite.acl.granted_rows(users):raise Refusal('reset ACL matrix differs')
        data['venueOwnedResetPending']={'marker':str(marker)};stage.write_ledger(p,data)
        if not marker_removed:marker.unlink()
        fd=os.open(marker.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        reset['phase']='empty-owned';data.pop('venueOwnedResetPending');data['status']='units-staged'
        data['venueInstallerPhase']='reset-complete';stage.write_ledger(p,data)
        return {'status':'reset-complete','emptiedExactOwnedDirectories':len(rows),
                'retiredExactNativeNetworks':len(reset['retiredNetworks']),'backupsCreated':False,
                'servicesStarted':False,'activationAuthorized':False,'acceptedIntegratedInstalls':0}


def activate(bundle,selector,ledger,*,reviewed_failed_sha=None):
    lifecycle=load('venue_lifecycle','venue-start-quarantine.py')
    try:return lifecycle.start(bundle,selector,ledger,**({'reviewed_failed_sha':reviewed_failed_sha} if reviewed_failed_sha is not None else {}))
    except Exception as failure:
        state=receipt(ledger)
        if state.get('venueInstallerVersion')==2 and state.get('venueStartPhase') in ('starting','running','failed-quarantining'):
            try:lifecycle.quarantine(bundle,selector,ledger,failure_reason=str(failure))
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
    mode.add_argument('--retire-interrupted-import-sha',metavar='SHA256')
    mode.add_argument('--activate-isolated',action='store_true')
    mode.add_argument('--quarantine-start',action='store_true')
    mode.add_argument('--retry-reviewed-failed-sha',metavar='SHA256')
    mode.add_argument('--reset-experimental-owned-sha',metavar='SHA256')
    a=p.parse_args()
    try:
        if a.prepare_inactive:
            if not a.sops_age_key_file or not a.image_inputs:raise Refusal('exact SOPS/image inputs required')
            result=prepare(a.bundle,a.selector,a.protected_inventory,a.ledger,a.sops_age_key_file,a.image_inputs)
        else:
            if a.sops_age_key_file or a.image_inputs:raise Refusal('lifecycle actions must not accept new secret/image inputs')
            if a.retire_interrupted_import_sha is not None:
                result=retire_interrupted_import(a.bundle,a.selector,a.protected_inventory,a.ledger,a.retire_interrupted_import_sha)
            elif a.activate_isolated:result=activate(a.bundle,a.selector,a.ledger)
            elif a.retry_reviewed_failed_sha is not None:
                result=activate(a.bundle,a.selector,a.ledger,reviewed_failed_sha=a.retry_reviewed_failed_sha)
            elif a.reset_experimental_owned_sha is not None:
                result=reset_owned(a.bundle,a.selector,a.protected_inventory,a.ledger,a.reset_experimental_owned_sha)
            elif a.quarantine_start:
                result=load('venue_lifecycle','venue-start-quarantine.py').quarantine(a.bundle,a.selector,a.ledger)
            else:result=retire(a.bundle,a.selector,a.protected_inventory,a.ledger)
        print(json.dumps(result,sort_keys=True))
    except (Refusal,KeyError,TypeError,ValueError,OSError) as exc:
        raise SystemExit('venue versioned installer refused: '+str(exc)) from exc
if __name__=='__main__':main()
