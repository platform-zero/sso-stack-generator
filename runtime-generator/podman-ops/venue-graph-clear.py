#!/usr/bin/env python3
"""Retire exact, exclusively staged Podman image graphs with ZERO live objects.

Only for the seven-account/rootful venue before any service/volume activity.
Not a substitute for an installed 95-service scoped reset. Refuses foreign
images, any containers/pods/volumes or non-default networks. No global prune.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_owned_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def run(command,*,check=False,timeout=45):
    return subprocess.run(command,check=check,capture_output=True,text=True,timeout=timeout,cwd='/')

def stores(bundle,plan):
    r=plan['roots'];out=[('root',r['rootful-graph'],[
        'env','CONTAINERS_STORAGE_CONF='+r['rootful-state']+'/containers-storage.conf',
        'CONTAINERS_CONF='+r['rootful-state']+'/containers.conf',
        'podman','--root',r['rootful-graph'],'--runroot',r['rootful-run'],
        '--network-config-dir',r['rootful-state']+'/networks'])]
    for a in plan['accounts']:
        uid=a['uid'];out.append((a['name'],a['graph'],['runuser','-u',a['name'],'--','env','-u','CONTAINERS_STORAGE_CONF',
            'HOME='+a['home'],'XDG_RUNTIME_DIR=/run/user/'+str(uid),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(uid)+'/bus','podman']))
    return out

def selected_images(bundle):
    path=Path(bundle)/'site/global.settings/registry-image-ids.json'
    if path.is_symlink() or not path.is_file():raise Refusal('missing site-pinned image identities')
    identities=json.loads(path.read_text())
    if not isinstance(identities,dict) or not identities:raise Refusal('empty frozen image authority')
    out={}
    for key,value in identities.items():
        user,sep,image=key.partition('|')
        if not sep or not user or not image or not isinstance(value,str) or not value.startswith('sha256:') or len(value)!=71:
            raise Refusal('malformed selected frozen image identity')
        out.setdefault(user,set()).add(value)
    return out

def journaled_build_base_ids(bundle,selector,state,source=None):
    """Only locally inspect exactly journaled FROM identities before removal."""
    phase=state.get('venueBuildBasePhase')
    if phase is None:return {}
    source_spec=importlib.util.spec_from_file_location('venue_image_authority',HERE/'venue-image-authority.py')
    authority=importlib.util.module_from_spec(source_spec);source_spec.loader.exec_module(authority)
    if source is None:source=authority.authority(bundle,selector)
    verified=state.get('venueBuildBaseVerified')
    if (phase not in ('preparing','inert-ready') or state.get('venueBuildBasePending') or
            state.get('venueRegistryPhase')!='inert-ready' or
            state.get('venueBuildBasePlan')!=source['buildBaseStores'] or
            state.get('venueBuildBaseFrozenSha256')!=source['frozenBuildBaseSha256'] or
            not source['frozenBuildBaseSha256'] or not isinstance(verified,dict) or
            any(k not in source['buildBaseStores'] or not isinstance(v,str) or
                not authority.HEX.fullmatch(v) for k,v in verified.items()) or
            (phase=='inert-ready' and set(verified)!=set(source['buildBaseStores']))):
        raise Refusal('build-base image journal lacks exact selected FROM authority')
    commands={user:command for user,_,command in stores(bundle,stage.owned_plan(bundle,selector))}
    result={user:set() for user in commands}
    partially_clearing=state.get('status')=='graphs-clearing'
    for key,value in verified.items():
        user,sep,ref=key.partition('|');pinned=source['buildBaseImages'].get(key)
        if (not sep or user not in commands or
                (pinned and value!=pinned['configId']) or
                (not pinned and not re.search(r'@sha256:[0-9a-f]{64}\Z',ref))):
            raise Refusal('build-base key/config ID differs from selected source')
        if user in state.get('graphCleared',[]):
            result[user].add(value);continue
        observed=run(commands[user]+['image','inspect','--format','{{.Id}}',ref],timeout=35)
        arch=run(commands[user]+['image','inspect','--format','{{.Architecture}}/{{.Os}}',ref],timeout=35)
        if observed.returncode and partially_clearing and arch.returncode:
            # Earlier exact graph removal can have deleted this previously
            # attested image. The full graph inventory below must still be a
            # subset of the immutable selected IDs; record any absent IDs.
            result[user].add(value);continue
        if (observed.returncode or arch.returncode or arch.stdout.strip()!='amd64/linux' or
                'sha256:'+observed.stdout.strip().removeprefix('sha256:')!=value):
            raise Refusal('local selected build FROM image/tag drift')
        result[user].add(value)
    return result

def journaled_local_output_ids(bundle,selector,state,source=None):
    phase=state.get('venueLocalBuildPhase')
    if phase is None:return {}
    spec=importlib.util.spec_from_file_location('venue_local_build_images',HERE/'venue-local-build-images.py')
    local=importlib.util.module_from_spec(spec);spec.loader.exec_module(local)
    if source is None:source=local.authority.authority(bundle,selector)
    expected=local.plan_for(bundle,source)
    outputs=state.get('venueLocalBuildOutputs')
    if (phase not in ('preparing','inert-ready','abandoned-inert') or state.get('venueLocalBuildPending') or
            state.get('venueLocalBuildPlan')!=expected or not isinstance(outputs,dict) or
            any(k not in expected or not isinstance(v,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',v)
                for k,v in outputs.items()) or
            (phase=='inert-ready' and set(outputs)!=set(expected))):
        raise Refusal('local build output image journal/source differs')
    commands={user:command for user,_,command in stores(bundle,stage.owned_plan(bundle,selector))}
    by_user={user:set() for user in commands}
    intermediates=state.get('venueLocalBuildIntermediates',{})
    if (not isinstance(intermediates,dict) or any(key not in outputs or not isinstance(ids,list) or
            len(ids)!=len(set(ids)) or any(not isinstance(image,str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}',image) for image in ids)
            for key,ids in intermediates.items())):
        raise Refusal('unclassified local build intermediate image journal')
    failed=state.get('venueFailedBuildIntermediates',{})
    skipped=state.get('venueLocalBuildSkipped',[])
    twin=state.get('venueLocalBuildDuplicateSkip')
    permitted_skips=set(failed)|({twin} if twin else set())
    failures=state.get('venueLocalBuildFailures',{})
    if (not isinstance(failed,dict) or not isinstance(skipped,list) or len(skipped)>14 or
            len(skipped)!=len(set(skipped)) or set(skipped)!=permitted_skips or
            not isinstance(failures,dict) or (failures and set(failures)!=set(failed)) or
            (twin and (not twin.endswith('/android-test-runner-api36:bundle') or
                not skipped[0].endswith('/android-test-runner-api34:bundle'))) or
            any(key not in expected or key in outputs or
                not isinstance(ids,list) or len(ids)!=len(set(ids)) or
                any(not isinstance(image,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',image)
                    for image in ids) for key,ids in failed.items()) or
            (skipped and state.get('venueLocalBuildFailure',{}).get('key')!=skipped[0]) or
            any(key not in failed or not isinstance(row,dict) or row.get('key')!=key
                for key,row in failures.items())):
        raise Refusal('failed selected build intermediate IDs are not journaled')
    for key,ids in failed.items():
        user=key.partition('|')[0]
        if user not in by_user:raise Refusal('failed build store not selected')
        if user not in state.get('graphCleared',[]):
            for image in ids:
                observed=run(commands[user]+['image','inspect','--format','{{.Id}}',image],timeout=30)
                if observed.returncode or 'sha256:'+observed.stdout.strip().removeprefix('sha256:')!=image:
                    if state.get('status')!='graphs-clearing':raise Refusal('failed build intermediate image drift')
        by_user[user].update(ids)
    for key,value in outputs.items():
        user,sep,tag=key.partition('|')
        if not sep or user not in commands:raise Refusal('unknown local output store authority')
        if user not in state.get('graphCleared',[]):
            observed=run(commands[user]+['image','inspect','--format','{{.Id}}',tag],timeout=30)
            if observed.returncode:
                if state.get('status')!='graphs-clearing':raise Refusal('selected built output tag absent')
            elif 'sha256:'+observed.stdout.strip().removeprefix('sha256:')!=value:
                raise Refusal('selected built output config ID changed')
        by_user[user].add(value)
        if user not in state.get('graphCleared',[]):
            for image in intermediates.get(key,[]):
                observed=run(commands[user]+['image','inspect','--format','{{.Id}}',image],timeout=30)
                if observed.returncode or 'sha256:'+observed.stdout.strip().removeprefix('sha256:')!=image:
                    if state.get('status')!='graphs-clearing':
                        raise Refusal('selected intermediate build image absent or changed')
        by_user[user].update(intermediates.get(key,[]))
    return by_user

def remove_exact_dual_named_base(bundle,selector,state,path,user,image,command,source=None):
    """Never force an image: untag only its frozen site-owned mutable alias."""
    spec=importlib.util.spec_from_file_location('venue_image_authority',HERE/'venue-image-authority.py')
    authority=importlib.util.module_from_spec(spec);spec.loader.exec_module(authority)
    if source is None:source=authority.authority(bundle,selector)
    matches=[row for key,row in source['buildBaseImages'].items()
             if key.startswith(user+'|') and row['configId']==image and
             state.get('venueBuildBaseVerified',{}).get(key)==image]
    if len(matches)!=1:raise Refusal('multi-name image lacks unique frozen selected build-base alias')
    row=matches[0];tag=row['registryReference'];digest=tag.rsplit(':',1)[0]+'@'+row['linuxAmd64ManifestDigest']
    details=run(command+['image','inspect','--format','{{json .RepoTags}}|{{json .RepoDigests}}',image],timeout=35)
    if details.returncode or details.stdout.count('|')!=1:
        raise Refusal('selected dual-name image metadata unavailable')
    tagged,digested=details.stdout.strip().split('|',1)
    if (set(json.loads(tagged))!={tag} or set(json.loads(digested))!={digest}):
        raise Refusal('selected base image has foreign alias/digest; no untag')
    state['pendingGraphImageUntag']={'user':user,'image':image,'tag':tag,'digest':digest}
    stage.write_ledger(path,state)
    result=run(command+['image','untag',image,tag],timeout=35)
    if result.returncode:raise Refusal('exact selected base alias untag failed')
    state.setdefault('graphUntaggedSelectedBases',[]).append(state.pop('pendingGraphImageUntag'))
    stage.write_ledger(path,state)
    result=run(command+['image','rm',image],timeout=180)
    if result.returncode:
        remaining=run(command+['image','inspect','--format','{{.Id}}',image],timeout=35)
        if remaining.returncode==0:
            raise Refusal('exact selected base image removal after untag failed')

def inspect_graph(command):
    observations={}
    for label,args in (('containers',['ps','-aq']),('pods',['pod','ps','--quiet']),
                       ('volumes',['volume','ls','-q'])):
        result=run(command+args)
        if result.returncode:raise Refusal('selected Podman '+label+' inventory unavailable')
        observations[label]=result.stdout.strip().splitlines() if result.stdout.strip() else []
    images=run(command+['image','ls','-a','--no-trunc','--format','{{.ID}}'])
    if images.returncode:raise Refusal('selected image inventory unavailable')
    observations['images']={('sha256:'+value.removeprefix('sha256:')) for value in images.stdout.splitlines() if value.strip()}
    networks=run(command+['network','ls','--format','{{.Name}}'])
    if networks.returncode:raise Refusal('selected network inventory unavailable')
    observations['networks']={x.strip() for x in networks.stdout.splitlines() if x.strip()}
    if observations['containers'] or observations['pods'] or observations['volumes'] or observations['networks']-{'podman'}:
        raise Refusal('graph has container, pod, named volume or nondefault network')
    return observations

def removal_order(command,images):
    """Exact child-first order for selected Buildah stage and output IDs."""
    images=set(images);parents={}
    for image in images:
        row=run(command+['image','inspect','--format','{{.Parent}}',image],timeout=30)
        if row.returncode:raise Refusal('selected image dependency cannot be inventoried')
        parent=row.stdout.strip()
        if parent and parent!='<nil>':
            parent='sha256:'+parent.removeprefix('sha256:')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}',parent):
                raise Refusal('selected image parent identity malformed')
        parents[image]=parent if parent in images else None
    remaining=images.copy();order=[]
    while remaining:
        ancestors={p for image,p in parents.items() if image in remaining and p in remaining}
        leaves=sorted(remaining-ancestors)
        if not leaves:raise Refusal('selected image parent graph has a cycle')
        order.extend(leaves);remaining.difference_update(leaves)
    return order

def graph_has_live_mount(graph_paths):
    mountpoints=[row.split()[4].replace('\\040',' ') for row in Path('/proc/self/mountinfo').read_text().splitlines()]
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try: lines=(process/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        mountpoints.extend(row.split()[4].replace('\\040',' ') for row in lines if len(row.split())>=5)
    return any(mp==g or mp.startswith(g.rstrip('/')+'/') for mp in mountpoints for g in graph_paths)

def clear(bundle,selector,ledger):
    if os.geteuid()!=0 or not shutil.rmtree.avoids_symlink_attacks:
        raise Refusal('root and fd-safe recursive deletion support required')
    path=Path(ledger)
    if not path.is_file() or path.is_symlink() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('missing protected exact graph ledger')
    state=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('status') not in ('managers-ready','graphs-clearing') or
            state.get('managerStarted')!=[a['name'] for a in plan['accounts']] or state.get('managerStopped')):
        raise Refusal('graph stage/manager authority differs')
    # Inspect foreign/live mounts BEFORE any of our own Podman image-inspect
    # calls: rootless Podman creates its managed pause namespace on first use.
    graph_paths=[g for _,g,_ in stores(bundle,plan)]
    if graph_has_live_mount(graph_paths):
        raise Refusal('Podman graph has a live mount')
    allowed=selected_images(bundle)
    if state.get('venueCompositeVersion')==2:
        imported=state.get('venueCompositeOfflineImages',[])
        if not isinstance(imported,list) or len(imported)>1:
            raise Refusal('composite image import journal differs')
        exact={key:set() for key in allowed}
        for row in imported:
            if not isinstance(row,dict) or not isinstance(row.get('authorities'),list) or not row['authorities']:
                raise Refusal('incomplete composite image authority')
            for user in row['authorities']:
                if user not in exact or row.get('image') not in allowed[user]:
                    raise Refusal('composite image is not site-selected in exact authority')
                exact[user].add(row['image'])
        registry_phase=state.get('venueRegistryPhase')
        if registry_phase is not None:
            approved=json.loads((Path(bundle)/'site/global.settings/registry-image-ids.json').read_text())
            recorded=state.get('venueRegistryVerified')
            if (registry_phase not in ('preparing','inert-ready') or state.get('venueRegistryPending') or
                    state.get('venueRegistryPlan')!=approved or not isinstance(recorded,dict) or
                    any(k not in approved or v!=approved[k] for k,v in recorded.items()) or
                    (registry_phase=='inert-ready' and recorded!=approved)):
                raise Refusal('registry image graph lacks exact completed/partial frozen authority')
            for key,value in recorded.items():
                user,sep,_=key.partition('|')
                if not sep or user not in exact:raise Refusal('unknown registry image graph authority')
                exact[user].add(value)
        selected_stores={user for user,_,_ in stores(bundle,plan)}
        for selected in (journaled_build_base_ids(bundle,selector,state),
                         journaled_local_output_ids(bundle,selector,state)):
            for user,values in selected.items():
                if user not in selected_stores:raise Refusal('unknown build image authority')
                exact.setdefault(user,set()).update(values)
        allowed=exact
    # The netavark rootful default is /etc/containers/networks even with a
    # private image graph. Never enumerate/mutate that shared directory as
    # though it belonged to this stage: create and journal a private empty
    # inspection-only network authority under its exclusive stage root.
    netdir=Path(plan['roots']['rootful-state'])/'networks'
    parent=netdir.parent;entry=state.get('graphNetworkDir')
    parent_record=state['pathIdentities'].get(str(parent));parent_stat=parent.lstat()
    if not parent_record or (parent_stat.st_dev,parent_stat.st_ino,parent_stat.st_uid)!=(parent_record['dev'],parent_record['ino'],0):
        raise Refusal('rootful network parent is not the staged exclusive inode')
    staged_network=plan['roots'].get('rootful-network')==str(netdir)
    if staged_network:
        record=state['pathIdentities'].get(str(netdir));st=netdir.lstat()
        config=Path(plan['roots']['rootful-state'])/'containers.conf'
        if (not record or not stat.S_ISDIR(st.st_mode) or netdir.is_symlink() or
                (st.st_dev,st.st_ino,st.st_uid)!=(record['dev'],record['ino'],0) or
                config.read_text()!=plan['configs'].get(str(config))):
            raise Refusal('isolated rootful netavark stage/config differs')
    elif entry:
        st=netdir.lstat()
        if not stat.S_ISDIR(st.st_mode) or netdir.is_symlink() or (st.st_dev,st.st_ino,st.st_uid)!=(entry['dev'],entry['ino'],0):
            raise Refusal('journaled private network directory changed')
    else:
        if os.path.lexists(netdir):raise Refusal('private network path was not staged')
        state['pendingGraphNetworkDir']=str(netdir);stage.write_ledger(path,state)
        netdir.mkdir(mode=0o700)
        st=netdir.lstat();state['graphNetworkDir']={'path':str(netdir),'dev':st.st_dev,'ino':st.st_ino}
        state.pop('pendingGraphNetworkDir');stage.write_ledger(path,state)
    if any(netdir.iterdir()):raise Refusal('private graph inspection network dir not empty')
    graph_entries=stores(bundle,plan)
    if len(graph_entries)!=8:raise Refusal('incomplete eight-graph authority')
    observations=[]
    for user,graph,command in graph_entries:
        g=Path(graph);st=g.lstat();record=state['pathIdentities'].get(graph)
        if (not record or not stat.S_ISDIR(st.st_mode) or g.is_symlink() or
                (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))!=(record['dev'],record['ino'],record['uid'],record['mode'])):
            raise Refusal('graph root identity differs from exclusive fresh stage')
        if user in state.get('graphCleared',[]):
            # Podman inventory itself initializes a cleared graph. Preserve
            # its proven empty inode instead of recreating metadata to query.
            if any(g.iterdir()):raise Refusal('previously cleared selected graph repopulated')
            observations.append((user,graph,command,{'images':set()}));continue
        o=inspect_graph(command)
        expected=allowed.get(user,set())
        if (bool(o['images']-expected) or
                (state.get('venueCompositeVersion')==2 and state['status']!='graphs-clearing' and o['images']!=expected) or
                (user in state.get('graphCleared',[]) and o['images'])):
            raise Refusal('unselected, unjournaled or missing image in test-only graph: '+user)
        observations.append((user,graph,command,o))
    if state['status']=='graphs-clearing':
        pending=state.get('pendingGraphImageRemoval')
        if pending and (not isinstance(pending,dict) or
                        pending.get('image') not in allowed.get(pending.get('user'),set())):
            raise Refusal('interrupted image removal lacks selected exact CAS')
        missing={user:sorted(allowed.get(user,set())-o['images']) for user,_,_,o in observations
                 if allowed.get(user,set())-o['images']}
        if missing:
            state['graphRecoveredMissingSelectedImages']=missing
            stage.write_ledger(path,state)
    # All eight graphs were checked before removing even one selected image.
    state['status']='graphs-clearing';state.setdefault('graphCleared',[]);stage.write_ledger(path,state)
    for user,graph,command,o in observations:
        g=Path(graph)
        if user in state['graphCleared']:
            if any(g.iterdir()):raise Refusal('previously cleared selected graph repopulated')
            continue
        for image in removal_order(command,o['images']):
            state['pendingGraphImageRemoval']={'user':user,'image':image}
            stage.write_ledger(path,state)
            removed=run(command+['image','rm',image],timeout=180)
            if removed.returncode:
                if 'by digest with more than one tag' in removed.stderr:
                    remove_exact_dual_named_base(bundle,selector,state,path,user,image,command)
                elif 'image not known' in removed.stderr:
                    # Podman can collect a now-unreferenced selected parent
                    # while deleting its last child. This is NOT permission
                    # to ignore a failed removal: re-inventory this exclusive
                    # graph and attest every missing ID against the complete
                    # before snapshot and immutable selected image allowlist.
                    observed=inspect_graph(command)
                    if (image in observed['images'] or not observed['images']<=o['images'] or
                            not observed['images']<=allowed.get(user,set()) or
                            any(observed[k] for k in ('containers','pods','volumes')) or
                            observed['networks']-{'podman'}):
                        raise Refusal('failed image removal changed selected graph unexpectedly')
                    state.setdefault('graphAutoRemovedSelectedImages',[]).append(
                        {'user':user,'image':image,'missing':sorted(o['images']-observed['images'])})
                    stage.write_ledger(path,state)
                else:
                    raise Refusal('exact selected image removal failed: '+user+'; '+removed.stderr.strip()[:240])
            state.pop('pendingGraphImageRemoval');stage.write_ledger(path,state)
        current=inspect_graph(command)
        if current['images'] or any(current[k] for k in ('containers','pods','volumes')):
            raise Refusal('selected graph objects remained after image removal')
        g=Path(graph);st=g.lstat();record=state['pathIdentities'][graph]
        if (st.st_dev,st.st_ino)!=(record['dev'],record['ino']):raise Refusal('graph replaced during retirement')
        for child in sorted(g.iterdir(),key=lambda p:p.name):
            if child.is_symlink() or not child.is_dir():child.unlink()
            else:shutil.rmtree(child)
        if any(g.iterdir()):raise Refusal('selected graph metadata still present')
        state['graphCleared'].append(user);stage.write_ledger(path,state)
    if any(netdir.iterdir()):raise Refusal('private inspection network unexpectedly materialized')
    if staged_network:state['graphNetworkIsolated']=True
    else:
        netdir.rmdir();state['graphNetworkDirRetired']=True
    state['status']='managers-ready';stage.write_ledger(path,state)
    return {'graphRootsCleared':len(state['graphCleared']),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire_image_cache(bundle,selector,ledger):
    """Remove only Podman's exact SQLite blob cache in a fresh owned home."""
    if os.geteuid()!=0:raise Refusal('root required to retire exact image cache')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('missing protected image graph ledger')
    state=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('status')!='managers-ready' or len(state.get('graphCleared',[]))!=8 or
            not (state.get('graphNetworkDirRetired') or state.get('graphNetworkIsolated'))):
        raise Refusal('all exclusive graph roots must be cleared before cache retirement')
    if state.get('podmanImageCacheRetired'):raise Refusal('image cache already retired')
    checked=[]
    mountpoints=[line.split()[4].replace('\\040',' ') for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    for a in plan['accounts']:
        home=Path(a['home']);st=home.lstat();record=state['pathIdentities'].get(str(home))
        if not record or home.is_symlink() or (st.st_dev,st.st_ino,st.st_uid)!=(record['dev'],record['ino'],a['uid']):
            raise Refusal('test-only account home identity drift')
        root=home/'.local'
        if not os.path.lexists(root):continue
        dirs=[root,root/'share',root/'share/containers',root/'share/containers/cache']
        for index,d in enumerate(dirs):
            info=d.lstat()
            if not stat.S_ISDIR(info.st_mode) or d.is_symlink() or info.st_uid!=a['uid'] or stat.S_IMODE(info.st_mode)!=0o700:
                raise Refusal('unreviewed Podman cache parent')
            expected={dirs[index+1].name} if index+1<len(dirs) else {'blob-info-cache-v1.sqlite'}
            if {c.name for c in d.iterdir()}!=expected:raise Refusal('unreviewed Podman home content')
        file=dirs[-1]/'blob-info-cache-v1.sqlite';info=file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=a['uid'] or file.is_symlink():
            raise Refusal('unreviewed blob cache identity')
        if any(mp==str(root) or mp.startswith(str(root)+'/') for mp in mountpoints):
            raise Refusal('Podman home cache is mounted')
        checked.append((file,dirs,{'path':str(file),'dev':info.st_dev,'ino':info.st_ino,
                                   'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'uid':a['uid']}))
    state['podmanImageCaches']=[r for _,_,r in checked];state['podmanCacheRetiring']=True
    stage.write_ledger(path,state)
    for file,dirs,record in checked:
        info=file.lstat()
        if (info.st_dev,info.st_ino,info.st_uid)!=(record['dev'],record['ino'],record['uid']) or hashlib.sha256(file.read_bytes()).hexdigest()!=record['sha256']:
            raise Refusal('cache byte/inode drift before retirement')
        file.unlink()
        for d in reversed(dirs):d.rmdir()
    state.pop('podmanCacheRetiring');state['podmanImageCacheRetired']=True
    stage.write_ledger(path,state)
    return {'retiredExactImageCaches':len(checked),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire_empty_runroot(bundle,selector,ledger):
    """Remove only classified Podman bookkeeping left in the staged /run root."""
    if os.geteuid()!=0:raise Refusal('root required for isolated runroot metadata')
    path=Path(ledger)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('protected stage ledger required')
    state=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('status')!='staged-empty' or
            len(state.get('graphCleared',[]))!=8 or not (state.get('graphNetworkDirRetired') or state.get('graphNetworkIsolated')) or
            not state.get('podmanImageCacheRetired') or
            state.get('managerStopped')!=[a['name'] for a in reversed(plan['accounts'])]):
        raise Refusal('empty stopped eight-store proof required before runroot cleanup')
    root=Path(plan['roots']['rootful-run']);st=root.lstat();record=state['pathIdentities'].get(str(root))
    if not record or root.is_symlink() or (st.st_dev,st.st_ino,st.st_uid)!=(record['dev'],record['ino'],0):
        raise Refusal('rootful runroot inode changed')
    # No running process, including one in another mount namespace, may hold
    # a mount under this exact test-only runroot. Host Podman is not stopped.
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try: lines=(process/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        if any((mp:=line.split()[4].replace('\\040',' '))==str(root) or mp.startswith(str(root)+'/')
               for line in lines if len(line.split())>=5):
            raise Refusal('live mount in staged Podman runroot')
    # A fully populated selected image graph (even after exact image removal)
    # also leaves an empty mountpoint list, a 64-byte lock and the probed
    # idmapped-lower marker. An unknown file/content still stops retirement.
    allowed={'overlay-layers':{'mountpoints.lock'},'overlay-locks':set(),
             'overlay-containers':set(),'overlay':{'native-diff()-true','metacopy()-false','overlay-true'}}
    if {p.name for p in root.iterdir()}!=set(allowed):raise Refusal('unreviewed Podman runroot directory')
    if (root/'overlay-layers/mountpoints.json').exists() and (root/'overlay/idmapped-lower-dir-true').exists():
        allowed['overlay-layers'].add('mountpoints.json');allowed['overlay'].add('idmapped-lower-dir-true')
    files=[];dirs=[]
    for name,names in allowed.items():
        d=root/name;info=d.lstat()
        if (d.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or
                stat.S_IMODE(info.st_mode)!=0o700 or {p.name for p in d.iterdir()}!=names):
            raise Refusal('unreviewed Podman runroot metadata directory')
        dirs.append({'path':str(d),'dev':info.st_dev,'ino':info.st_ino})
        for child in d.iterdir():
            info=child.lstat()
            mode=stat.S_IMODE(info.st_mode)
            if (not stat.S_ISREG(info.st_mode) or child.is_symlink() or info.st_uid!=0 or
                    info.st_nlink!=1 or
                    (child.name=='mountpoints.lock' and (mode!=0o644 or info.st_size not in (0,64))) or
                    (child.name=='mountpoints.json' and (mode!=0o600 or child.read_bytes()!=b'[]')) or
                    (child.name not in ('mountpoints.lock','mountpoints.json') and (mode!=0o644 or info.st_size!=0))):
                raise Refusal('unreviewed Podman runroot metadata file')
            files.append({'path':str(child),'dev':info.st_dev,'ino':info.st_ino,
                          'uid':info.st_uid,'mode':mode,'sha256':hashlib.sha256(child.read_bytes()).hexdigest()})
    state['podmanRunrootProof']={'directories':dirs,'exactFiles':files}
    state['podmanRunrootRetiring']=True;stage.write_ledger(path,state)
    for item in files:
        file=Path(item['path']);info=file.lstat()
        if (file.is_symlink() or not stat.S_ISREG(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))!=
                (item['dev'],item['ino'],item['uid'],item['mode']) or
                hashlib.sha256(file.read_bytes()).hexdigest()!=item['sha256']):
            raise Refusal('runroot metadata inode/bytes drift before exact retirement')
        file.unlink()
    for item in dirs:Path(item['path']).rmdir()
    if any(root.iterdir()):raise Refusal('runroot bookkeeping remained')
    state.pop('podmanRunrootRetiring');state['podmanRunrootRetired']=True;stage.write_ledger(path,state)
    return {'retiredRunrootFiles':len(files),'retiredRunrootDirectories':len(dirs),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','ledger'):p.add_argument('--'+key,required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--clear-unactivated-image-graphs',action='store_true')
    mode.add_argument('--retire-podman-image-cache',action='store_true')
    mode.add_argument('--retire-empty-runroot',action='store_true')
    args=p.parse_args()
    handler=clear if args.clear_unactivated_image_graphs else retire_image_cache if args.retire_podman_image_cache else retire_empty_runroot
    try:print(json.dumps(handler(args.bundle,args.selector,args.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue graph clear refused: '+str(exc)) from exc
if __name__=='__main__':main()
