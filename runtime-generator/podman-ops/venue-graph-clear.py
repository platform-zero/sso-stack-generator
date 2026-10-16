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

def inspect_graph(command):
    observations={}
    for label,args in (('containers',['ps','-aq']),('pods',['pod','ps','--quiet']),
                       ('volumes',['volume','ls','-q'])):
        result=run(command+args)
        if result.returncode:raise Refusal('selected Podman '+label+' inventory unavailable')
        observations[label]=result.stdout.strip().splitlines() if result.stdout.strip() else []
    images=run(command+['image','ls','--no-trunc','--format','{{.ID}}'])
    if images.returncode:raise Refusal('selected image inventory unavailable')
    observations['images']={('sha256:'+value.removeprefix('sha256:')) for value in images.stdout.splitlines() if value.strip()}
    networks=run(command+['network','ls','--format','{{.Name}}'])
    if networks.returncode:raise Refusal('selected network inventory unavailable')
    observations['networks']={x.strip() for x in networks.stdout.splitlines() if x.strip()}
    if observations['containers'] or observations['pods'] or observations['volumes'] or observations['networks']-{'podman'}:
        raise Refusal('graph has container, pod, named volume or nondefault network')
    return observations

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
    allowed=selected_images(bundle)
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
    mountpoints=[row.split()[4].replace('\\040',' ') for row in Path('/proc/self/mountinfo').read_text().splitlines()]
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try: lines=(process/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        mountpoints.extend(row.split()[4].replace('\\040',' ') for row in lines if len(row.split())>=5)
    observations=[]
    for user,graph,command in graph_entries:
        g=Path(graph);st=g.lstat();record=state['pathIdentities'].get(graph)
        if (not record or not stat.S_ISDIR(st.st_mode) or g.is_symlink() or
                (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))!=(record['dev'],record['ino'],record['uid'],record['mode'])):
            raise Refusal('graph root identity differs from exclusive fresh stage')
        if any(mp==graph or mp.startswith(graph.rstrip('/')+'/') for mp in mountpoints):
            raise Refusal('Podman graph has a live mount')
        o=inspect_graph(command)
        if o['images']-allowed.get(user,set()):
            raise Refusal('unselected image in test-only graph: '+user)
        observations.append((user,graph,command,o))
    # All eight graphs were checked before removing even one selected image.
    state['status']='graphs-clearing';state.setdefault('graphCleared',[]);stage.write_ledger(path,state)
    for user,graph,command,o in observations:
        if user in state['graphCleared']:continue
        for image in sorted(o['images']):
            removed=run(command+['image','rm',image],timeout=180)
            if removed.returncode:raise Refusal('exact selected image removal failed: '+user)
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
    allowed={'overlay-layers':{'mountpoints.lock'},'overlay-locks':set(),
             'overlay-containers':set(),'overlay':{'native-diff()-true','metacopy()-false','overlay-true'}}
    if {p.name for p in root.iterdir()}!=set(allowed):raise Refusal('unreviewed Podman runroot directory')
    files=[];dirs=[]
    for name,names in allowed.items():
        d=root/name;info=d.lstat()
        if (d.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or
                stat.S_IMODE(info.st_mode)!=0o700 or {p.name for p in d.iterdir()}!=names):
            raise Refusal('unreviewed Podman runroot metadata directory')
        dirs.append({'path':str(d),'dev':info.st_dev,'ino':info.st_ino})
        for child in d.iterdir():
            info=child.lstat()
            if (not stat.S_ISREG(info.st_mode) or child.is_symlink() or info.st_uid!=0 or
                    info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o644 or info.st_size!=0):
                raise Refusal('unreviewed Podman runroot metadata file')
            files.append({'path':str(child),'dev':info.st_dev,'ino':info.st_ino})
    state['podmanRunrootProof']={'directories':dirs,'zeroByteFiles':files}
    state['podmanRunrootRetiring']=True;stage.write_ledger(path,state)
    for item in files:Path(item['path']).unlink()
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
