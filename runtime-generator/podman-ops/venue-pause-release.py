#!/usr/bin/env python3
"""Release ONLY the selected rootless Podman pause mount after failed builds.

No force, prune, shared graph or container removal. A rootless Buildah build
can leave a persistent Podman pause process owning an overlay namespace even
when all exact selected build units and containers are stopped. Podman's
supported `system migrate` operation releases it after strict ID/UID/graph
and mount/process CAS checks; images must remain byte-identical in inventory.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_graph',HERE/'venue-graph-clear.py')
graph=importlib.util.module_from_spec(spec);spec.loader.exec_module(graph)
stage=graph.stage
Refusal=stage.Refusal

def pause_identity(pid,uid,graphroot):
    p=Path('/proc')/str(pid)
    if type(pid) is not int or pid<2 or not p.is_dir():raise Refusal('selected rootless pause PID absent')
    state=(p/'status').read_text().splitlines()
    owners=next(x.split()[1:] for x in state if x.startswith('Uid:'))
    if (owners!=[str(uid)]*4 or (p/'comm').read_text().strip()!='catatonit' or
            (p/'exe').resolve()!=Path('/usr/bin/catatonit')):
        raise Refusal('rootless pause executable or effective ownership changed')
    cgroup=(p/'cgroup').read_text().strip()
    if not re.fullmatch(r'0::/user\.slice/user-'+str(uid)+r'\.slice/user@'+str(uid)+
                        r'\.service/user\.slice/podman-pause-[0-9a-f]+\.scope',cgroup):
        raise Refusal('unselected rootless pause cgroup')
    ticks=(p/'stat').read_text().split(') ',1)[1].split()[19]
    if not ticks.isdigit():raise Refusal('rootless pause start time unavailable')
    found=[row.split()[4].replace('\\040',' ') for row in (p/'mountinfo').read_text().splitlines()
           if len(row.split())>4]
    if not any(x.startswith(graphroot.rstrip('/')+'/') for x in found):
        raise Refusal('pause process does not own selected isolated overlay mount')
    return {'pid':pid,'startTicks':ticks,'uid':uid,'cgroup':cgroup}

def mounted_by_other_processes(pid,graphroot):
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==pid:continue
        try:
            for row in (p/'mountinfo').read_text().splitlines():
                cells=row.split()
                if len(cells)>4 and cells[4].replace('\\040',' ').startswith(graphroot.rstrip('/')+'/'):
                    raise Refusal('another process holds selected graph overlay mount')
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue

def release(bundle,selector,ledger,pid):
    if os.geteuid()!=0:raise Refusal('root only for selected pause release')
    path=Path(ledger);st=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600:
        raise Refusal('exact root0600 selected pause ledger required')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    account=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-test-runners')
    if (data.get('plan')!=plan or data.get('status')!='managers-ready' or
            data.get('venueCompositeMode')!='retiring' or data.get('managerStopped') or
            len(data.get('retiredUnits',[]))!=194 or data.get('graphCleared') or
            data.get('activationAuthorized') is not False):
        raise Refusal('only fully stopped and uncleared selected build graph can release pause')
    root=Path(account['graph']);info=root.lstat();record=data['pathIdentities'].get(str(root))
    if (root.is_symlink() or not record or (info.st_dev,info.st_ino,info.st_uid)!=
            (record['dev'],record['ino'],account['uid'])):
        raise Refusal('selected rootless graph inode/owner changed')
    ident=pause_identity(pid,account['uid'],str(root))
    mounted_by_other_processes(pid,str(root))
    command=next(cmd for user,_,cmd in graph.stores(bundle,plan) if user==account['name'])
    before=graph.inspect_graph(command)
    if before['containers'] or before['pods'] or before['volumes'] or before['networks']-{'podman'}:
        raise Refusal('selected pause graph still contains containers, pods, volumes or foreign network')
    expected=set()
    for mapping in (data.get('venueRegistryVerified',{}),data.get('venueBuildBaseVerified',{}),
                    data.get('venueLocalBuildOutputs',{})):
        expected.update(value for key,value in mapping.items() if key.startswith(account['name']+'|'))
    for mapping in (data.get('venueLocalBuildIntermediates',{}),data.get('venueFailedBuildIntermediates',{})):
        expected.update(value for key,rows in mapping.items() if key.startswith(account['name']+'|') for value in rows)
    if before['images']!=expected:raise Refusal('selected pause graph has unreviewed/missing images')
    intent={'process':ident,'graph':{'path':str(root),'dev':info.st_dev,'ino':info.st_ino},
            'images':sorted(expected)}
    previous=data.get('venuePauseReleaseIntent')
    if previous not in (None,intent):
        if (data.get('venuePauseReleasePhase')!='released' or
                not isinstance(previous,dict) or previous.get('graph')!=intent['graph'] or
                previous.get('images')!=intent['images'] or
                previous.get('process',{}).get('pid')==pid):
            raise Refusal('selected pause migration intent changed')
        old=previous['process'];oldproc=Path('/proc')/str(old['pid'])
        if oldproc.exists() and oldproc.joinpath('stat').read_text().split(') ',1)[1].split()[19]==old['startTicks']:
            raise Refusal('previous selected pause was not released')
    data['venuePauseReleaseIntent']=intent;stage.write_ledger(path,data)
    result=graph.run(command+['system','migrate'],timeout=180)
    if result.returncode:raise Refusal('selected Podman migrate refused; pause receipt retained')
    if (Path('/proc')/str(pid)).exists() and (Path('/proc')/str(pid)/'stat').read_text().split(') ',1)[1].split()[19]==ident['startTicks']:
        raise Refusal('selected pause process still owns graph after migration')
    # Any subsequent rootless Podman inventory recreates a fresh pause process.
    # Never query Podman again here: graph.clear will independently inventory all
    # eight stores, compare exact IDs and refuse before its first deletion.
    new=root.lstat()
    if (new.st_dev,new.st_ino,new.st_uid)!=(info.st_dev,info.st_ino,account['uid']):
        raise Refusal('selected graph root changed after pause release')
    data['venuePauseReleasePhase']='released';stage.write_ledger(path,data)
    return {'status':'released-selected-pause-awaiting-independent-graph-inventory','imageIdsBeforeRelease':len(expected),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):ap.add_argument('--'+name,required=True)
    ap.add_argument('--selected-pause-pid',type=int,required=True)
    a=ap.parse_args()
    try:print(json.dumps(release(a.bundle,a.selector,a.ledger,a.selected_pause_pid),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('selected Podman pause release refused: '+str(exc)) from exc
if __name__=='__main__':main()
