#!/usr/bin/env python3
"""Retire only failed selected Android Buildah working containers, no prune."""
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

def retire(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root required for selected Buildah retirement')
    path=Path(ledger);info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
        raise Refusal('selected root0600 Buildah ledger required')
    state=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    account=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-test-runners')
    user=account['name'];pending=state.get('pendingGraphImageRemoval',{})
    if (state.get('plan')!=plan or state.get('status')!='graphs-clearing' or
            state.get('venueCompositeMode')!='retiring' or user in state.get('graphCleared',[]) or
            pending.get('user')!=user or state.get('activationAuthorized') is not False or
            not any(k.startswith(user+'|localhost/webservices/android-test-runner-api34:')
                    for k in state.get('venueFailedBuildIntermediates',{}))):
        raise Refusal('failed Android graph not exclusively selected for builder-container removal')
    command=next(cmd for name,_,cmd in graph.stores(bundle,plan) if name==user)
    def listing():
        rows=graph.run(command[:command.index('podman')]+['buildah','containers','--all','--json'],timeout=40)
        if rows.returncode:raise Refusal('selected Buildah container inventory unavailable')
        parsed=json.loads(rows.stdout)
        if parsed is None:parsed=[]  # Buildah serializes an empty list as null.
        if not isinstance(parsed,list):raise Refusal('selected Buildah inventory malformed')
        return parsed
    failed=state['venueFailedBuildIntermediates'][user+'|localhost/webservices/android-test-runner-api34:bundle']
    bases={value for key,value in state.get('venueBuildBaseVerified',{}).items()
           if key.startswith(user+'|') and key.endswith('|debian:13-slim')}
    if len(bases)!=1 or len(failed)!=5:raise Refusal('Android failed base/stage identities incomplete')
    images=bases|set(failed)
    previous=state.get('venueFailedBuildahContainers')
    if previous is None:
        found=listing()
        if (len(found)!=6 or len({x.get('id') for x in found})!=6 or
                {'sha256:'+str(x.get('imageid','')).removeprefix('sha256:') for x in found}!=images):
            raise Refusal('Buildah graph contains unselected or missing working container')
        rows=[]
        for x in found:
            image='sha256:'+x['imageid'].removeprefix('sha256:')
            expected='debian-working-container' if image in bases else image[7:19]+'-working-container'
            if (x.get('builder') is not True or x.get('containername')!=expected or
                    not re.fullmatch('[0-9a-f]{64}',x['id'])):
                raise Refusal('unreviewed Buildah working container name or builder flag')
            rows.append({'id':x['id'],'image':image,'name':expected})
        state['venueFailedBuildahContainers']=sorted(rows,key=lambda x:x['id'])
        state['venueFailedBuildahRemoved']=[]
        stage.write_ledger(path,state)
        previous=state['venueFailedBuildahContainers']
    if not isinstance(previous,list) or len(previous)!=6 or {r.get('image') for r in previous}!=images:
        raise Refusal('journaled Buildah container authority changed')
    removed=state.get('venueFailedBuildahRemoved',[])
    if not isinstance(removed,list) or len(removed)!=len(set(removed)) or not set(removed)<={r['id'] for r in previous}:
        raise Refusal('Buildah container retirement receipt malformed')
    observed=listing();expected={r['id']:r for r in previous if r['id'] not in removed}
    pending_row=state.get('venueFailedBuildahPendingRemoval')
    if (pending_row is not None and pending_row in previous and
            pending_row['id'] in expected and pending_row['id'] not in {x.get('id') for x in observed} and
            {x.get('id') for x in observed}==set(expected)-{pending_row['id']}):
        graph_images=graph.inspect_graph(command)['images']
        if graph_images!=images:raise Refusal('interrupted Buildah removal changed selected image graph')
        state['venueFailedBuildahRemoved'].append(pending_row['id'])
        state.pop('venueFailedBuildahPendingRemoval');stage.write_ledger(path,state)
        removed=state['venueFailedBuildahRemoved']
        expected.pop(pending_row['id'])
    if len(observed)!=len(expected) or {x.get('id') for x in observed}!=set(expected):
        raise Refusal('Buildah working container set differs from exact pending journal')
    for x in observed:
        ref=expected[x['id']]
        if x.get('builder') is not True or x.get('containername')!=ref['name'] or \
                'sha256:'+x.get('imageid','').removeprefix('sha256:')!=ref['image']:
            raise Refusal('Buildah working container ID/image/name changed')
    for row in previous:
        if row['id'] in removed:continue
        state['venueFailedBuildahPendingRemoval']=row;stage.write_ledger(path,state)
        cmd=command[:command.index('podman')]+['buildah','rm',row['id']]
        result=graph.run(cmd,timeout=120)
        if result.returncode:raise Refusal('selected Buildah working container removal failed')
        state['venueFailedBuildahRemoved'].append(row['id'])
        state.pop('venueFailedBuildahPendingRemoval');stage.write_ledger(path,state)
    if listing():raise Refusal('selected Buildah working containers still present')
    return {'status':'retired-exact-failed-buildah-containers','count':len(previous),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):ap.add_argument('--'+name,required=True)
    a=ap.parse_args()
    try:print(json.dumps(retire(a.bundle,a.selector,a.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,TypeError) as exc:
        raise SystemExit('selected failed Buildah retirement refused: '+str(exc)) from exc
if __name__=='__main__':main()
