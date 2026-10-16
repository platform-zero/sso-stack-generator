#!/usr/bin/env python3
"""Build ONLY 3 offline/no-pull selected Quadlets in inactive exact-CAS venue.

This is output-ID discovery, not a claim of pinned 14-image release or of any
running service. All other 11 builds remain refused pending dependency/output
pin review. Never start target units or issue a data readiness marker.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import time

HERE=Path(__file__).resolve().parent
def load(name,file):
    s=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
registry=load('venue_registry_images','venue-registry-images.py')
base=load('venue_build_base_images','venue-build-base-images.py')
graph=registry.graph;authority=registry.authority;stage=registry.stage;Refusal=stage.Refusal
LOCAL={'p0test-r1-apps':('mastodon-rss-publisher',),
       'p0test-r1-platform':('keycloak','onboarding')}

def plan_for(bundle,source):
    plan={}
    for user,names in LOCAL.items():
        domain=user.removeprefix('p0test-r1-')
        for name in names:
            quadlet='quadlet/rootless-'+domain+'/p0test-r1-'+name+'.build'
            entry=source['buildUnits'].get(quadlet)
            path=Path(bundle)/quadlet
            if not entry or entry['user']!=user or path.is_symlink():
                raise Refusal('selected offline build unit/source missing')
            text=path.read_text().splitlines()
            tag='localhost/webservices/'+name+':bundle'
            if text.count('ImageTag='+tag)!=1 or text.count('Pull=never')!=1 or text.count('Network=none')!=1:
                raise Refusal('selected local-only Quadlet may pull or use build network')
            key=user+'|'+tag
            plan[key]={'unit':'p0test-r1-'+name+'-build.service','quadletSha256':entry['sha256']}
    if len(plan)!=3:raise Refusal('exactly three selected offline-only builds required')
    return dict(sorted(plan.items()))

def probe(bundle,selector,plan,data,outputs):
    all_ids=data['venueRegistryVerified'].copy();all_ids.update(data['venueBuildBaseVerified']);all_ids.update(outputs)
    roots,found=registry.probe(bundle,plan,data,all_ids)
    base_ids=graph.journaled_build_base_ids(bundle,selector,data)
    for user,ids in base_ids.items():
        if ids-{v for k,v in data['venueBuildBaseVerified'].items() if k.startswith(user+'|')}:
            raise Refusal('selected build base alias/config differs before output build')
    for key,value in outputs.items():
        user,_,tag=key.partition('|')
        if user not in roots or registry.pulled(roots[user][1],tag)!=value:
            raise Refusal('built selected image tag/config ID drift')
    return roots

def unit_command(plan,user,unit):
    account=next((a for a in plan['accounts'] if a['name']==user),None)
    if account is None:raise Refusal('selected local build UID missing')
    uid=account['uid']
    return ['runuser','-u',user,'--','env','HOME='+account['home'],
            'XDG_RUNTIME_DIR=/run/user/'+str(uid),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(uid)+'/bus',
            'systemctl','--user']

def selected_unit(command,unit,tag,source_path=None):
    cat=graph.run(command+['cat',unit],timeout=30)
    starts=[line for line in cat.stdout.splitlines() if line.startswith('ExecStart=')]
    if (cat.returncode or len(starts)!=1 or
            (source_path is not None and cat.stdout.splitlines().count('SourcePath='+str(source_path))!=1)):
        raise Refusal('generated selected local build unit unavailable or source path changed')
    start=starts[0];words=start.split()
    network=('--network=none' in words or any(words[i:i+2]==['--network','none'] for i in range(len(words)-1)))
    if (not start.startswith('ExecStart=/usr/bin/podman build ') or
            '--pull=never' not in words or not network or
            '--tag '+tag not in start or '--push' in start):
        raise Refusal('installed selected build unit could pull or reach network')
    info=graph.run(command+['show',unit,'-p','LoadState','-p','ActiveState','-p','Job','-p','Result',
                             '-p','ExecMainStatus','-p','ExecMainStartTimestampMonotonic',
                             '-p','ExecMainExitTimestampMonotonic'],timeout=30)
    if info.returncode:raise Refusal('selected build unit state unreadable')
    status=dict(x.split('=',1) for x in info.stdout.splitlines() if '=' in x)
    if status.get('LoadState')!='loaded':raise Refusal('selected local build unit not loaded')
    return status

def journaled_unloaded_success(ledger,uid,unit):
    """User oneshot units unload and erase ExecMain timestamps; prove one exact
    start/finish pair AFTER the pending CAS write in the current boot instead.
    """
    since=str(max(0,int(Path(ledger).stat().st_mtime)-1))
    result=graph.run(['journalctl','--boot','--no-pager','--output=json','--since=@'+since,
                      '_UID='+str(uid),'USER_UNIT='+unit],timeout=30)
    if result.returncode or len(result.stdout)>131072:
        raise Refusal('selected user build journal unavailable or unbounded')
    starts=set();finishes=set();floor=Path(ledger).stat().st_mtime_ns//1000
    for line in result.stdout.splitlines():
        row=json.loads(line)
        if (row.get('_UID')!=str(uid) or row.get('USER_UNIT')!=unit or
                int(row.get('__REALTIME_TIMESTAMP','0'))<=floor):continue
        job=row.get('JOB_ID')
        if not job:continue
        if row.get('MESSAGE_ID')=='7d4958e842da4a758f6c1cdc7b36dcc5' and row.get('JOB_TYPE')=='start':
            starts.add(job)
        elif (row.get('MESSAGE_ID')=='39f53479d3a045ac8e11786248231fbf' and
              row.get('JOB_TYPE')=='start' and row.get('JOB_RESULT')=='done'):
            finishes.add(job)
    return len(starts)==1 and starts==finishes

def prepare(bundle,selector,site_source,ledger,max_new,recover_pending=False,abandon_failed_pending=False):
    p,data,plan,_=registry.journal(bundle,selector,site_source,ledger)
    source=authority.authority(bundle,selector,site_source,require_pinned_bases=True)
    selected=plan_for(bundle,source)
    if (data.get('venueRegistryPhase')!='inert-ready' or data.get('venueRegistryVerified')!=source['imageIds'] or
            data.get('venueBuildBasePhase')!='inert-ready' or
            set(data.get('venueBuildBaseVerified',{}))!=set(source['buildBaseStores']) or
            data.get('venueBuildBaseFrozenSha256')!=source['frozenBuildBaseSha256'] or
            data.get('venueCompositeMode')!='inert-ready' or data.get('status')!='units-staged'):
        raise Refusal('three builds need 60 direct and 14 frozen build-base inputs in fully inert installer')
    if type(max_new) is not int or not 1<=max_new<=3:raise Refusal('one to three bounded local builds per invocation')
    if data.get('venueLocalBuildPhase') is None:
        data['venueLocalBuildPhase']='preparing';data['venueLocalBuildPlan']=selected
        data['venueLocalBuildOutputs']={};stage.write_ledger(p,data)
    outputs=data.get('venueLocalBuildOutputs')
    if (data.get('venueLocalBuildPhase') not in ('preparing','inert-ready','abandoned-inert') or
            data.get('venueLocalBuildPlan')!=selected or not isinstance(outputs,dict) or
            any(key not in selected or not isinstance(value,str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}',value) for key,value in outputs.items()) or
            (data['venueLocalBuildPhase']=='inert-ready' and set(outputs)!=set(selected))):
        raise Refusal('selected local build output CAS differs')
    pending=data.get('venueLocalBuildPending')
    if pending:
        if (not recover_pending and not abandon_failed_pending) or pending not in selected or pending in outputs:
            raise Refusal('interrupted build output requires explicit exact review; never auto-restart')
        user,_,tag=pending.partition('|');unit=selected[pending]['unit']
        account=next(a for a in plan['accounts'] if a['name']==user)
        path=Path(account['home'])/'.config/containers/systemd'/unit.replace('-build.service','.build')
        entry=next((r for r in data['installedUnits'] if r['path']==str(path)),None)
        if not entry or path.is_symlink() or path.stat().st_ino!=entry['ino'] or path.stat().st_uid!=account['uid']:
            raise Refusal('interrupted selected build unit source changed')
        state=selected_unit(unit_command(plan,user,unit),unit,tag,path)
        prior=data.get('venueLocalBuildPriorStartTimestamp')
        started=int(state.get('ExecMainStartTimestampMonotonic','0'))
        exited=int(state.get('ExecMainExitTimestampMonotonic','0'))
        if abandon_failed_pending:
            if (state.get('ActiveState')!='inactive' and state.get('ActiveState')!='failed' or
                    state.get('Job') not in (None,'','0') or type(prior) is not int or
                    (started>prior and exited<started)):
                raise Refusal('failed selected build still running or completion unverified')
            roots=registry.command_graphs(bundle,plan)
            if registry.pulled(roots[user][1],tag) is not None:
                raise Refusal('failed selected build produced an image; exact manual image review required')
            probe(bundle,selector,plan,data,outputs)
            data['venueLocalBuildFailure']={'key':pending,'result':state.get('Result'),
                                             'execMainStatus':state.get('ExecMainStatus')}
            data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
            data['venueLocalBuildPhase']='abandoned-inert';stage.write_ledger(p,data)
            return {'status':'abandoned-inert','builtOutputIds':len(outputs),
                    'remaining':len(selected)-len(outputs),'activationAuthorized':False,'acceptedIntegratedInstalls':0}
        unloaded=(started==0 and exited==0 and state.get('Job') in (None,'','0') and
                  journaled_unloaded_success(p,account['uid'],unit))
        if (type(prior) is not int or state.get('ActiveState')!='inactive' or
                state.get('Result')!='success' or state.get('ExecMainStatus')!='0' or
                not ((started>prior and exited>=started) or unloaded)):
            raise Refusal('interrupted local image build not proved successful and idle')
        roots=registry.command_graphs(bundle,plan)
        image=registry.pulled(roots[user][1],tag)
        if image is None:raise Refusal('interrupted local image output absent')
        staged=outputs.copy();staged[pending]=image
        probe(bundle,selector,plan,data,staged)  # all 8 graphs checked prewrite
        outputs[pending]=image
        data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
        if set(outputs)==set(selected):data['venueLocalBuildPhase']='inert-ready'
        stage.write_ledger(p,data)
        return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
                'remaining':len(selected)-len(outputs),'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    if recover_pending or abandon_failed_pending:raise Refusal('no interrupted selected output pending review')
    roots=probe(bundle,selector,plan,data,outputs)
    if data['venueLocalBuildPhase']=='abandoned-inert':
        raise Refusal('failed selected build may retire only; never retry under the same ledger')
    if data['venueLocalBuildPhase']=='inert-ready':
        return {'status':'inert-ready','builtOutputIds':len(outputs),'remaining':0,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    for key in sorted(set(selected)-set(outputs))[:max_new]:
        user,_,tag=key.partition('|');unit=selected[key]['unit']
        command=unit_command(plan,user,unit)
        account=next(a for a in plan['accounts'] if a['name']==user)
        source_path=Path(account['home'])/'.config/containers/systemd'/unit.replace('-build.service','.build')
        staged=next((row for row in data['installedUnits'] if row['path']==str(source_path)),None)
        if (not staged or source_path.is_symlink() or not source_path.is_file() or
                source_path.stat().st_ino!=staged['ino'] or source_path.stat().st_uid!=account['uid']):
            raise Refusal('selected local Quadlet build source inode changed')
        before=selected_unit(command,unit,tag,source_path)
        prior=int(before.get('ExecMainStartTimestampMonotonic','0'))
        if before.get('ActiveState')!='inactive' or registry.pulled(roots[user][1],tag) is not None:
            raise Refusal('selected local output not fresh/idle')
        registry.reserve()
        data['venueLocalBuildPending']=key
        data['venueLocalBuildPriorStartTimestamp']=prior;stage.write_ledger(p,data)
        queued=graph.run(command+['start','--no-block',unit],timeout=30)
        if queued.returncode:raise Refusal('selected offline build unit could not queue; pending ledger retained')
        began=time.monotonic()
        while True:
            try:registry.reserve()
            except Refusal:
                graph.run(command+['stop',unit],timeout=35)
                raise
            state=selected_unit(command,unit,tag,source_path)
            started=int(state.get('ExecMainStartTimestampMonotonic','0'))
            exited=int(state.get('ExecMainExitTimestampMonotonic','0'))
            if state.get('ActiveState')=='failed':
                raise Refusal('selected offline build failed; output and pending ledger retained')
            unloaded=(state.get('ActiveState')=='inactive' and started==0 and exited==0 and
                      state.get('Job') in (None,'','0') and
                      journaled_unloaded_success(p,account['uid'],unit))
            if state.get('ActiveState')=='inactive' and ((started>prior and exited>=started) or unloaded):
                if state.get('Result')!='success' or state.get('ExecMainStatus')!='0':
                    raise Refusal('selected offline build failed; output and pending ledger retained')
                break
            if time.monotonic()-began>1800:
                graph.run(command+['stop',unit],timeout=35)
                raise Refusal('selected offline build timeout; pending ledger retained')
            time.sleep(1)
        image=registry.pulled(roots[user][1],tag)
        if image is None:raise Refusal('selected build completed without a local output image')
        outputs[key]=image
        data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
        stage.write_ledger(p,data)
        roots=probe(bundle,selector,plan,data,outputs)
    if set(outputs)==set(selected):
        data['venueLocalBuildPhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
            'remaining':len(selected)-len(outputs),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','site-source','ledger'):a.add_argument('--'+key,required=True)
    a.add_argument('--max-new',type=int,default=1)
    pending=a.add_mutually_exclusive_group()
    pending.add_argument('--recover-pending-only',action='store_true')
    pending.add_argument('--abandon-failed-pending-only',action='store_true')
    args=a.parse_args()
    try:print(json.dumps(prepare(args.bundle,args.selector,args.site_source,args.ledger,args.max_new,
                                 args.recover_pending_only,args.abandon_failed_pending_only),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('venue three offline-only local builds refused: '+str(exc)) from exc
if __name__=='__main__':main()
