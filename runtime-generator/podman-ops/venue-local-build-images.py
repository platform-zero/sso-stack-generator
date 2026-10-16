#!/usr/bin/env python3
"""Build 14 no-pull selected Quadlets in an inactive exact-CAS venue.

Three are network-disabled. Eleven may fetch mutable dependencies while being
built: their resulting IDs are DISCOVERY, never release pins until separately
reviewed and frozen in clean site source. Never start container target units,
issue a data readiness marker or credit a trial as an integrated installation.
"""
import argparse
from datetime import datetime
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
OFFLINE={'p0test-r1-apps':('mastodon-rss-publisher',),
         'p0test-r1-platform':('keycloak','onboarding')}
NETWORK={'p0test-r1-apps':('forgejo','jellyfin','legal-research-mcp'),
         'p0test-r1-ci-runner':('forgejo-runner',),
         'p0test-r1-platform':('market-data-exporter',),
         'p0test-r1-test-runners':('android-test-runner-api34','android-test-runner-api36'),
         'p0test-r1-workloads':('jupyter-notebook-build','jupyterhub',
                                'workload-spawner-api','workload-spawner-router')}

def plan_for(bundle,source):
    plan={}
    for user,names in {name:OFFLINE.get(name,())+NETWORK.get(name,())
                       for name in set(OFFLINE)|set(NETWORK)}.items():
        domain=user.removeprefix('p0test-r1-')
        for name in names:
            quadlet='quadlet/rootless-'+domain+'/p0test-r1-'+name+'.build'
            entry=source['buildUnits'].get(quadlet)
            path=Path(bundle)/quadlet
            if not entry or entry['user']!=user or path.is_symlink():
                raise Refusal('selected offline build unit/source missing')
            text=path.read_text().splitlines()
            tag='localhost/webservices/'+name+':bundle'
            offline=name in OFFLINE.get(user,())
            if (text.count('ImageTag='+tag)!=1 or text.count('Pull=never')!=1 or
                    [row for row in text if row.startswith('Network=')]!=(['Network=none'] if offline else [])):
                raise Refusal('selected build Quadlet pull/network authority differs')
            key=user+'|'+tag
            plan[key]={'unit':'p0test-r1-'+name+'-build.service','quadletSha256':entry['sha256'],
                       'offline':offline}
    if len(plan)!=14 or sum(row['offline'] for row in plan.values())!=3:
        raise Refusal('selected 3 offline and 11 egress build units differ')
    return dict(sorted(plan.items()))

def probe(bundle,selector,plan,data,outputs,intermediates=None):
    all_ids=data['venueRegistryVerified'].copy();all_ids.update(data['venueBuildBaseVerified']);all_ids.update(outputs)
    for key,ids in {**(intermediates if intermediates is not None else data.get('venueLocalBuildIntermediates',{})),
                    **data.get('venueFailedBuildIntermediates',{})}.items():
        user,sep,_=key.partition('|')
        failed=(key==data.get('venueLocalBuildFailure',{}).get('key') or
                key in data.get('venueLocalBuildFailures',{}))
        if not sep or (key not in outputs and not failed) or not isinstance(ids,list):
            raise Refusal('unbound local build intermediate images')
        for image in ids:
            if not isinstance(image,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',image):
                raise Refusal('malformed local build intermediate image')
            all_ids[user+'|'+image]=image
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

def selected_unit(command,unit,tag,source_path=None,offline=True):
    cat=graph.run(command+['cat',unit],timeout=30)
    starts=[line for line in cat.stdout.splitlines() if line.startswith('ExecStart=')]
    if (cat.returncode or len(starts)!=1 or
            (source_path is not None and cat.stdout.splitlines().count('SourcePath='+str(source_path))!=1)):
        raise Refusal('generated selected local build unit unavailable or source path changed')
    if not offline and cat.stdout.splitlines().count('TimeoutStartSec=1800')!=1:
        raise Refusal('network-fetching selected build lacks bounded systemd start timeout')
    start=starts[0];words=start.split()
    network=('--network=none' in words or any(words[i:i+2]==['--network','none'] for i in range(len(words)-1)))
    any_network=any(word.startswith('--network') for word in words)
    if (not start.startswith('ExecStart=/usr/bin/podman build ') or
            words.count('--pull=never')!=1 or (network if offline else not any_network) is False or
            words.count('--tag')!=1 or words[words.index('--tag')+1]!=tag or '--push' in words):
        raise Refusal('installed selected build unit pull/network/tag authority differs')
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

def classify_intermediates(bundle,selector,plan,data,key,image,outputs,recorded):
    """Attest every Buildah layer against ONE selected user-unit start/finish.

    A multi-stage Containerfile leaves anonymous images, sometimes hidden by
    Podman's default image list. Neither an image prune nor a guessed tag is
    authority. Refuse ANY unexplained new ID, process or graph object.
    """
    user,_,tag=key.partition('|');row=data['venueLocalBuildPlan'][key]
    account=next(a for a in plan['accounts'] if a['name']==user)
    unit=row['unit'];source=Path(account['home'])/'.config/containers/systemd'/unit.replace('-build.service','.build')
    state=selected_unit(unit_command(plan,user,unit),unit,tag,source,row['offline'])
    if state.get('ActiveState')!='inactive' or state.get('Job') not in (None,'','0'):
        raise Refusal('build unit still active while classifying generated layers')
    start_floor=source.stat().st_ctime_ns//1000000-1000
    since='--since=@'+str(max(0,start_floor//1000))
    def journal(selector,limit):
        result=graph.run(['journalctl','--boot','--no-pager','--output=json',since,
                          '_UID='+str(account['uid']),selector+'='+unit],timeout=60)
        if result.returncode or len(result.stdout)>limit:
            raise Refusal('selected build journal cannot bound intermediate images')
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    rows=journal('USER_UNIT',262144)
    starts={r.get('JOB_ID'):int(r.get('__REALTIME_TIMESTAMP','0')) for r in rows
            if r.get('MESSAGE_ID')=='7d4958e842da4a758f6c1cdc7b36dcc5' and
               r.get('JOB_TYPE')=='start' and int(r.get('__REALTIME_TIMESTAMP','0'))>start_floor*1000}
    finishes={r.get('JOB_ID'):int(r.get('__REALTIME_TIMESTAMP','0')) for r in rows
              if r.get('MESSAGE_ID')=='39f53479d3a045ac8e11786248231fbf' and
                 r.get('JOB_TYPE')=='start' and r.get('JOB_RESULT')=='done'}
    if len(starts)!=1 or set(starts)!=set(finishes) or None in starts:
        raise Refusal('one completed selected build job not proved for anonymous images')
    began=next(iter(starts.values()));ended=finishes[next(iter(starts))]
    if ended<began:raise Refusal('selected build job clock reversed')
    logs=journal('_SYSTEMD_USER_UNIT',8388608)
    steps={m.group(1) for r in logs if began<=int(r.get('__REALTIME_TIMESTAMP','0'))<=ended+2000000
           if isinstance(r.get('MESSAGE'),str)
           if (m:=re.fullmatch(r'--> ([0-9a-f]{12,64})',r['MESSAGE']))}
    if not any(image.removeprefix('sha256:').startswith(short) for short in steps):
        raise Refusal('built output ID absent from selected build job transcript')
    roots=registry.command_graphs(bundle,plan);command=roots[user][1]
    observed=graph.run(command+['image','ls','-a','--no-trunc','--format','{{.ID}}'],timeout=45)
    if observed.returncode:raise Refusal('selected all-images inventory unavailable')
    found={'sha256:'+x.removeprefix('sha256:') for x in observed.stdout.splitlines() if x.strip()}
    prior={v for k,v in {**data['venueRegistryVerified'],**data['venueBuildBaseVerified'],**outputs}.items()
           if k.startswith(user+'|')}
    prior.update(v for k,ids in recorded.items() if k.startswith(user+'|') for v in ids)
    if image not in found or not prior<=found:
        raise Refusal('selected build graph lost a prior exact image')
    extra=found-prior-{image}
    if len(extra)>128:raise Refusal('selected build generated unbounded anonymous images')
    for ref in extra:
        matching=[short for short in steps if ref.removeprefix('sha256:').startswith(short)]
        if len(matching)!=1:raise Refusal('anonymous build image absent from exact step transcript')
        res=graph.run(command+['image','inspect','--format','{{json .}}',ref],timeout=30)
        if res.returncode:raise Refusal('anonymous selected build image cannot be inspected')
        info=json.loads(res.stdout)
        created=datetime.fromisoformat(info['Created'].replace('Z','+00:00')).timestamp()*1000000
        if (info.get('Id','').removeprefix('sha256:')!=ref.removeprefix('sha256:') or
                info.get('RepoTags') or not info.get('Labels',{}).get('io.buildah.version') or
                created<began-2000000 or created>ended+2000000):
            raise Refusal('anonymous image not a selected completed Buildah step')
    candidate=recorded.copy();candidate[key]=sorted(extra)
    attested=outputs.copy();attested[key]=image
    probe(bundle,selector,plan,data,attested,candidate)  # all eight graphs prewrite
    return sorted(extra)

def classify_failed_intermediates(bundle,selector,plan,data,key,outputs,intermediates):
    user,_,tag=key.partition('|');row=data['venueLocalBuildPlan'][key]
    account=next(a for a in plan['accounts'] if a['name']==user)
    unit=row['unit'];source=Path(account['home'])/'.config/containers/systemd'/unit.replace('-build.service','.build')
    status=selected_unit(unit_command(plan,user,unit),unit,tag,source,row['offline'])
    if status.get('ActiveState') not in ('inactive','failed') or status.get('Job') not in (None,'','0'):
        raise Refusal('failed build has an active selected unit/job')
    floor=source.stat().st_ctime_ns//1000
    since='--since=@'+str(max(0,floor//1000000-1))
    def journal(selector,cap):
        result=graph.run(['journalctl','--boot','--no-pager','--output=json',since,
                          '_UID='+str(account['uid']),selector+'='+unit],timeout=60)
        if result.returncode or len(result.stdout)>cap:
            raise Refusal('failed selected build journal not bounded')
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    events=journal('USER_UNIT',262144)
    starts=[int(r.get('__REALTIME_TIMESTAMP','0')) for r in events
            if r.get('MESSAGE_ID')=='7d4958e842da4a758f6c1cdc7b36dcc5' and
               r.get('JOB_TYPE')=='start' and int(r.get('__REALTIME_TIMESTAMP','0'))>floor]
    failures=[int(r.get('__REALTIME_TIMESTAMP','0')) for r in events
              if r.get('MESSAGE_ID')=='d9b373ed55a64feb8242e02dbe79a49c' and
                 r.get('MESSAGE')==unit+": Failed with result 'exit-code'."]
    if len(starts)!=1 or len(failures)!=1 or failures[0]<=starts[0]:
        raise Refusal('one exact failed selected build job not proved')
    logs=journal('_SYSTEMD_USER_UNIT',8388608)
    steps={m.group(1) for r in logs
           if starts[0]<=int(r.get('__REALTIME_TIMESTAMP','0'))<=failures[0]+2000000
           if isinstance(r.get('MESSAGE'),str)
           if (m:=re.fullmatch(r'--> ([0-9a-f]{12,64})',r['MESSAGE']))}
    roots=registry.command_graphs(bundle,plan);command=roots[user][1]
    if registry.pulled(command,tag) is not None:raise Refusal('failed selected build produced an output')
    listing=graph.run(command+['image','ls','-a','--no-trunc','--format','{{.ID}}'],timeout=45)
    if listing.returncode:raise Refusal('failed selected build image inventory unavailable')
    found={'sha256:'+x.removeprefix('sha256:') for x in listing.stdout.splitlines() if x.strip()}
    prior={v for k,v in {**data['venueRegistryVerified'],**data['venueBuildBaseVerified'],**outputs}.items()
           if k.startswith(user+'|')}
    prior.update(v for k,ids in intermediates.items() if k.startswith(user+'|') for v in ids)
    if not prior<=found:raise Refusal('failed build lost selected prior image')
    extras=found-prior
    if len(extras)>128:raise Refusal('unbounded failed build layers')
    for ref in extras:
        if len([short for short in steps if ref.removeprefix('sha256:').startswith(short)])!=1:
            raise Refusal('failed anonymous image absent from selected step log')
        res=graph.run(command+['image','inspect','--format','{{json .}}',ref],timeout=30)
        if res.returncode:raise Refusal('failed anonymous image cannot be inspected')
        info=json.loads(res.stdout)
        created=datetime.fromisoformat(info['Created'].replace('Z','+00:00')).timestamp()*1000000
        if (info.get('Id','').removeprefix('sha256:')!=ref.removeprefix('sha256:') or
                info.get('RepoTags') or not info.get('Labels',{}).get('io.buildah.version') or
                created<starts[0]-2000000 or created>failures[0]+2000000):
            raise Refusal('failed anonymous image not from selected job')
    # Check all eight graphs with provisional evidence BEFORE ledger authority.
    expected={**data['venueRegistryVerified'],**data['venueBuildBaseVerified'],**outputs}
    for k,ids in intermediates.items():
        for ref in ids:expected[k.partition('|')[0]+'|'+ref]=ref
    for ref in extras:expected[user+'|'+ref]=ref
    registry.probe(bundle,plan,data,expected)
    return sorted(extras)

def prepare(bundle,selector,site_source,ledger,max_new,recover_pending=False,abandon_failed_pending=False,
            classify_only=False,skip_identical_failed_twin=False):
    p,data,plan,_=registry.journal(bundle,selector,site_source,ledger)
    source=authority.authority(bundle,selector,site_source,require_pinned_bases=True)
    selected=plan_for(bundle,source)
    if (data.get('venueRegistryPhase')!='inert-ready' or data.get('venueRegistryVerified')!=source['imageIds'] or
            data.get('venueBuildBasePhase')!='inert-ready' or
            set(data.get('venueBuildBaseVerified',{}))!=set(source['buildBaseStores']) or
            data.get('venueBuildBaseFrozenSha256')!=source['frozenBuildBaseSha256'] or
            data.get('venueCompositeMode')!='inert-ready' or data.get('status')!='units-staged'):
        raise Refusal('three builds need 60 direct and 14 frozen build-base inputs in fully inert installer')
    if type(max_new) is not int or not 1<=max_new<=14:raise Refusal('one to fourteen bounded local builds per invocation')
    if data.get('venueLocalBuildPhase') is None:
        data['venueLocalBuildPhase']='preparing';data['venueLocalBuildPlan']=selected
        data['venueLocalBuildOutputs']={};data['venueLocalBuildIntermediates']={}
        stage.write_ledger(p,data)
    outputs=data.get('venueLocalBuildOutputs')
    intermediates=data.setdefault('venueLocalBuildIntermediates',{})
    if (data.get('venueLocalBuildPhase') not in ('preparing','inert-ready','abandoned-inert') or
            data.get('venueLocalBuildPlan')!=selected or not isinstance(outputs,dict) or
            any(key not in selected or not isinstance(value,str) or
                not re.fullmatch(r'sha256:[0-9a-f]{64}',value) for key,value in outputs.items()) or
            (data['venueLocalBuildPhase']=='inert-ready' and set(outputs)!=set(selected)) or
            not isinstance(intermediates,dict) or any(k not in outputs or not isinstance(v,list)
                 for k,v in intermediates.items()) or
            not isinstance(data.get('venueLocalBuildSkipped',[]),list) or
            any(k not in selected or k in outputs for k in data.get('venueLocalBuildSkipped',[])) or
            len(data.get('venueLocalBuildSkipped',[]))>14):
        raise Refusal('selected local build output CAS differs')
    if classify_only:
        if data.get('venueLocalBuildPending'):
            raise Refusal('pending build process cannot classify image layers')
        missing=sorted(set(outputs)-set(intermediates))
        if len(missing)!=1:raise Refusal('one completed unclassified build output required')
        key=missing[0]
        intermediates[key]=classify_intermediates(bundle,selector,plan,data,key,outputs[key],outputs,intermediates)
        stage.write_ledger(p,data)
        return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
                'classifiedIntermediateIds':sum(map(len,intermediates.values())),
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
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
        state=selected_unit(unit_command(plan,user,unit),unit,tag,path,selected[pending]['offline'])
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
            if (pending.endswith('/android-test-runner-api34:bundle') and
                    len(data.get('venueFailedBuildTmpRetired',[]))!=4):
                raise Refusal('selected failed Android scratch must be exactly retired first')
            failed=classify_failed_intermediates(bundle,selector,plan,data,pending,outputs,intermediates)
            receipt={'key':pending,'result':state.get('Result'),
                     'execMainStatus':state.get('ExecMainStatus')}
            if not data.get('venueLocalBuildFailure'):
                data['venueLocalBuildFailure']=receipt
            failures=data.setdefault('venueLocalBuildFailures',{})
            failures.setdefault(data['venueLocalBuildFailure']['key'],data['venueLocalBuildFailure'])
            failures[pending]=receipt
            data.setdefault('venueFailedBuildIntermediates',{})[pending]=failed
            data.setdefault('venueLocalBuildSkipped',[]).append(pending)
            data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
            if set(outputs)|set(data['venueLocalBuildSkipped'])==set(selected):
                data['venueLocalBuildPhase']='abandoned-inert'
            stage.write_ledger(p,data)
            return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
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
        intermediates[pending]=classify_intermediates(bundle,selector,plan,data,pending,image,outputs,intermediates)
        outputs[pending]=image
        data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
        if set(outputs)==set(selected):data['venueLocalBuildPhase']='inert-ready'
        stage.write_ledger(p,data)
        return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
                'remaining':len(selected)-len(outputs),'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    if recover_pending or abandon_failed_pending:raise Refusal('no interrupted selected output pending review')
    if skip_identical_failed_twin:
        failed=plan['prefix']+'-test-runners|localhost/webservices/android-test-runner-api34:bundle'
        twin=plan['prefix']+'-test-runners|localhost/webservices/android-test-runner-api36:bundle'
        if (data.get('venueLocalBuildSkipped')!=[failed] or
                data.get('venueLocalBuildFailure',{}).get('key')!=failed or
                data.get('venueLocalBuildDuplicateSkip') or twin in outputs or
                data.get('venueLocalBuildPending')):
            raise Refusal('no exact selected failed-build twin to skip')
        a,b=(Path(bundle)/'quadlet/rootless-test-runners'/('p0test-r1-android-test-runner-'+n+'.build')
             for n in ('api34','api36'))
        left=a.read_text().replace('localhost/webservices/android-test-runner-api34:bundle','SAME-TAG')
        right=b.read_text().replace('localhost/webservices/android-test-runner-api36:bundle','SAME-TAG')
        if left!=right or left.count('SAME-TAG')!=1:raise Refusal('failed Android source twin differs')
        user=twin.partition('|')[0];tag=twin.partition('|')[2]
        account=next(x for x in plan['accounts'] if x['name']==user)
        installed=Path(account['home'])/'.config/containers/systemd'/b.name
        record=next((x for x in data['installedUnits'] if x['path']==str(installed)),None)
        if (not record or installed.is_symlink() or installed.stat().st_ino!=record['ino'] or
                installed.read_bytes()!=b.read_bytes()):
            raise Refusal('failed twin installed build source changed')
        state=selected_unit(unit_command(plan,user,selected[twin]['unit']),selected[twin]['unit'],tag,installed,False)
        if state.get('ActiveState')!='inactive' or state.get('Job') not in ('',None,'0') or registry.pulled(
                registry.command_graphs(bundle,plan)[user][1],tag) is not None:
            raise Refusal('failed Android twin is not a fresh inactive output')
        probe(bundle,selector,plan,data,outputs)
        data['venueLocalBuildDuplicateSkip']=twin
        data['venueLocalBuildSkipped']=[failed,twin];stage.write_ledger(p,data)
        return {'status':'preparing','builtOutputIds':len(outputs),'skippedFailedTwins':2,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    roots=probe(bundle,selector,plan,data,outputs)
    if data['venueLocalBuildPhase']=='abandoned-inert':
        raise Refusal('failed selected build may retire only; never retry under the same ledger')
    if data['venueLocalBuildPhase']=='inert-ready':
        return {'status':'inert-ready','builtOutputIds':len(outputs),'remaining':0,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    for key in sorted(set(selected)-set(outputs)-set(data.get('venueLocalBuildSkipped',[])))[:max_new]:
        user,_,tag=key.partition('|');unit=selected[key]['unit']
        command=unit_command(plan,user,unit)
        account=next(a for a in plan['accounts'] if a['name']==user)
        source_path=Path(account['home'])/'.config/containers/systemd'/unit.replace('-build.service','.build')
        staged=next((row for row in data['installedUnits'] if row['path']==str(source_path)),None)
        if (not staged or source_path.is_symlink() or not source_path.is_file() or
                source_path.stat().st_ino!=staged['ino'] or source_path.stat().st_uid!=account['uid']):
            raise Refusal('selected local Quadlet build source inode changed')
        before=selected_unit(command,unit,tag,source_path,selected[key]['offline'])
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
            state=selected_unit(command,unit,tag,source_path,selected[key]['offline'])
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
        intermediates[key]=classify_intermediates(bundle,selector,plan,data,key,image,outputs,intermediates)
        outputs[key]=image
        data.pop('venueLocalBuildPending');data.pop('venueLocalBuildPriorStartTimestamp')
        stage.write_ledger(p,data)
        roots=probe(bundle,selector,plan,data,outputs)
    if set(outputs)==set(selected):
        data['venueLocalBuildPhase']='inert-ready';stage.write_ledger(p,data)
    elif set(outputs)|set(data.get('venueLocalBuildSkipped',[]))==set(selected):
        data['venueLocalBuildPhase']='abandoned-inert';stage.write_ledger(p,data)
    return {'status':data['venueLocalBuildPhase'],'builtOutputIds':len(outputs),
            'remaining':len(selected)-len(outputs),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','site-source','ledger'):a.add_argument('--'+key,required=True)
    a.add_argument('--max-new',type=int,default=1)
    pending=a.add_mutually_exclusive_group()
    pending.add_argument('--recover-pending-only',action='store_true')
    pending.add_argument('--abandon-failed-pending-only',action='store_true')
    pending.add_argument('--classify-intermediates-only',action='store_true')
    pending.add_argument('--skip-identical-failed-twin-only',action='store_true')
    args=a.parse_args()
    try:print(json.dumps(prepare(args.bundle,args.selector,args.site_source,args.ledger,args.max_new,
                                 args.recover_pending_only,args.abandon_failed_pending_only,
                                 args.classify_intermediates_only,args.skip_identical_failed_twin_only),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('venue fourteen local build discovery refused: '+str(exc)) from exc
if __name__=='__main__':main()
