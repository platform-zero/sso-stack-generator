#!/usr/bin/env python3
"""Quarantine ONLY an exact version-2 failed start; never reset populated data.

A crash during activation can leave a target partly active. The selected
version-2 installer must journal the intent BEFORE queuing any unit. This
worker stops only the selected 194-unit namespace in reverse declared order,
retains all data/graphs/inputs, and will not issue an automatic retry.
"""
import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import time

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
stage=load('venue_stage','venue-owned-stage.py')
units=load('venue_units','venue-unit-stage.py')
graph=load('venue_graph','venue-graph-clear.py')
Refusal=stage.Refusal

def selected_commands(plan):
    root=['systemctl']
    return [(None,root)]+[(a, ['runuser','-u',a['name'],'--','env',
                'HOME='+a['home'],'XDG_RUNTIME_DIR=/run/user/'+str(a['uid']),
                'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/'+str(a['uid'])+'/bus',
                'systemctl','--user']) for a in plan['accounts']]

def targets(bundle,plan,state):
    selected=units.manifest(bundle,plan)
    if (selected!=state.get('unitFiles') or len(selected)!=194 or
            len(state.get('installedUnits',[]))!=194):
        raise Refusal('installed unit names/source SHA not selected')
    paths={row['path']:row for row in state['installedUnits']}
    if set(paths)!=set(selected):raise Refusal('installed unit inode set changed')
    commands={None:[],**{a['name']:[] for a in plan['accounts']}}
    for dest,entry in selected.items():
        p=Path(dest);s=p.lstat();row=paths[dest]
        if (p.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or
                (s.st_dev,s.st_ino,s.st_uid)!=(row['dev'],row['ino'],entry['uid']) or
                units.hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']):
            raise Refusal('selected installed unit inode/content changed before quarantine')
        account=next((a for a in plan['accounts'] if a['uid']==entry['uid']),None) if entry['uid'] else None
        owner=account['name'] if account else None
        if entry['uid'] and account is None:raise Refusal('unit UID not selected account')
        if p.suffix in ('.container','.build','.network','.target'):
            commands[owner].append(p.name if p.suffix=='.target' else p.stem+(
                              '-build.service' if p.suffix=='.build' else
                              '-network.service' if p.suffix=='.network' else '.service'))
    api=api_owners(bundle,plan)
    if 'venueStartApiSockets' in state:
        if state['venueStartApiSockets']!=api:raise Refusal('API socket intent differs from exact native mounts')
        for owner in api:commands[owner].extend(['podman.socket','podman.service'])
    return commands

def api_owners(bundle,plan):
    result=[]
    for account in plan['accounts']:
        domain=account['name'].removeprefix(plan['prefix']+'-')
        directory=Path(bundle)/'quadlet'/('rootless-'+domain)
        if any('Volume=%t/podman/podman.sock:/run/podman/podman.sock' in p.read_text().splitlines()
               for p in directory.glob('*.container')):result.append(account['name'])
    return result

def host_context(bundle,plan):
    base=Path('/usr/local/libexec')/(plan['prefix']+'-control')
    pointer=base/'agent-services-current-host'
    if not pointer.is_symlink() or pointer.lstat().st_uid!=0:
        raise Refusal('selected installed isolated host role required')
    slot=pointer.resolve(strict=True)
    if slot.parent!=base/'agent-service-releases':raise Refusal('host role escaped selected namespace')
    file=slot/'p0_host_context.py';info=file.lstat()
    if file.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode&0o022 or info.st_nlink!=1:
        raise Refusal('unsafe installed host context code')
    module=load('installed_host_context',file)
    context=module.current(source=file)
    if (context is None or context.namespace!=plan['prefix'] or
            context.data['sourceProvenanceSha256']!=stage.sha(Path(bundle)/'source-provenance.json') or
            context.data['siteVmSpecSha256']!=stage.sha(Path(bundle)/'site/agent-vm.json')):
        raise Refusal('host context does not bind this exact installed bundle/site')
    return context

@contextmanager
def lifecycle(context):
    """Same private lease as controller mutation_lease; no cold-start fallback."""
    parent=context.runtime;s=parent.lstat()
    if (parent.is_symlink() or any(p.is_symlink() for p in parent.parents) or
            not stat.S_ISDIR(s.st_mode) or s.st_uid or stat.S_IMODE(s.st_mode)!=0o700):
        raise Refusal('unsafe installed lifecycle directory')
    fd=os.open(parent/'lifecycle.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:
            raise Refusal('unsafe installed lifecycle lease')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Refusal('lifecycle operation already in progress') from None
        yield
    finally:os.close(fd)

def runtime_receipt(context,phase,authorized):
    path=context.runtime/'runtime-authority.json'
    if os.path.lexists(path):
        s=path.lstat()
        if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:
            raise Refusal('unsafe installed runtime authority')
        prior=json.loads(path.read_text())
        if (prior.get('schemaVersion')!=2 or prior.get('namespace')!=context.namespace or
                prior.get('hostContextSha256')!=context.digest):
            raise Refusal('runtime authority belongs to another installed context')
    else:prior={}
    receipt={**prior,'schemaVersion':2,'namespace':context.namespace,
             'hostContextSha256':context.digest,'sourceProvenanceSha256':context.data['sourceProvenanceSha256'],
             'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'phase':phase,'activationAuthorized':authorized}
    stage.write_ledger(path,receipt,create=not os.path.lexists(path))

def cancel_starts(command,names):
    result=graph.run(command+['list-jobs','--no-legend','--no-pager'],timeout=30)
    if result.returncode:raise Refusal('cannot enumerate selected jobs for quarantine')
    for line in result.stdout.splitlines():
        fields=line.split()
        if len(fields)<4:raise Refusal('malformed native job inventory')
        if fields[1] in names and fields[2]!='stop':
            if not fields[0].isdigit():raise Refusal('invalid selected native job identity')
            if graph.run(command+['cancel',fields[0]],timeout=30).returncode:
                # A job can finish between enumeration and cancellation. It is
                # safe only if a fresh successful inventory proves that exact
                # ID absent; the following explicit stop still fences its unit.
                again=graph.run(command+['list-jobs','--no-legend','--no-pager'],timeout=30)
                rows=[line.split() for line in again.stdout.splitlines()]
                if again.returncode or any(len(row)<4 or row[0]==fields[0] for row in rows):
                    raise Refusal('selected late start job could not be cancelled')

def observed_ready(row,epoch,name):
    changed=max(int(row.get('ExecMainStartTimestampMonotonic','0')),
                int(row.get('InactiveExitTimestampMonotonic','0')))>=epoch
    failed=row.get('ActiveState')=='failed' or row.get('Result','success') not in ('','success')
    if failed:
        if changed:raise Refusal('native selected service failed: '+name)
        return False  # prior attempt's retained Result is not this start's failure
    return changed and (row.get('ActiveState')=='active' or
           (row.get('ActiveState')=='inactive' and row.get('ExecMainStatus')=='0'))


def reviewed_retry(state,plan,context,*,require_repair=True):
    repair=state.get('venueStartRepair',{})
    if (state.get('plan')!=plan or state.get('venueInstallerVersion')!=2 or
            state.get('status')!='installed-starting' or state.get('venueInstallerPhase')!='starting' or
            state.get('venueStartPhase')!='failed-quarantined' or state.get('activationAuthorized') is not False or
            state.get('venueStartIntent')!=plan['quadletTreeSha256'] or
            state.get('venueStartHostContextSha256')!=context.digest or
            state.get('venueRegistryPhase')!='inert-ready' or state.get('managerStopped') or
            state.get('managerStarted')!=[a['name'] for a in plan['accounts']]):
        raise Refusal('exact quarantined intent required')
    if require_repair:
        kind=repair.get('kind');source={'missing-owned-log-bind':HERE/'venue-bind-dirs.py',
                                     'stale-native-result':Path(__file__)}.get(kind)
        if (source is None or repair.get('sourceSha256')!=stage.sha(source) or
                repair.get('appliesToStartMonotonicUsec')!=state.get('venueStartMonotonicUsec') or
                (kind=='missing-owned-log-bind' and not repair.get('paths')) or
                (kind=='stale-native-result' and (not repair.get('unit') or
                    max(int(repair.get('observed',{}).get('ExecMainStartTimestampMonotonic','0')),
                        int(repair.get('observed',{}).get('InactiveExitTimestampMonotonic','0')))>=state['venueStartMonotonicUsec']))):
            raise Refusal('unconsumed specific changed-source repair required')
    path=context.runtime/'runtime-authority.json';info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
        raise Refusal('unsafe failed runtime receipt')
    receipt=json.loads(path.read_text())
    expected={'schemaVersion':2,'namespace':context.namespace,'hostContextSha256':context.digest,
              'sourceProvenanceSha256':context.data['sourceProvenanceSha256'],
              'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'phase':'failed-quarantined','activationAuthorized':False}
    if any(receipt.get(key)!=value for key,value in expected.items()):
        raise Refusal('failed runtime receipt not fenced in this exact current-boot context')


def start(bundle,selector,ledger,timeout=900,*,reviewed_failed_sha=None):
    """First real activation only. Partial failure fences/stops, never retries."""
    registry=load('venue_registry','venue-registry-images.py')
    screen=load('venue_screen','verify-existing-host-venue.py')
    p=Path(ledger)
    if os.geteuid()!=0 or p.is_symlink() or not p.is_file() or p.stat().st_uid or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('root0600 installed preparation journal required')
    state=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    context=host_context(bundle,plan)
    selected=targets(bundle,plan,state)
    marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
    with lifecycle(context):
        recovering=reviewed_failed_sha is not None
        if recovering and stage.sha(p)!=reviewed_failed_sha:raise Refusal('reviewed failed-stage SHA CAS changed')
        state=json.loads(p.read_text())
        if recovering:reviewed_retry(state,plan,context)
        if not recovering and (state.get('plan')!=plan or state.get('venueInstallerVersion')!=1 or
                state.get('venueInstallerPhase')!='inert-ready' or state.get('status')!='units-staged' or
                state.get('activationAuthorized') is not False or state.get('venueStartPhase') is not None or
                state.get('venueRegistryPhase')!='inert-ready' or state.get('managerStopped') or
                state.get('managerStarted')!=[a['name'] for a in plan['accounts']] or
                os.path.lexists(marker) or os.path.lexists(context.runtime/'runtime-authority.json')):
            raise Refusal('fresh exact inert stage required; no automatic activation retry')
        source=registry.authority.authority(bundle,selector)
        if (not source['frozenLocalImagePairs'] or state.get('venueRegistryPlan')!=source['imageIds'] or
                state.get('venueRegistryVerified')!=source['imageIds']):
            raise Refusal('all selected frozen native inputs must be installed and verified')
        units.units_idle(plan);screen.port_screen(json.loads(Path(selector).read_text()))
        registry.reserve();context.physical_reserves()
        registry.probe(bundle,plan,state,source['imageIds'],**({'recovering':True} if recovering else {}))
        if recovering and state.get('venueRecoveryContainers'):
            raise Refusal('retained native bootstrap containers require exact non-volume cleanup before recovery')
        commands={name:command for name,_,command in graph.stores(bundle,plan)}
        metadata=json.loads((Path(bundle)/'podman-domains.json').read_text())
        for (image,user),aliases in registry.authority.pinned_images.frozen_aliases(Path(bundle),metadata).items():
            if any(registry.pulled(commands[user],alias)!=image for alias in aliases):
                raise Refusal('frozen dynamic alias missing or substituted')
        binds=load('venue_binds','venue-bind-dirs.py')
        _,_,sources=binds.checked_stage(bundle,selector,ledger,('units-staged','installed-starting') if recovering else ('units-staged',))
        logs=binds.log_sources(bundle,plan)
        if {row['path']:row['consumers'] for row in state.get('venueLogBindDirs',[])}!=logs:
            raise Refusal('actual namespace log binds were not prepared/receipted')
        for row in state.get('venueLogBindDirs',[]):
            path=Path(row['path']);info=path.lstat()
            if path.is_symlink() or not path.is_dir() or (info.st_dev,info.st_ino,info.st_uid)!=(row['dev'],row['ino'],0):
                raise Refusal('prepared namespace log bind identity changed')
        if {row['path'] for row in state.get('venueDataBindDirs',[])}!=set(sources):
            raise Refusal('exact selected data bind set differs')
        api=api_owners(bundle,plan)
        for account,command in selected_commands(plan):
            if account is None or account['name'] not in api:continue
            socket_path=Path('/run/user/'+str(account['uid'])+'/podman/podman.sock')
            if os.path.lexists(socket_path):
                info=socket_path.lstat()
                stopped=graph.run(command+['is-active','podman.socket','podman.service'],timeout=30)
                if (not recovering or socket_path.is_symlink() or not stat.S_ISSOCK(info.st_mode) or info.st_uid!=account['uid'] or
                        stopped.stdout.split()!=['inactive','inactive']):
                    raise Refusal('API socket is not an exact stopped selected recovery socket')
            result=graph.run(command+['show-environment'],timeout=30)
            if result.returncode:raise Refusal('cannot inspect selected API manager environment')
            environment=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
            if (environment.get('HOME')!=account['home'] or
                    any(key in environment for key in ('CONTAINER_HOST','CONTAINER_CONNECTION',
                        'CONTAINERS_STORAGE_CONF','CONTAINERS_CONF','CONTAINERS_CONF_OVERRIDE','XDG_CONFIG_HOME'))):
                raise Refusal('API manager environment can escape selected storage authority')
        for row in state.get('venueDataBindDirs',[]):
            path=Path(row['path']);info=path.lstat()
            if (path.is_symlink() or not path.is_dir() or (info.st_dev,info.st_ino)!=(row['dev'],row['ino']) or
                    (not recovering and (info.st_uid!=sources[str(path)]['owner'] or any(path.iterdir())))):
                raise Refusal('selected data bind identity changed or fresh bind contains authored data')
        if len(state.get('venueDataBindDirs',[]))!=61:raise Refusal('all 61 exact fresh data binds required')
        if recovering:
            info=marker.lstat()
            if (marker.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or
                    stat.S_IMODE(info.st_mode)!=0o600 or marker.read_text()!=plan['prefix']+'-volume-ready-v1\n'):
                raise Refusal('original exact failed-intent readiness marker changed')
            state.setdefault('venueStartAttempts',[]).append({key:state.get(key) for key in
                  ('venueStartPhase','venueStartIntent','venueStartMonotonicUsec','venueStartRepair',
                   'venueStartQuarantineUnits','venueRecoveryNetworks','venueRecoveryContainers',
                   'venueStartLifecycleSha256','venueStartFailure','venueStartFenceMonotonicUsec')})
        state.update(venueInstallerVersion=2,venueInstallerPhase='starting',status='installed-starting',
                     venueStartPhase='starting',venueStartIntent=plan['quadletTreeSha256'],
                     venueStartHostContextSha256=context.digest,venueStartLifecycleSha256=stage.sha(__file__),activationAuthorized=True,
                     venueStartMonotonicUsec=time.monotonic_ns()//1000,venueStartQueued=[],venueStartApiSockets=api)
        stage.write_ledger(p,state)  # intent BEFORE marker, authority or native start
        try:
            if not recovering:
                fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'w') as out:
                    out.write(plan['prefix']+'-volume-ready-v1\n');out.flush();os.fsync(out.fileno())
            runtime_receipt(context,'starting',True)
            for account,command in selected_commands(plan):
                if account is None or account['name'] not in api:continue
                if graph.run(command+['start','podman.socket'],timeout=30).returncode:
                    raise Refusal('selected rootless API socket start failed')
                socket=Path('/run/user/'+str(account['uid'])+'/podman/podman.sock');info=socket.lstat()
                if socket.is_symlink() or not stat.S_ISSOCK(info.st_mode) or info.st_uid!=account['uid']:
                    raise Refusal('selected API socket identity differs')
            for account,command in selected_commands(plan):
                registry.reserve()
                owner=account['name'] if account else 'root'
                state['venueStartPending']=owner;stage.write_ledger(p,state)
                result=graph.run(command+['start','--job-mode=fail','--no-block',plan['prefix']+'.target'],timeout=30)
                if result.returncode:raise Refusal('selected native start request failed: '+owner)
                state['venueStartQueued'].append(owner);state.pop('venueStartPending');stage.write_ledger(p,state)
        except Exception:
            runtime_receipt(context,'failed-quarantining',False)
            raise  # caller performs the same exact journaled stop below
    deadline=time.monotonic()+timeout
    while True:
        registry.reserve();context.physical_reserves()
        pending=[]
        for account,command in selected_commands(plan):
            owner=account['name'] if account else None
            # Build recipes and on-demand Android services are intentionally not
            # boot targets. Inspect actual declared startup leaves, not target
            # ActiveState (Wants failures do not fail a target).
            directory=Path(bundle)/'quadlet'/('rootless-'+account['name'].removeprefix(plan['prefix']+'-') if account else 'rootful')
            wanted=set()
            for file in directory.glob('*.target'):
                for line in file.read_text().splitlines():
                    if line.startswith(('Wants=','Requires=')):
                        wanted.update(x for x in line.split('=',1)[1].split() if x.endswith('.service'))
            if not wanted<=set(selected[owner]):raise Refusal('startup dependency escaped selected unit set')
            for name in sorted(wanted|{plan['prefix']+'.target'}):
                registry.reserve()
                result=graph.run(command+['show',name,'-p','ActiveState','-p','Result','-p','ExecMainStatus','-p','ExecMainStartTimestampMonotonic','-p','InactiveExitTimestampMonotonic'],timeout=30)
                if result.returncode:raise Refusal('cannot inspect selected startup state')
                row=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
                if not observed_ready(row,state['venueStartMonotonicUsec'],name):pending.append(name)
        if not pending:
            with lifecycle(context):
                state=json.loads(p.read_text())
                if state.get('venueStartPhase')!='starting':raise Refusal('activation was fenced during observation')
                state.update(venueStartPhase='running',venueInstallerPhase='running',status='installed-running')
                stage.write_ledger(p,state);runtime_receipt(context,'running',True)
            return {'status':'running','activationAuthorized':True,'acceptedIntegratedInstalls':0}
        if time.monotonic()>=deadline:raise Refusal('selected native startup deadline; pending '+','.join(pending))
        time.sleep(2)

def quarantine(bundle,selector,ledger,*,failure_reason=None):
    plan=stage.owned_plan(bundle,selector);context=host_context(bundle,plan)
    with lifecycle(context):return quarantine_locked(bundle,selector,ledger,context,failure_reason=failure_reason)

def quarantine_locked(bundle,selector,ledger,context,*,failure_reason=None):
    p=Path(ledger)
    if os.geteuid()!=0 or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('exact root0600 failed-start journal required')
    state=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('venueInstallerVersion')!=2 or
            state.get('venueStartPhase') not in ('starting','running','failed-quarantining') or
            state.get('status') not in ('units-staged','installed-starting','installed-running') or
            state.get('managerStarted')!=[a['name'] for a in plan['accounts']] or
            state.get('managerStopped') or state.get('activationAuthorized') is not True or
            state.get('venueStartIntent')!=plan['quadletTreeSha256']):
        raise Refusal('no exact version-2 failed activation intent; never stop an inert or other venue')
    selected=targets(bundle,plan,state)
    marker=Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt'
    if marker.is_symlink() or (marker.exists() and
            (not marker.is_file() or marker.stat().st_uid!=0 or stat.S_IMODE(marker.stat().st_mode)!=0o600)):
        raise Refusal('readiness marker changed before failed-start stop')
    if state.get('venueStartHostContextSha256')!=context.digest:
        raise Refusal('failed-start intent belongs to another host context')
    runtime_receipt(context,'failed-quarantining',False)
    state['venueStartPhase']='failed-quarantining'
    state['venueStartFenceMonotonicUsec']=time.monotonic_ns()//1000
    if failure_reason is not None:
        state['venueStartFailure']={'reason':str(failure_reason)[:1000],
            'startMonotonicUsec':state['venueStartMonotonicUsec'],'sourceSha256':stage.sha(__file__)}
    stage.write_ledger(p,state)
    # Stop exact namespace units, never restart previously stopped production.
    # Targets first, then containers/builds/networks; the latter cannot be
    # inferred stopped merely because a target has entered inactive state.
    for account,command in reversed(selected_commands(plan)):
        owner=account['name'] if account else None
        names=selected[owner]
        cancel_starts(command,names)
        ordered=sorted(names,key=lambda x:(not x.endswith('.target'),x),reverse=False)
        result=graph.run(command+['stop','--no-block',*ordered],timeout=30)
        if result.returncode:raise Refusal('selected start quarantine stop request failed; receipt retained')
        cancel_starts(command,names)
    # units_idle checks every selected namespace on every manager AND jobs.
    # No graph/data retirement occurs here. Failed or partly stopped intent
    # remains quarantining and requires explicit review/resume.
    deadline=time.monotonic()+180
    while True:
        try:
            units.units_idle(plan)
            for account,command in selected_commands(plan):
                if account is None or account['name'] not in state.get('venueStartApiSockets',[]):continue
                result=graph.run(command+['is-active','podman.socket','podman.service'],timeout=30)
                if any(x not in ('inactive','failed') for x in result.stdout.splitlines()) or not result.stdout.strip():
                    raise Refusal('selected API unit became active during quarantine')
                jobs=graph.run(command+['list-jobs','--no-legend','--no-pager'],timeout=30)
                if jobs.returncode or any(len(x.split())>=2 and x.split()[1] in selected[account['name']] for x in jobs.stdout.splitlines()):
                    raise Refusal('unexpected systemd job during API quarantine')
            break
        except ValueError as exc:
            if ('became active' not in str(exc) and 'unexpected systemd job' not in str(exc)) or time.monotonic()>=deadline:
                raise
            time.sleep(2)
    state['venueStartPhase']='failed-quarantined'
    state['activationAuthorized']=False  # no restart after failure without a fresh exact intent
    state['venueStartQuarantineUnits']=sum(map(len,selected.values()))
    stage.write_ledger(p,state)
    runtime_receipt(context,'failed-quarantined',False)
    return {'status':'failed-quarantined','selectedUnitNames':state['venueStartQuarantineUnits'],
            'populatedDataRetained':True,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def review_stale_result(bundle,selector,ledger,reviewed_failed_sha,unit):
    p=Path(ledger);plan=stage.owned_plan(bundle,selector);context=host_context(bundle,plan)
    with lifecycle(context):
        if stage.sha(p)!=reviewed_failed_sha:raise Refusal('stale observation review ledger CAS changed')
        state=json.loads(p.read_text());reviewed_retry(state,plan,context,require_repair=False)
        units.units_idle(plan);selected=targets(bundle,plan,state)
        matches=[cmd for account,cmd in selected_commands(plan) if unit in selected[account['name'] if account else None]]
        if len(matches)!=1:raise Refusal('failed native observation must identify one exact selected owner/unit')
        result=graph.run(matches[0]+['show',unit,'-p','ActiveState','-p','Result','-p','ExecMainStartTimestampMonotonic',
                                     '-p','InactiveExitTimestampMonotonic'],timeout=30)
        row=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        epoch=state['venueStartMonotonicUsec'];source_sha=stage.sha(__file__)
        if (result.returncode or row.get('Result','success') in ('','success') or
                row.get('ActiveState') not in ('failed','inactive') or observed_ready(row,epoch,unit) or
                state.get('venueStartLifecycleSha256')==source_sha):
            raise Refusal('no proven stale prior-epoch failure or no changed observation source')
        state['venueStartRepair']={'kind':'stale-native-result','unit':unit,'observed':row,
            'sourceSha256':source_sha,'previousLifecycleSha256':state.get('venueStartLifecycleSha256'),
            'appliesToStartMonotonicUsec':epoch}
        stage.write_ledger(p,state)
        return {'reviewedStaleNativeResult':unit,'legacySourceHashUnrecorded':state.get('venueStartLifecycleSha256') is None,
                'servicesStarted':False,'dataReset':False}


def cleanup_stopped(bundle,selector,ledger,reviewed_failed_sha):
    p=Path(ledger);plan=stage.owned_plan(bundle,selector)
    context=host_context(bundle,plan);registry=load('bootstrap_cleanup_registry','venue-registry-images.py')
    with lifecycle(context):
        if stage.sha(p)!=reviewed_failed_sha:raise Refusal('stopped native cleanup ledger CAS changed')
        state=json.loads(p.read_text());reviewed_retry(state,plan,context,require_repair=False);units.units_idle(plan)
        source=registry.authority.authority(bundle,selector)
        roots,_=registry.probe(bundle,plan,state,source['imageIds'],recovering=True)
        for key,proof in list(state.get('venueRecoveryContainers',{}).items()):
            user=key.split('|',1)[0];command=roots[user][1];identity=proof['id']
            state['venueStoppedBootstrapCleanupIntent']={**proof,'user':user,'sourceSha256':stage.sha(__file__)}
            stage.write_ledger(p,state)
            # Neither command removes volumes or stops/races a live container.
            # Inspection above proves exact stopped IDs from this native epoch.
            for operation in ('cleanup','rm'):
                result=graph.run(command+['container',operation,identity],timeout=60)
                if result.returncode:raise Refusal('exact stopped bootstrap '+operation+' failed; intent retained')
            state.setdefault('venueStoppedBootstrapCleaned',{})[identity]=state.pop('venueStoppedBootstrapCleanupIntent')
            stage.write_ledger(p,state)
        registry.probe(bundle,plan,state,source['imageIds'],recovering=True);stage.write_ledger(p,state)
        return {'retiredStoppedNativeContainers':len(state.get('venueStoppedBootstrapCleaned',{})),
                'dataAndVolumesRetained':True,'servicesStarted':False,'activationAuthorized':False}


def retire_authority(bundle,selector,ledger,expected_sha):
    """Remove only a false old runtime capability after complete exact retirement."""
    path=Path(ledger);info=path.lstat()
    if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600):
        raise Refusal('protected exact retired-ledger required')
    state=json.loads(path.read_bytes());plan=stage.owned_plan(bundle,selector)
    if stage.sha(path)!=expected_sha:raise Refusal('exact retired-ledger SHA review required')
    context=host_context(bundle,plan)
    with lifecycle(context):
        state=json.loads(path.read_bytes())
        if (stage.sha(path)!=expected_sha or state.get('plan')!=plan or state.get('status')!='retired-empty' or
                state.get('venueInstallerVersion')!=2 or state.get('venueInstallerPhase')!='retired-inert' or
                state.get('activationAuthorized') is not False or state.get('venueStartHostContextSha256')!=context.digest or
                state.get('venueOwnedReset',{}).get('phase')!='empty-owned' or
                state.get('graphCleared')!=['root']+[a['name'] for a in plan['accounts']] or
                set(state.get('managerStopped',[]))!={a['name'] for a in plan['accounts']} or
                not state.get('createdPaths') or set(state.get('pathIdentities',{}))!=set(state['createdPaths']) or
                any(os.path.lexists(p) for p in state['pathIdentities'])):
            raise Refusal('complete exact experimental retirement required before authority removal')
        for account in plan['accounts']:
            for lookup,value in ((stage.pwd.getpwnam,account['name']),(stage.pwd.getpwuid,account['uid'])):
                try:lookup(value)
                except KeyError:continue
                raise Refusal('retired account name/UID still exists or was reused')
        runtime=context.runtime/'runtime-authority.json';intent=state.get('venueRuntimeAuthorityRetireIntent')
        if os.path.lexists(runtime):
            info=runtime.lstat();body=runtime.read_bytes();receipt=json.loads(body)
            if (runtime.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or
                    stat.S_IMODE(info.st_mode)!=0o600 or receipt.get('schemaVersion')!=2 or
                    receipt.get('namespace')!=context.namespace or receipt.get('hostContextSha256')!=context.digest or
                    receipt.get('sourceProvenanceSha256')!=context.data['sourceProvenanceSha256'] or
                    receipt.get('phase')!='failed-quarantined' or receipt.get('activationAuthorized') is not False):
                raise Refusal('only the exact false failed-context receipt may be retired')
            current={'path':str(runtime),'dev':info.st_dev,'ino':info.st_ino,'sha256':stage.hashlib.sha256(body).hexdigest(),'contextSha256':context.digest}
            if intent is not None and intent!=current:raise Refusal('interrupted authority retirement identity differs')
            state['venueRuntimeAuthorityRetireIntent']=current;stage.write_ledger(path,state);runtime.unlink();intent=current
        elif not intent or intent.get('path')!=str(runtime) or intent.get('contextSha256')!=context.digest:
            raise Refusal('missing authority without exact pending retirement intent')
        fd=os.open(context.runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        state['venueRuntimeAuthorityRetired']=state.pop('venueRuntimeAuthorityRetireIntent');stage.write_ledger(path,state)
        return {'status':'retired-runtime-authority','activationAuthorized':False,'servicesStarted':False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):ap.add_argument('--'+name,required=True)
    mode=ap.add_mutually_exclusive_group()
    mode.add_argument('--cleanup-stopped-native',metavar='REVIEWED_LEDGER_SHA256')
    mode.add_argument('--retire-runtime-authority',metavar='RETIRED_LEDGER_SHA256')
    mode.add_argument('--review-stale-result-unit',metavar='UNIT')
    ap.add_argument('--reviewed-ledger-sha',metavar='SHA256')
    a=ap.parse_args()
    try:
        if a.review_stale_result_unit:
            if not a.reviewed_ledger_sha:raise Refusal('explicit stale-result ledger SHA review required')
            result=review_stale_result(a.bundle,a.selector,a.ledger,a.reviewed_ledger_sha,a.review_stale_result_unit)
        else:
            if a.reviewed_ledger_sha is not None:raise Refusal('ledger SHA is only for explicit stale-result review')
            if a.retire_runtime_authority is not None:result=retire_authority(a.bundle,a.selector,a.ledger,a.retire_runtime_authority)
            else:result=(cleanup_stopped(a.bundle,a.selector,a.ledger,a.cleanup_stopped_native)
                         if a.cleanup_stopped_native is not None else quarantine(a.bundle,a.selector,a.ledger))
        print(json.dumps(result,sort_keys=True))
    except (Refusal,OSError,KeyError,ValueError,TypeError) as exc:
        raise SystemExit('venue exact failed-start quarantine refused: '+str(exc)) from exc
if __name__=='__main__':main()
