#!/usr/bin/env python3
"""One scoped native health tick for isolated rootful Podman 5.4 stores.

Podman's transient health units forward PATH only, not storage configuration.
This adapter retains native health commands/logs/sdnotify, without default-store
access, backend starts, retries, global manager environment or daemon changes.
"""
import argparse
import datetime
import importlib.util
import json
import hashlib
import os
import stat
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('root_health_lifecycle',HERE/'venue-start-quarantine.py')
lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
Refusal=lifecycle.Refusal
UNIT_DIRECTORY=Path('/etc/systemd/system')
RUNTIME_DIRECTORY=Path('/run')
PROC_DIRECTORY=Path('/proc')

def files(bundle,selector,ledger,plan):
    paths=[str(Path(p).resolve()) for p in (bundle,selector,ledger)]
    if any(any(c.isspace() for c in p) for p in paths):raise Refusal('ambiguous health adapter argument path')
    prefix=plan['prefix'];name=prefix+'-root-health'
    service=(f'[Unit]\nDescription=Scoped {prefix} native root health checks\nPartOf={prefix}.target\n'
        f'[Service]\nType=oneshot\nWorkingDirectory=/\nExecStart=/usr/bin/python3 -B {paths[0]}/ops/venue-root-health.py --bundle {paths[0]} --selector {paths[1]} --ledger {paths[2]}\n'
        'TimeoutStartSec=300\nMemoryMax=4G\nCPUQuota=200%\nRestart=no\nUMask=0077\n')
    timer=(f'[Unit]\nDescription=Scoped {prefix} health cadence\nPartOf={prefix}.target\n'
        f'[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=5s\nAccuracySec=1s\nUnit={name}.service\n')
    return {str(UNIT_DIRECTORY/(name+'.'+suffix)):body for suffix,body in [('service',service),('timer',timer)]}

def native_files(rows,*,fresh=False):
    if fresh:
        jobs=lifecycle.graph.run(['systemctl','list-jobs','--no-legend','--no-pager'],timeout=30)
        names={Path(path).name for path in rows};pending=[line.split() for line in jobs.stdout.splitlines()]
        if jobs.returncode or any(len(row)<4 or row[1] in names for row in pending):raise Refusal('scoped health native jobs pending or unreadable')
    for path in rows:
        result=lifecycle.graph.run(['systemctl','show',Path(path).name,'-p','LoadState','-p','FragmentPath','-p','DropInPaths','-p','ActiveState','-p','UnitFileState','-p','MainPID','-p','ControlGroup'],timeout=30)
        props=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if result.returncode or props.get('DropInPaths')!='':raise Refusal('unobservable/overridden scoped health unit')
        if fresh:
            # A retained failed result is not a live unit. Never reset it to make
            # preparation pass: require no fragment/override/job and no process or
            # cgroup instead. New source/epoch execution retains historical proof.
            service=path.endswith('.service')
            if (props.get('LoadState')!='not-found' or props.get('ActiveState') not in (('inactive','failed') if service else ('inactive',)) or
                    props.get('FragmentPath')!='' or service and (props.get('MainPID')!='0' or props.get('ControlGroup')!='')):
                raise Refusal('foreign/live scoped health native unit exists')
        elif props.get('LoadState')!='loaded' or props.get('FragmentPath')!=path or props.get('UnitFileState')!='static':raise Refusal('scoped health native fragment/enabling differs')

def checked(bundle,selector,ledger):
    b,p,data,plan=lifecycle.ingress.context(bundle,selector,ledger);rows=files(b,selector,p,plan)
    records=data.get('venueRootHealthUnits',{})
    if data.get('venueRootHealthPhase')!='inert-ready' or set(records)!=set(rows):raise Refusal('complete scoped root health receipt required')
    for name,body in rows.items():
        path=Path(name);s=path.lstat();row=records[name];digest=hashlib.sha256(body.encode()).hexdigest()
        if (path.is_symlink() or any(v.is_symlink() for v in path.parents) or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or
                (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=(row['dev'],row['ino'],0,0o644) or
                lifecycle.stage.sha(path)!=digest or row['sha256']!=digest):raise Refusal('scoped root health file CAS changed')
    native_files(rows)
    return rows

def prepare(bundle,selector,ledger):
    b,p,data,plan=lifecycle.ingress.context(bundle,selector,ledger);rows=files(b,selector,p,plan)
    if (data.get('venueInstallerVersion')!=1 or data.get('venueInstallerPhase')!='preparing' or data.get('activationAuthorized') is not False or
            'venueRootHealthPhase' in data or UNIT_DIRECTORY.is_symlink() or UNIT_DIRECTORY.stat().st_uid or UNIT_DIRECTORY.stat().st_mode&0o022 or
            any(os.path.lexists(path) for path in rows)):raise Refusal('fresh inactive scoped root health preparation required')
    native_files(rows,fresh=True)
    data.update(venueRootHealthPhase='preparing',venueRootHealthUnits={});lifecycle.stage.write_ledger(p,data)
    for name,body in rows.items():
        data['venueRootHealthPending']=name;lifecycle.stage.write_ledger(p,data)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as out:out.write(body);out.flush();os.fsync(out.fileno())
        Path(name).chmod(0o644);s=Path(name).lstat()
        data['venueRootHealthUnits'][name]={'dev':s.st_dev,'ino':s.st_ino,'sha256':hashlib.sha256(body.encode()).hexdigest()}
        data.pop('venueRootHealthPending');lifecycle.stage.write_ledger(p,data)
    if lifecycle.graph.run(['systemctl','daemon-reload'],timeout=30).returncode:raise Refusal('scoped health reload failed')
    data['venueRootHealthPhase']='inert-ready';lifecycle.stage.write_ledger(p,data);checked(b,selector,p)

def retire(bundle,selector,ledger):
    rows=checked(bundle,selector,ledger);b,p,data,plan=lifecycle.ingress.context(bundle,selector,ledger)
    if data.get('activationAuthorized') is not False or data.get('venueInstallerPhase')!='retiring':raise Refusal('inactive scoped health retirement required')
    names=[Path(v).name for v in rows];result=lifecycle.graph.run(['systemctl','show',*names,'-p','ActiveState','-p','UnitFileState'],timeout=30)
    states=[v.partition('=')[2] for v in result.stdout.splitlines() if v.startswith('ActiveState=')]
    enabled=[v.partition('=')[2] for v in result.stdout.splitlines() if v.startswith('UnitFileState=')]
    jobs=lifecycle.graph.run(['systemctl','list-jobs','--no-legend','--no-pager'],timeout=30)
    if (result.returncode or len(states)!=2 or any(v not in ('inactive','failed') for v in states) or
            len(enabled)!=2 or any(v not in ('static','disabled') for v in enabled) or jobs.returncode or
            any(len(v)<4 or v[1] in names for v in [line.split() for line in jobs.stdout.splitlines()])):
        raise Refusal('scoped health remains active/enabled/busy or unobservable')
    checked(b,selector,p)
    for name in rows:
        data['venueRootHealthRetirePending']=name;lifecycle.stage.write_ledger(p,data);Path(name).unlink()
        data.setdefault('venueRootHealthRetired',[]).append(name);data.pop('venueRootHealthRetirePending');lifecycle.stage.write_ledger(p,data)
    if lifecycle.graph.run(['systemctl','daemon-reload'],timeout=30).returncode:raise Refusal('scoped health retirement reload failed')
    data['venueRootHealthPhase']='retired-inert';lifecycle.stage.write_ledger(p,data)

def authority(bundle,selector,ledger,controller):
    b=Path(bundle);p=Path(ledger);data=lifecycle.ingress.context(b,selector,p)[2]
    if (data.get('venueInstallerVersion')!=2 or data.get('venueStartPhase') not in ('starting','running') or
            data.get('activationAuthorized') is not True or data.get('venueStartHostContextSha256')!=controller.digest or
            data.get('venueRegistryPhase')!='inert-ready' or 'venueRootHealthPending' in data):
        raise Refusal('scoped root health tick fenced')
    runtime=controller.require_runtime()
    if runtime['phase']!=data['venueStartPhase']:raise Refusal('scoped root health authority differs')
    lifecycle.ingress.checked(b,selector,p);checked(b,selector,p)
    return data

def due(row,now):
    config=row['Config']['Healthcheck'];interval=config['Interval']
    if type(interval) is not int or interval<=0:raise Refusal('invalid native health interval')
    logs=row['State']['Health'].get('Log')
    if logs is None:return True  # Native Podman represents never-run as null, not an inventory error.
    if not isinstance(logs,list):raise Refusal('unreadable native health history')
    if not logs:return True
    end=datetime.datetime.fromisoformat(logs[-1]['End'].replace('Z','+00:00'))
    if end.tzinfo is None:raise Refusal('native health timestamp lacks timezone')
    return (now-end).total_seconds()>=interval/1e9

def native_owner(row,name,data):
    path=RUNTIME_DIRECTORY/(name+'.cid');s=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_mode&0o022 or s.st_nlink!=1 or path.read_text().strip()!=row['Id']:
        raise Refusal('scoped native health CID receipt differs')
    result=lifecycle.graph.run(['systemctl','show',name+'.service','-p','MainPID','-p','ActiveState','-p','ExecMainStartTimestampMonotonic','-p','DropInPaths','-p','ControlGroup'],timeout=30)
    props=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if (result.returncode or props.get('DropInPaths')!='' or props.get('ActiveState') not in ('activating','active') or
            int(props.get('MainPID','0'))<=0 or not props.get('ControlGroup') or
            int(props.get('ExecMainStartTimestampMonotonic','0'))<data['venueStartMonotonicUsec']):
        raise Refusal('scoped health native owner/current epoch differs')
    conmon=row['State']['ConmonPid']
    if type(conmon) is not int or conmon<=1:raise Refusal('invalid scoped health supervisor PID')
    groups=[line.split(':',2)[2] for line in (PROC_DIRECTORY/str(conmon)/'cgroup').read_text().splitlines()]
    group=props['ControlGroup']
    if not any(value==group or value.startswith(group+'/') for value in groups):raise Refusal('scoped health supervisor outside native unit')

def tick(bundle,selector,ledger):
    b=Path(bundle);plan=lifecycle.stage.owned_plan(b,selector);controller=lifecycle.host_context(b,plan)
    services=json.loads((b/'stack.ir.json').read_text())['services'];selected={}
    identities=lifecycle.graph.selected_pairs(b)
    for file in (b/'quadlet/rootful').glob('*.container'):
        name=file.stem.removeprefix(plan['prefix']+'-');health=services[name].get('health',{})
        if health.get('test') and health['test']!=['NONE'] and not health.get('disable',False):
            images=[line.partition('=')[2] for line in file.read_text().splitlines() if line.startswith('Image=')]
            if len(images)!=1 or 'root|'+images[0] not in identities:raise Refusal('missing exact unit native health image authority')
            selected[file.stem]=identities['root|'+images[0]]
    if plan['prefix']+'-caddy' not in selected:raise Refusal('missing declared root health producers')
    command=lifecycle.graph.stores(b,plan)[0][2]
    with lifecycle.lifecycle(controller):
        data=authority(b,selector,ledger,controller)
        result=lifecycle.graph.run(command+['ps','--all','--format','json'],timeout=30)
        if result.returncode:raise Refusal('cannot inventory scoped root health containers')
        rows=json.loads(result.stdout)
        if not isinstance(rows,list):raise Refusal('invalid scoped root health inventory')
        candidates=[]
        for row in rows:
            names=row['Names']
            if not isinstance(names,list) or len(names)!=1:raise Refusal('ambiguous scoped container name')
            if names[0] in selected and row['State']=='running':
                identity=row['Id']
                if not isinstance(identity,str) or len(identity)!=64 or any(c not in '0123456789abcdef' for c in identity):raise Refusal('invalid scoped health container ID')
                candidates.append((names[0],identity))
    checked=0
    for name,identity in candidates:
        with lifecycle.lifecycle(controller):
            data=authority(b,selector,ledger,controller)
            result=lifecycle.graph.run(command+['container','inspect',identity],timeout=30)
            if result.returncode:raise Refusal('scoped health container changed during observation')
            row=json.loads(result.stdout)[0]
            image=row['Image']
            if isinstance(image,str) and len(image)==64 and all(c in '0123456789abcdef' for c in image):image='sha256:'+image
            if (row['Id']!=identity or row['Name']!=name or image!=selected[name]):
                raise Refusal('scoped health container identity/image/owner differs')
            if not row['State']['Running']:continue
            native_owner(row,name,data)
            if not due(row,datetime.datetime.now(datetime.timezone.utc)):continue
            # Native health execution is a scoped mutation, under the same lease;
            # no unscoped command and no container/service restart is permitted.
            data['venueRootHealthPending']={'container':identity,'monotonicUsec':time.monotonic_ns()//1000}
            lifecycle.stage.write_ledger(Path(ledger),data)
            result=lifecycle.graph.run(command+['healthcheck','run',identity],timeout=90)
            if result.returncode not in (0,1):raise Refusal('scoped native health execution unavailable; intent retained')
            data.pop('venueRootHealthPending');lifecycle.stage.write_ledger(Path(ledger),data)
            checked+=1
    return {'scope':'isolated-rootful-native-health','checked':checked,'backendStarts':0}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:print(json.dumps(tick(args.bundle,args.selector,args.ledger),sort_keys=True))
    except Refusal as exc:raise SystemExit(str(exc)+'; no fallback')
    except (ValueError,OSError,KeyError,TypeError) as exc:raise SystemExit('scoped root health tick refused ('+type(exc).__name__+'); no fallback')
