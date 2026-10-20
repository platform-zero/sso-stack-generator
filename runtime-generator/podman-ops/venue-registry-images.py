#!/usr/bin/env python3
"""Incremental exact-authority registry image preparation, NEVER activation.

Populate only eight fresh CAS-selected venue graphs. Every one of 57 direct
image/authority pairs is frozen in the clean site commit; 13 local builds
remain separate and MUST NOT be credited as pulled. One selected archive ID
is already imported by the inert installer. On registry/tag drift, resource
reserve loss or graph foreign data, stop this operation and retain the ledger.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
authority=load('venue_image_authority','venue-image-authority.py')
graph=load('venue_graph','venue-graph-clear.py')
composite=load('venue_composite','venue-composite-inert.py')
stage=authority.stage
Refusal=stage.Refusal
HULY={'huly_cockroach','huly_elastic','huly_minio','huly_redpanda'}

def reserve():
    for path,minimum in (('/',60),('/mnt/stack',140)):
        fs=os.statvfs(path)
        if fs.f_bavail*fs.f_frsize<minimum*(1<<30):
            raise Refusal('physical filesystem proactive reserve reached: '+path)
    memory=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))
    if memory<16*(1<<20):raise Refusal('physical memory proactive reserve reached')

def journal(bundle,selector,site_source,ledger):
    if os.geteuid()!=0:raise Refusal('root-only selected registry graph preparation')
    p=Path(ledger);info=p.lstat()
    if p.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:
        raise Refusal('protected release ledger missing')
    data=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or data.get('venueInstallerVersion')!=1 or
            data.get('venueInstallerPhase')!='inert-ready' or data.get('venueCompositeMode')!='inert-ready' or
            data.get('status')!='units-staged' or data.get('activationAuthorized') is not False or
            data.get('managerStopped') or len(data.get('installedUnits',[]))!=190 or
            len(data.get('managerStarted',[]))!=7):
        raise Refusal('only complete inactive exact-CAS installer is a registry input')
    source=authority.authority(bundle,selector,site_source)
    if (source['generatorCommit']!=plan['sourceCommit'] or
            source['selectorSha256']!=plan['selectorSha256'] or
            source['quadletTreeSha256']!=plan['quadletTreeSha256']):
        raise Refusal('selected frozen image source differs from release CAS')
    offline=data.get('venueCompositeOfflineImages',[])
    composite.offline_plan(bundle,plan,offline)
    if (any(source['imageIds'].get(user+'|'+row['image'])!=row['image']
            for row in offline for user in row['authorities']) or
            {x.get('name') for x in data.get('venueHulyVolumes',[])}!=HULY):
        raise Refusal('exact selected offline image authorities differ')
    if (Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt').exists():
        raise Refusal('activation marker present in image-only preparation')
    return p,data,plan,source

def command_graphs(bundle,plan):
    roots={name:(Path(path),command) for name,path,command in graph.stores(bundle,plan)}
    if len(roots)!=8:raise Refusal('all eight selected image graphs required')
    return roots

def recovery_networks(bundle,plan,data,user,command,names):
    """Post-quarantine only: prove retained native networks by source and epoch."""
    if (data.get('venueInstallerVersion')!=2 or data.get('venueStartPhase')!='failed-quarantined' or
            data.get('activationAuthorized') is not False or data.get('venueStartIntent')!=plan['quadletTreeSha256']):
        raise Refusal('no exact failed-start network recovery authority')
    lifecycle=load('network_recovery_lifecycle','venue-start-quarantine.py')
    systemd={a['name'] if a else 'root':cmd for a,cmd in lifecycle.selected_commands(plan)}
    scope='rootful' if user=='root' else 'rootless-'+user.removeprefix(plan['prefix']+'-')
    source={}
    for file in (Path(bundle)/'quadlet'/scope).glob('*.network'):
        selected=[line.split('=',1)[1] for line in file.read_text().splitlines() if line.startswith('NetworkName=')]
        if len(selected)!=1:raise Refusal('selected network lacks exact native name')
        source[selected[0]]=file.stem+'-network.service'
    proofs={}
    for name in names:
        if name not in source:raise Refusal('post-start graph contains unselected network')
        prior=data.get('venueRecoveryNetworks',{}).get(user+'|'+name)
        if prior is not None:
            inspect=graph.run(command+['network','inspect',name],timeout=30)
            rows=json.loads(inspect.stdout) if not inspect.returncode else []
            if (len(rows)!=1 or rows[0].get('name')!=name or prior.get('unit')!=source[name] or
                    rows[0].get('id')!=prior.get('id') or not re.fullmatch(r'[0-9a-f]{64}',prior.get('id',''))):
                raise Refusal('previously proven native network ID changed')
            proofs[user+'|'+name]=prior;continue
        native=graph.run(systemd[user]+['show',source[name],'-p','ExecMainStatus','-p','ExecMainStartTimestampMonotonic'],timeout=30)
        fields=dict(line.split('=',1) for line in native.stdout.splitlines() if '=' in line)
        if native.returncode or fields.get('ExecMainStatus')!='0':
            raise Refusal('retained network native creation failed')
        if int(fields.get('ExecMainStartTimestampMonotonic','0'))<data['venueStartMonotonicUsec']:
            # systemd may garbage-collect an inactive successful oneshot. Use
            # its durable, UID/unit-bound Podman success output, never name-only
            # adoption or missing volatile timestamps as permission.
            uid=0 if user=='root' else next(a['uid'] for a in plan['accounts'] if a['name']==user)
            field='_SYSTEMD_UNIT' if user=='root' else '_SYSTEMD_USER_UNIT'
            journal=graph.run(['journalctl','--boot','--no-pager','-n','100','_UID='+str(uid),
                              field+'='+source[name],'-o','json'],timeout=30)
            records=[json.loads(line) for line in journal.stdout.splitlines()] if not journal.returncode else []
            if not any(row.get('_COMM')=='podman' and row.get(field)==source[name] and
                       str(row.get('_UID'))==str(uid) and row.get('MESSAGE')==name and
                       int(row.get('__MONOTONIC_TIMESTAMP','0'))>=data['venueStartMonotonicUsec'] for row in records):
                raise Refusal('retained network lacks native failed-epoch creation proof')
        inspect=graph.run(command+['network','inspect',name],timeout=30)
        rows=json.loads(inspect.stdout) if not inspect.returncode else []
        if len(rows)!=1 or rows[0].get('name')!=name or not re.fullmatch(r'[0-9a-f]{64}',rows[0].get('id','')):
            raise Refusal('retained native network identity unavailable')
        proofs[user+'|'+name]={'id':rows[0]['id'],'unit':source[name]}
    return proofs


def recovery_containers(bundle,plan,data,user,command,ids,expected):
    if (data.get('venueInstallerVersion')!=2 or data.get('venueStartPhase')!='failed-quarantined' or
            data.get('activationAuthorized') is not False or data.get('venueStartIntent')!=plan['quadletTreeSha256']):
        raise Refusal('no exact completed quarantine for retained container inspection')
    scope='rootful' if user=='root' else 'rootless-'+user.removeprefix(plan['prefix']+'-')
    selected={}
    for file in (Path(bundle)/'quadlet'/scope).glob('*.container'):
        fields={line.split('=',1)[0]:line.split('=',1)[1] for line in file.read_text().splitlines() if line.startswith(('ContainerName=','Image='))}
        selected[fields['ContainerName']]=(file.stem+'.service',fields['Image'])
    proofs={}
    for value in ids:
        result=graph.run(command+['container','inspect',value],timeout=30)
        rows=json.loads(result.stdout) if not result.returncode else []
        if len(rows)!=1:raise Refusal('retained container identity unavailable')
        row=rows[0];name=row.get('Name','').removeprefix('/');state=row.get('State',{})
        if name not in selected:raise Refusal('unselected retained container')
        unit,image=selected[name]
        config='sha256:'+row.get('Image','').removeprefix('sha256:')
        if (state.get('Running') is not False or state.get('Status')!='exited' or
                type(state.get('ExitCode')) is not int or not -1<=state['ExitCode']<=255 or
                row.get('Config',{}).get('Labels',{}).get('PODMAN_SYSTEMD_UNIT')!=unit or
                config!=expected.get(user+'|'+image) or not re.fullmatch(r'[0-9a-f]{64}',row.get('Id',''))):
            raise Refusal('retained object is not the exact stopped native bootstrap')
        lifecycle=load('bootstrap_epoch_lifecycle','venue-start-quarantine.py')
        systemd={a['name'] if a else 'root':cmd for a,cmd in lifecycle.selected_commands(plan)}
        started=graph.run(systemd[user]+['show',unit,'-p','ExecMainStartTimestampMonotonic'],timeout=30)
        fields=dict(line.split('=',1) for line in started.stdout.splitlines() if '=' in line)
        if started.returncode or int(fields.get('ExecMainStartTimestampMonotonic','0'))<data['venueStartMonotonicUsec']:
            raise Refusal('retained bootstrap not created in the exact failed epoch')
        proofs[user+'|'+name]={'id':row['Id'],'unit':unit,'image':config,'exitCode':state['ExitCode']}
    return proofs


def probe(bundle,plan,data,expected,*,recovering=False):
    roots=command_graphs(bundle,plan)
    permitted={user:set() for user in roots}
    for key,value in expected.items():
        user,sep,ref=key.partition('|')
        if not sep or user not in permitted:raise Refusal('registry image authority differs from eight stores')
        permitted[user].add(value)
    found={};network_proofs={};container_proofs={}
    for user,(path,command) in roots.items():
        info=path.lstat();record=data['pathIdentities'].get(str(path),{})
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid)!=(record.get('dev'),record.get('ino'),record.get('uid'))):
            raise Refusal('selected image graph inode/owner drift')
        def listing(args):
            run=graph.run(command+args,timeout=45)
            if run.returncode:raise Refusal('selected Podman inventory unavailable')
            return set(run.stdout.strip().splitlines()) if run.stdout.strip() else set()
        containers=listing(['ps','-aq'])
        if listing(['pod','ps','--quiet']):raise Refusal('pod in inactive image graph')
        if containers:
            if not recovering:raise Refusal('container/pod in inactive image graph')
            container_proofs.update(recovery_containers(bundle,plan,data,user,command,containers,expected))
        volumes=listing(['volume','ls','-q'])
        if volumes!=(HULY if user==plan['prefix']+'-apps' else set()):
            raise Refusal('foreign or missing selected named image-graph volume')
        networks=listing(['network','ls','--format','{{.Name}}'])-{'podman'}
        if networks:
            if not recovering:raise Refusal('selected image graph has foreign network')
            network_proofs.update(recovery_networks(bundle,plan,data,user,command,networks))
        ids={'sha256:'+v.removeprefix('sha256:') for v in listing(['image','ls','-a','--no-trunc','--format','{{.ID}}'])}
        if ids!=permitted[user]:raise Refusal('selected graph image IDs differ from completed journal')
        found[user]=ids
    if recovering:
        prior=data.get('venueRecoveryNetworks')
        retired=set(data.get('venueOwnedReset',{}).get('retiredNetworks',[]))
        if prior is not None and any(network_proofs.get(key)!=value for key,value in prior.items() if value['id'] not in retired):
            raise Refusal('recorded retained network identities changed')
        data['venueRecoveryNetworks']=network_proofs
        prior=data.get('venueRecoveryContainers')
        if prior is not None:
            remaining={key:value for key,value in prior.items() if value['id'] not in data.get('venueStoppedBootstrapCleaned',{})}
            if any(container_proofs.get(key)!=value for key,value in remaining.items()):
                raise Refusal('retained bootstrap identities changed')
        data['venueRecoveryContainers']=container_proofs
    return roots,found

def pulled(command,ref):
    run=graph.run(command+['image','inspect','--format','{{.Id}}',ref],timeout=30)
    if run.returncode:return None
    value=run.stdout.strip()
    if re.fullmatch(r'[0-9a-f]{64}',value):value='sha256:'+value
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',value):raise Refusal('invalid registry image inspect identity')
    return value

def fetch(command,ref):
    reserve()
    process=subprocess.Popen(command+['pull',ref],cwd='/',stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    start=time.monotonic()
    while process.poll() is None:
        try:reserve()
        except Refusal:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=12)
            raise
        if time.monotonic()-start>1800:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=12)
            raise Refusal('selected registry pull timed out; incomplete graph retained')
        time.sleep(.5)
    if process.returncode:raise Refusal('selected registry pull failed; exact partial graph retained')
    reserve()

def prepare(bundle,selector,site_source,ledger,max_new,retry_pending=False):
    p,data,plan,source=journal(bundle,selector,site_source,ledger)
    if type(max_new) is not int or not 1<=max_new<=60:raise Refusal('one to sixty bounded new images per invocation')
    ids=source['imageIds'];offline=data['venueCompositeOfflineImages']
    imported={user+'|'+row['image']:row['image'] for row in offline for user in row['authorities']}
    if data.get('venueRegistryPhase') is None:
        data['venueRegistryPhase']='preparing'
        data['venueRegistryFrozenSha256']=source['frozenRegistrySha256']
        data['venueRegistryPlan']=ids
        data['venueRegistryVerified']=dict(imported)
        stage.write_ledger(p,data)
    if (data.get('venueRegistryPhase') not in ('preparing','inert-ready') or
            data.get('venueRegistryFrozenSha256')!=source['frozenRegistrySha256'] or
            data.get('venueRegistryPlan')!=ids or not isinstance(data.get('venueRegistryVerified'),dict) or
            any(data['venueRegistryVerified'].get(key)!=image for key,image in imported.items())):
        raise Refusal('registry progress not bound to exact selected-input source CAS')
    verified=data['venueRegistryVerified']
    if any(k not in ids or ids[k]!=v for k,v in verified.items()):
        raise Refusal('journaled image config ID differs from frozen site source')
    pending=data.get('venueRegistryPending')
    if pending is not None:
        if pending not in ids or pending in verified:raise Refusal('unreviewed pending registry pull')
        user,_,ref=pending.partition('|');command=command_graphs(bundle,plan)[user][1]
        identity=pulled(command,ref)
        if retry_pending and identity is None:
            if ref.startswith('sha256:') or data.get('venueRegistryRetryCount',{}).get(pending,0)>=1:
                raise Refusal('selected pending registry pull already retried or is offline ID')
            probe(bundle,plan,data,verified)  # no foreign graph objects before retry
            data.setdefault('venueRegistryRetryCount',{})[pending]=1;stage.write_ledger(p,data)
            fetch(command,ref)
            identity=pulled(command,ref)
        if identity!=ids[pending]:raise Refusal('interrupted registry pull needs exact selected-image review')
        verified[pending]=identity;data.pop('venueRegistryPending');stage.write_ledger(p,data)
    elif retry_pending:raise Refusal('no selected registry pull awaiting explicit review')
    if data['venueRegistryPhase']=='inert-ready':
        if verified!=ids:raise Refusal('claimed complete registry images differ')
        roots,_=probe(bundle,plan,data,verified)
        return {'status':'inert-ready','verifiedImages':len(verified),'remaining':0,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    roots,_=probe(bundle,plan,data,verified)
    remaining=sorted(set(ids)-set(verified))
    for candidate in remaining[:(0 if retry_pending else max_new)]:
        user,_,ref=candidate.partition('|');command=roots[user][1]
        reserve()
        data['venueRegistryPending']=candidate;stage.write_ledger(p,data)
        identity=pulled(command,ref)
        if identity is None:
            if ref.startswith('sha256:'):raise Refusal('offline image missing; never pull ID')
            fetch(command,ref)
            identity=pulled(command,ref)
        if identity!=ids[candidate]:raise Refusal('registry image ID drift; no selected substitution')
        verified[candidate]=identity;data.pop('venueRegistryPending');stage.write_ledger(p,data)
        roots,_=probe(bundle,plan,data,verified)
    if verified==ids:
        data['venueRegistryPhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':data['venueRegistryPhase'],'verifiedImages':len(verified),
            'remaining':len(ids)-len(verified),'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','site-source','ledger'):ap.add_argument('--'+key,required=True)
    ap.add_argument('--max-new',type=int,default=1)
    ap.add_argument('--retry-pending-only',action='store_true')
    a=ap.parse_args()
    try:print(json.dumps(prepare(a.bundle,a.selector,a.site_source,a.ledger,a.max_new,a.retry_pending_only),sort_keys=True))
    except (Refusal,OSError,KeyError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue complete registry preparation refused: '+str(exc)) from exc
if __name__=='__main__':main()
