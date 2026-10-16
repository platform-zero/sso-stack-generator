#!/usr/bin/env python3
"""Incremental exact-authority registry image preparation, NEVER activation.

Populate only eight fresh CAS-selected venue graphs. Every one of 60 direct
image/authority pairs is frozen in the clean site commit; 14 local builds
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
            data.get('managerStopped') or len(data.get('installedUnits',[]))!=194 or
            len(data.get('managerStarted',[]))!=7):
        raise Refusal('only complete inactive exact-CAS installer is a registry input')
    source=authority.authority(bundle,selector,site_source)
    if (source['generatorCommit']!=plan['sourceCommit'] or
            source['selectorSha256']!=plan['selectorSha256'] or
            source['quadletTreeSha256']!=plan['quadletTreeSha256']):
        raise Refusal('selected frozen image source differs from release CAS')
    offline=data.get('venueCompositeOfflineImages',[])
    if (len(offline)!=1 or offline[0].get('authorities')!=[plan['prefix']+'-apps'] or
            source['imageIds'].get(offline[0]['authorities'][0]+'|'+offline[0]['image'])!=offline[0]['image'] or
            {x.get('name') for x in data.get('venueHulyVolumes',[])}!=HULY):
        raise Refusal('single selected offline image authority differs')
    if (Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt').exists():
        raise Refusal('activation marker present in image-only preparation')
    return p,data,plan,source

def command_graphs(bundle,plan):
    roots={name:(Path(path),command) for name,path,command in graph.stores(bundle,plan)}
    if len(roots)!=8:raise Refusal('all eight selected image graphs required')
    return roots

def probe(bundle,plan,data,expected):
    roots=command_graphs(bundle,plan)
    permitted={user:set() for user in roots}
    for key,value in expected.items():
        user,sep,ref=key.partition('|')
        if not sep or user not in permitted:raise Refusal('registry image authority differs from eight stores')
        permitted[user].add(value)
    found={}
    for user,(path,command) in roots.items():
        info=path.lstat();record=data['pathIdentities'].get(str(path),{})
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid)!=(record.get('dev'),record.get('ino'),record.get('uid'))):
            raise Refusal('selected image graph inode/owner drift')
        def listing(args):
            run=graph.run(command+args,timeout=45)
            if run.returncode:raise Refusal('selected Podman inventory unavailable')
            return set(run.stdout.strip().splitlines()) if run.stdout.strip() else set()
        if listing(['ps','-aq']) or listing(['pod','ps','--quiet']):
            raise Refusal('container/pod in inactive image graph')
        volumes=listing(['volume','ls','-q'])
        if volumes!=(HULY if user==plan['prefix']+'-apps' else set()):
            raise Refusal('foreign or missing selected named image-graph volume')
        if listing(['network','ls','--format','{{.Name}}'])-{'podman'}:
            raise Refusal('selected image graph has foreign network')
        ids={'sha256:'+v.removeprefix('sha256:') for v in listing(['image','ls','--no-trunc','--format','{{.ID}}'])}
        if ids!=permitted[user]:raise Refusal('selected graph image IDs differ from completed journal')
        found[user]=ids
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

def prepare(bundle,selector,site_source,ledger,max_new):
    p,data,plan,source=journal(bundle,selector,site_source,ledger)
    if type(max_new) is not int or not 1<=max_new<=60:raise Refusal('one to sixty bounded new images per invocation')
    ids=source['imageIds'];offline=data['venueCompositeOfflineImages'][0]
    key=offline['authorities'][0]+'|'+offline['image']
    if data.get('venueRegistryPhase') is None:
        data['venueRegistryPhase']='preparing'
        data['venueRegistryFrozenSha256']=source['frozenRegistrySha256']
        data['venueRegistryPlan']=ids
        data['venueRegistryVerified']={key:offline['image']}
        stage.write_ledger(p,data)
    if (data.get('venueRegistryPhase') not in ('preparing','inert-ready') or
            data.get('venueRegistryFrozenSha256')!=source['frozenRegistrySha256'] or
            data.get('venueRegistryPlan')!=ids or not isinstance(data.get('venueRegistryVerified'),dict) or
            data['venueRegistryVerified'].get(key)!=offline['image']):
        raise Refusal('registry progress not bound to exact 60-input source CAS')
    verified=data['venueRegistryVerified']
    if any(k not in ids or ids[k]!=v for k,v in verified.items()):
        raise Refusal('journaled image config ID differs from frozen site source')
    pending=data.get('venueRegistryPending')
    if pending is not None:
        if pending not in ids or pending in verified:raise Refusal('unreviewed pending registry pull')
        user,_,ref=pending.partition('|');command=command_graphs(bundle,plan)[user][1]
        identity=pulled(command,ref)
        if identity!=ids[pending]:raise Refusal('interrupted registry pull needs exact selected-image review')
        verified[pending]=identity;data.pop('venueRegistryPending');stage.write_ledger(p,data)
    if data['venueRegistryPhase']=='inert-ready':
        if verified!=ids:raise Refusal('claimed complete registry images differ')
        roots,_=probe(bundle,plan,data,verified)
        return {'status':'inert-ready','verifiedImages':len(verified),'remaining':0,
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    roots,_=probe(bundle,plan,data,verified)
    remaining=sorted(set(ids)-set(verified))
    for candidate in remaining[:max_new]:
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
    a=ap.parse_args()
    try:print(json.dumps(prepare(a.bundle,a.selector,a.site_source,a.ledger,a.max_new),sort_keys=True))
    except (Refusal,OSError,KeyError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue complete registry preparation refused: '+str(exc)) from exc
if __name__=='__main__':main()
