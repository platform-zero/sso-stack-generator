#!/usr/bin/env python3
"""Stage seven isolated, config-only rootless current trees, inactive.

Never share the root-owned aggregate/SOPS release with rootless users. Exact
per-domain allowlists come from the generated 60/95 IR. This is an empty,
pre-activation lifecycle, NOT a populated-data or service reset.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_release',HERE/'venue-release-inert.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
stage=release.stage;Refusal=release.Refusal

def domains(bundle,plan):
    ir=json.loads((bundle/'stack.ir.json').read_text())
    services=ir.get('services',{})
    if len(services)!=95 or len(plan['accounts'])!=7:raise Refusal('60/95 seven-domain source required')
    result={}
    for a in plan['accounts']:
        name=a['name']
        if not name.startswith(plan['prefix']+'-') or a['uid']==0:raise Refusal('selected rootless account identity differs')
        domain=name.removeprefix(plan['prefix']+'-')
        owned={k:v for k,v in services.items() if v.get('placement')=='rootless' and v.get('rootlessDomain')==domain}
        if not owned or not (bundle/'quadlet'/('rootless-'+domain)).is_dir():
            raise Refusal('selected account lacks generated runtime domain')
        config=set()
        for service in owned.values():
            for mount in service.get('volumes',[]):
                source=mount.split(':',1)[0] if isinstance(mount,str) else mount.get('source','')
                if source.startswith('./configs/'):
                    parts=Path(source.removeprefix('./configs/')).parts
                    if not parts or any(x in ('','.','..') for x in parts):raise Refusal('invalid rootless config source')
                    config.add(parts[0])
        build_units=sorted(x.name for x in (bundle/'quadlet'/('rootless-'+domain)).glob('*.build'))
        if any((bundle/'quadlet'/('rootless-'+domain)/x).is_symlink() for x in build_units):
            raise Refusal('selected build unit source changed')
        result[name]={'uid':a['uid'],'state':a['state'],'domain':domain,
                      'configs':sorted(config),'buildUnits':build_units}
    if len(result)!=7:raise Refusal('generated domain account count differs')
    return result

def assert_parent(path,row,uid):
    st=Path(path).lstat()
    if Path(path).is_symlink() or not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))!=(row.get('dev'),row.get('ino'),uid,0o700):
        raise Refusal('selected rootless state parent changed')

def root_record(path):
    p=Path(path);s=p.lstat()
    if p.is_symlink() or not stat.S_ISDIR(s.st_mode):raise Refusal('rootless domain release directory changed')
    return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode)}

def verify_tree(root,identity,items):
    if root_record(root)!=identity or release.inventory(root)!=items:
        raise Refusal('rootless domain release files or directory identities differ')

def context(bundle,selector,ledger):
    b,p,data,plan,state=release.context(bundle,selector,ledger)
    original=Path(data.get('releaseRoot') or '')
    started=data.get('managerStarted',[])
    stopped=data.get('managerStopped',[])
    if (data.get('venueReleasePhase')!='inert-ready' or data.get('status')!='staged-empty' or
            (started and (started!=[a['name'] for a in plan['accounts']] or
                          stopped!=[a['name'] for a in reversed(plan['accounts'])])) or
            original!=Path(data.get('venueReleaseRoot') or '') or
            data.get('venueReleaseManifest')!=release.inventory(original)):
        raise Refusal('exact completed, inactive private rootful release required')
    return b,p,data,plan,domains(b,plan),original

def prepare(bundle,selector,ledger):
    b,p,data,plan,selected,original=context(bundle,selector,ledger)
    if data.get('venueDomainRuntimePhase') or data.get('managerStarted'):
        raise Refusal('domain copies require fresh pre-manager stage')
    root_configs=original/'runtime/configs';root_build=original/'build';records={}
    if any(domain['buildUnits'] for domain in selected.values()):
        if (root_build.is_symlink() or not root_build.is_dir() or
                any(x.is_symlink() or (not x.is_dir() and not x.is_file()) for x in root_build.rglob('*'))):
            raise Refusal('rendered selected build tree unsafe')
    for name,domain in selected.items():
        state_root=Path(domain['state'])
        assert_parent(state_root,data['pathIdentities'].get(str(state_root),{}),domain['uid'])
        parent=state_root/'releases';slot=parent/original.name;current=state_root/'current'
        if any(os.path.lexists(x) for x in (parent,slot,current)):
            raise Refusal('rootless release slot not fresh')
        for config in domain['configs']:
            source=root_configs/config
            if source.exists() and (source.is_symlink() or not source.is_dir() or
                                    not str(source.resolve()).startswith(str(root_configs.resolve())+'/')):
                raise Refusal('rootless generated config root changed')
        records[name]={'state':str(state_root),'uid':domain['uid'],'configs':domain['configs'],
                       'buildUnits':domain['buildUnits'],'releaseRoot':str(slot),'current':str(current)}
    data['venueDomainRuntimePhase']='preparing';data['venueDomainRuntimePlan']=records
    stage.write_ledger(p,data)
    for name,row in records.items():
        uid=row['uid'];parent=Path(row['releaseRoot']).parent;slot=Path(row['releaseRoot']);current=Path(row['current'])
        parent.mkdir(mode=0o700);parent.chmod(0o700)
        slot.mkdir(mode=0o700);slot.chmod(0o700)
        (slot/'runtime/configs').mkdir(parents=True)
        (slot/'repos').mkdir()
        if row['buildUnits']:
            shutil.copytree(root_build,slot/'build',symlinks=False)
        for config in row['configs']:
            source=root_configs/config
            if source.is_dir():shutil.copytree(source,slot/'runtime/configs'/config,symlinks=False)
        for item in sorted(slot.rglob('*')):
            if item.is_symlink():raise Refusal('rootless domain runtime contains symlink')
            is_dir=item.is_dir()
            if not is_dir and not item.is_file():raise Refusal('rootless runtime inode class differs')
            os.chown(item,uid,uid)
            item.chmod(0o755 if is_dir else (0o755 if item.read_bytes().startswith(b'#!') else 0o644))
        os.chown(slot,uid,uid);slot.chmod(0o700)
        os.chown(parent,uid,uid);parent.chmod(0o700)
        row['parentIdentity']=root_record(parent);row['releaseIdentity']=root_record(slot)
        row['files']=domain_inventory(slot,uid)
        # Record fully materialized bytes before linking a current pointer.
        stage.write_ledger(p,data)
        os.symlink('releases/'+slot.name,current)
        link=current.lstat();row['pointer']={'dev':link.st_dev,'ino':link.st_ino,'target':os.readlink(current)}
        stage.write_ledger(p,data)
    data['venueDomainRuntimePhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':'inert-ready','rootlessCurrentTrees':7,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def domain_inventory(root,uid):
    root=Path(root);result={}
    for p in sorted(root.rglob('*')):
        s=p.lstat()
        if (p.is_symlink() or s.st_uid!=uid or (not stat.S_ISDIR(s.st_mode) and not stat.S_ISREG(s.st_mode)) or
                (stat.S_ISREG(s.st_mode) and s.st_nlink!=1)):
            raise Refusal('rootless domain config file is foreign or linked')
        result[str(p.relative_to(root))]={'dev':s.st_dev,'ino':s.st_ino,'uid':uid,
            'mode':stat.S_IMODE(s.st_mode),'type':'dir' if p.is_dir() else 'file',
            'sha256':release.sha(p) if p.is_file() else None}
    return result

def retire(bundle,selector,ledger):
    b,p,data,plan,selected,original=context(bundle,selector,ledger)
    if data.get('venueDomainRuntimePhase')!='inert-ready' or set(data.get('venueDomainRuntimePlan',{}))!=set(selected):
        raise Refusal('only a complete inactive seven-domain release may retire')
    entries=data['venueDomainRuntimePlan']
    # Preflight all seven before the first unlink. An active service or
    # foreign/new config file refuses rather than deleting populated data.
    for name,row in entries.items():
        domain=selected[name];state_root=Path(row['state']);uid=row['uid']
        assert_parent(state_root,data['pathIdentities'].get(str(state_root),{}),uid)
        parent=state_root/'releases';slot=Path(row['releaseRoot']);current=Path(row['current'])
        staged_children={Path(x).name for x in data['createdPaths'] if Path(x).parent==state_root}
        if (uid!=domain['uid'] or row['configs']!=domain['configs'] or
                row.get('buildUnits')!=domain['buildUnits'] or
                slot!=parent/original.name or current!=state_root/'current' or
                root_record(parent)!=row['parentIdentity'] or root_record(slot)!=row['releaseIdentity'] or
                {x.name for x in parent.iterdir()}!={slot.name} or
                {x.name for x in state_root.iterdir()}!=staged_children|{'releases','current'}):
            raise Refusal('selected rootless release state, path or inode changed')
        s=current.lstat();ptr=row['pointer']
        if (not current.is_symlink() or (s.st_dev,s.st_ino,os.readlink(current))!=
                (ptr['dev'],ptr['ino'],ptr['target']) or current.resolve()!=slot or
                domain_inventory(slot,uid)!=row['files']):
            raise Refusal('rootless runtime pointer or file bytes changed')
    # A process namespace mount on any selected release prohibits unlink.
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:lines=(proc/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        for row in entries.values():
            slot=row['releaseRoot']
            if any((mp:=line.split()[4].replace('\\040',' '))==slot or mp.startswith(slot+'/') for line in lines if len(line.split())>=5):
                raise Refusal('selected rootless release still mounted')
    # Requires never having started a manager in this ledger. No Quadlets,
    # named volumes, images or data binds are admitted by context.
    data['venueDomainRuntimePhase']='retiring';stage.write_ledger(p,data)
    for name,row in reversed(list(entries.items())):
        Path(row['current']).unlink();shutil.rmtree(row['releaseRoot']);Path(row['releaseRoot']).parent.rmdir()
    data['venueDomainRuntimePhase']='retired-inert';stage.write_ledger(p,data)
    return {'status':'retired-inert','rootlessCurrentTrees':7,'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    a=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):a.add_argument('--'+name,required=True)
    mode=a.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true');mode.add_argument('--retire',action='store_true')
    args=a.parse_args()
    try:print(json.dumps(prepare(args.bundle,args.selector,args.ledger) if args.prepare else retire(args.bundle,args.selector,args.ledger),sort_keys=True))
    except (Refusal,KeyError,ValueError,OSError,TypeError) as exc:
        raise SystemExit('venue rootless runtime lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
