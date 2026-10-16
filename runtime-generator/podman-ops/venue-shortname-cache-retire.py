#!/usr/bin/env python3
"""Retire ONLY two CAS-journaled Podman short-name lock files after graph reset.

This is an inactive-stage repair, not a populated-data reset. Never call
Podman while inspecting cleared graphs: even image listing recreates metadata.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal
NAMES={'p0test-r1-test-runners':'debian:13-slim',
       'p0test-r1-workloads':'python:3.13-alpine'}

def check_ledger(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('root required for exact short-name cache cleanup')
    path=Path(ledger);s=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:
        raise Refusal('protected selected stage ledger required')
    data=json.loads(path.read_text());plan=stage.owned_plan(bundle,selector)
    if (data.get('plan')!=plan or data.get('status')!='staged-empty' or
            data.get('venueInstallerPhase')!='retiring' or
            any(data.get(k)!='retired-inert' for k in ('venueCompositeMode','venueRegistryPhase','venueBuildBasePhase')) or
            data.get('graphCleared')!=['root']+[a['name'] for a in plan['accounts']] or
            data.get('managerStopped')!=[a['name'] for a in reversed(plan['accounts'])] or
            not data.get('podmanImageCacheRetired') or not data.get('podmanRunrootRetired') or
            data.get('retiredPaths') or data.get('retiredAccounts') or
            data.get('venueShortnameCachePhase') not in (None,'prepared','retiring','retired-inert')):
        raise Refusal('only stopped, fully cleared, never-active selected image venue can retire short-name locks')
    if ((Path(plan['roots']['rootful-state'])/'volume-ready-r1.txt').exists() or
            set(NAMES)-{a['name'] for a in plan['accounts']}):
        raise Refusal('active marker or unexpected short-name account')
    pins=Path(bundle)/'site/global.settings/build-base-image-ids.json'
    if pins.is_symlink() or not pins.is_file() or hashlib.sha256(pins.read_bytes()).hexdigest()!=data.get('venueBuildBaseFrozenSha256'):
        raise Refusal('frozen site build-base authority changed')
    declared=json.loads(pins.read_text())
    if declared.get('schemaVersion')!=1 or declared.get('platform')!='linux/amd64':
        raise Refusal('site build-base schema changed')
    for name,ref in NAMES.items():
        if name+'|'+ref not in declared.get('baseImages',{}) or name+'|'+ref not in data.get('venueBuildBaseVerified',{}):
            raise Refusal('short-name alias was not a verified selected base')
    return path,data,plan

def metadata(path,uid,mode,is_dir,size=None):
    s=path.lstat()
    if (path.is_symlink() or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=mode or
            (not stat.S_ISDIR(s.st_mode) if is_dir else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1) or
            (size is not None and s.st_size!=size)):
        raise Refusal('foreign Podman short-name cache inode/owner/mode')
    return {'path':str(path),'dev':s.st_dev,'ino':s.st_ino,'uid':uid,'mode':mode,
            'kind':'dir' if is_dir else 'file',
            'sha256':None if is_dir else hashlib.sha256(path.read_bytes()).hexdigest()}

def process_and_mount_check(plan):
    selected={str(a['uid']) for a in plan['accounts'] if a['name'] in NAMES}
    cache_roots=[Path(a['home'])/'.cache' for a in plan['accounts'] if a['name'] in NAMES]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            status=(proc/'status').read_text().splitlines()
            uids=next(x for x in status if x.startswith('Uid:')).split()[1:]
            lines=(proc/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError,StopIteration):continue
        if selected.intersection(uids):raise Refusal('selected short-name cache UID has live process')
        for line in lines:
            cells=line.split()
            if len(cells)<5:continue
            mount=cells[4].replace('\\040',' ')
            if any(mount==str(p) or mount.startswith(str(p)+'/') for p in cache_roots):
                raise Refusal('mount under selected short-name cache')

def rows_for(plan,data):
    result=[]
    for a in plan['accounts']:
        if a['name'] not in NAMES:
            other=Path(a['home'])/'.cache'
            if os.path.lexists(other):raise Refusal('unselected account has cache data')
            continue
        home=Path(a['home']);record=data['pathIdentities'].get(str(home),{})
        s=home.lstat()
        if (home.is_symlink() or not stat.S_ISDIR(s.st_mode) or
                (s.st_dev,s.st_ino,s.st_uid)!=(record.get('dev'),record.get('ino'),a['uid'])):
            raise Refusal('selected account home identity changed')
        top=home/'.cache';child=top/'containers';file=child/'short-name-aliases.conf.lock'
        if {x.name for x in home.iterdir()}!={'.config','.cache'}:
            raise Refusal('selected short-name home has foreign content')
        if {x.name for x in top.iterdir()}!={'containers'} or {x.name for x in child.iterdir()}!={file.name}:
            raise Refusal('foreign short-name cache contents')
        result.extend((metadata(file,a['uid'],0o644,False,0),
                       metadata(child,a['uid'],0o700,True),
                       metadata(top,a['uid'],0o700,True)))
    return result

def validate_remaining(data,plan,rows):
    retired=data.get('venueShortnameCacheRetiredPaths',[])
    expected=[x['path'] for x in rows]
    if (not isinstance(retired,list) or retired!=expected[:len(retired)] or
            len(set(retired))!=len(retired)):
        raise Refusal('short-name exact retirement sequence changed')
    pending=data.get('venueShortnameCachePending')
    if pending is not None and (len(retired)==len(expected) or pending!=expected[len(retired)]):
        raise Refusal('short-name pending inode differs from next selected path')
    for row in rows:
        p=Path(row['path']);exists=os.path.lexists(p)
        if row['path'] in retired:
            if exists:raise Refusal('already retired short-name inode reappeared')
            continue
        if not exists:
            if pending==row['path']:continue  # crash after the CAS-journaled unlink
            raise Refusal('unjournaled short-name inode disappeared')
        s=p.lstat()
        if (p.is_symlink() or (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=
                (row['dev'],row['ino'],row['uid'],row['mode']) or
                (not stat.S_ISDIR(s.st_mode) if row['kind']=='dir' else
                 not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256'])):
            raise Refusal('selected short-name inode/bytes changed')
    # Never remove an enclosing directory if it contains a foreign child.
    for a in plan['accounts']:
        if a['name'] not in NAMES:continue
        home=Path(a['home']);top=home/'.cache';child=top/'containers';file=child/'short-name-aliases.conf.lock'
        if {p.name for p in home.iterdir()}!=({'.config','.cache'} if os.path.lexists(top) else {'.config'}):
            raise Refusal('selected home has new content')
        if os.path.lexists(top) and {p.name for p in top.iterdir()}!=({'containers'} if os.path.lexists(child) else set()):
            raise Refusal('selected short-name cache directory has new content')
        if os.path.lexists(child) and {p.name for p in child.iterdir()}!=({file.name} if os.path.lexists(file) else set()):
            raise Refusal('selected short-name lock parent has new content')
    return retired

def retire(bundle,selector,ledger):
    path,data,plan=check_ledger(bundle,selector,ledger)
    process_and_mount_check(plan)
    if data.get('venueShortnameCachePhase') is None:
        rows=rows_for(plan,data)  # inventory BOTH accounts before the first unlink
        data['venueShortnameCacheRows']=rows
        data['venueShortnameCacheRetiredPaths']=[]
        data['venueShortnameCachePhase']='prepared';stage.write_ledger(path,data)
    if data['venueShortnameCachePhase']=='retired-inert':
        if any(os.path.lexists(Path(a['home'])/'.cache') for a in plan['accounts']):
            raise Refusal('short-name cache reappeared')
        return {'status':'retired-inert','retiredExactCacheInodes':len(data['venueShortnameCacheRows']),
                'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    rows=data.get('venueShortnameCacheRows')
    if not isinstance(rows,list) or len(rows)!=6 or len({x['path'] for x in rows})!=6:
        raise Refusal('missing exact six-inode short-name cache ledger')
    # Verify the rows correspond to the only two site-selected account homes,
    # not merely six arbitrary paths asserted in a writable journal.
    expected=[]
    for a in plan['accounts']:
        if a['name'] in NAMES:
            home=Path(a['home']);top=home/'.cache';child=top/'containers'
            expected.extend((str(child/'short-name-aliases.conf.lock'),str(child),str(top)))
    if [x.get('path') for x in rows]!=expected:raise Refusal('short-name cache rows not selected homes')
    retired=validate_remaining(data,plan,rows)
    data['venueShortnameCachePhase']='retiring';stage.write_ledger(path,data)
    for row in rows[len(retired):]:
        p=Path(row['path'])
        data['venueShortnameCachePending']=str(p);stage.write_ledger(path,data)
        if os.path.lexists(p):
            s=p.lstat()
            if ((s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=
                    (row['dev'],row['ino'],row['uid'],row['mode'])):
                raise Refusal('short-name inode changed just before retirement')
            if row['kind']=='file':
                if s.st_size!=0 or s.st_nlink!=1 or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256']:
                    raise Refusal('short-name lock bytes changed just before retirement')
                p.unlink()
            else:
                p.rmdir()  # empty exact child, never recursive
        data['venueShortnameCacheRetiredPaths'].append(str(p))
        data.pop('venueShortnameCachePending');stage.write_ledger(path,data)
    data['venueShortnameCachePhase']='retired-inert';stage.write_ledger(path,data)
    return {'status':'retired-inert','retiredExactCacheInodes':len(rows),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','selector','ledger'):ap.add_argument('--'+name,required=True)
    args=ap.parse_args()
    try:print(json.dumps(retire(args.bundle,args.selector,args.ledger),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('venue short-name cache retirement refused: '+str(exc)) from exc
if __name__=='__main__':main()
