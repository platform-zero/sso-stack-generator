#!/usr/bin/env python3
"""Retire only CAS-journaled selected failed-build /var/tmp scratch inodes.

Never prune, glob or remove another user's Buildah scratch. The only accepted
case is a stopped failed Android build with two explicitly supplied new UID-
owned directories, one private regular scratch file each. All byte contents
are disposable test build scratch, NOT a release artifact or recovery copy.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
spec=importlib.util.spec_from_file_location('venue_build',HERE/'venue-local-build-images.py')
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
Refusal=stage.Refusal

def inode(p,uid,mode,kind):
    s=p.lstat()
    if (p.is_symlink() or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=mode or
            (not stat.S_ISDIR(s.st_mode) if kind=='dir' else not stat.S_ISREG(s.st_mode) or s.st_nlink!=1)):
        raise Refusal('selected failed-build scratch inode/owner/mode differs')
    return {'path':str(p),'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,
            'mode':mode,'kind':kind,'size':s.st_size if kind=='file' else 0}

def classify(root,names,uid):
    base=Path(root)
    s=base.lstat()
    if base.is_symlink() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o1777:
        raise Refusal('build scratch parent not isolated sticky root directory')
    if not isinstance(names,list) or len(names)!=2 or len(set(names))!=2:
        raise Refusal('exactly two selected failed-build scratch names required')
    result=[]
    for name in names:
        if (not isinstance(name,str) or '/' in name or name in ('.','..') or
                not (name.startswith('buildah') or name.startswith('container_images_storage')) or
                not name[len('buildah' if name.startswith('buildah') else 'container_images_storage'):].isdigit()):
            raise Refusal('unreviewed scratch directory name')
        p=base/name;parent=inode(p,uid,0o700,'dir')
        if parent['dev']!=s.st_dev:raise Refusal('mounted or foreign scratch filesystem')
        children=list(p.iterdir())
        if len(children)!=1:raise Refusal('failed build scratch contains unexpected members')
        child=inode(children[0],uid,0o600,'file')
        if child['dev']!=s.st_dev:raise Refusal('mounted or foreign scratch child')
        result.extend((child,parent))
    return result

def mounted_or_open(paths):
    roots=[Path(p) for p in paths]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            for line in (proc/'mountinfo').read_text().splitlines():
                cells=line.split()
                if len(cells)>4:
                    mp=cells[4].replace('\\040',' ')
                    if any(mp==str(p) or mp.startswith(str(p)+'/') for p in roots):
                        raise Refusal('selected failed-build scratch has a mount')
            for fd in (proc/'fd').iterdir():
                try:link=os.readlink(fd)
                except (FileNotFoundError,PermissionError,ProcessLookupError):continue
                if any(link==str(p) or link.startswith(str(p)+'/') for p in roots):
                    raise Refusal('selected failed-build scratch has a live file descriptor')
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue

def retire(bundle,selector,ledger,names):
    p=Path(ledger)
    if os.geteuid()!=0 or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('selected root0600 build-failure ledger required')
    data=json.loads(p.read_text());plan=stage.owned_plan(bundle,selector)
    key=plan['prefix']+'-test-runners|localhost/webservices/android-test-runner-api34:bundle'
    account=next(a for a in plan['accounts'] if a['name']==plan['prefix']+'-test-runners')
    if (data.get('plan')!=plan or data.get('venueInstallerVersion')!=1 or
            data.get('venueInstallerPhase')!='inert-ready' or
            data.get('venueCompositeMode')!='inert-ready' or data.get('status')!='units-staged' or
            data.get('venueLocalBuildPending')!=key or data.get('activationAuthorized') is not False):
        raise Refusal('only exact inactive failed Android output may retire scratch')
    unit=data['venueLocalBuildPlan'][key]['unit']
    state=build.selected_unit(build.unit_command(plan,account['name'],unit),unit,key.split('|',1)[1],offline=False)
    if state.get('ActiveState') not in ('inactive','failed') or state.get('Job') not in ('',None,'0'):
        raise Refusal('selected failed build or job still active')
    if build.registry.pulled(build.registry.command_graphs(bundle,plan)[account['name']][1],key.split('|',1)[1]):
        raise Refusal('selected build has an output image; scratch needs separate review')
    root=Path('/var/tmp');prev=data.get('venueFailedBuildTmpPlan')
    if prev is None:
        rows=classify(root,names,account['uid']);retired=[]
    else:
        rows=prev;retired=data.get('venueFailedBuildTmpRetired',[])
        if (not isinstance(rows,list) or len(rows)!=4 or not isinstance(retired,list) or
                retired!=[r['path'] for r in rows[:len(retired)]] or
                [Path(r['path']).name for r in rows if r.get('kind')=='dir']!=names or
                any(not str(r.get('path','')).startswith('/var/tmp/') for r in rows)):
            raise Refusal('failed build scratch recovery CAS differs')
        for row in rows[len(retired):]:
            child=Path(row['path'])
            if inode(child,account['uid'],row['mode'],row['kind'])!=row:
                raise Refusal('failed build scratch recovery inode changed')
            if row['kind']=='dir' and any(child.iterdir()):
                raise Refusal('foreign file appeared after scratch child retirement')
        for row in rows[:len(retired)]:
            if os.path.lexists(row['path']):raise Refusal('retired scratch inode reappeared')
    mounted_or_open([r['path'] for r in rows[len(retired):] if r['kind']=='dir'])
    if prev is None:
        data['venueFailedBuildTmpPlan']=rows;data['venueFailedBuildTmpRetired']=[]
        stage.write_ledger(p,data)
    for row in rows[len(retired):]:
        file=Path(row['path']);current=inode(file,account['uid'],row['mode'],row['kind'])
        if current!=row:raise Refusal('failed build scratch changed before exact retirement')
        if row['kind']=='file':file.unlink()
        else:file.rmdir()
        data['venueFailedBuildTmpRetired'].append(row['path']);stage.write_ledger(p,data)
    return {'status':'retired-exact-scratch','retiredInodes':len(rows),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for x in ('bundle','selector','ledger'):ap.add_argument('--'+x,required=True)
    ap.add_argument('--selected-scratch-name',action='append',required=True)
    a=ap.parse_args()
    try:print(json.dumps(retire(a.bundle,a.selector,a.ledger,a.selected_scratch_name),sort_keys=True))
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('venue exact failed-build scratch retirement refused: '+str(exc)) from exc
if __name__=='__main__':main()
