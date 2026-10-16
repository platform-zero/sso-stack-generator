#!/usr/bin/env python3
"""Stage/retire ONLY the exact reviewed isolated-venue host-control SOURCE.

Distinct root-private role; never select, configure, register, enable or start
legacy /etc/p0-control, /run/p0-control, /usr/local/libexec/p0-control or
p0-* host units. This is NOT an installed/operational host-control role.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_owned_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def sha(value):return hashlib.sha256(value).hexdigest()

def git(checkout,*args):
    result=subprocess.run(['git','-c','safe.directory='+str(checkout),'-C',str(checkout),*args],
                          capture_output=True,timeout=30,cwd='/')
    if result.returncode:raise Refusal('control source commit/files cannot be verified')
    return result.stdout

def inputs(bundle,selector,checkout):
    plan=stage.owned_plan(bundle,selector)
    data=json.loads(Path(selector).read_text())
    site=json.loads((Path(bundle)/'site/agent-vm.json').read_text())
    commit=site['runtime']['controlCommit']
    if (not re.fullmatch(r'[0-9a-f]{40}',commit) or data['guest']['controlCommit']!=commit or
            git(checkout,'rev-parse','HEAD').decode().strip()!=commit or
            git(checkout,'status','--porcelain').strip()):
        raise Refusal('host-control source/site pin or clean checkout differs')
    script=Path(checkout)/'ops/install-agent-services.py'
    if script.is_symlink() or script.read_bytes()!=git(checkout,'show',commit+':ops/install-agent-services.py'):
        raise Refusal('reviewed host-control inventory source changed')
    module_spec=importlib.util.spec_from_file_location('reviewed_legacy_control_map',script)
    module=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module)
    members={name:path for name,path in module.HOST.items()}
    members.update({'units/'+name:'ops/'+name for name in module.HOST_UNITS})
    static=sorted(Path(checkout,'static').iterdir())
    if not members or any(p.is_symlink() or not p.is_file() for p in static):
        raise Refusal('host-control staged source inventory changed')
    for p in static:members['static/'+p.name]='static/'+p.name
    if any(Path(name).is_absolute() or '..' in Path(name).parts or not re.fullmatch(r'[A-Za-z0-9._/-]+',name)
           for name in members):raise Refusal('unsafe control source member')
    content={name:git(checkout,'show',commit+':'+source) for name,source in sorted(members.items())}
    return plan,commit,content

def stage_source(bundle,selector,checkout,root,ledger):
    root=Path(root);ledger=Path(ledger)
    if not root.is_dir() or root.is_symlink() or root.stat().st_uid!=os.geteuid() or stat.S_IMODE(root.stat().st_mode)!=0o700:
        raise Refusal('private source parent must be owned 0700')
    if ledger.parent!=root or os.path.lexists(ledger):raise Refusal('unsafe or occupied control-source journal')
    plan,commit,content=inputs(bundle,selector,checkout)
    release=root/('host-'+commit)
    if os.path.lexists(release):raise Refusal('separate host-control source slot already occupied')
    manifest={'schemaVersion':1,'role':'p0test-r1-host-control-source-only','controlCommit':commit,
              'selectorSha256':plan['selectorSha256'],'bundleIrSha256':plan['bundleIrSha256'],
              'files':{name:sha(value) for name,value in content.items()},
              'activationAuthorized':False,'acceptedIntegratedInstalls':0}
    temp=Path(tempfile.mkdtemp(prefix='.venue-control-source-',dir=root));temp.chmod(0o700)
    try:
        for name,value in content.items():
            p=temp/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out:out.write(value);out.flush();os.fsync(out.fileno())
        (temp/'manifest.json').write_text(json.dumps(manifest,sort_keys=True)+'\n')
        (temp/'manifest.json').chmod(0o600)
        os.rename(temp,release)
    finally:
        if temp.exists():shutil.rmtree(temp)
    entry={'status':'source-staged','manifest':manifest,'release':str(release),'sourceFiles':len(content),
           'releaseDev':release.lstat().st_dev,'releaseIno':release.lstat().st_ino}
    stage.write_ledger(ledger,entry,create=True)
    return entry

def retire_source(bundle,selector,checkout,root,ledger):
    root=Path(root);ledger=Path(ledger)
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.geteuid() or stat.S_IMODE(root.stat().st_mode)!=0o700:
        raise Refusal('private source parent authority changed')
    if (ledger.parent!=root or ledger.is_symlink() or not ledger.is_file() or
            ledger.stat().st_uid!=os.geteuid() or stat.S_IMODE(ledger.stat().st_mode)!=0o600):
        raise Refusal('protected control-source journal missing')
    data=json.loads(ledger.read_text());plan,commit,content=inputs(bundle,selector,checkout)
    release=root/('host-'+commit)
    manifest=data.get('manifest',{})
    if (data.get('status')!='source-staged' or data.get('release')!=str(release) or
            manifest.get('controlCommit')!=commit or manifest.get('selectorSha256')!=plan['selectorSha256'] or
            manifest.get('bundleIrSha256')!=plan['bundleIrSha256'] or
            manifest.get('files')!={name:sha(value) for name,value in content.items()}):
        raise Refusal('exact source role journal/provenance drift')
    st=release.lstat()
    if release.is_symlink() or not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino,st.st_uid)!=(data['releaseDev'],data['releaseIno'],os.geteuid()):
        raise Refusal('control source release inode changed')
    allowed={str(release/'manifest.json'),*(str(release/name) for name in content)}
    dirs={str(p) for name in content for p in (release/name).parents if p!=release and str(p).startswith(str(release)+'/')}
    present={str(p) for p in release.rglob('*')}
    if present!=allowed|dirs:raise Refusal('unreviewed control-role source content')
    for name in dirs:
        info=Path(name).lstat()
        if not stat.S_ISDIR(info.st_mode) or Path(name).is_symlink() or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise Refusal('linked or modified control-source parent')
    for name,value in content.items():
        p=release/name;info=p.lstat()
        if p.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or sha(p.read_bytes())!=sha(value):
            raise Refusal('reviewed host-control source file changed')
    m=release/'manifest.json'
    if m.is_symlink() or json.loads(m.read_text())!=manifest:raise Refusal('source manifest changed')
    mounts=[line.split()[4].replace('\\040',' ') for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    if any(p==str(release) or p.startswith(str(release)+'/') for p in mounts):
        raise Refusal('source role contains a mount')
    for p in sorted((release/name for name in content),reverse=True):p.unlink()
    m.unlink()
    for p in sorted((Path(p) for p in dirs),key=lambda p:len(p.parts),reverse=True):p.rmdir()
    release.rmdir()
    data['status']='source-retired';stage.write_ledger(ledger,data)
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','checkout','ledger','private-root'):p.add_argument('--'+key,required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--stage-source',action='store_true');mode.add_argument('--retire-source',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('venue control-source staging requires root')
    try:
        result=(stage_source if a.stage_source else retire_source)(a.bundle,a.selector,a.checkout,a.private_root,a.ledger)
        print(json.dumps({'status':result['status'],'sourceFiles':result['sourceFiles'],
                          'activationAuthorized':False,'acceptedIntegratedInstalls':0},sort_keys=True))
    except (Refusal,KeyError,TypeError,ValueError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue host-control source lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
