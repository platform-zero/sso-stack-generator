#!/usr/bin/env python3
"""Stage a rendered, CAS-bound PRIVATE venue release without activation.

Only a clean, pre-data, exclusive stage may be used. The immutable input
bundle is copied under a new root0700 release parent; SOPS is rendered inside
that copy. A captured full-tree hash/inode manifest and exact current symlink
permit pre-activation exact retirement, not populated-data reset/rollback.
No volume readiness marker, unit enable/start, ingress, host-control or guest.
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

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('venue_stage',HERE/'venue-owned-stage.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
Refusal=stage.Refusal

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def attributes(path):
    p=Path(path);s=p.lstat()
    if p.is_symlink() or not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) or s.st_uid!=0:
        raise Refusal('venue release contains a linked, foreign or unclassified inode')
    if stat.S_ISREG(s.st_mode) and s.st_nlink!=1:raise Refusal('linked venue release file')
    return {'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,
            'type':'dir' if stat.S_ISDIR(s.st_mode) else 'file',
            'sha256':sha(p) if stat.S_ISREG(s.st_mode) else None}

def inventory(root):
    root=Path(root)
    return {str(p.relative_to(root)):attributes(p) for p in sorted(root.rglob('*'))}

def context(bundle,selector,ledger):
    b=Path(bundle);p=Path(ledger)
    if os.geteuid()!=0 or b.is_symlink() or not b.is_dir() or p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or stat.S_IMODE(p.stat().st_mode)!=0o600:
        raise Refusal('root-only immutable bundle and root0600 stage ledger required')
    data=json.loads(p.read_text());plan=stage.owned_plan(b,selector)
    if data.get('plan')!=plan or data.get('activationAuthorized') not in (False,None):
        raise Refusal('release source/stage CAS or activation authority differs')
    if not re.fullmatch(r'[0-9a-f]{40}',plan['sourceCommit']):raise Refusal('generator commit unpinned')
    state=Path(plan['roots']['rootful-state']);s=state.lstat();row=data.get('pathIdentities',{}).get(str(state))
    if state.is_symlink() or not row or (s.st_dev,s.st_ino,s.st_uid,stat.S_IMODE(s.st_mode))!=(row['dev'],row['ino'],0,0o700):
        raise Refusal('fresh rootful state parent identity changed')
    return b,p,data,plan,state

def layout(bundle,plan,state):
    provenance=json.loads((bundle/'source-provenance.json').read_text())
    if provenance.get('generatorCommit')!=plan['sourceCommit'] or provenance.get('generatorDirty') or provenance.get('siteDirty'):
        raise Refusal('unclean or mixed release source')
    site=provenance.get('siteCommit','')
    if not re.fullmatch(r'[0-9a-f]{40}',site):raise Refusal('unreviewed site commit')
    return state/'releases',state/'releases'/('r1-'+plan['sourceCommit'][:12]+'-'+site[:12]),state/'current'

def prepare(bundle,selector,ledger,age_key):
    b,p,data,plan,state=context(bundle,selector,ledger)
    if (data.get('status')!='staged-empty' or data.get('managerStarted') or data.get('venueReleasePhase') or
            data.get('unitFiles') or data.get('venueDataBindDirs') or data.get('venueHulyVolumes')):
        raise Refusal('only fresh, pre-data stage may render release')
    key=Path(age_key);ki=key.lstat()
    if key.is_symlink() or not stat.S_ISREG(ki.st_mode) or ki.st_uid!=0 or stat.S_IMODE(ki.st_mode)&0o077:
        raise Refusal('protected SOPS age identity required')
    releases,release,current=layout(b,plan,state)
    if any(os.path.lexists(x) for x in (releases,release,current)) or not shutil.rmtree.avoids_symlink_attacks:
        raise Refusal('occupied or unsupported isolated release authority')
    source_tree=inventory(b)
    if not source_tree or len(list((b/'quadlet').glob('*/*')))!=194:
        raise Refusal('incomplete immutable 60/95 source tree')
    data['venueReleasePhase']='copying'
    data['venueReleaseRoot']=str(release)
    data['venueReleaseSourceEntries']=len(source_tree)
    data['venueReleaseSourceManifest']=source_tree
    data['venueReleaseSourceRootSha256']=sha(b/'source-provenance.json')
    stage.write_ledger(p,data)
    releases.mkdir(mode=0o700);releases.chmod(0o700)
    rs=releases.lstat();data['venueReleasesParentIdentity']={'dev':rs.st_dev,'ino':rs.st_ino,'uid':0,'mode':0o700};stage.write_ledger(p,data)
    release.mkdir(mode=0o700);release.chmod(0o700)
    st=release.lstat();data['venueReleaseIdentity']={'dev':st.st_dev,'ino':st.st_ino,'uid':0,'mode':0o700}
    stage.write_ledger(p,data)
    shutil.copytree(b,release,symlinks=False,copy_function=shutil.copy2,dirs_exist_ok=True)
    release.chmod(0o700)
    copied=inventory(release)
    if (set(copied)!=set(source_tree) or any(
            (copied[name]['type'],copied[name]['mode'],copied[name]['sha256']) !=
            (row['type'],row['mode'],row['sha256']) for name,row in source_tree.items() if name!='.') or
            sha(release/'source-provenance.json')!=data['venueReleaseSourceRootSha256'] or
            stage.owned_plan(release,selector)!=plan):
        raise Refusal('private release copy source CAS differs')
    data['venueReleasePhase']='rendering';stage.write_ledger(p,data)
    command=[str(release/'scripts/deploy/render-runtime.sh'),'--bundle-root',str(release),
             '--deploy-root',str(release),'--runtime-root',str(release/'runtime'),
             '--skip-runtime-model-validate']
    env={**os.environ,'HOME':'/root','SOPS_AGE_KEY_FILE':str(key)}
    result=subprocess.run(command,env=env,cwd='/',capture_output=True,timeout=200)
    if result.returncode:
        # Never print private render stdout/stderr or remove unknown partial
        # plaintext on an interrupted renderer. Retain the root0700 slot.
        raise Refusal('selected private SOPS runtime render failed; retain exact journal and slot')
    config=release/'runtime/configs/caddy/Caddyfile';caddy=config.read_text()
    if (caddy.count('admin off')!=1 or caddy.count('default_bind 127.0.0.1')!=1 or
            caddy.count('http_port 56045')!=1 or caddy.count('https_port 56042')!=1 or
            caddy.count('redir https://{host}{uri} 308')!=1 or
            not (release/'runtime/stack.env').is_file() or
            stat.S_IMODE((release/'runtime/stack.env').stat().st_mode)!=0o600):
        raise Refusal('full rendered Caddy or protected runtime env is incomplete')
    whole=inventory(release)
    if len(whole)<len(source_tree)-100 or len(whole)>len(source_tree)+100:
        raise Refusal('runtime release content shape differs from source')
    data['venueReleaseManifest']=whole
    data['releaseRoot']=str(release)
    data['renderedCaddyPath']=str(config)
    data['renderedCaddySha256']=sha(config)
    st=release.lstat();data['venueReleaseIdentity']={'dev':st.st_dev,'ino':st.st_ino,'uid':0,'mode':0o700}
    data['venueReleasePhase']='linking';stage.write_ledger(p,data)
    os.symlink('releases/'+release.name,current)
    cur=current.lstat();data['venueCurrentIdentity']={'dev':cur.st_dev,'ino':cur.st_ino,'target':os.readlink(current)}
    data['venueReleasePhase']='inert-ready';stage.write_ledger(p,data)
    return {'status':'inert-ready','releaseFiles':sum(v['type']=='file' for v in whole.values()),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def retire(bundle,selector,ledger):
    b,p,data,plan,state=context(bundle,selector,ledger)
    if data.get('venueReleasePhase')!='inert-ready' or data.get('status')!='staged-empty':
        raise Refusal('only complete inactive release may use empty release retirement')
    started=data.get('managerStarted',[])
    if started:
        if (started!=[a['name'] for a in plan['accounts']] or
                data.get('managerStopped')!=[a['name'] for a in reversed(plan['accounts'])] or
                len(data.get('retiredUnits',[]))!=194 or
                len(data.get('retiredDataBindDirs',[]))!=61 or
                len(data.get('retiredHulyVolumes',[]))!=4 or
                len(data.get('graphCleared',[]))!=8 or
                not data.get('podmanImageCacheRetired') or not data.get('podmanRunrootRetired')):
            raise Refusal('all inert co-staged assets must be exactly retired first')
    releases,release,current=layout(b,plan,state)
    if (str(release)!=data.get('venueReleaseRoot') or
            data.get('releaseRoot')!=str(release) or
            data.get('renderedCaddyPath')!=str(release/'runtime/configs/caddy/Caddyfile') or
            not data.get('venueReleaseManifest')):
        raise Refusal('release slot and journal differ')
    for target,key in ((releases,'venueReleasesParentIdentity'),(release,'venueReleaseIdentity')):
        st=target.lstat();row=data.get(key,{})
        if (target.is_symlink() or not stat.S_ISDIR(st.st_mode) or
                (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode)) !=
                (row.get('dev'),row.get('ino'),0,0o700)):
            raise Refusal('selected release directory inode changed')
    st=current.lstat();row=data.get('venueCurrentIdentity',{})
    if (not current.is_symlink() or
            (st.st_dev,st.st_ino,os.readlink(current))!=(row.get('dev'),row.get('ino'),row.get('target')) or
            current.resolve()!=release):
        raise Refusal('installed-release pointer replaced')
    allowed_state={releases.name,current.name,Path(plan['roots']['rootful-network']).name}
    allowed_state.update(Path(x).name for x in plan['configs'] if Path(x).parent==state)
    if ({child.name for child in releases.iterdir()}!={release.name} or
            {child.name for child in state.iterdir()}!=allowed_state):
        raise Refusal('foreign rootful-state/release entry; no release deletion')
    if inventory(release)!=data['venueReleaseManifest'] or sha(release/'runtime/configs/caddy/Caddyfile')!=data.get('renderedCaddySha256'):
        raise Refusal('rendered release data, inode or ACL changed; not an installed-data reset')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:lines=(proc/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        if any((mp:=line.split()[4].replace('\\040',' '))==str(release) or mp.startswith(str(release)+'/') for line in lines if len(line.split())>=5):
            raise Refusal('selected release still mounted')
    data['venueReleasePhase']='retiring';stage.write_ledger(p,data)
    current.unlink()
    shutil.rmtree(release)
    releases.rmdir()
    data['venueReleasePhase']='retired-inert';stage.write_ledger(p,data)
    return {'status':'retired-inert','activationAuthorized':False,'acceptedIntegratedInstalls':0}

def recover_interrupted_copy(bundle,selector,ledger):
    """Retire ONLY prefix-identical, journaled release-copy files.

    A renderer might have emitted secrets or rewritten configs already; it
    must never be classified as a partial copy. Missing inode records also
    require inspected manual recovery, not an unlink by pathname alone.
    """
    b,p,data,plan,state=context(bundle,selector,ledger)
    if (data.get('venueReleasePhase')!='copying' or data.get('status')!='staged-empty' or
            data.get('managerStarted') or data.get('unitFiles') or data.get('venueDataBindDirs') or
            data.get('venueHulyVolumes') or data.get('crossDomainAclStatus')):
        raise Refusal('only a pre-render interrupted copy is recoverable')
    releases,release,current=layout(b,plan,state)
    if str(release)!=data.get('venueReleaseRoot') or os.path.lexists(current):
        raise Refusal('release copy slot or current pointer is not untouched')
    saved=data.get('venueReleaseSourceManifest')
    if not isinstance(saved,dict) or not saved or len(saved)!=data.get('venueReleaseSourceEntries') or inventory(b)!=saved:
        raise Refusal('immutable source changed since copying began')
    for path,key in ((releases,'venueReleasesParentIdentity'),(release,'venueReleaseIdentity')):
        row=data.get(key,{})
        try:s=path.lstat()
        except FileNotFoundError as exc:raise Refusal('interrupted copy directory inode was not recorded') from exc
        if (path.is_symlink() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or
                (s.st_dev,s.st_ino)!=(row.get('dev'),row.get('ino')) or
                (stat.S_IMODE(s.st_mode) not in ({0o700} if path==releases else {0o700,stat.S_IMODE(b.stat().st_mode)}))):
            raise Refusal('interrupted copy inode or mode differs')
    if {child.name for child in releases.iterdir()}!={release.name}:
        raise Refusal('foreign private release slot')
    found=inventory(release)
    if not set(found)<=set(saved):raise Refusal('foreign partial-copy entry')
    for name,row in found.items():
        source=saved[name]
        if row['type']!=source['type'] or row['uid']!=0:
            raise Refusal('interrupted copy inode class changed')
        if row['type']=='dir':
            if row['mode'] not in (source['mode'],0o700,0o755):
                raise Refusal('interrupted copy directory mode changed')
        else:
            original=b/name;partial=release/name
            if row['mode'] not in (source['mode'],0o644,0o600):
                raise Refusal('interrupted copy file mode changed')
            if partial.stat().st_size>original.stat().st_size:
                raise Refusal('partial copy exceeds source')
            with partial.open('rb') as inp,original.open('rb') as known:
                while block:=inp.read(1024*1024):
                    if known.read(len(block))!=block:
                        raise Refusal('partial copy differs from exact source prefix')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:lines=(proc/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        if any((mp:=line.split()[4].replace('\\040',' '))==str(release) or mp.startswith(str(release)+'/') for line in lines if len(line.split())>=5):
            raise Refusal('interrupted release copy still mounted')
    data['venueReleasePhase']='retiring-interrupted-copy';stage.write_ledger(p,data)
    shutil.rmtree(release);releases.rmdir()
    data['venueReleasePhase']='retired-interrupted-copy';stage.write_ledger(p,data)
    return {'status':'retired-interrupted-copy','sourceEntries':len(saved),'partialEntries':len(found),
            'activationAuthorized':False,'acceptedIntegratedInstalls':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','ledger'):p.add_argument('--'+key,required=True)
    p.add_argument('--sops-age-key-file')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true');mode.add_argument('--retire',action='store_true')
    mode.add_argument('--recover-interrupted-copy',action='store_true')
    a=p.parse_args()
    try:
        if (a.prepare and not a.sops_age_key_file) or (a.retire and a.sops_age_key_file):
            raise Refusal('SOPS identity only for fresh private rendering')
        if a.prepare:result=prepare(a.bundle,a.selector,a.ledger,a.sops_age_key_file)
        elif a.retire:result=retire(a.bundle,a.selector,a.ledger)
        else:result=recover_interrupted_copy(a.bundle,a.selector,a.ledger)
        print(json.dumps(result,sort_keys=True))
    except (Refusal,KeyError,ValueError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('venue inactive release lifecycle refused: '+str(exc)) from exc
if __name__=='__main__':main()
