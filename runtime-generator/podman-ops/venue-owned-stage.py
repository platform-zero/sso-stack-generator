#!/usr/bin/env python3
"""Stage ONLY exclusive empty venue identities/storage; never activate a service.

This is NOT the complete venue installer or integrated acceptance. The ledger
precedes host mutations. A half-written ledger is retained for exact recovery;
no broad rollback, pruning, deletion of data or graph repair is attempted.
"""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent

class Refusal(ValueError):pass

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def quadlet_tree_hash(bundle):
    root=Path(bundle)/'quadlet'
    sources=sorted(root.glob('*/*'))
    if len(sources)!=190 or any(p.is_symlink() or not p.is_file() for p in sources):
        raise Refusal('unreviewed 190-member Quadlet tree')
    digest=hashlib.sha256()
    for source in sources:
        relative=source.relative_to(root).as_posix().encode()
        data=source.read_bytes()
        digest.update(len(relative).to_bytes(4,'big')+relative+len(data).to_bytes(8,'big')+data)
    return digest.hexdigest()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,HERE/path)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj)
    return obj

def owned_plan(bundle,selector):
    s=json.loads(Path(selector).read_text());d=json.loads((Path(bundle)/'podman-domains.json').read_text())
    if s.get('unitPrefix')!='p0test-r1' or d.get('venue',{}).get('unitPrefix')!=s['unitPrefix']:
        raise Refusal('unreviewed isolated venue prefix')
    domains=list(d['domains']);entries=s['domains']
    if len(domains)!=7 or set(entries)!={v['name'] for v in domains}:
        raise Refusal('seven-account domain authority incomplete')
    accounts=[]
    for domain in domains:
        v=entries[domain['name']]
        if any(v.get(k)!=domain.get(k) for k in ('user','uid','subuidStart','stateRoot','graphRoot','volumeRoot')):
            raise Refusal('account/graph authority differs from generated bundle')
        accounts.append({'name':v['user'],'uid':v['uid'],'subuid':v['subuidStart'],
                         'home':'/home/'+v['user'],'state':v['stateRoot'],
                         'graph':v['graphRoot'],'volume':v['volumeRoot']})
    venue=d['venue'];r=s['rootful'];roots={
        'rootful-state':r['stateRoot'],'rootful-graph':r['graphRoot'],
        'rootful-network':r['stateRoot']+'/networks',
        'rootful-run':r['runRoot'],'rootful-volume':r['volumeRoot'],
        'rootful-runtime':venue['rootfulRuntimeRoot'],
        'postgres':s['storageRoots']['pgSsdRoot'],
        'vectors':s['storageRoots']['vectorDbsRoot'],
        'log':s['storageRoots']['logRoot']}
    for account in accounts:
        for kind in ('home','state','graph','volume'):
            roots[account['name']+'-'+kind]=account[kind]
        if account['name']==s['unitPrefix']+'-ci-runner':
            roots['ci-runner-ssh']=account['state']+'/forgejo-runner-ssh'
    if len(set(roots.values()))!=38 or any(not Path(p).is_absolute() or '..' in Path(p).parts for p in roots.values()):
        raise Refusal('duplicate or unsafe stage root')
    conf='[storage]\ndriver = "overlay"\nrunroot = "'+r['runRoot']+'"\ngraphroot = "'+r['graphRoot']+'"\n'
    configs={r['stateRoot']+'/containers-storage.conf':conf,
             r['stateRoot']+'/containers.conf':'[network]\nnetwork_config_dir = "'+r['stateRoot']+'/networks"\n'}
    for account in accounts:
        c=account['home']+'/.config/containers/'
        configs[c+'storage.conf']='[storage]\ndriver = "overlay"\ngraphroot = "'+account['graph']+'"\n'
        configs[c+'containers.conf']='[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n'
    return {'schemaVersion':1,'prefix':s['unitPrefix'],'selectorSha256':sha(selector),
            'bundleIrSha256':sha(Path(bundle)/'stack.ir.json'),
            'quadletTreeSha256':quadlet_tree_hash(bundle),
            'sourceCommit':json.loads((Path(bundle)/'source-provenance.json').read_text())['generatorCommit'],
            'accounts':accounts,'roots':roots,'configs':configs,'activationAuthorized':False}

def safe_parents(paths):
    """No symlink or unsafe owner along a proposed new path, including /home."""
    missing=set()
    for value in paths:
        p=Path(value)
        if not p.is_absolute() or p==Path('/') or '..' in p.parts or os.path.normpath(value)!=value:
            raise Refusal('noncanonical stage path')
        for ancestor in (p,*p.parents):
            if ancestor==Path('/'):break
            try:info=ancestor.lstat()
            except FileNotFoundError:missing.add(str(ancestor));continue
            reviewed_ssd_mount=(str(ancestor)=='/mnt/stack' and info.st_uid==1000 and
                                stat.S_IMODE(info.st_mode)==0o2775)
            if not stat.S_ISDIR(info.st_mode) or (info.st_uid!=0 and not reviewed_ssd_mount):
                raise Refusal('existing stage ancestor is not root or the reviewed SSD mount')
            if info.st_mode & 0o002:
                raise Refusal('world-writable stage ancestor')
            if ancestor==p:raise Refusal('existing target is not fresh stage ownership')
    return sorted(missing,key=lambda value:(len(Path(value).parts),value))

def create_private_directory(path,uid,mode):
    """Only fresh stage nodes: do not inherit host ACLs into rootless graphs.

    chmod alone masks named access entries but leaves default ACL inheritance
    intact. Unmapped host principals then make namespace ACL copies fail with
    EINVAL and can change access inside extracted images. Never scrub an
    existing parent or recursively rewrite an existing graph.
    """
    path=Path(path)
    path.mkdir(mode=0o700)  # exclusive: existing files/directories must refuse
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in ('system.posix_acl_default','system.posix_acl_access'):
            if name in os.listxattr(fd):os.removexattr(fd,name)
        os.fchown(fd,uid,uid)
        os.fchmod(fd,mode)
        st=os.fstat(fd)
        current=path.lstat()
        if ((st.st_dev,st.st_ino)!=(current.st_dev,current.st_ino) or
                any(name.startswith('system.posix_acl_') for name in os.listxattr(fd)) or
                st.st_uid!=uid or st.st_gid!=uid or stat.S_IMODE(st.st_mode)!=mode):
            raise Refusal('fresh stage directory identity or ACL isolation failed')
        return st
    finally:os.close(fd)


def write_ledger(path,data,*,create=False):
    path=Path(path)
    parent=path.parent
    if not parent.is_dir() or parent.is_symlink() or parent.stat().st_uid!=0 or stat.S_IMODE(parent.stat().st_mode)!=0o700:
        raise Refusal('ledger parent must be existing root-owned 0700')
    if create and os.path.lexists(path):raise Refusal('stage ledger already exists')
    if not create and (not path.is_file() or path.is_symlink() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600):
        raise Refusal('unsafe existing stage ledger')
    tmp=parent/(path.name+'.new')
    if os.path.lexists(tmp):raise Refusal('stage ledger swap already exists')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as out:json.dump(data,out,sort_keys=True,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
        os.replace(tmp,path)
        dirfd=os.open(parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        if tmp.exists():tmp.unlink()

def preflight(bundle,selector,inventory):
    diagnostic=load('venue_diagnostic','inspect-existing-host-venue-beyond-listeners.py')
    return diagnostic.inspect(bundle,selector,inventory)

def static_boundary(checked):
    # Measured cuts/finance composition; includes private source configs and
    # retained Huly CA. Missing OR additional mounts/publishers still refuse.
    expected={'checkedMounts':237,'checkedRootfulStoreUnits':12,'checkedPublishedPorts':47}
    if any(type(checked.get(key)) is not int or checked[key]!=value for key,value in expected.items()):
        raise Refusal('incomplete static venue boundary')

def stage(bundle,selector,inventory,ledger,*,mutate=False):
    plan=owned_plan(bundle,selector)
    checked=preflight(bundle,selector,inventory)
    static_boundary(checked)
    provenance=json.loads((Path(bundle)/'source-provenance.json').read_text())
    if provenance['generatorDirty'] or provenance['siteDirty']:
        raise Refusal('dirty source cannot stage physical venue')
    if os.path.lexists(ledger):raise Refusal('venue stage ledger already exists')
    usernames={x.pw_name for x in pwd.getpwall()};uids={x.pw_uid for x in pwd.getpwall()}
    groups={x.gr_name for x in grp.getgrall()};gids={x.gr_gid for x in grp.getgrall()}
    for account in plan['accounts']:
        if account['name'] in usernames|groups or account['uid'] in uids|gids:
            raise Refusal('stage identity or private group is occupied')
    if any(os.path.lexists(name) for name in plan['configs']):
        raise Refusal('stage storage configuration path already exists')
    roots=safe_parents(list(plan['roots'].values())+[str(Path(name).parent) for name in plan['configs']])
    for account in plan['accounts']:
        if account['home'] in plan['roots'].values() and account['home'] not in roots:
            raise Refusal('home path is not fresh')
    fs=os.statvfs('/');ssd=os.statvfs('/mnt/stack')
    avail=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))
    if fs.f_bavail*fs.f_frsize<50*2**30 or ssd.f_bavail*ssd.f_frsize<100*2**30 or avail<12*2**20:
        raise Refusal('physical storage or RAM reserve')
    output={'schemaVersion':1,'status':'planned','activationAuthorized':False,'plan':plan,
            'createPaths':roots,'createdGroups':[],'createdAccounts':[],'createdPaths':[],'pathIdentities':{},'createdConfigs':[],
            'retiredConfigs':[],'retiredPaths':[],'retiredAccounts':[]}
    if not mutate:return output
    if os.geteuid()!=0:raise Refusal('physical stage requires root')
    output['status']='preparing'
    write_ledger(ledger,output,create=True)
    def persist():write_ledger(ledger,output)
    try:
        for account in plan['accounts']:
            name=str(account['name']);uid=int(account['uid']);start=int(account['subuid'])
            output['pending']={'operation':'groupadd','name':name};persist()
            subprocess.run(['groupadd','--system','--gid',str(uid),name],check=True,timeout=25)
            output['createdGroups'].append(name);output.pop('pending');persist()
            output['pending']={'operation':'useradd','name':name};persist()
            subprocess.run(['useradd','--system','--uid',str(uid),'--gid',name,'--no-create-home',
                            '--home-dir',account['home'],'--shell','/usr/sbin/nologin',name],check=True,timeout=25)
            output['createdAccounts'].append(name);output.pop('pending');persist()
            output['pending']={'operation':'subids','name':name};persist()
            subprocess.run(['usermod','--add-subuids',f'{start}-{start+65535}',
                            '--add-subgids',f'{start}-{start+65535}',name],check=True,timeout=25)
            output.pop('pending');persist()
        def owned_by(name):
            for account in plan['accounts']:
                if name==account['home'] or name.startswith(account['home']+'/') or name in (account['state'],account['graph'],account['volume']) or (account['name']==plan['prefix']+'-ci-runner' and name==plan['roots']['ci-runner-ssh']):
                    return account
            return None
        for name in roots:
            p=Path(name);powner=owned_by(name);identity=int(powner['uid']) if powner else 0
            output['pending']={'operation':'mkdir','path':name};persist()
            st=create_private_directory(p,identity,
                    0o711 if powner is None and name not in plan['roots'].values() else 0o700)
            output['createdPaths'].append(name)
            output['pathIdentities'][name]={'dev':st.st_dev,'ino':st.st_ino,'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode)}
            output.pop('pending');persist()
        for name,content in plan['configs'].items():
            p=Path(name);powner=next((a for a in plan['accounts'] if name.startswith(a['home']+'/')),None)
            output['pending']={'operation':'config','path':name};persist()
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as out:out.write(content);out.flush();os.fsync(out.fileno())
            if powner:os.chown(p,int(powner['uid']),int(powner['uid']))
            output['createdConfigs'].append(name);output.pop('pending');persist()
        for account in plan['accounts']:
            name=account['name'];identity=pwd.getpwnam(name)
            if identity.pw_uid!=account['uid'] or identity.pw_gid!=account['uid'] or identity.pw_dir!=account['home']:
                raise Refusal('new test account identity drift after stage')
            for subfile in ('/etc/subuid','/etc/subgid'):
                rows=[r for r in Path(subfile).read_text().splitlines() if r.startswith(name+':')]
                if rows!=[f"{name}:{account['subuid']}:65536"]:
                    raise Refusal('new test account subordinate range drift')
        output['status']='staged-empty';persist()
        return output
    except Exception:
        # Preserve the exact ledger and partial state; never guess a rollback.
        raise

def boot_observation():
    import time
    rows=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    return {'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'monotonicUsec':int(time.monotonic()*1_000_000),
            'runTmpfs':any(len(row)>6 and row[4]=='/run' and row[row.index('-')+1]=='tmpfs' for row in rows)}


def boot_lost_runtime_paths(plan,state,observation):
    """Only receipted /run roots may disappear across a positively proven boot."""
    prior=state.get('venueBootLostRuntimePaths');epoch=state.get('venueStartMonotonicUsec',0)
    if prior:
        if prior.get('bootId')!=observation['bootId'] or prior.get('startMonotonicUsec')!=epoch:
            raise Refusal('boot-lost runtime path review belongs to another boot/epoch')
        missing=set(prior['paths'])
    else:
        eligible=(state.get('venueInstallerVersion')==2 and state.get('venueInstallerPhase')=='retiring' and
                  state.get('activationAuthorized') is False and state.get('venueOwnedReset',{}).get('phase')=='empty-owned' and
                  all(state.get(key)=='retired-inert' for key in ('venueReleasePhase','venueDomainRuntimePhase','venueRuntimeEnvPhase','venueCompositeMode')) and
                  state.get('managerStopped')==[a['name'] for a in reversed(plan['accounts'])] and
                  state.get('graphCleared')==['root']+[a['name'] for a in plan['accounts']] and
                  epoch>observation['monotonicUsec'] and observation['runTmpfs'])
        if not eligible:return set()
        allowed={'/run/'+plan['prefix'],'/run/'+plan['prefix']+'-podman'}&set(plan['roots'].values())&set(state['createdPaths'])
        missing={name for name in allowed if not os.path.lexists(name)}
        if not missing:return set()
        state['venueBootLostRuntimePaths']={'bootId':observation['bootId'],'startMonotonicUsec':epoch,
             'observedMonotonicUsec':observation['monotonicUsec'],'paths':sorted(missing),'evidence':'recorded-start-monotonic-exceeds-current-boot'}
    if (not observation['runTmpfs'] or not missing<={'/run/'+plan['prefix'],'/run/'+plan['prefix']+'-podman'} or
            not missing<=set(plan['roots'].values()) or not missing<=set(state['createdPaths']) or
            any(os.path.lexists(name) for name in missing)):
        raise Refusal('boot-lost path is not an absent exact selected tmpfs runtime root')
    return missing


def retire_empty(bundle,selector,ledger):
    if os.geteuid()!=0:raise Refusal('empty-stage retirement requires root')
    path=Path(ledger)
    if not path.is_file() or path.is_symlink() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600:
        raise Refusal('missing or unsafe exact stage ledger')
    state=json.loads(path.read_text());plan=owned_plan(bundle,selector)
    if state.get('schemaVersion')!=1 or state.get('plan')!=plan or state.get('status') not in ('staged-empty','retiring-empty'):
        raise Refusal('stage ledger/source CAS differs or state is not empty-stage')
    if (state.get('createdGroups')!=[a['name'] for a in plan['accounts']]
            or state.get('createdAccounts')!=[a['name'] for a in plan['accounts']]
            or state.get('createdPaths')!=state.get('createPaths')
            or set(state.get('createdConfigs',[]))!=set(plan['configs'])
            or len(state['pathIdentities'])!=len(state['createPaths'])):
        raise Refusal('stage creation journal is incomplete')
    prefix=plan['prefix']
    for parent in (Path('/etc/containers/systemd'),Path('/etc/systemd/system')):
        if parent.exists() and any(p.name.startswith(prefix) for p in parent.iterdir()):
            raise Refusal('installed venue unit is not an empty-stage resource')
    if any(p.name.startswith(prefix) for p in Path('/run/systemd/system').glob('*')):
        raise Refusal('runtime venue unit is not an empty-stage resource')
    for account in plan['accounts']:
        current=pwd.getpwnam(account['name'])
        group=grp.getgrnam(account['name'])
        if current.pw_uid!=account['uid'] or current.pw_gid!=account['uid'] or current.pw_dir!=account['home'] or current.pw_shell!='/usr/sbin/nologin' or group.gr_gid!=account['uid']:
            raise Refusal('test account or primary group identity drift')
        for filename in ('/etc/subuid','/etc/subgid'):
            rows=[row for row in Path(filename).read_text().splitlines() if row.startswith(account['name']+':')]
            if rows!=[f"{account['name']}:{account['subuid']}:65536"]:
                raise Refusal('test subordinate range drift')
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():continue
            try:
                info=(entry/'status').read_text().splitlines()
                uids=next(row for row in info if row.startswith('Uid:')).split()[1:]
            except (FileNotFoundError,PermissionError,StopIteration):continue
            if str(account['uid']) in uids:
                raise Refusal('test account still owns a live process')
    def check_identity(name):
        value=state['pathIdentities'][name];p=Path(name)
        if p.is_symlink():raise Refusal('symlink appeared in staged tree')
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode):
            raise Refusal('staged directory identity drift')
        if (st.st_dev,st.st_ino,st.st_uid,stat.S_IMODE(st.st_mode))!=(value['dev'],value['ino'],value['uid'],value['mode']):
            raise Refusal('staged directory identity drift')
    boot_lost=boot_lost_runtime_paths(plan,state,boot_observation())
    if boot_lost:write_ledger(path,state)
    remaining=[name for name in state['createdPaths'] if name not in state.get('retiredPaths',[]) and name not in boot_lost]
    mountpoints=[]
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        parts=row.split()
        if len(parts)<6:raise Refusal('unparseable host mount table')
        mountpoints.append(parts[4].replace('\\040',' ').replace('\\011','\t'))
    if any(mp==root or mp.startswith(root.rstrip('/')+'/') for mp in mountpoints for root in remaining):
        raise Refusal('live mount in exact stage-owned tree')
    for name in remaining:check_identity(name)
    for name in state['createdConfigs']:
        if name in state.get('retiredConfigs',[]):continue
        p=Path(name)
        if not p.is_file() or p.is_symlink() or p.read_text()!=plan['configs'][name] or stat.S_IMODE(p.stat().st_mode)!=0o600:
            raise Refusal('staged storage config changed')
    for name in remaining:
        contents={p.name for p in Path(name).iterdir()}
        allowed={Path(c).name for c in state['createdConfigs'] if Path(c).parent==Path(name) and c not in state.get('retiredConfigs',[])}
        allowed|={Path(child).name for child in remaining if Path(child).parent==Path(name)}
        if contents!=allowed:raise Refusal('stage root is not empty or has unreviewed content: '+name)
    state['status']='retiring-empty';write_ledger(path,state)
    for name in state['createdConfigs']:
        if name in state['retiredConfigs']:continue
        Path(name).unlink()
        state['retiredConfigs'].append(name);write_ledger(path,state)
    for name in reversed(state['createdPaths']):
        if name in state['retiredPaths']:continue
        if name in boot_lost:
            if os.path.lexists(name):raise Refusal('boot-lost runtime path was repopulated; no adoption/deletion')
        else:
            check_identity(name)
            Path(name).rmdir()  # never recursive; refuse unreviewed contents
        state['retiredPaths'].append(name);write_ledger(path,state)
    for account in reversed(plan['accounts']):
        name=account['name']
        if name in state['retiredAccounts']:continue
        subprocess.run(['userdel',name],check=True,timeout=25)
        # Refuse instead of deleting another group's identity on drift.
        try:group=grp.getgrnam(name)
        except KeyError:group=None
        if group is not None:
            if group.gr_gid!=account['uid'] or group.gr_mem:
                raise Refusal('residual group is not the exact test group')
            subprocess.run(['groupdel',name],check=True,timeout=25)
        state['retiredAccounts'].append(name);write_ledger(path,state)
    state['status']='retired-empty';write_ledger(path,state)
    return state


def retire_partial(bundle,selector,ledger):
    """Retire only a journaled, interrupted PRE-DATA stage, never installed assets."""
    if os.geteuid()!=0:raise Refusal('partial stage retirement requires root')
    path=Path(ledger)
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or
            stat.S_IMODE(path.stat().st_mode)!=0o600):
        raise Refusal('protected interrupted-stage journal required')
    state=json.loads(path.read_text());plan=owned_plan(bundle,selector)
    if (state.get('plan')!=plan or state.get('status') not in ('preparing','retiring-partial') or
            state.get('pending') or state.get('createdConfigs') or
            any(state.get(k) for k in ('managerStarted','unitFiles','venueDataBindDirs',
                                      'venueHulyVolumes','crossDomainAclStatus','venueCompositeVersion')) or
            state.get('createdGroups')!=[a['name'] for a in plan['accounts']] or
            state.get('createdAccounts')!=state['createdGroups']):
        raise Refusal('interrupted stage crossed the empty identity/path-only boundary')
    created=state.get('createdPaths',[]);full=state.get('createPaths',[])
    retired=state.get('retiredPaths',[]);retired_accounts=state.get('retiredAccounts',[])
    names=[a['name'] for a in plan['accounts']]
    if (not created or len(created)>=len(full) or created!=full[:len(created)] or
            len(state.get('pathIdentities',{}))!=len(created) or
            set(state['pathIdentities'])!=set(created) or
            retired!=list(reversed(created))[:len(retired)] or
            retired_accounts!=list(reversed(names))[:len(retired_accounts)]):
        raise Refusal('partial directory/account journal differs from ordered stage')
    for parent in (Path('/etc/containers/systemd'),Path('/etc/systemd/system'),Path('/run/systemd/system')):
        if parent.exists() and any(p.name.startswith(plan['prefix']) for p in parent.iterdir()):
            raise Refusal('venue unit appeared during interrupted empty stage')
    for a in plan['accounts']:
        name=a['name']
        if name in retired_accounts:continue
        user=pwd.getpwnam(name);group=grp.getgrnam(name)
        if ((user.pw_uid,user.pw_gid,user.pw_dir,user.pw_shell)!=(a['uid'],a['uid'],a['home'],'/usr/sbin/nologin') or
                group.gr_gid!=a['uid'] or group.gr_mem or
                (Path('/var/lib/systemd/linger')/name).exists() or
                subprocess.run(['systemctl','is-active','--quiet','user@'+str(a['uid'])+'.service'],
                               capture_output=True,timeout=15,cwd='/').returncode==0):
            raise Refusal('partial stage account, group or manager changed')
        for filename in ('/etc/subuid','/etc/subgid'):
            if [line for line in Path(filename).read_text().splitlines() if line.startswith(name+':')] != [f"{name}:{a['subuid']}:65536"]:
                raise Refusal('partial stage subordinate identity changed')
    active_uids={str(a['uid']) for a in plan['accounts'] if a['name'] not in retired_accounts}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            lines=(proc/'status').read_text().splitlines()
            uids=next(line for line in lines if line.startswith('Uid:')).split()[1:]
        except (FileNotFoundError,PermissionError,StopIteration):continue
        if active_uids.intersection(uids):raise Refusal('interrupted test account has a live process')
    mountpoints=[]
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:lines=(proc/'mountinfo').read_text().splitlines()
        except (FileNotFoundError,PermissionError,ProcessLookupError):continue
        mountpoints.extend(line.split()[4].replace('\\040',' ') for line in lines if len(line.split())>=5)
    remaining=[name for name in created if name not in retired]
    for name in remaining:
        p=Path(name);info=p.lstat();row=state['pathIdentities'][name]
        children={Path(child).name for child in remaining if Path(child).parent==p}
        if (p.is_symlink() or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))!=
                (row['dev'],row['ino'],row['uid'],row['mode']) or
                {child.name for child in p.iterdir()}!=children or
                any(mp==name or mp.startswith(name.rstrip('/')+'/') for mp in mountpoints)):
            raise Refusal('interrupted stage directory altered, populated or mounted')
    state['status']='retiring-partial';write_ledger(path,state)
    for name in reversed(created):
        if name in retired:continue
        Path(name).rmdir();state.setdefault('retiredPaths',[]).append(name);write_ledger(path,state)
    for a in reversed(plan['accounts']):
        name=a['name']
        if name in retired_accounts:continue
        subprocess.run(['userdel',name],check=True,timeout=25,cwd='/')
        try:group=grp.getgrnam(name)
        except KeyError:group=None
        if group is not None:
            if group.gr_gid!=a['uid'] or group.gr_mem:raise Refusal('test group changed after user removal')
            subprocess.run(['groupdel',name],check=True,timeout=25,cwd='/')
        state.setdefault('retiredAccounts',[]).append(name);write_ledger(path,state)
    state['status']='retired-empty';write_ledger(path,state)
    return state

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','selector','protected-inventory','ledger'):ap.add_argument('--'+key,required=True)
    mode=ap.add_mutually_exclusive_group()
    mode.add_argument('--stage-empty',action='store_true')
    mode.add_argument('--retire-empty-stage',action='store_true')
    mode.add_argument('--retire-partial-stage',action='store_true')
    a=ap.parse_args()
    try:
        result=(retire_partial(a.bundle,a.selector,a.ledger) if a.retire_partial_stage else
                retire_empty(a.bundle,a.selector,a.ledger) if a.retire_empty_stage else
                stage(a.bundle,a.selector,a.protected_inventory,a.ledger,mutate=a.stage_empty))
        print(json.dumps({'schemaVersion':1,'status':result['status'],'accounts':len(result['plan']['accounts']),
                          'freshPaths':len(result['createPaths']),'activationAuthorized':False},sort_keys=True))
    except (Refusal,KeyError,TypeError,OSError,ValueError,subprocess.SubprocessError) as exc:
        raise SystemExit('venue empty-stage refused: '+str(exc)) from exc

if __name__=='__main__':main()
