"""SOURCE ONLY: two exact generated policy files, never root-executed in tests.

Native defaults require actual protected initial-root execution. No caller model,
context, boolean, callback or deletion path grants authority. Requires S1 exclusive
cooperative Root maintenance; POSIX does NOT supply an inode-CAS unlink or freeze.
"""
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import importlib.util
import json
import math
import grp
import pwd
import subprocess
import selectors
import time
import os
from pathlib import Path
import re
import stat
import sys

MAX_LEDGER=64*1024*1024
KEY='venueInertHostPolicyFence'
C17_SOURCE_SHA='ec4e8fb6e30d9d3ef8d32950c095cfaeafdacb322d131f2d75f837840f520602'

class Refused(Exception):
    """Only fixed reason tokens, never private paths/bodies/argv/errors."""

def require(value):
    if not value:raise Refused('protected-boundary-refused')

# The following three functions reuse the ec4 public reader's admission/stable
# read contract. This standalone file authenticates ITSELF, not an imported model.
def protected_tree(path):
    path=Path(path)
    require(path.is_absolute() and str(path)==os.path.realpath(path))
    for item in [path,*path.parents]:
        info=item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)

def protected_file(path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=_fd_stat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
                and not before.st_mode&0o022 and 0<before.st_size<=maximum)
        chunks=[];budget=maximum+1
        while budget:
            part=os.read(fd,min(65536,budget))
            if not part:break
            chunks.append(part);budget-=len(part)
        raw=b''.join(chunks);after=_fd_stat(fd)
        def stable(s):
            return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(stable(before)==stable(after) and len(raw)==before.st_size)
        return raw
    finally:os.close(fd)

def root_admission():
    require(os.geteuid()==0 and os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
    require(Path('/proc/self/uid_map').read_bytes().split()==[b'0',b'0',b'4294967295'])
    require(os.stat('/proc/self/ns/user').st_ino==os.stat('/proc/1/ns/user').st_ino)
    for namespace in ('pid','mnt'):
        require(os.stat('/proc/self/ns/'+namespace).st_ino==os.stat('/proc/1/ns/'+namespace).st_ino)
    path=Path(__file__)
    protected_tree(path.parent);protected_file(path,262144)

def strict_json(raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_LEDGER)
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result);result[key]=value
        return result
    def constant(value):raise Refused('nonfinite-ledger')
    def number(value):
        result=float(value);require(math.isfinite(result));return result
    try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=constant,parse_float=number)
    except (ValueError,UnicodeError,RecursionError):raise Refused('malformed-ledger') from None
    require(type(value) is dict)
    return value

def closed_code_tree(root):
    """Close protected transitive local tree BEFORE exec_module, not after load."""
    protected_tree(root)
    require(sys.dont_write_bytecode and sys.pycache_prefix is None)
    count=0;fingerprints={};deadline=time.monotonic()+5
    for directory,dirs,files in os.walk(root,followlinks=False):
        protected_tree(directory)
        for name in dirs:
            require(name!='__pycache__');protected_tree(Path(directory)/name)
        for name in files:
            count+=1;require(count<=2048 and time.monotonic()<deadline)
            file=Path(directory)/name
            require(file.suffix not in ('.pyc','.pyo') and not file.is_symlink())
            fingerprints[str(file.relative_to(root))]=hashlib.sha256(protected_file(file,1024*1024)).hexdigest()
    return hashlib.sha256(encode(fingerprints)).hexdigest()

# DATA bounds are separate from the deliberately unchanged executable-code bounds.
INPUT_MAX_ENTRIES=32768
INPUT_MAX_FILE=64*1024*1024
INPUT_MAX_TOTAL=512*1024*1024
INPUT_SECONDS=60

def protected_input_tree(root):
    """Stream every protected DATA file; close cache/symlink aliases before load.

    Empty files and large build artifacts are data, not executable-code admission.
    Same relative-path -> SHA dictionary and encode/hash wire as closed_code_tree.
    Snapshots are not Root-writer exclusion, inode-CAS or a kernel freeze.
    """
    root=Path(root);protected_tree(root)
    require(sys.dont_write_bytecode and sys.pycache_prefix is None)
    deadline=time.monotonic()+INPUT_SECONDS;count=0;total=0;fingerprints={}
    pending=[(root,None)];directories=[];leaves=[]
    def timely():require(time.monotonic()<deadline)
    while pending:
        timely();directory,expected=pending.pop();protected_tree(directory)
        fd=_directory_fd(directory)
        try:
            before=file_identity(_fd_stat(fd))
            require(stat.S_ISDIR(before['mode']) and before['uid']==0 and not before['mode']&0o022
                    and file_identity(_path_stat(directory))==before
                    and (expected is None or expected==before))
            names=set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    timely();count+=1;require(count<=INPUT_MAX_ENTRIES)
                    name=entry.name;require(name not in names);names.add(name);child=directory/name
                    require(name!='__pycache__' and child.suffix not in ('.pyc','.pyo'))
                    identity=file_identity(_entry_stat(fd,name))
                    require(not stat.S_ISLNK(identity['mode']))
                    if stat.S_ISDIR(identity['mode']):
                        require(identity['uid']==0 and not identity['mode']&0o022)
                        pending.append((child,identity));continue
                    require(stat.S_ISREG(identity['mode']) and identity['uid']==0
                            and not identity['mode']&0o022 and identity['nlink']==1
                            and 0<=identity['size']<=INPUT_MAX_FILE
                            and total+identity['size']<=INPUT_MAX_TOTAL)
                    leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
                    try:
                        observed=file_identity(_fd_stat(leaf))
                        require(observed==identity and stat.S_ISREG(observed['mode'])
                                and observed['uid']==0 and not observed['mode']&0o022
                                and observed['nlink']==1 and 0<=observed['size']<=INPUT_MAX_FILE)
                        total+=observed['size'];require(total<=INPUT_MAX_TOTAL)
                        hashed=hashlib.sha256();size=0;remaining=observed['size']+1
                        while remaining:
                            timely();chunk=os.read(leaf,min(65536,remaining))
                            if not chunk:break
                            size+=len(chunk);remaining-=len(chunk);hashed.update(chunk)
                        require(size==observed['size'] and file_identity(_fd_stat(leaf))==observed
                                and file_identity(_entry_stat(fd,name))==observed)
                        fingerprints[str(child.relative_to(root))]=hashed.hexdigest()
                        leaves.append((child,observed))
                    finally:os.close(leaf)
            require(file_identity(_fd_stat(fd))==before and file_identity(_path_stat(directory))==before)
            directories.append((directory,before,names))
        finally:os.close(fd)
    # Detect named/parent changes after their individual streaming snapshots too.
    for directory,identity,names in directories:
        timely();protected_tree(directory);fd=_directory_fd(directory)
        try:
            require(file_identity(_fd_stat(fd))==identity and file_identity(_path_stat(directory))==identity)
            seen=set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    timely();require(entry.name in names and entry.name not in seen);seen.add(entry.name)
            require(seen==names and file_identity(_fd_stat(fd))==identity
                    and file_identity(_path_stat(directory))==identity)
        finally:os.close(fd)
    for leaf,identity in leaves:
        timely();require(file_identity(_path_stat(leaf))==identity)
    timely();result=hashlib.sha256(encode(fingerprints)).hexdigest();timely();return result

def load_closed(path,name):
    # Callers must close the complete directory tree, including external context,
    # BEFORE reaching this private loader; no public module/context injection seam.
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

PUBLIC_CODE_AUTHORITY_SHA='8bf87a9c7456e3f860540243bfefe937762aae9aabfb325b16f8e65092c0d128'
PUBLIC_TARGET_OPS_SHA='e0553c7d789c61e12949d8f239f42ddad17b487c9ba39185e58badd867cb4a2f'
TARGET_COMMIT='b7bd52768235619b5fd1b8496e9143fe957c45e7'
GENERATED_OPS=frozenset(('materialize-workspaces.py','migrate-domain-authorities.py',
 'platform-zero-worklane-idle-reaper.service','platform-zero-worklane-idle-reaper.timer',
 'platform-zero-worklanes.service','platform-zero.nft','provision-domain-accounts.sh',
 'reap-idle-worklanes.py','retire-legacy-webservices-account.sh','start-worklane-containers.py'))
ARTIFACT_FIELDS=frozenset(('source-provenance.json','podman-domains.json','stack.ir.json',
 'site/agent-vm.json','site/global.settings/registry-image-ids.json'))
CONTROLLER={'commit':'2e0f9c8a73ecfafb1bcbc2fdea4718d25cf14e29','file':'p0_host_context.py',
 'sha256':'36323e5b1afd6106da677b028aa47d4c4b4f0552437b8f8e91d8b2f92eb9927d'}

def _flat_members(directory,maximum):
    protected_tree(directory);deadline=time.monotonic()+5;names=set()
    with os.scandir(directory) as entries:
        for entry in entries:
            require(time.monotonic()<deadline and len(names)<maximum and entry.name not in names)
            names.add(entry.name)
    return names

def _slot_members(slot):
    # Same complete relative-file map/hash wire as CODE closure, not root-only names.
    files={};deadline=time.monotonic()+5
    for directory,dirs,names in os.walk(slot,followlinks=False):
        protected_tree(directory)
        for name in dirs:require(name!='__pycache__');protected_tree(Path(directory)/name)
        for name in names:
            require(time.monotonic()<deadline and len(files)<2048 and not name.endswith(('.pyc','.pyo')))
            member=Path(directory)/name
            files[str(member.relative_to(slot))]=sha(protected_file(member,1024*1024))
    return files

def _policy_inputs(bundle,selector):
    """Private configured default: immutable CODE and original TARGET DATA differ.

    Same C39 schema. Root-owned private configuration is not caller authority.
    No invented interpretation of historical receipt bytes; no target imports.
    """
    root=Path(__file__).parent;protected_tree(root)
    lock=root/'SOURCE-LOCK.json'
    require(stat.S_IMODE(_path_stat(lock).st_mode)==0o600)
    pins=strict_json(protected_file(lock,262144))
    require(set(pins)=={'schemaVersion','codeRoot','codeAuthority','targetAuthority','controller',
                       'ec4','policyFenceSha256','nativeLeaseSha256'}
            and type(pins['schemaVersion']) is int and pins['schemaVersion']==2 and pins['codeRoot']=='.')
    code=pins['codeAuthority'];target=pins['targetAuthority']
    require(type(code) is dict and set(code)=={'generatorCommit','ops'}
            and sha(canonical(code))==PUBLIC_CODE_AUTHORITY_SHA
            and type(target) is dict and set(target)=={'artifactFields','generatedNames','generatorCommit','inputConfiguration','namespace','ops'}
            and type(target['ops']) is dict and len(target['ops'])==57
            and sha(canonical(target['ops']))==PUBLIC_TARGET_OPS_SHA and target['generatorCommit']==TARGET_COMMIT)
    require(type(target['artifactFields']) is list and len(target['artifactFields'])==5 and set(target['artifactFields'])==ARTIFACT_FIELDS
            and type(target['generatedNames']) is list and len(target['generatedNames'])==10 and set(target['generatedNames'])==GENERATED_OPS
            and type(target['namespace']) is str and re.fullmatch(r'p0test-[a-z0-9-]{1,24}',target['namespace'])
            and canonical(pins['controller'])==canonical(CONTROLLER) and pins['ec4']==C17_SOURCE_SHA)
    names=set(code['ops'])|{'policy_fence.py','inert_control_lease_native.py','retire-failed-venue-registry-image.py','SOURCE-LOCK.json'}
    require(len(code['ops'])==57 and len(names)==61 and _flat_members(root,61)==names)
    closed_code_tree(root) # Complete transitive flat CODE, including registry, BEFORE ANY load.
    flat={n:sha(protected_file(root/n,1024*1024)) for n in sorted(names)}
    require(all(flat[n]==v for n,v in code['ops'].items()) and flat['policy_fence.py']==pins['policyFenceSha256']
            and flat['inert_control_lease_native.py']==pins['nativeLeaseSha256']
            and flat['retire-failed-venue-registry-image.py']==pins['ec4'])
    cfg=target['inputConfiguration']
    require(type(cfg) is dict and set(cfg)=={'schemaVersion','bundlePath','selectorPath','ledgerPath','provenanceSha256',
            'planSha256','initialReviewedLedgerSha256','historicalArtifactReceiptPath','historicalArtifactReceiptSha256','ops'}
            and type(cfg['schemaVersion']) is int and cfg['schemaVersion']==1)
    for key in ('bundlePath','selectorPath','ledgerPath','historicalArtifactReceiptPath'):
        value=cfg[key];require(type(value) is str and Path(value).is_absolute() and os.path.normpath(value)==value
                               and '..' not in Path(value).parts and '\x00' not in value)
    require(cfg['bundlePath']==str(bundle) and cfg['selectorPath']==str(selector))
    for key in ('provenanceSha256','planSha256','initialReviewedLedgerSha256','historicalArtifactReceiptSha256'):
        require(type(cfg[key]) is str and re.fullmatch('[0-9a-f]{64}',cfg[key]))
    require(type(cfg['ops']) is dict and set(cfg['ops'])==set(target['ops'])|GENERATED_OPS and len(cfg['ops'])==67)
    for name,row in cfg['ops'].items():
        require(type(row) is dict and set(row)=={'sha256','mode'} and type(row['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}',row['sha256']) and type(row['mode']) is int
                and 0<=row['mode']<=0o777 and not row['mode']&0o022)
    require(all(cfg['ops'][n]['sha256']==v for n,v in target['ops'].items()))
    receipt=Path(cfg['historicalArtifactReceiptPath']);protected_tree(receipt.parent)
    require(stat.S_IMODE(_path_stat(receipt).st_mode)==0o600
            and sha(protected_file(receipt,MAX_LEDGER))==cfg['historicalArtifactReceiptSha256'])
    original=bundle/'ops';require(_flat_members(original,67)==set(cfg['ops']))
    ops_sha=protected_input_tree(original)
    require(ops_sha==sha(encode({n:v['sha256'] for n,v in cfg['ops'].items()})))
    for name,row in cfg['ops'].items():require(stat.S_IMODE(_path_stat(original/name).st_mode)==row['mode'])
    for member in ARTIFACT_FIELDS:
        protected_tree((bundle/member).parent);protected_file(bundle/member,MAX_LEDGER)
    provenance=protected_file(bundle/'source-provenance.json',262144);doc=strict_json(provenance)
    require(sha(provenance)==cfg['provenanceSha256'] and doc.get('generatorCommit')==TARGET_COMMIT
            and doc.get('generatorDirty') is False and doc.get('siteDirty') is False)
    return {'root':str(root),'pins':pins,'opsSha256':ops_sha,'flat61Sha256':sha(canonical(flat)),
            'code59Sha256':sha(canonical({n:h for n,h in flat.items() if n not in ('SOURCE-LOCK.json','inert_control_lease_native.py')}))}

def actual_context(bundle,selector):
    inputs=_policy_inputs(bundle,selector);ops=Path(inputs['root']);ops_sha=inputs['opsSha256']
    cfg=inputs['pins']['targetAuthority']['inputConfiguration']
    for file in ('podman-domains.json','stack.ir.json','source-provenance.json','site/agent-vm.json'):
        protected_tree((bundle/file).parent);protected_file(bundle/file,MAX_LEDGER)
    quadlet_sha=closed_code_tree(bundle/'quadlet')
    site_sha=closed_code_tree(bundle/'site');build_sha=protected_input_tree(bundle/'build')
    stage=load_closed(ops/'venue-owned-stage.py','policy_fence_stage')
    plan=stage.owned_plan(bundle,selector)
    require(sha(canonical(plan))==cfg['planSha256'] and plan.get('sourceCommit')==TARGET_COMMIT)
    ns=plan.get('prefix');require(type(ns) is str and re.fullmatch(r'p0test-[a-z0-9-]{1,24}',ns)
                               and ns==inputs['pins']['targetAuthority']['namespace'])
    base=Path('/usr/local/libexec')/(ns+'-control');protected_tree(base)
    pointer=base/'agent-services-current-host';info=pointer.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid==0)
    slot=pointer.resolve(strict=True)
    require(slot.parent==base/'agent-service-releases')
    # lifecycle.host_context imports installed code: MUST close that external
    # tree first, including all sibling .py files and cache rejection.
    slot_sha=closed_code_tree(slot)
    slot_manifest=strict_json(protected_file(slot/'manifest.json',1024*1024))
    require(type(slot_manifest.get('files')) is dict)
    for member,expected in slot_manifest['files'].items():
        require(type(member) is str and not Path(member).is_absolute() and '..' not in Path(member).parts
                and type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected))
        protected_tree((slot/member).parent)
        require(sha(protected_file(slot/member,1024*1024))==expected)
    slot_files=_slot_members(slot)
    require(set(slot_manifest['files'])|{'manifest.json'}==set(slot_files)
            and sha(encode(slot_files))==slot_sha
            and slot_files.get('p0_host_context.py')==CONTROLLER['sha256'])
    lifecycle=load_closed(ops/'venue-start-quarantine.py','policy_fence_lifecycle')
    context=lifecycle.host_context(bundle,plan)
    require(context.namespace==ns and context.source==base and context.runtime==Path('/run')/(ns+'-control')
            and pointer.resolve(strict=True)==slot)
    require(context.data['controlCommit']==CONTROLLER['commit']
            and context.data['sourceProvenanceSha256']==cfg['provenanceSha256']
            and context.data['siteVmSpecSha256']==sha(protected_file(bundle/'site/agent-vm.json',MAX_LEDGER)))
    units=load_closed(ops/'venue-unit-stage.py','policy_fence_units')
    unit_manifest=units.manifest(bundle,plan)
    require(type(unit_manifest) is dict and len(unit_manifest)==190)
    # safe_parents is the owning public stage's actual planned creation algorithm.
    created=stage.safe_parents(list(plan['roots'].values())+[str(Path(n).parent) for n in plan['configs']])
    authority=load_closed(ops/'venue-image-authority.py','policy_fence_image_authority').authority(bundle,selector)
    return plan,context,unit_manifest,created,{'ops':ops_sha,'slot':slot_sha,'quadlet':quadlet_sha,
        'site':site_sha,'build':build_sha,'imageIds':authority['imageIds'],
        'frozenRegistrySha256':authority['frozenRegistrySha256'],
        'provenanceSha256':sha(protected_file(bundle/'source-provenance.json',262144)),
        'slotPath':str(slot),'manifest':slot_manifest}

@contextmanager
def existing_lease(context):
    directory=Directory(context.runtime);lease=None
    try:
        require(stat.S_IMODE(_fd_stat(directory.fd).st_mode)==0o700)
        lease=os.open('lifecycle.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory.fd)
        value=_fd_stat(lease);identity=file_identity(value)
        require(stat.S_ISREG(value.st_mode) and value.st_uid==value.st_gid==0 and value.st_nlink==1
                and stat.S_IMODE(value.st_mode)==0o600 and value.st_size==0 and value.st_dev==_fd_stat(directory.fd).st_dev)
        fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        def check():
            directory.check();require(set(os.listdir(directory.fd))=={'lifecycle.lock'})
            require(file_identity(_fd_stat(lease))==identity
                    and file_identity(_entry_stat(directory.fd,'lifecycle.lock'))==identity)
        check.identity={'directory':directory.identity,'file':identity}
        check();yield check
    finally:
        if lease is not None:os.close(lease)
        directory.close()

def policy_spec(context):
    # PRIVATE helper used ONLY after actual_context in the public callable.
    ns=context.namespace
    require(type(ns) is str and re.fullmatch(r'p0test-[a-z0-9-]{1,24}',ns))
    require(context.source==Path('/usr/local/libexec')/(ns+'-control') and context.runtime==Path('/run')/(ns+'-control'))
    return ((Path('/etc/sudoers.d')/(ns+'-agent-identity'),0o440,
             (ns+'-provisioner ALL=(root) NOPASSWD: '+str(context.source/'agent-identity-host.py')+' *\n').encode()),
            (Path('/etc/tmpfiles.d')/(ns+'-control.conf'),0o644,
             ('d '+str(context.runtime)+' 0700 root root -\n').encode()))

def retirement_shape(state,plan,context):
    """Necessary strict schema; native_observations additionally proves host facts."""
    require(type(state.get('venueInstallerVersion')) is int and state['venueInstallerVersion']==1)
    require(state.get('status')=='retired-empty' and state.get('venueInstallerPhase')=='retired-inert'
            and state.get('activationAuthorized') is False and canonical(state.get('plan'))==canonical(plan))
    require(not any(k.startswith(('venueStart','venueRuntimeAuthority')) for k in state))
    for key in state:
        if 'pending' not in key.lower():continue
        require(key=='venueRegistryFailedPendingRetirement')
        history=state[key]
        require(type(history) is dict and set(history)=={'schemaVersion','pending','selectedImageId','retiredImageId',
            'verifiedSha256','sourceProvenanceSha256','operationSourceSha256','phase','ledgerSha256Before'})
        require(type(history['schemaVersion']) is int and history['schemaVersion']==1
                and history['phase']=='retired-drifted-pending' and type(history['pending']) is str
                and 0<len(history['pending'])<=2048 and history['pending'].count('|')==1)
        for field in ('selectedImageId','retiredImageId'):
            require(type(history[field]) is str and re.fullmatch('sha256:[0-9a-f]{64}',history[field]))
        require(history['selectedImageId']!=history['retiredImageId'])
        for field in ('verifiedSha256','sourceProvenanceSha256','operationSourceSha256','ledgerSha256Before'):
            require(type(history[field]) is str and re.fullmatch('[0-9a-f]{64}',history[field]))
    accounts=plan.get('accounts');require(type(accounts) is list and len(accounts)==7)
    names=[a['name'] for a in accounts];require(len(set(names))==7)
    require(state.get('graphCleared')==['root']+names and type(state.get('managerStopped')) is list
            and len(state['managerStopped'])==7 and set(state['managerStopped'])==set(names))
    for field in ('venueCompositeMode','venueRuntimeEnvPhase','venueDomainRuntimePhase','venueReleasePhase','venueRegistryPhase','venueBuildBasePhase'):
        require(state.get(field)=='retired-inert')
    installed=state.get('installedUnits');retired=state.get('retiredUnits')
    require(type(installed) is list and len(installed)==190 and type(retired) is list and len(retired)==190)
    require(all(type(r) is dict and set(r)=={'dev','ino','path'} and type(r['dev']) is int and r['dev']>=0
                and type(r['ino']) is int and r['ino']>0 and type(r['path']) is str for r in installed))
    require(len({r['path'] for r in installed})==190 and all(type(p) is str for p in retired)
            and len(set(retired))==190 and {r['path'] for r in installed}==set(retired))
    host=state.get('venueHostUnitsRetirement')
    require(type(host) is dict and host.get('phase')=='retired' and host.get('contextSha256')==context.digest
            and type(host.get('neverStartedInstallerVersion')) is int and host['neverStartedInstallerVersion']==1)
    expected={str(Path('/etc/systemd/system')/context.unit(n)) for n in
              ('p0-identity-reconcile.service','p0-identity-reconcile.timer','p0-web.service')}
    require(type(host.get('units')) is list and {r['path'] for r in host['units']}==expected
            and len(host['units'])==3 and type(host.get('removed')) is list and len(host['removed'])==3
            and set(host['removed'])==expected)

def encode(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def sha(value):return hashlib.sha256(value).hexdigest()
def _directory_fd(path):return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
def _fd_stat(fd):return os.fstat(fd)
def _path_stat(path):return Path(path).lstat()
def _entry_stat(fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)
def file_identity(s):
    return {k:getattr(s,'st_'+k) for k in ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')}

def _absent(path):
    try:_path_stat(path)
    except FileNotFoundError:return True
    return False

class Directory:
    def __init__(self,path):
        self.path=Path(path);protected_tree(self.path)
        self.fd=_directory_fd(self.path)
        try:
            s=_fd_stat(self.fd)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022)
            self.identity={k:v for k,v in file_identity(s).items() if k in ('dev','ino','mode','uid','gid','nlink')}
            self.check()
        except BaseException:os.close(self.fd);raise
    def check(self):
        protected_tree(self.path)
        for s in (_fd_stat(self.fd),_path_stat(self.path)):
            require(all(file_identity(s)[k]==v for k,v in self.identity.items()))
    def close(self):os.close(self.fd)
    def entry(self,name):
        self.check()
        try:return file_identity(_entry_stat(self.fd,name))
        except FileNotFoundError:return None
    def read(self,name,maximum,mode=None):
        self.check();fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=self.fd)
        try:
            s=_fd_stat(fd);ident=file_identity(s)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
                    and (stat.S_IMODE(s.st_mode)==mode if mode is not None else not s.st_mode&0o022)
                    and 0<s.st_size<=maximum)
            chunks=[];remaining=maximum+1
            while remaining:
                chunk=os.read(fd,min(remaining,65536))
                if not chunk:break
                chunks.append(chunk);remaining-=len(chunk)
            raw=b''.join(chunks)
            require(len(raw)==s.st_size and file_identity(_fd_stat(fd))==ident and self.entry(name)==ident)
            return raw,ident
        finally:os.close(fd)

class HeldPolicy:
    """Original policy FD, retained through own unlink/fsync and final checks.

    This lifetime is NOT an inode-CAS or a fence against arbitrary Root writers.
    Journal/other transient Directory.read callers keep their existing semantics.
    """
    def __init__(self,parent,name,maximum,mode):
        self.parent=parent;self.name=name;self.maximum=maximum;self.fd=None;self.unlinked_identity=None
        try:
            parent.check()
            self.fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent.fd)
            s=_fd_stat(self.fd);self.identity=file_identity(s)
            require(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<=maximum)
            self.raw=self._body()
            require(len(self.raw)==s.st_size)
            self.check()
        except BaseException:
            self.close();raise
    def _body(self):
        os.lseek(self.fd,0,os.SEEK_SET);chunks=[];remaining=self.maximum+1
        while remaining:
            chunk=os.read(self.fd,min(remaining,65536))
            if not chunk:break
            chunks.append(chunk);remaining-=len(chunk)
        raw=b''.join(chunks);require(len(raw)<=self.maximum);return raw
    def check(self):
        self.parent.check()
        expected=self.identity if self.unlinked_identity is None else self.unlinked_identity
        require(file_identity(_fd_stat(self.fd))==expected and self._body()==self.raw
                and file_identity(_fd_stat(self.fd))==expected)
        require(self.parent.entry(self.name)==(self.identity if self.unlinked_identity is None else None))
        return self.raw,self.identity
    def own_unlinked(self):
        # Only after THIS invocation's successful unlink. nlink and ctime are
        # deliberate kernel effects; every other saved field and bytes stay fixed.
        require(self.unlinked_identity is None and self.parent.entry(self.name) is None)
        now=file_identity(_fd_stat(self.fd))
        require(now['nlink']==0 and type(now['ctime_ns']) is int
                and now['ctime_ns']>=self.identity['ctime_ns']
                and all(now[k]==v for k,v in self.identity.items() if k not in ('nlink','ctime_ns')))
        self.unlinked_identity=now;self.check()
    def close(self):
        if self.fd is not None:
            fd=self.fd;self.fd=None;os.close(fd)

class Journal:
    def __init__(self,path):
        self.path=Path(path);self.parent=Directory(self.path.parent);self.name=self.path.name
    def read(self):return self.parent.read(self.name,MAX_LEDGER,0o600)
    def check(self,epoch):
        raw,identity=self.read();require(sha(raw)==epoch);return raw,identity
    def write(self,epoch,state):
        before,old_identity=self.check(epoch);intended=encode(state)
        require(0<len(intended)<=MAX_LEDGER)
        name='.policy-fence-'+os.urandom(16).hex()+'.tmp';fd=None;identity=None
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.parent.fd)
            identity=file_identity(_fd_stat(fd));view=memoryview(intended)
            require(identity['uid']==identity['gid']==0 and identity['nlink']==1 and stat.S_IMODE(identity['mode'])==0o600)
            while view:
                count=os.write(fd,view);require(0<count<=len(view));view=view[count:]
            os.fsync(fd)
            require(self.check(epoch)==(before,old_identity));self.parent.check()
            os.replace(name,self.name,src_dir_fd=self.parent.fd,dst_dir_fd=self.parent.fd)
            os.fsync(self.parent.fd)
            epoch=sha(intended);require(self.check(epoch)[0]==intended)
            return epoch
        finally:
            if fd is not None:os.close(fd)
            # Only our exclusively created temporary inode, NEVER a foreign name.
            if identity is not None:
                now=self.parent.entry(name)
                if now is not None and (now['dev'],now['ino'])==(identity['dev'],identity['ino']):
                    os.unlink(name,dir_fd=self.parent.fd);os.fsync(self.parent.fd)
    def close(self):self.parent.close()

class HeldOperation:
    def __init__(self):
        self.parent=Directory(Path(__file__).parent);self.name=Path(__file__).name;self.fd=None
        try:
            self.raw,self.identity=self.parent.read(self.name,262144)
            self.fd=os.open(self.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent.fd)
            require(file_identity(_fd_stat(self.fd))==self.identity)
        except BaseException:self.close();raise
    def check(self):
        require(file_identity(_fd_stat(self.fd))==self.identity
                and self.parent.read(self.name,262144)==(self.raw,self.identity))
    def close(self):
        if self.fd is not None:os.close(self.fd)
        self.parent.close()

def _accounts_absent(accounts):
    for account in accounts:
        name,uid=account['name'],account['uid']
        require(type(name) is str and type(uid) is int and uid>0)
        for lookup,key in ((pwd.getpwnam,name),(pwd.getpwuid,uid),(grp.getgrnam,name),(grp.getgrgid,uid)):
            try:lookup(key)
            except KeyError:continue
            raise Refused('account-or-uid-reused')

def _systemctl(args):
    child=subprocess.Popen(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},close_fds=True,shell=False)
    try:
        deadline=time.monotonic()+2;chunks=[];size=0
        os.set_blocking(child.stdout.fileno(),False)
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic();require(remaining>0)
                require(ready.select(remaining))
                chunk=os.read(child.stdout.fileno(),min(65536,262145-size))
                if not chunk:break
                size+=len(chunk);require(size<=262144);chunks.append(chunk)
        return child.wait(timeout=max(0.001,deadline-time.monotonic())),b''.join(chunks).decode('utf-8','strict')
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=2) # ONLY our read-only client, no host service action
        child.stdout.close()

def _unit_inactive(name,*,missing=False):
    fields=('LoadState','ActiveState','SubState','FragmentPath','DropInPaths')
    code,text=_systemctl(['show',name,'--no-pager','--property='+','.join(fields)])
    require(code in (0,1,4));pairs=[line.split('=',1) for line in text.splitlines()]
    require(all(len(x)==2 for x in pairs) and len(pairs)==len(fields) and len({x[0] for x in pairs})==len(fields))
    row=dict(pairs);require(set(row)==set(fields) and row['ActiveState'] in ('inactive','failed')
        and row['SubState'] in ('dead','failed') and row['DropInPaths']=='')
    if missing:require(row['LoadState']=='not-found' and row['FragmentPath']=='')
    else:require(row['LoadState'] in ('loaded','not-found') and (code==0 or row['LoadState']=='not-found'))

TMPFILES=('systemd-tmpfiles-setup.service','systemd-tmpfiles-setup-dev.service','systemd-tmpfiles-setup-dev-early.service')
HOST_UNITS=('p0-identity-reconcile.service','p0-identity-reconcile.timer','p0-web.service')
def _tmpfiles_quiescent(name,search):
    """Writer quiescence, not readiness or a freeze of future Root processes."""
    require(name in TMPFILES)
    fields=('LoadState','ActiveState','SubState','FragmentPath','DropInPaths','Type',
            'RemainAfterExit','MainPID','ControlPID','Result','ExecMainStatus','ControlGroup')
    code,text=_systemctl(['show',name,'--no-pager','--property='+','.join(fields)])
    require(code in (0,1,4));pairs=[line.split('=',1) for line in text.splitlines()]
    require(all(len(x)==2 for x in pairs) and len(pairs)==len(fields)
            and len({x[0] for x in pairs})==len(fields))
    row=dict(pairs);require(set(row)==set(fields) and row['DropInPaths']==''
            and row['MainPID']=='0' and row['ControlPID']=='0')
    group='/system.slice/'+name
    require(row['ControlGroup'] in ('',group) and _absent(Path('/sys/fs/cgroup')/group.lstrip('/')))
    if row['LoadState']=='not-found':
        require(row['ActiveState']=='inactive' and row['SubState']=='dead' and row['FragmentPath']=='')
        for base in search:
            require(_absent(Path(base)/name) and _absent(Path(base)/(name+'.d')))
        return
    require(code==0 and row['LoadState']=='loaded')
    fragment=row['FragmentPath']
    require(Path(fragment).is_absolute() and os.path.normpath(fragment)==fragment
            and '..' not in Path(fragment).parts and Path(fragment).name==name
            and str(Path(fragment).parent) in search)
    inactive=row['ActiveState'] in ('inactive','failed') and row['SubState'] in ('dead','failed')
    exited=(row['ActiveState']=='active' and row['SubState']=='exited' and row['Type']=='oneshot'
            and row['RemainAfterExit']=='yes' and row['Result']=='success' and row['ExecMainStatus']=='0')
    require(inactive or exited)
    # _check_jobs rejects every queued TMPFILES job. native_observations also
    # invokes the unchanged private Root-process scanner after these queries.

def _check_jobs(plan,context):
    code,text=_systemctl(['show','--property=UnitPath','--value']);require(code==0)
    search=text.split();require(0<len(search)<=32 and len(set(search))==len(search))
    for base in search:
        require(Path(base).is_absolute() and os.path.normpath(base)==base and '..' not in Path(base).parts)
        for original in HOST_UNITS:
            name=context.unit(original)
            require(_absent(Path(base)/name) and _absent(Path(base)/(name+'.d')))
    forbidden={context.unit(n) for n in HOST_UNITS}|set(TMPFILES)|{'user@'+str(a['uid'])+'.service' for a in plan['accounts']}
    code,text=_systemctl(['list-jobs','--plain','--no-legend','--no-pager']);require(code==0)
    for line in text.splitlines():
        if not line.strip():continue
        parts=line.split();require(len(parts)>=4 and parts[0].isdigit())
        require(parts[1] not in forbidden and not parts[1].startswith(context.namespace))
    code,text=_systemctl(['list-units','--all','--plain','--no-legend','--no-pager',context.namespace+'*']);require(code==0)
    for line in text.splitlines():
        if not line.strip():continue
        parts=line.split();require(len(parts)>=4 and parts[0].startswith(context.namespace)
                                 and parts[2] in ('inactive','failed'))
    for name in (context.unit(n) for n in HOST_UNITS):_unit_inactive(name,missing=True)
    for name in TMPFILES:_tmpfiles_quiescent(name,search)
    for account in plan['accounts']:_unit_inactive('user@'+str(account['uid'])+'.service')

def _proc_ids():
    values=[]
    with os.scandir('/proc') as entries:
        for entry in entries:
            if entry.name.isdecimal():
                require(len(values)<65536);values.append(int(entry.name))
    return sorted(values)

def _proc_bytes(pid,name,limit):
    fd=os.open('/proc/'+str(pid)+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        raw=os.read(fd,limit+1);require(len(raw)<=limit);return raw
    finally:os.close(fd)

def _start_time(raw,pid):
    require(raw.startswith(str(pid).encode()+b' (') and b') ' in raw)
    fields=raw.rsplit(b') ',1)[1].split();require(len(fields)>=20 and fields[19].isdigit())
    return int(fields[19])

def _process_row(pid,context):
    try:
        before=_start_time(_proc_bytes(pid,'stat',4096),pid)
        rows=[line.split()[1:] for line in _proc_bytes(pid,'status',65536).splitlines() if line.startswith(b'Uid:')]
        require(len(rows)==1 and len(rows[0])==4 and all(x.isdigit() for x in rows[0]));uids=tuple(map(int,rows[0]))
        raw=_proc_bytes(pid,'cmdline',65536) if 0 in uids else b''
        require(not raw or raw.endswith(b'\0'));args=raw.split(b'\0')[:-1] if raw else []
        require(len(args)<=256 and all(len(arg)<=8192 for arg in args))
        source=str(context.source).encode()
        blocked=any(source in arg or str(context.runtime).encode() in arg or
                    (b'systemd-tmpfiles' in arg and b'--create' in arg) or arg.rsplit(b'/',1)[-1] in (b'agent-identity-host.py',b'systemd-tmpfiles') for arg in args)
        require(_start_time(_proc_bytes(pid,'stat',4096),pid)==before)
        return (pid,before,uids,sha(raw),blocked)
    except FileNotFoundError:
        # Positively gone may be recognized; a reused/still-present PID is NOT gone.
        try:_proc_bytes(pid,'stat',4096)
        except FileNotFoundError:return None
        raise Refused('process-identity-unstable') from None

def _check_processes(context,accounts=()):
    selected_uids={a['uid'] for a in accounts}
    deadline=time.monotonic()+2;previous=None
    for attempt in range(3):
        rows=[]
        for pid in _proc_ids():
            require(time.monotonic()<deadline)
            row=_process_row(pid,context)
            if row is not None:rows.append(row)
        snapshot=tuple(rows)
        if not any(row[-1] or any(uid in selected_uids for uid in row[2]) for row in snapshot) and snapshot==previous:return
        previous=snapshot
    raise Refused('root-processes-not-confirmed-idle')

def _completed_registry_history(state,plan,closure):
    record=state.get('venueRegistryFailedPendingRetirement')
    if record is None:return
    sources=closure['imageIds'];pending=record['pending'];verified=state.get('venueRegistryVerified')
    require(type(sources) is dict and sources and state.get('venueRegistryPlan')==sources
            and all(type(k) is str and type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for k,v in sources.items())
            and pending in sources and pending.count('|')==1)
    owner,ref=pending.split('|')
    require(owner in ['root']+[a['name'] for a in plan['accounts']]
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}',ref) and not ref.startswith('sha256:')
            and type(verified) is dict and pending not in verified
            and all(type(k) is str and type(v) is str and sources.get(k)==v for k,v in verified.items())
            and state.get('venueRegistryPreparationAbandoned') is True
            and state.get('venueRegistryFrozenSha256')==closure['frozenRegistrySha256']
            and record['selectedImageId']==sources[pending] and record['retiredImageId'] not in sources.values()
            and record['verifiedSha256']==sha(canonical(verified))
            and record['sourceProvenanceSha256']==closure['provenanceSha256']
            and record['operationSourceSha256']==C17_SOURCE_SHA)

def native_observations(state,plan,context,units,created,closure):
    retirement_shape(state,plan,context);_completed_registry_history(state,plan,closure)
    require(set(units)=={row['path'] for row in state['installedUnits']})
    require(type(created) is list and len(created)==len(set(created)) and created
            and state.get('createPaths')==created and state.get('createdPaths')==created
            and set(state.get('pathIdentities',{}))==set(created))
    for name,identity in state['pathIdentities'].items():
        require(type(identity) is dict and set(identity)=={'dev','ino','uid','mode'}
                and all(type(v) is int for v in identity.values()) and identity['dev']>=0 and identity['ino']>0
                and identity['uid']>=0 and identity['mode'] in (0o700,0o711))
    require(len({a['name'] for a in plan['accounts']})==len({a['uid'] for a in plan['accounts']})==7)
    _accounts_absent(plan['accounts'])
    for name in [*units,*created,*plan['configs']]:require(_absent(name))
    host=state['venueHostUnitsRetirement'];manifest=closure['manifest']
    for original in HOST_UNITS:
        path=str(Path('/etc/systemd/system')/context.unit(original))
        rows=[row for row in host['units'] if row['path']==path]
        require(len(rows)==1 and rows[0].get('sha256')==manifest['files']['units/'+original] and _absent(path))
    _check_jobs(plan,context);_check_processes(context,plan['accounts'])

PHASES=('intended','sudo-issued','sudo-done','tmpfiles-issued','tmpfiles-done','fenced')
def _fence(bundle,selector,ledger,reviewed_sha,provenance_sha):
    root_admission()
    require(all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in (reviewed_sha,provenance_sha)))
    bundle,selector,ledger=Path(bundle),Path(selector),Path(ledger)
    protected_tree(bundle);protected_tree(selector.parent)
    selector_raw=protected_file(selector,262144);provenance=protected_file(bundle/'source-provenance.json',262144)
    require(sha(provenance)==provenance_sha)
    operation=HeldOperation();journal=None;parents=[];held={};deadline=None
    try:
        journal=Journal(ledger);initial,_=journal.check(reviewed_sha);state=strict_json(initial)
        require(encode(state)==initial) # preserve existing canonical history bytes
        configured=_policy_inputs(bundle,selector);configured_bytes=canonical(configured)
        cfg=configured['pins']['targetAuthority']['inputConfiguration']
        prior=state.get(KEY)
        require(cfg['ledgerPath']==str(ledger) and cfg['initialReviewedLedgerSha256']==
                (prior.get('ledgerSha256Before') if type(prior) is dict else reviewed_sha))
        plan,context,units,created,closure=actual_context(bundle,selector)
        baseline={k:v for k,v in state.items() if k!=KEY};history=encode(baseline)
        binding={'schemaVersion':1,'namespace':context.namespace,'hostContextSha256':context.digest,
            'provenanceSha256':provenance_sha,'planSha256':sha(canonical(plan)),
            'operationSha256':sha(operation.raw),'sourceClosureSha256':sha(canonical(closure)),
            'ledgerPath':str(ledger),'ledgerParent':journal.parent.identity}
        epoch=reviewed_sha;deadline=time.monotonic()+90
        specs=policy_spec(context)
        for path,mode,body in specs:parents.append(Directory(path.parent))
        with existing_lease(context) as check_lease:
            binding['leaseIdentity']=check_lease.identity
            def check_held():
                for policy in held.values():policy.check()
            def check_budget():
                require(time.monotonic()<deadline)
            def fresh():
                check_budget();root_admission();operation.check();check_lease();check_held()
                journal.check(epoch)
                require(protected_file(selector,262144)==selector_raw
                        and protected_file(bundle/'source-provenance.json',262144)==provenance)
                require(canonical(_policy_inputs(bundle,selector))==configured_bytes)
                check_budget();now=actual_context(bundle,selector);check_budget()
                require(canonical(now[0])==canonical(plan) and now[1].namespace==context.namespace
                        and now[1].digest==context.digest and now[1].source==context.source
                        and now[1].runtime==context.runtime and canonical(now[2:])==canonical((units,created,closure)))
                require(encode({k:v for k,v in state.items() if k!=KEY})==history)
                check_budget();native_observations(state,plan,context,units,created,closure);check_budget()
                for parent in parents:parent.check()
                # Observations may take time: never let changes DURING the private
                # process/job scan evade late source/epoch/held-lease checks.
                operation.check();check_lease();check_budget()
                latest=actual_context(bundle,selector);check_budget()
                require(canonical(latest[0])==canonical(plan) and latest[1].digest==context.digest
                        and latest[1].namespace==context.namespace and latest[1].source==context.source
                        and latest[1].runtime==context.runtime and canonical(latest[2:])==canonical((units,created,closure)))
                require(protected_file(selector,262144)==selector_raw
                        and protected_file(bundle/'source-provenance.json',262144)==provenance)
                journal.check(epoch);check_held()
                require(canonical(_policy_inputs(bundle,selector))==configured_bytes);check_budget()
            def commit(phase):
                nonlocal epoch
                fresh();record['phase']=phase
                # Before hashes are an append-only chain of our exact CAS epochs.
                record['intendedEpochs'].append(epoch)
                check_budget();epoch=journal.write(epoch,state);check_budget()
            fresh();record=state.get(KEY)
            if record is None:
                policies=[]
                for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                    held[i]=HeldPolicy(parent,path.name,16384,mode)
                    raw,identity=held[i].check();require(raw==body)
                    policies.append({'path':str(path),'mode':mode,'bodySha256':sha(body),'parent':parent.identity,'file':identity})
                record={**binding,'phase':'intended','ledgerSha256Before':reviewed_sha,'policies':policies,'intendedEpochs':[]}
                state[KEY]=record;commit('intended')
            else:
                require(type(record) is dict and set(record)==set(binding)|{'phase','ledgerSha256Before','policies','intendedEpochs'}
                        and all(record[k]==v and type(record[k]) is type(v) for k,v in binding.items())
                        and canonical({k:record[k] for k in binding})==canonical(binding)
                        and record['phase'] in PHASES and type(record['ledgerSha256Before']) is str
                        and re.fullmatch('[0-9a-f]{64}',record['ledgerSha256Before'])
                        and type(record['intendedEpochs']) is list and 1<=len(record['intendedEpochs'])<=6
                        and all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in record['intendedEpochs'])
                        and record['intendedEpochs'][0]==record['ledgerSha256Before']
                        and len(record['intendedEpochs'])==PHASES.index(record['phase'])+1
                        and len(set(record['intendedEpochs']))==len(record['intendedEpochs'])
                        and type(record['policies']) is list and len(record['policies'])==2)
            # Validate the ENTIRE pair before the first deletion or any resumption.
            # Unowned missing/foreign tmpfiles may not be discovered only AFTER sudo.
            for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                saved=record['policies'][i]
                require(type(saved) is dict and set(saved)=={'path','mode','bodySha256','parent','file'}
                        and saved['path']==str(path) and type(saved['mode']) is int and saved['mode']==mode
                        and saved['bodySha256']==sha(body) and type(saved['parent']) is dict
                        and set(saved['parent'])==set(parent.identity)
                        and all(type(x) is int for x in saved['parent'].values()) and saved['parent']==parent.identity)
                identity=saved['file']
                require(type(identity) is dict and set(identity)=={'dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'}
                        and all(type(x) is int for x in identity.values()) and identity['dev']>=0 and identity['ino']>0
                        and identity['uid']==identity['gid']==0 and identity['nlink']==1
                        and identity['mode']==stat.S_IFREG|mode and identity['size']==len(body))
                issued='sudo-issued' if i==0 else 'tmpfiles-issued'
                done='sudo-done' if i==0 else 'tmpfiles-done'
                if record['phase']==issued or PHASES.index(record['phase'])>=PHASES.index(done):
                    require(parent.entry(path.name) is None)
                else:
                    if i not in held:held[i]=HeldPolicy(parent,path.name,16384,mode)
                    require(held[i].check()==(body,identity))
            for i,((path,mode,body),parent) in enumerate(zip(specs,parents)):
                saved=record['policies'][i]
                require(type(saved) is dict and set(saved)=={'path','mode','bodySha256','parent','file'}
                        and saved['path']==str(path) and type(saved['mode']) is int and saved['mode']==mode
                        and saved['bodySha256']==sha(body) and saved['parent']==parent.identity)
                identity=saved['file']
                require(type(identity) is dict and set(identity)=={'dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'}
                        and all(type(x) is int for x in identity.values()) and identity['dev']>=0 and identity['ino']>0
                        and identity['uid']==identity['gid']==0 and identity['nlink']==1
                        and identity['mode']==stat.S_IFREG|mode and identity['size']==len(body))
                issued='sudo-issued' if i==0 else 'tmpfiles-issued';done='sudo-done' if i==0 else 'tmpfiles-done'
                current=PHASES.index(record['phase'])
                if current>=PHASES.index(done):require(parent.entry(path.name) is None);continue
                if record['phase']==issued:
                    require(parent.entry(path.name) is None) # PRESENT even original => no second delete
                    fresh();os.fsync(parent.fd);check_budget();commit(done);continue
                require(record['phase']==('intended' if i==0 else 'sudo-done'))
                require(held[i].check()==(body,identity))
                commit(issued)
                # Issued durability precedes ALL destructive calls. Recheck late.
                fresh();require(held[i].check()==(body,identity))
                if i:require(parents[0].entry(specs[0][0].name) is None)
                parent.check();check_held();check_budget();os.unlink(path.name,dir_fd=parent.fd)
                held[i].own_unlinked();os.fsync(parent.fd);check_held();check_budget()
                require(parent.entry(path.name) is None);commit(done)
            fresh();require(all(parent.entry(path.name) is None for (path,_,_),parent in zip(specs,parents)))
            if record['phase']!='fenced':commit('fenced')
            fresh();require(all(parent.entry(path.name) is None for (path,_,_),parent in zip(specs,parents)));check_budget()
            return {'status':'fenced-two-generated-host-policies','policiesAbsent':2,'servicesStarted':False,
                    'nativeRecoveryAuthorized':False,'acceptedIntegratedInstalls':0}
    finally:
        # Attempt every close, including when an earlier cleanup itself fails.
        with ExitStack() as closing:
            closing.callback(operation.close)
            if journal is not None:closing.callback(journal.close)
            for parent in parents:closing.callback(parent.close)
            for policy in held.values():closing.callback(policy.close)
        # A pending success return must not escape after slow descriptor cleanup.
        # Early admission failures have not yet established the original epoch.
        if deadline is not None:require(time.monotonic()<deadline)

def fence_host_transport_policies(bundle,selector,ledger,reviewed_sha,provenance_sha):
    """Native defaults, no caller adapter/context/bool. Fixed refusal privacy."""
    try:return _fence(bundle,selector,ledger,reviewed_sha,provenance_sha)
    except BaseException:raise Refused('policy-fence-refused') from None
