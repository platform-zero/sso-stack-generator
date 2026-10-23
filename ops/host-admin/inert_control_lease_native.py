"""Native callable SOURCE, NOT selected/deployed or authorized by its unit tests.

Requires external exclusive/cooperative ROOT maintenance. No POSIX inode-CAS,
flock-only global writer fencing or kernel-wide fork-freeze is claimed.
Only existing lifecycle.lock and its exact empty runtime directory are removed.
"""
from contextlib import ExitStack
import copy
import fcntl
import grp
import hashlib
import importlib.util
import json
import math
import os as _os
from pathlib import PurePosixPath as P
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time

MAX=64*1024*1024
KEY='venueInertControlLeaseRetirement'
FENCE='venueInertHostPolicyFence'
HEX=re.compile(r'[0-9a-f]{64}')
_SELF=str(P(__file__).absolute()) if hasattr(P(__file__),'absolute') else str(__file__)
HOST_NAMES=('p0-identity-reconcile.service','p0-identity-reconcile.timer','p0-web.service')

class Refused(Exception):
    """Fixed public tokens only; never interpolate OS/private exceptions."""

def need(ok,reason='boundary'):
    if not ok:raise Refused(reason)
def digest(body):return hashlib.sha256(body).hexdigest()
def canonical(value):
    try:body=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (ValueError,TypeError,RecursionError):raise Refused('serialization') from None
    need(len(body)<=MAX,'serialization-bound');return body
def encoded(value):
    try:
        body=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    except (ValueError,TypeError,RecursionError):raise Refused('serialization') from None
    need(0<len(body)<=MAX,'ledger-size');return body

def decoded(body):
    need(type(body) is bytes and 0<len(body)<=MAX,'ledger-size')
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,'json-duplicate');out[k]=v
        return out
    def constant(_):raise Refused('json-nonfinite')
    def floating(s):
        v=float(s);need(math.isfinite(v),'json-nonfinite');return v
    try:value=json.loads(body,object_pairs_hook=pairs,parse_constant=constant,parse_float=floating)
    except (ValueError,UnicodeError,RecursionError,TypeError):raise Refused('json-malformed') from None
    need(type(value) is dict,'json-object');return value

def path(value):
    value=_os.fspath(value)
    need(type(value) is str and value.startswith('/') and value!='/' and '\x00' not in value
         and all(x not in ('','.','..') for x in value[1:].split('/')),'path')
    return P(value)

def ident(s,leaf=False):
    names=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')+ (('st_size',) if leaf else ())
    need(all(type(getattr(s,k,None)) is int for k in names),'observation-type')
    return {k[3:]:getattr(s,k) for k in names}

def stable(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def _read_fd(fd,maximum):
    chunks=[];budget=maximum+1
    while budget:
        part=_os.read(fd,min(budget,65536))
        if not part:break
        chunks.append(part);budget-=len(part)
    body=b''.join(chunks);need(len(body)<=maximum,'read-bound');return body

def _kernel(file,maximum=65536):
    fd=_os.open(str(file),_os.O_RDONLY|_os.O_NOFOLLOW|_os.O_CLOEXEC|_os.O_NONBLOCK)
    try:return _read_fd(fd,maximum)
    finally:_os.close(fd)

def protected_tree(value):
    p=path(value) if str(value)!='/' else P('/')
    for node in (p,*p.parents):
        s=_os.lstat(str(node));need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'protected-tree')

def _root_now():
    # Short circuit is essential: NO proc/private source access for unprivileged entry.
    need(_os.geteuid()==0 and _os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'root-admission')
    need(sys.pycache_prefix is None,'cache-prefix')
    need(_kernel('/proc/self/uid_map').split()==[b'0',b'0',b'4294967295'],'initial-userns')
    for namespace in ('user','pid','mnt'):
        a=_os.stat('/proc/self/ns/'+namespace);b=_os.stat('/proc/1/ns/'+namespace)
        need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'initial-namespace')

def root_admission():
    _root_now();protected_tree(P(_SELF).parent)
    with ExitStack() as stack:_file(_SELF,262144,stack)

class _Guard:
    def __init__(self,name,fd,meta,body=None):self.name=str(name);self.fd=fd;self.meta=meta;self.body=body
    def check(self):
        protected_tree(P(self.name).parent)
        a=_os.fstat(self.fd);b=_os.lstat(self.name)
        if self.body is None:
            need(ident(a)==ident(self.meta)==ident(b),'source-directory-race')
            if hasattr(self,'entries'):need(tuple(sorted(_os.listdir(self.fd)))==self.entries,'source-entries-race')
        else:
            need(stable(a)==stable(self.meta)==stable(b),'source-file-race')
            _os.lseek(self.fd,0,0);need(_read_fd(self.fd,len(self.body))==self.body,'source-bytes-race')


def _directory(name,stack,mode=None):
    protected_tree(name);fd=_os.open(str(name),_os.O_RDONLY|_os.O_DIRECTORY|_os.O_NOFOLLOW|_os.O_CLOEXEC)
    stack.callback(_os.close,fd);s=_os.fstat(fd)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'directory')
    if mode is not None:need(stat.S_IMODE(s.st_mode)==mode,'directory-mode')
    g=_Guard(name,fd,s);g.check();return g

def _file(name,maximum,stack,mode=None):
    protected_tree(P(name).parent)
    fd=_os.open(str(name),_os.O_RDONLY|_os.O_NOFOLLOW|_os.O_CLOEXEC|_os.O_NONBLOCK)
    stack.callback(_os.close,fd);a=_os.fstat(fd)
    need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and not a.st_mode&0o022 and 0<a.st_size<=maximum,'protected-file')
    if mode is not None:need(stat.S_IMODE(a.st_mode)==mode,'file-mode')
    body=_read_fd(fd,maximum);need(len(body)==a.st_size and stable(a)==stable(_os.fstat(fd)),'stable-read')
    g=_Guard(name,fd,a,body);g.check();return body,g

GENERATED_OPS=frozenset(('materialize-workspaces.py','migrate-domain-authorities.py',
 'platform-zero-worklane-idle-reaper.service','platform-zero-worklane-idle-reaper.timer',
 'platform-zero-worklanes.service','platform-zero.nft','provision-domain-accounts.sh',
 'reap-idle-worklanes.py','retire-legacy-webservices-account.sh','start-worklane-containers.py'))

DATA_ENTRIES=32768
DATA_FILES=32768
DATA_DIRECTORIES=32768
DATA_FILE_BYTES=64*1024*1024
DATA_TOTAL_BYTES=512*1024*1024
DATA_SECONDS=60

def _scan_data_observe(root):
    """Streaming DATA snapshot, not executable/import authority.

    Every file including empty/legacy node_modules data is hashed; no filtering.
    Directory and file descriptors are transient (bounded O(1)), never one per
    data member. Root writer exclusion is still an external prerequisite.
    """
    deadline=time.monotonic()+DATA_SECONDS;files={};metadata={};directories={};total=0;entries=0
    def budget():need(time.monotonic()<deadline,'data-timeout')
    def walk_error(error):raise Refused('data-walk') from None
    protected_tree(root)
    for directory,dirs,names in _os.walk(str(root),followlinks=False,onerror=walk_error):
        budget();entries+=len(dirs)+len(names)
        need(entries<=DATA_ENTRIES,'data-entry-bound')
        need(len(directories)<DATA_DIRECTORIES,'data-directory-bound')
        with ExitStack() as stack:
            g=_directory(directory,stack);g.entries=tuple(sorted(_os.listdir(g.fd)))
            need(tuple(sorted(dirs+names))==g.entries,'data-enumeration')
            directory_meta=stable(_os.fstat(g.fd))
            for n in dirs:
                need(n!='__pycache__','source-cache');protected_tree(P(directory)/n)
            for n in names:
                budget();need(not n.endswith(('.pyc','.pyo')),'source-cache')
                need(len(files)<DATA_FILES,'data-file-bound')
                fd=_os.open(n,_os.O_RDONLY|_os.O_NOFOLLOW|_os.O_CLOEXEC|_os.O_NONBLOCK,dir_fd=g.fd)
                try:
                    a=_os.fstat(fd)
                    need(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1
                        and not a.st_mode&0o022 and 0<=a.st_size<=DATA_FILE_BYTES,'protected-data-file')
                    need(total+a.st_size<=DATA_TOTAL_BYTES,'data-total-bound')
                    hasher=hashlib.sha256();size=0
                    while True:
                        budget();part=_os.read(fd,65536)
                        if not part:break
                        size+=len(part);need(size<=DATA_FILE_BYTES and total+size<=DATA_TOTAL_BYTES,'data-read-bound')
                        hasher.update(part)
                    named=_os.stat(n,dir_fd=g.fd,follow_symlinks=False)
                    need(size==a.st_size and stable(a)==stable(_os.fstat(fd))==stable(named),'data-file-race')
                    relative=str((P(directory)/n).relative_to(root));files[relative]=hasher.hexdigest();metadata[relative]=stable(a)
                    total+=size
                finally:_os.close(fd)
            g.check();need(stable(_os.fstat(g.fd))==directory_meta,'data-directory-race')
            directories[str(P(directory).relative_to(root))]=(directory_meta,g.entries)
    # Catch earlier members changing while later members were streamed.
    for relative,(saved,entries_before) in directories.items():
        budget();directory=root if relative=='.' else root/relative
        with ExitStack() as stack:
            g=_directory(directory,stack)
            need(stable(_os.fstat(g.fd))==saved==stable(_os.lstat(str(directory)))
                and tuple(sorted(_os.listdir(g.fd)))==entries_before,'data-final-directory-race')
    for relative,saved in metadata.items():
        budget();need(stable(_os.lstat(str(root/relative)))==saved,'data-final-file-race')
    budget();return files,metadata,directories

def _scan_data(root):
    try:return _scan_data_observe(root)
    except Refused:raise
    except Exception:raise Refused('data-observation') from None

class _DataGuard:
    def __init__(self,root,anchor,snapshot):self.root=root;self.anchor=anchor;self.snapshot=snapshot
    def check(self):
        self.anchor.check();current=_scan_data(self.root);self.anchor.check()
        need(current==self.snapshot,'data-closure-race')

def _data_tree(root,stack):
    # Hold one protected anchor, not thousands of data FDs or complete bodies.
    anchor=_directory(root,stack);anchor.entries=tuple(sorted(_os.listdir(anchor.fd)))
    snapshot=_scan_data(root);anchor.check()
    return snapshot[0],[_DataGuard(root,anchor,snapshot)]

def _tree(root,stack):
    """All files/dirs protected and held BEFORE imports; no cached code anywhere."""
    guards=[];files={}
    for directory,dirs,names in _os.walk(str(root),followlinks=False):
        directory_guard=_directory(directory,stack)
        directory_guard.entries=tuple(sorted(_os.listdir(directory_guard.fd)))
        guards.append(directory_guard)
        for n in dirs:need(n!='__pycache__','source-cache');protected_tree(P(directory)/n)
        for n in names:
            need(not n.endswith(('.pyc','.pyo')),'source-cache')
            p=P(directory)/n;body,g=_file(p,2*1024*1024,stack)
            guards.append(g);files[str(p.relative_to(root))]=digest(body)
            need(len(files)<=2048,'source-tree-bound')
    need(files,'source-tree-empty');return files,guards

def _load(file,name):
    spec=importlib.util.spec_from_file_location(name,str(file));need(spec is not None,'source-loader')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def _absent(value):
    try:_os.lstat(str(value))
    except FileNotFoundError:return True
    return False

def _command(argv):
    """Private bounded output, fixed env, no raw stderr/argv exposure."""
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},close_fds=True)
    chunks=[];size=0;deadline=time.monotonic()+5
    try:
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic();need(remaining>0,'systemd-timeout')
                ready=reader.select(remaining);need(ready,'systemd-timeout')
                part=_os.read(process.stdout.fileno(),4096)
                if not part:break
                size+=len(part);need(size<=65536,'systemd-bound');chunks.append(part)
        need(process.wait(timeout=max(0.01,deadline-time.monotonic()))==0,'systemd-query')
        return b''.join(chunks).decode('utf-8',errors='strict')
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=2)
        process.stdout.close()

def _fields(unit,properties):
    text=_command(['/usr/bin/systemctl','show',unit,'--no-pager','--property='+','.join(properties)])
    out={}
    for line in text.splitlines():
        need('=' in line,'systemd-shape');k,v=line.split('=',1);need(k in properties and k not in out,'systemd-shape');out[k]=v
    need(set(out)==set(properties),'systemd-shape');return out

TMPFILES=('systemd-tmpfiles-setup.service','systemd-tmpfiles-setup-dev.service','systemd-tmpfiles-setup-dev-early.service')

def _tmpfiles_quiescent():
    search=_command(['/usr/bin/systemctl','show','--property=UnitPath','--value']).split()
    need(0<len(search)<=32 and len(set(search))==len(search)
        and all(str(path(p))==p for p in search),'systemd-search-path')
    props=('LoadState','ActiveState','SubState','Type','RemainAfterExit','MainPID','ControlPID','Result','ExecMainStatus','ControlGroup','FragmentPath','DropInPaths')
    for unit in TMPFILES:
        f=_fields(unit,props)
        need(f['MainPID']==f['ControlPID']=='0' and f['DropInPaths']=='','tmpfiles-unit-active')
        if f['LoadState']=='not-found':
            need((f['ActiveState'],f['SubState'],f['FragmentPath'])==('inactive','dead',''),'tmpfiles-unit-active')
            need(all(_absent(P(base)/unit) and _absent(P(base)/(unit+'.d')) for base in search),'tmpfiles-unit-present')
        else:
            fragment=path(f['FragmentPath'])
            need(f['LoadState']=='loaded' and fragment.name==unit and str(fragment.parent) in search,'tmpfiles-fragment')
            inactive=f['ActiveState'] in ('inactive','failed') and f['SubState'] in ('dead','failed')
            exited=(f['ActiveState']=='active' and f['SubState']=='exited' and f['Type']=='oneshot'
                and f['RemainAfterExit']=='yes' and f['Result']=='success' and f['ExecMainStatus']=='0')
            need(inactive or exited,'tmpfiles-unit-active')
        group=f['ControlGroup']
        need(group in ('','/system.slice/'+unit),'tmpfiles-cgroup-shape')
        protected_tree('/sys/fs/cgroup')
        expected_group='/system.slice/'+unit
        cursor=P('/sys/fs/cgroup')
        for part in P(expected_group).parts[1:]:
            cursor=cursor/part
            if _absent(cursor):break
            need(cursor!=P('/sys/fs/cgroup')/expected_group.lstrip('/'),'tmpfiles-cgroup-present')
            protected_tree(cursor)
        else:raise Refused('tmpfiles-cgroup-present')

def _accounts_absent(accounts):
    for a in accounts:
        for fn,arg in ((pwd.getpwnam,a['name']),(pwd.getpwuid,a['uid']),(grp.getgrnam,a['name']),(grp.getgrgid,a['uid'])):
            try:fn(arg)
            except KeyError:continue
            raise Refused('account-or-group-present')

def _processes_quiescent(ns,retired_uids):
    """Private proc snapshot, PID/starttime identity, gone vs unknown fail closed.

    Snapshot is NOT a kernel fork freeze. Cooperative ROOT maintenance excludes
    new controllers/writers between these observations and filesystem actions.
    """
    pids={x for x in _os.listdir('/proc') if x.isdigit()};need(len(pids)<=8192,'process-bound')
    own=_os.getpid()
    for pid in sorted(pids,key=int):
        if int(pid)==own:continue
        base=P('/proc')/pid
        try:
            first=_kernel(base/'stat',16384);tail=first.rsplit(b') ',1)[1].split()
            need(len(tail)>=20 and tail[19].isdigit(),'process-shape')
            status=_kernel(base/'status',65536);argv=_kernel(base/'cmdline',65536)
            second=_kernel(base/'stat',16384).rsplit(b') ',1)[1].split()
        except FileNotFoundError:
            need(_absent(base),'process-unknown');continue
        need(len(second)>=20 and (tail[19],tail[0])==(second[19],second[0]),'process-reused')
        uid=[x for x in status.splitlines() if x.startswith(b'Uid:')]
        need(len(uid)==1,'process-shape');uids=uid[0].split()[1:]
        need(len(uids)==4 and all(x.isdigit() for x in uids),'process-shape')
        need(not {int(x) for x in uids}&set(retired_uids),'retired-uid-process')
        if b'0' not in uids:continue
        if not argv:
            need(tail[6].isdigit() and int(tail[6])&0x00200000,'process-unknown');continue
        words=argv.rstrip(b'\0').split(b'\0');need(all(words),'process-shape')
        executable=words[0].rsplit(b'/',1)[-1]
        need(not (executable.startswith(b'systemd-tmpfiles') and any(w==b'--create' or w.startswith(b'--create=') for w in words)),'tmpfiles-create-active')
        joined=b'\0'.join(words)
        controllers=(b'p0-host-broker',b'p0-host-operations',b'p0-hostctl',b'agent-identity-host',b'p0-identity-reconcile')
        known_operation=any(w.rsplit(b'/',1)[-1].startswith((b'venue-',b'p0-',b'agent-services')) for w in words)
        need(ns.encode() not in joined and not any(x in joined for x in controllers)
             and not known_operation,'root-controller-active')
        need(_kernel(base/'stat',16384).rsplit(b') ',1)[1].split()[19]==tail[19],'process-reused')
    need({x for x in _os.listdir('/proc') if x.isdigit()}==pids,'process-inventory-race')

def _terminal_history(state,provenance,images,owners,ec4_sha):
    for k in state:
        need(not k.startswith(('venueStart','venueRuntimeAuthority')),'start-authority-history')
        if 'pending' not in k.lower():continue
        need(k=='venueRegistryFailedPendingRetirement','pending-state')
        h=state[k];fields={'schemaVersion','pending','selectedImageId','retiredImageId','verifiedSha256',
            'sourceProvenanceSha256','operationSourceSha256','ledgerSha256Before','phase'}
        need(type(h) is dict and set(h)==fields and type(h['schemaVersion']) is int and h['schemaVersion']==1
            and h['phase']=='retired-drifted-pending' and state.get('venueRegistryPreparationAbandoned') is True,'pending-history')
        need(type(h['pending']) is str and '|' in h['pending'] and all(type(h[x]) is str and HEX.fullmatch(h[x])
            for x in ('verifiedSha256','sourceProvenanceSha256','operationSourceSha256','ledgerSha256Before')),'pending-history')
        need(h['sourceProvenanceSha256']==provenance and all(type(h[x]) is str and re.fullmatch('sha256:[0-9a-f]{64}',h[x])
            for x in ('selectedImageId','retiredImageId')) and h['selectedImageId']!=h['retiredImageId'],'pending-history')
        need(type(images) is dict and images and state.get('venueRegistryPlan')==images and
            all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v) for v in images.values()),'history-source-map')
        pending=h['pending'];need(pending.count('|')==1 and pending in images,'history-pending')
        owner,ref=pending.split('|');need(owner in owners and not ref.startswith('sha256:') and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}',ref),'history-pending')
        verified=state.get('venueRegistryVerified')
        need(type(verified) is dict and pending not in verified and all(type(k) is str and type(v) is str
            and images.get(k)==v for k,v in verified.items()),'history-verified')
        need(h['verifiedSha256']==digest(canonical(verified)) and h['selectedImageId']==images[pending]
            and h['retiredImageId'] not in images.values() and h['operationSourceSha256']==ec4_sha,'history-binding')

def _json_exact(left,right):
    """JSON-native recursive TYPE equality AND canonical-byte equality.

    Python True==1 / 1.0==1 is not wire equality. Reject non-string object
    keys and non-JSON containers too; json.dumps must never coerce their types.
    No mutation, normalization or conversion of either plan is performed.
    """
    pending=[(left,right)]
    while pending:
        a,b=pending.pop();kind=type(a)
        if kind is not type(b):return False
        if kind is dict:
            if not all(type(k) is str for k in a) or not all(type(k) is str for k in b) or a.keys()!=b.keys():return False
            pending.extend((a[k],b[k]) for k in a)
        elif kind is list:
            if len(a)!=len(b):return False
            pending.extend(zip(a,b))
        elif kind is float:
            if not math.isfinite(a) or not math.isfinite(b):return False
        elif kind not in (str,int,bool,type(None)):return False
    return canonical(left)==canonical(right)

def _shape(state,plan,context,provenance,plan_sha,policy_sha,manifest,closure_sha,images,ec4_sha):
    need(type(state) is dict and type(state.get('plan')) is dict and _json_exact(state['plan'],plan) and type(state.get('venueInstallerVersion')) is int
         and state['venueInstallerVersion']==1 and state.get('status')=='retired-empty'
         and state.get('venueInstallerPhase')=='retired-inert' and state.get('activationAuthorized') is False,'retirement')
    _terminal_history(state,provenance,images,['root']+[a['name'] for a in plan['accounts']],ec4_sha)
    need(all(state.get(k)=='retired-inert' for k in ('venueCompositeMode','venueRuntimeEnvPhase','venueDomainRuntimePhase',
        'venueReleasePhase','venueRegistryPhase','venueBuildBasePhase')),'retirement-phases')
    accounts=plan['accounts'];need(type(accounts) is list and len(accounts)==7,'accounts-schema')
    ns=plan['prefix'];names=[];uids=[]
    for a in accounts:
        need(type(a) is dict and type(a.get('name')) is str and re.fullmatch(re.escape(ns)+r'-[a-z0-9-]+',a['name'])
             and type(a.get('uid')) is int and a['uid']>0,'accounts-schema');names.append(a['name']);uids.append(a['uid'])
    need(len(set(names))==len(set(uids))==7,'accounts-schema')
    need(state.get('graphCleared')==['root']+names and type(state.get('managerStopped')) is list
         and len(state['managerStopped'])==7 and set(state['managerStopped'])==set(names),'graph-manager-scope')
    installed=state.get('installedUnits');retired=state.get('retiredUnits')
    need(type(installed) is list and len(installed)==190 and all(type(r) is dict and set(r)=={'path','dev','ino'}
        and type(r['path']) is str and type(r['dev']) is int and r['dev']>=0 and type(r['ino']) is int and r['ino']>0 for r in installed),'units-schema')
    need(type(retired) is list and all(type(p) is str for p in retired) and len(retired)==len(set(retired))==190
        and len({r['path'] for r in installed})==190 and {r['path'] for r in installed}==set(retired)==set(manifest),'units-scope')
    created=state.get('createdPaths');identities=state.get('pathIdentities')
    need(type(created) is list and created and all(type(p) is str for p in created)
        and len(created)==len(set(created)) and created==state.get('createPaths') and type(identities) is dict
        and set(identities)==set(created),'created-path-scope')
    allowed=set()
    for name in list(plan['roots'].values())+[str(P(p).parent) for p in plan['configs']]:
        p=path(name);allowed.add(str(p));allowed.update(str(x) for x in p.parents if str(x)!='/')
    need(set(created)<=allowed and set(plan['roots'].values())<=set(created),'created-path-source')
    for name in created:
        row=identities[name];need(type(row) is dict and set(row)=={'dev','ino','uid','mode'} and all(type(v) is int and v>=0 for v in row.values()) and row['ino']>0,'path-identity')
        need(not (str(context.runtime)==name or str(context.runtime).startswith(name+'/') or name.startswith(str(context.runtime)+'/')),'runtime-overlap')
    host=state.get('venueHostUnitsRetirement');expected={str(P('/etc/systemd/system')/context.unit(x)) for x in HOST_NAMES}
    need(type(host) is dict and host.get('phase')=='retired' and host.get('contextSha256')==context.digest
        and type(host.get('neverStartedInstallerVersion')) is int and host['neverStartedInstallerVersion']==1,'host-unit-retirement')
    need(type(host.get('units')) is list and len(host['units'])==3 and {r['path'] for r in host['units']}==expected
        and type(host.get('removed')) is list and len(host['removed'])==3 and set(host['removed'])==expected,'host-unit-scope')
    fence=state.get(FENCE)
    need(type(fence) is dict and fence.get('phase')=='fenced' and all(fence.get(k)==v for k,v in {
        'namespace':ns,'hostContextSha256':context.digest,'provenanceSha256':provenance,'planSha256':plan_sha,
        'operationSha256':policy_sha,'sourceClosureSha256':closure_sha}.items())
        and type(fence.get('schemaVersion')) is int and fence['schemaVersion']==1,'policy-fence-binding')
    required_host={'contextSha256','units','identities','removed','phase','neverStartedInstallerVersion'}
    need(set(host)==required_host and type(host['identities']) is dict and set(host['identities'])==expected,'host-unit-full-record')
    for original in HOST_NAMES:
        name=str(P('/etc/systemd/system')/context.unit(original))
        rows=[r for r in host['units'] if r['path']==name]
        need(len(rows)==1 and set(rows[0])=={'path','sha256'} and rows[0]['sha256']==context._lease_slot_manifest['files']['units/'+original], 'host-unit-source-hash')
        saved=host['identities'][name]
        need(type(saved) is dict and set(saved)=={'dev','ino'} and all(type(v) is int and v>=0 for v in saved.values()) and saved['ino']>0,'host-unit-original-identity')
    return accounts,set(created)|set(retired)|set(plan['configs']),expected

class _Native:
    """Private real-OS implementation, NEVER a public injectable host adapter."""
    def __init__(self):self.stack=ExitStack();self.guards=[];self.rfd=None;self.lfd=None;self.deadline=time.monotonic()+120
    def close(self):self.stack.close()
    def budget(self):need(time.monotonic()<self.deadline,'operation-timeout')
    def bind(self,bundle,selector,ledger,reviewed,provenance,plan_sha):
        self.budget()
        self.bundle=path(bundle);self.selector=path(selector);self.ledger=path(ledger)
        self.provenance=provenance;self.plan_sha=plan_sha;self.epoch=reviewed
        root=P(_SELF).parent
        lock,g=_file(root/'SOURCE-LOCK.json',262144,self.stack);self.guards.append(g);pins=decoded(lock)
        need(type(pins) is dict and pins.get('schemaVersion')==2 and pins.get('codeRoot')=='.','source-lock-schema')
        code=pins['codeAuthority'];target_authority=pins['targetAuthority'];self.pins=pins
        need(type(code) is dict and type(code.get('ops')) is dict and len(code['ops'])==57
            and type(target_authority) is dict and type(target_authority.get('ops')) is dict
            and len(target_authority['ops'])==57,'ops-manifest')
        artifact_fields={'source-provenance.json','podman-domains.json','stack.ir.json','site/agent-vm.json','site/global.settings/registry-image-ids.json'}
        need(type(target_authority.get('artifactFields')) is list and set(target_authority['artifactFields'])==artifact_fields,'target-artifact-schema')
        flat,guards=_tree(root,self.stack);self.guards+=guards
        ec4='retire-failed-venue-registry-image.py';native=P(_SELF).name
        need(set(flat)==set(code['ops'])|{ec4,'policy_fence.py',native,'SOURCE-LOCK.json'},'flat-closure')
        need(all(flat.get(n)==h for n,h in code['ops'].items()) and flat.get(ec4)==pins.get('ec4')
            and flat.get('policy_fence.py')==pins.get('policyFenceSha256')
            and flat.get(native)==pins.get('nativeLeaseSha256'),'flat-pins')
        self.operation_sha=flat[native];self.policy_sha=flat['policy_fence.py'];self.ec4_sha=flat[ec4]
        self.flat_sha=digest(canonical(flat))
        cfg=target_authority.get('inputConfiguration')
        fields={'schemaVersion','bundlePath','selectorPath','ledgerPath','provenanceSha256','planSha256',
            'initialReviewedLedgerSha256','historicalArtifactReceiptPath','historicalArtifactReceiptSha256','ops'}
        need(type(cfg) is dict and set(cfg)==fields and type(cfg['schemaVersion']) is int and cfg['schemaVersion']==1,'target-input-configuration')
        need(cfg['bundlePath']==str(self.bundle) and cfg['selectorPath']==str(self.selector) and cfg['ledgerPath']==str(self.ledger)
            and cfg['planSha256']==plan_sha,'target-input-binding')
        for key in ('provenanceSha256','planSha256','initialReviewedLedgerSha256','historicalArtifactReceiptSha256'):
            need(type(cfg[key]) is str and HEX.fullmatch(cfg[key]),'target-input-hash')
        expected_names=set(target_authority['ops'])|GENERATED_OPS
        need(len(expected_names)==67 and type(cfg['ops']) is dict and set(cfg['ops'])==expected_names,'target-input-members')
        for name,record in cfg['ops'].items():
            need(type(record) is dict and set(record)=={'sha256','mode'} and type(record['sha256']) is str
                and HEX.fullmatch(record['sha256']) and type(record['mode']) is int and 0<=record['mode']<=0o777
                and not record['mode']&0o022,'target-input-record')
        need(all(cfg['ops'][n]['sha256']==h for n,h in target_authority['ops'].items()),'original-target-ops-pins')
        receipt,g=_file(path(cfg['historicalArtifactReceiptPath']),MAX,self.stack,0o600);self.guards.append(g)
        need(digest(receipt)==cfg['historicalArtifactReceiptSha256'],'historical-artifact-receipt')
        # Opaque historical bytes are bound, NOT interpreted as an invented output
        # manifest. S1 independently assembles/checks this protected configuration.
        selected,guards=_tree(self.bundle/'ops',self.stack);self.guards+=guards
        need(selected=={n:r['sha256'] for n,r in cfg['ops'].items()},'original-target-ops-pins')
        for g in guards:
            if g.body is not None:need(stat.S_IMODE(g.meta.st_mode)==cfg['ops'][str(P(g.name).relative_to(self.bundle/'ops'))]['mode'],'original-target-ops-mode')
        self.target_cfg=cfg;target_hashes={} 
        for p,maximum in ((self.selector,262144),(self.bundle/'source-provenance.json',262144),
            (self.bundle/'podman-domains.json',2*1024*1024),(self.bundle/'stack.ir.json',MAX),
            (self.bundle/'site/agent-vm.json',2*1024*1024),
            (self.bundle/'site/global.settings/registry-image-ids.json',MAX)):
            body,g=_file(p,maximum,self.stack);self.guards.append(g)
            if p!=self.selector:target_hashes[str(p.relative_to(self.bundle))]=digest(body)
            if p==self.bundle/'source-provenance.json':
                need(digest(body)==provenance,'provenance');original_provenance=decoded(body)
                need(original_provenance.get('generatorCommit')==target_authority['generatorCommit']
                    and original_provenance.get('generatorDirty') is False and original_provenance.get('siteDirty') is False,'original-target-provenance')
        need(set(target_hashes)==artifact_fields,'target-artifact-scope')
        need(cfg['provenanceSha256']==provenance,'target-input-provenance')
        quadlet_files,guards=_tree(self.bundle/'quadlet',self.stack);self.guards+=guards
        site_files,guards=_data_tree(self.bundle/'site',self.stack);self.guards+=guards
        build_files,guards=_data_tree(self.bundle/'build',self.stack);self.guards+=guards
        # Target files are ORIGINAL DATA authority and are NEVER imported/executed.
        # All executable operation modules load from the separately pinned new flat cohort.
        self.budget();self.registry=_load(root/'venue-registry-images.py','inert_lease_registry');self.budget()
        self.stage=self.registry.stage;self.plan=self.stage.owned_plan(self.bundle,self.selector);self.budget()
        need(digest(canonical(self.plan))==plan_sha,'plan-sha')
        # This is the SAME selected source map used by authority.authority, but
        # avoids unrelated build-Containerfile inspection/live preparation gates.
        # Its complete inputs (IR/domains/quadlets/frozen identity JSON) are held.
        authority=self.registry.authority.authority(self.bundle,self.selector);self.budget()
        self.images=authority['imageIds']
        need(original_provenance['generatorCommit']==self.plan.get('sourceCommit'),'original-target-plan')
        ns=self.plan.get('prefix');need(type(ns) is str and re.fullmatch('p0test-[a-z0-9-]{1,24}',ns)
            and ns==target_authority['namespace'],'namespace');self.ns=ns
        base=P('/usr/local/libexec')/(ns+'-control');self.guards.append(_directory(base,self.stack))
        pointer=base/'agent-services-current-host';meta=_os.lstat(str(pointer))
        need(stat.S_ISLNK(meta.st_mode) and meta.st_uid==0,'host-slot-pointer')
        target=_os.readlink(str(pointer));slot=P(target) if target.startswith('/') else base/target
        need(str(slot)==str(path(str(slot))) and slot.parent==base/'agent-service-releases','host-slot-scope')
        self.pointer=(pointer,ident(meta),target)
        slot_files,guards=_tree(slot,self.stack);self.guards+=guards
        manifest_body,next_guard=_file(slot/'manifest.json',1024*1024,self.stack);self.guards.append(next_guard)
        slot_manifest=decoded(manifest_body);need(type(slot_manifest.get('files')) is dict,'host-slot-manifest')
        need(set(slot_files)==set(slot_manifest['files'])|{'manifest.json'},'host-slot-complete-manifest')
        for member,expected in slot_manifest['files'].items():
            need(type(member) is str and not P(member).is_absolute() and '..' not in P(member).parts
                and slot_files.get(member)==expected,'host-slot-member')
        need(slot_files.get('p0_host_context.py')==pins['controller']['sha256'],'controller-source-pin')
        # Frozen fc98 exact TEN-key target closure. Code authority is separately bound.
        closure={'ops':digest(encoded(selected)),'slot':digest(encoded(slot_files)),
            'quadlet':digest(encoded(quadlet_files)),'slotPath':str(slot),'manifest':slot_manifest,
            'site':digest(encoded(site_files)),'build':digest(encoded(build_files)),
            'imageIds':self.images,'frozenRegistrySha256':authority['frozenRegistrySha256'],
            'provenanceSha256':provenance}
        need(closure['frozenRegistrySha256']==target_hashes['site/global.settings/registry-image-ids.json'],'frozen-registry-source')
        self.closure=closure;self.target_hashes=target_hashes
        self.closure_sha=digest(canonical(closure))
        # External installed HOST slot siblings/caches closed BEFORE host_context load.
        self.lifecycle=self.registry.load('inert_lease_lifecycle','venue-start-quarantine.py')
        self.context=self.lifecycle.host_context(self.bundle,self.plan);self.budget()
        need(self.context.namespace==ns and str(self.context.source)==str(base)
            and str(self.context.runtime)==str(P('/run')/(ns+'-control')) and type(self.context.digest) is str
            and HEX.fullmatch(self.context.digest) and self.context.data['controlCommit']==pins['controller']['commit']
            and self.context.data['sourceProvenanceSha256']==provenance
            and self.context.data['siteVmSpecSha256']==target_hashes['site/agent-vm.json'],'host-context')
        self.context._lease_slot_manifest=slot_manifest
        self.manifest=self.registry.composite.units.manifest(self.bundle,self.plan)
        need(type(self.manifest) is dict and len(self.manifest)==190,'manifest')
        self.parent=_directory(P(str(self.context.runtime)).parent,self.stack)
        # Existing parent FD, no newly created lock. Cooperative only, NOT a root-writer fence.
        fcntl.flock(self.parent.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.ledger_parent=_directory(self.ledger.parent,self.stack,0o700)
        self.policy_parents={}
        for fixed_parent in ('/etc/sudoers.d','/etc/tmpfiles.d','/etc/systemd/system'):
            parent_guard=_directory(fixed_parent,self.stack);self.guards.append(parent_guard)
            self.policy_parents[fixed_parent]=ident(parent_guard.meta)
        self.state=decoded(self.read_ledger());self.record=self.state.get(KEY)
        initial=self.record.get('ledgerSha256Before') if type(self.record) is dict else self.epoch
        need(initial==cfg['initialReviewedLedgerSha256'],'target-input-initial-ledger')
        self.accounts,self.gone,self.hostunits=_shape(self.state,self.plan,self.context,provenance,plan_sha,self.policy_sha,self.manifest,self.closure_sha,self.images,self.ec4_sha)
        self.policy_record_bytes=encoded(self.state[FENCE])
        self.binding={'namespace':ns,'path':str(self.context.runtime),'contextSha256':self.context.digest,
            'policyFenceSha256':digest(self.policy_record_bytes),'codeRoot':str(root),
            'originalArtifactReceiptSha256':cfg['historicalArtifactReceiptSha256'],
            'originalTargetConfigurationSha256':digest(canonical(cfg)),
            'targetArtifactsSha256':digest(canonical({'bundle':str(self.bundle),'selector':str(self.selector),
                'ledger':str(self.ledger),'originalOps':selected,'artifacts':target_hashes})),
            'sourceProvenanceSha256':provenance,'planSha256':plan_sha,'operationSourceSha256':self.operation_sha,
            'flatSourceClosureSha256':self.flat_sha,
            'parent':{k:v for k,v in ident(self.parent.meta).items() if k!='nlink'}}
        self.validate_fence(False);self.open_runtime();self.validate_fence(True);self.budget()
    def validate_fence(self,held):
        """Frozen fc98 FULL fourteen-field fenced wire, original IDs and six epochs.

        The record is preserved, not upgraded/coerced. This does NOT grant root.
        Physical absence/held identities/current CAS remain separate requirements.
        """
        f=self.state[FENCE]
        binding={'schemaVersion':1,'namespace':self.ns,'hostContextSha256':self.context.digest,
            'provenanceSha256':self.provenance,'planSha256':self.plan_sha,
            'operationSha256':self.policy_sha,'sourceClosureSha256':self.closure_sha,
            'ledgerPath':str(self.ledger),'ledgerParent':ident(self.ledger_parent.meta)}
        need(type(f) is dict and set(f)==set(binding)|{'leaseIdentity','phase','ledgerSha256Before','policies','intendedEpochs'}
            and all(type(f[k]) is type(v) and canonical(f[k])==canonical(v) for k,v in binding.items())
            and f['phase']=='fenced','complete-policy-fence')
        need(encoded(f)==self.policy_record_bytes,'policy-record-mutated')
        before=f['ledgerSha256Before'];epochs=f['intendedEpochs']
        need(type(before) is str and HEX.fullmatch(before) and type(epochs) is list and len(epochs)==6
            and all(type(x) is str and HEX.fullmatch(x) for x in epochs) and len(set(epochs))==6
            and epochs[0]==before,'policy-epochs')
        # Reconstruct the exact append-only policy epoch chain, excluding ONLY
        # this operation's new record. No current/failed history is removed.
        base={k:copy.deepcopy(v) for k,v in self.state.items() if k not in (KEY,FENCE)}
        need(digest(encoded(base))==before,'policy-before-cas')
        phases=('intended','sudo-issued','sudo-done','tmpfiles-issued','tmpfiles-done')
        for i,phase in enumerate(phases,1):
            prior=copy.deepcopy(f);prior['phase']=phase;prior['intendedEpochs']=epochs[:i]
            need(digest(encoded({**base,FENCE:prior}))==epochs[i],'policy-epoch-chain')
        policies=f['policies'];need(type(policies) is list and len(policies)==2,'policy-pair')
        specs=((P('/etc/sudoers.d')/(self.ns+'-agent-identity'),0o440,
            (self.ns+'-provisioner ALL=(root) NOPASSWD: '+str(self.context.source/'agent-identity-host.py')+' *\n').encode()),
            (P('/etc/tmpfiles.d')/(self.ns+'-control.conf'),0o644,
            ('d '+str(self.context.runtime)+' 0700 root root -\n').encode()))
        for saved,(name,mode,body) in zip(policies,specs):
            need(type(saved) is dict and set(saved)=={'path','mode','bodySha256','parent','file'}
                and saved['path']==str(name) and type(saved['mode']) is int and saved['mode']==mode
                and saved['bodySha256']==digest(body) and type(saved['parent']) is dict
                and canonical(saved['parent'])==canonical(self.policy_parents[str(name.parent)])
                and all(type(v) is int for v in saved['parent'].values()),'saved-policy')
            file=saved['file'];self.full_file_identity(file,stat.S_IFREG|mode,len(body))
        lease=f['leaseIdentity']
        need(type(lease) is dict and set(lease)=={'directory','file'},'fence-lease-shape')
        self.valid_identity(lease['directory'],True)
        self.full_file_identity(lease['file'],stat.S_IFREG|0o600,0)
        need(lease['file']['dev']==lease['directory']['dev'],'fence-lease-device')
        for saved_parent in (f['ledgerParent'],)+(tuple(p['parent'] for p in policies)):
            need(saved_parent['uid']==saved_parent['gid']==0 and stat.S_ISDIR(saved_parent['mode'])
                and not saved_parent['mode']&0o022,'fence-protected-parent')
        if not held:return
        rec=self.record
        original_directory=lease['directory'];original_leaf=lease['file']
        subset={k:v for k,v in original_leaf.items() if k in {'dev','ino','uid','gid','mode','nlink','size'}}
        if rec is not None:
            need(rec['directory']==original_directory and rec['lease']==subset,'fence-owned-identities')
        if self.rfd is not None:
            actual=ident(_os.fstat(self.rfd))
            if getattr(self,'directory_removed',False):
                need(actual==dict(original_directory,nlink=0),'fence-held-removed-directory')
            else:need(actual==original_directory,'fence-directory-identity')
        if self.lfd is not None:
            actual=self.full_stat(_os.fstat(self.lfd))
            if actual['nlink']==1:need(actual==original_leaf,'fence-lease-identity')
            else:need({k:v for k,v in actual.items() if k in subset}==dict(subset,nlink=0),'fence-held-unlinked-lease')
        elif self.rfd is not None:need(set(_os.listdir(self.rfd))==set(),'fence-absent-lease')
    @staticmethod
    def full_stat(s):
        return {k:getattr(s,'st_'+k) for k in ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')}
    def full_file_identity(self,value,mode,size):
        keys={'dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'}
        need(type(value) is dict and set(value)==keys and all(type(v) is int and v>=0 for v in value.values())
            and value['ino']>0 and value['uid']==value['gid']==0 and value['mode']==mode
            and value['size']==size and value['nlink']==1,'full-file-identity')
    def read_ledger(self):
        self.budget()
        with ExitStack() as stack:body,_=_file(self.ledger,MAX,stack,0o600)
        need(digest(body)==self.epoch,'ledger-cas');self.budget();return body
    def source_now(self):
        self.budget();_root_now()
        for g in self.guards:g.check()
        # Context.current() concrete I/O closure is held within the slot. Parent
        # namespace remains held even after our own directory removal.
        expected={k:v for k,v in ident(self.parent.meta).items() if k!='nlink'}
        need(all({k:v for k,v in ident(s).items() if k!='nlink'}==expected for s in
            (_os.fstat(self.parent.fd),_os.lstat(self.parent.name))),'held-parent-race')
        self.ledger_parent.check()
        p,i,target=self.pointer;need(ident(_os.lstat(str(p)))==i and _os.readlink(str(p))==target,'host-slot-race')
        # Audited controller2e0 current() reads slot metadata ONLY, never runtime.
        # Reenter the real context chain even for fresh/post-removal continuations.
        current=self.lifecycle.host_context(self.bundle,self.plan)
        need(current.digest==self.context.digest and current.namespace==self.ns
            and str(current.runtime)==str(self.context.runtime) and str(current.source)==str(self.context.source)
            and canonical(current.data)==canonical(self.context.data),'context-race')
        self.budget()
    def observe(self):
        self.source_now();_shape(self.state,self.plan,self.context,self.provenance,self.plan_sha,self.policy_sha,self.manifest,self.closure_sha,self.images,self.ec4_sha)
        self.validate_fence(True);self.budget()
        _accounts_absent(self.accounts);self.budget()
        for p in self.gone|self.hostunits:need(_absent(p),'retired-path-present')
        for p in (P('/etc/sudoers.d')/(self.ns+'-agent-identity'),P('/etc/tmpfiles.d')/(self.ns+'-control.conf')):need(_absent(p),'policy-present')
        for a in self.accounts:
            f=_fields('user@'+str(a['uid'])+'.service',('LoadState','ActiveState','SubState'))
            need(f['LoadState'] in ('loaded','not-found') and f['ActiveState']=='inactive' and f['SubState']=='dead','manager-active');self.budget()
        for name in HOST_NAMES:
            unit=self.context.unit(name)
            need(_absent(P('/run/systemd/system')/unit),'runtime-host-unit-present')
            f=_fields(unit,('LoadState','ActiveState','FragmentPath','DropInPaths'))
            need(f=={'LoadState':'not-found','ActiveState':'inactive','FragmentPath':'','DropInPaths':''},'host-unit-loaded');self.budget()
        _tmpfiles_quiescent();self.budget()
        need(not _command(['/usr/bin/systemctl','list-jobs','--no-legend','--no-pager']).strip(),'jobs-present');self.budget()
        _processes_quiescent(self.ns,[a['uid'] for a in self.accounts]);self.budget();self.source_now();self.budget()
    def open_runtime(self):
        rec=self.record
        if rec is not None:
            need(type(rec) is dict and set(rec)==set(self.binding)|{'directory','lease','phase','ledgerSha256Before'}
                and _json_exact({k:rec[k] for k in self.binding},self.binding) and type(rec['ledgerSha256Before']) is str
                and HEX.fullmatch(rec['ledgerSha256Before']) and rec['phase'] in ('intended','lease-delete-issued','directory-delete-issued','retired'),'intent-binding')
            self.valid_identity(rec['directory'],True);self.valid_identity(rec['lease'],False)
        phase=rec['phase'] if rec else None
        root=P(str(self.context.runtime));self.runtime_name=root.name
        if phase in ('directory-delete-issued','retired'):
            need(_absent(root),'issued-directory-present');self.directory_removed=True;return
        fd=_os.open(self.runtime_name,_os.O_RDONLY|_os.O_DIRECTORY|_os.O_NOFOLLOW|_os.O_CLOEXEC,dir_fd=self.parent.fd)
        self.stack.callback(_os.close,fd);self.rfd=fd;s=_os.fstat(fd);d=ident(s)
        self.valid_identity(d,True);self.directory=d if rec is None else rec['directory'];need(d==self.directory,'runtime-identity')
        entries=set(_os.listdir(fd))
        if phase=='lease-delete-issued':need(entries==set(),'issued-lease-present');return
        need(entries=={'lifecycle.lock'},'runtime-contents')
        leaf=_os.open('lifecycle.lock',_os.O_RDWR|_os.O_NOFOLLOW|_os.O_CLOEXEC|_os.O_NONBLOCK,dir_fd=fd)
        self.stack.callback(_os.close,leaf);self.lfd=leaf;l=ident(_os.fstat(leaf),True);self.valid_identity(l,False)
        need(l['dev']==d['dev'],'lease-device');fcntl.flock(leaf,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.lease=l if rec is None else rec['lease'];need(l==self.lease,'lease-identity')
        self.runtime_now(False)
    def valid_identity(self,value,directory):
        keys={'dev','ino','uid','gid','mode','nlink'}| (set() if directory else {'size'})
        need(type(value) is dict and set(value)==keys and all(type(v) is int and v>=0 for v in value.values())
            and value['ino']>0 and value['uid']==value['gid']==0 and value['mode']==(stat.S_IFDIR|0o700 if directory else stat.S_IFREG|0o600)
            and value['nlink']==(2 if directory else 1) and (directory or value['size']==0),'object-identity')
    def runtime_now(self,leaf_absent):
        current=ident(_os.stat(self.runtime_name,dir_fd=self.parent.fd,follow_symlinks=False))
        need(current==self.directory==ident(_os.fstat(self.rfd)),'held-runtime-race')
        need(set(_os.listdir(self.rfd))==(set() if leaf_absent else {'lifecycle.lock'}),'runtime-contents')
        if leaf_absent:
            if self.lfd is not None:
                held=ident(_os.fstat(self.lfd),True);want=dict(self.lease,nlink=0);need(held==want,'unlinked-held-lease-race')
        else:
            need(ident(_os.stat('lifecycle.lock',dir_fd=self.rfd,follow_symlinks=False),True)==self.lease
                ==ident(_os.fstat(self.lfd),True),'held-lease-race')
    def check(self):
        self.budget();self.read_ledger();self.budget()
        self.observe();self.budget();self.read_ledger();self.budget()
    def publish(self,phase):
        self.check();self.record['phase']=phase;body=encoded(self.state);expected=digest(body)
        temporary=self.ledger.name+'.inert-lease-new';self.budget()
        fd=_os.open(temporary,_os.O_WRONLY|_os.O_CREAT|_os.O_EXCL|_os.O_NOFOLLOW|_os.O_CLOEXEC,0o600,dir_fd=self.ledger_parent.fd)
        try:
            offset=0
            while offset<len(body):
                self.budget();written=_os.write(fd,body[offset:]);need(written>0,'ledger-write');offset+=written;self.budget()
            self.budget();_os.fsync(fd);self.budget();self.check();self.budget()
            _os.replace(temporary,self.ledger.name,src_dir_fd=self.ledger_parent.fd,dst_dir_fd=self.ledger_parent.fd)
            self.budget();_os.fsync(self.ledger_parent.fd);self.budget();self.epoch=expected
            need(self.read_ledger()==body,'ledger-postwrite');self.budget()
        finally:_os.close(fd)
        # Deliberately never delete uncertain leftover temp files on failure.
    def unlink(self):
        self.check();self.runtime_now(False);self.read_ledger();self.source_now();self.runtime_now(False)
        self.budget();_os.unlink('lifecycle.lock',dir_fd=self.rfd)
        self.budget();_os.fsync(self.rfd);self.budget()
    def rmdir(self):
        self.check();self.runtime_now(True);self.read_ledger();self.source_now();self.runtime_now(True)
        self.budget();_os.rmdir(self.runtime_name,dir_fd=self.parent.fd);self.directory_removed=True
        self.budget();_os.fsync(self.parent.fd);self.budget()
    def finish(self):
        self.check();need(_absent(self.context.runtime),'final-runtime-present')
        if self.lfd is not None:
            need(ident(_os.fstat(self.lfd),True)==dict(self.lease,nlink=0),'held-final-lease')
        self.budget();_os.fsync(self.parent.fd);self.budget();self.publish('retired');self.budget()

def _retire(bundle,selector,ledger,reviewed_sha,provenance_sha,plan_sha):
    for value in (reviewed_sha,provenance_sha,plan_sha):need(type(value) is str and HEX.fullmatch(value),'digest')
    native=_Native()
    try:
        native.bind(bundle,selector,ledger,reviewed_sha,provenance_sha,plan_sha)
        native.check()
        if native.record is None:
            native.record={**native.binding,'directory':native.directory,'lease':native.lease,'ledgerSha256Before':reviewed_sha,'phase':'intended'}
            native.state[KEY]=native.record;native.publish('intended')
        phase=native.record['phase']
        if phase=='intended':
            native.runtime_now(False);native.publish('lease-delete-issued');native.unlink()
        elif phase=='lease-delete-issued':
            native.runtime_now(True);native.budget();_os.fsync(native.rfd);native.budget()
        if native.record['phase']=='lease-delete-issued':
            native.runtime_now(True);native.publish('directory-delete-issued');native.rmdir()
        native.finish();native.budget()
        result={'status':'retired-inert-control-lease','activationAuthorized':False,'nativeRecoveryAuthorized':False,
            'acceptedIntegratedInstalls':0,'servicesStarted':False}
    finally:native.close()
    # Always finish descriptor cleanup, even if it consumes the remaining budget.
    # This is not interruption/undo of an already-issued syscall.
    native.budget();return result

def retire_inert_control_lease(bundle,selector,ledger,reviewed_sha,provenance_sha,plan_sha):
    """Real native default. Six selection/CAS inputs only; no host/context bypass.

    Source tests explicitly replace INTERNAL kernel/filesystem observations only.
    Caller-supplied marker JSON/UID flags/tuples never replace root admission.
    S1 MUST establish exclusive/cooperative maintenance excluding ALL relevant
    Root writers (source/context/target/ledger/policy/lease/parents, namespace
    and mount changes, controllers, jobs and process launchers) BEFORE protected
    import, throughout this invocation, final FD close and every continuation.
    This callable does not authenticate that external operational condition.
    Flock and snapshots are not arbitrary-Root exclusion, fork freeze or POSIX
    inode-CAS. Late rechecks narrow windows; a writer after the last check is
    still outside this contract, never evidence of native atomic deletion.
    """
    try:
        root_admission()
        return _retire(bundle,selector,ledger,reviewed_sha,provenance_sha,plan_sha)
    except Refused:raise
    except Exception:raise Refused('native-observation-refused') from None
