#!/usr/bin/env python3
"""Exact runtime-env adjunct owner; no lifecycle, journal, CLI or admission.

prepare_custody(root, release, intent) -> retained same-process FD custody.
The journal seals EXACT dict(intent,nativeRuntimeEnvUnitCustody=custody) in
both preparing records, then calls publish(root,release,new_intent) under FD9.
The adjunct service/drop-in and exact Root-issued per-role copy-custody leaf
are owned. verify_prepared_units checks persistent/source/unit proof before
any manager/socket/target, without runtime anchors or env copies; Root calls
seal_running_copies AFTER all eight restores and BEFORE graph admission. The
embedded isolated Python restore reads no journal, aggregate, glob or sibling
input. Its public manifest contains names/hashes/inode metadata, never values.
Updater, selected Quadlet files, pointer selection and manager control remain
with their existing owners. Failed inert stages remain for canonical disposition.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


m = load('_runtime_env_unit_files', 'native-install-files.py')
v, o, p, n = m.v, m.o, m.p, m.native
require, Refused = o.require, o.Refused
HOST = Path('/')
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
UNIT = 'webservices-runtime-env.service'
DROPIN = '10-runtime-env.conf'
_sessions = {}

# Standalone constant program. No dependency on private release paths or journal.
# Also executed verbatim in the real-FD tests; only numerical/kernel facts modelled.
RUNTIME_PROGRAM = r'''import base64,ctypes,errno,hashlib,json,os,pwd,secrets,stat,sys
from pathlib import Path
HOST=Path('/')
LIMIT=8388608
PATH=os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW
FILE=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
_uid=os.geteuid
_gid=os.getegid

def need(ok):
    if not ok: raise ValueError('exact runtime environment custody refused')

def canonical(value):
    need(isinstance(value,str) and value.startswith('/') and value!='/' and str(Path(value))==value
         and not any(x in ('','.','..') for x in value.split('/')[1:]))
    return Path(value)

def identity(s):
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def _acl(fd,name):
    try:
        try: return os.getxattr(fd,name)
        except OSError as error:
            if error.errno!=errno.EBADF: raise
            # fgetxattr rejects O_PATH. This EXACT self FD is a kernel-held
            # object, not a walk through an untrusted source symlink.
            return os.getxattr('/proc/self/fd/'+str(fd),name)
    except OSError as error:
        if error.errno!=errno.ENODATA: raise
        return b''

def _mount(fd):
    with open('/proc/self/fdinfo/'+str(fd),encoding='ascii') as stream:
        rows=[line.split()[1] for line in stream if line.startswith('mnt_id:')]
    need(len(rows)==1)
    return int(rows[0])

def _tmpfs(fd):
    buf=ctypes.create_string_buffer(256)
    need(ctypes.CDLL(None,use_errno=True).fstatfs(fd,ctypes.byref(buf))==0)
    return ctypes.cast(buf,ctypes.POINTER(ctypes.c_long))[0]==0x01021994

def child(parent,name,flags,no_xdev=True):
    need(isinstance(name,str) and name not in ('','.','..') and '/' not in name)
    class How(ctypes.Structure):
        _fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
    how=How(flags,0,0x08|0x04|(0x01 if no_xdev else 0))
    libc=ctypes.CDLL(None,use_errno=True)
    fd=libc.syscall(ctypes.c_long(437),ctypes.c_int(parent),ctypes.c_char_p(os.fsencode(name)),ctypes.byref(how),ctypes.sizeof(how))
    if fd<0: raise OSError(ctypes.get_errno(),'exact runtime path open refused')
    return fd

def record(fd,file=False):
    s=os.fstat(fd)
    result=dict(dev=s.st_dev,ino=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode),
                acl=_acl(fd,'system.posix_acl_access').hex(),defaultAcl=_acl(fd,'system.posix_acl_default').hex())
    if file: result['identity']=identity(s)
    return result

def portable(value):
    return {k:v for k,v in value.items() if k not in ('mountId','sha256')}

def walk(path,anchor,pins=None):
    fd=os.open('/',PATH); opened=[fd]; current=Path('/'); anchored=False
    try:
        if pins is not None: need(record(fd)==portable(pins[str(current)]))
        for part in path.parts[1:]:
            current/=part
            fd=child(fd,part,PATH,anchored); opened.append(fd)
            if pins is not None:
                need(str(current) in pins and record(fd)==portable(pins[str(current)]))
            else:
                rec=record(fd)
                need(rec['uid']==rec['gid']==0 and not rec['mode']&0o022 and not rec['acl'] and not rec['defaultAcl'])
            anchored|=current==anchor
        return os.dup(fd)
    finally:
        for fd in reversed(opened): os.close(fd)

def file_record(fd,uid,gid,digest,expected=None):
    before=os.fstat(fd); rec=record(fd,True)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=LIMIT
         and (rec['uid'],rec['gid'],rec['mode'])==(uid,gid,0o600) and not rec['acl'] and not rec['defaultAcl'])
    if expected is not None: need(rec==portable(expected))
    body=os.pread(fd,LIMIT+1,0)
    need(len(body)==before.st_size and identity(os.fstat(fd))==identity(before)
         and hashlib.sha256(body).hexdigest()==digest)
    return body,rec

def absent(parent,name):
    try: os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError: return
    raise ValueError('existing selected runtime environment requires canonical disposition')

def rename(parent,source,destination):
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.renameat2(parent,os.fsencode(source),parent,os.fsencode(destination),1):
        raise OSError(ctypes.get_errno(),'exact runtime publication refused')

def _boot():
    import re
    with open('/proc/sys/kernel/random/boot_id',encoding='ascii') as stream: value=stream.read(128).strip()
    need(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value) is not None)
    return value

def manifest_sha(spec):
    return hashlib.sha256((json.dumps(spec,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()

def receipt_base(spec):
    return dict(schemaVersion=1,kind='runtime-environment-copy-custody',release=spec['release'],role=spec['role'],
                uid=spec['uid'],gid=spec['gid'],manifestSha256=manifest_sha(spec),bootId=_boot(),
                activationAuthorized=False,readinessAuthorized=False,resetAuthorized=False)

def receipt_shape(spec,value,current_boot=True):
    base=receipt_base(spec)
    need(isinstance(value,dict) and type(value.get('schemaVersion')) is int
         and set(value)==set(base)|{'runtimeAnchor','runtimeDirectory','files'}
         and all(value.get(key)==item for key,item in base.items() if key!='bootId' or current_boot)
         and all(value.get(key) is False for key in ('activationAuthorized','readinessAuthorized','resetAuthorized')))
    import re
    need(isinstance(value.get('bootId'),str) and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value['bootId']) is not None)
    keys={'dev','ino','uid','gid','mode','acl','defaultAcl','mountId'}
    for name in ('runtimeAnchor','runtimeDirectory'):
        rec=value.get(name)
        need(isinstance(rec,dict) and set(rec)==keys and all(type(rec[k]) is int for k in keys-{'acl','defaultAcl'})
             and rec['dev']>=0 and rec['ino']>0 and rec['mountId']>0 and not rec['acl'] and not rec['defaultAcl'])
        if name=='runtimeAnchor' and spec['uid']==0:
            need(rec['uid']==0 and rec['gid']>=0 and not(rec['mode'] & 0o022))
        else: need((rec['uid'],rec['gid'],rec['mode'])==(spec['uid'],spec['gid'],0o700))
    files=value.get('files'); need(isinstance(files,dict) and set(files)==set(spec['files']))
    for name,seal in spec['files'].items():
        rec=files[name]; need(isinstance(rec,dict) and set(rec)==keys|{'identity','sha256'}
                             and all(type(rec[k]) is int for k in keys-{'acl','defaultAcl'}))
        ids=rec.get('identity'); need(isinstance(ids,list) and len(ids)==9 and all(type(v) is int for v in ids))
        need((rec['uid'],rec['gid'],rec['mode'])==(spec['uid'],spec['gid'],0o600) and not rec['acl'] and not rec['defaultAcl']
             and ids[:4]==[rec['dev'],rec['ino'],rec['uid'],rec['gid']] and ids[5]==1 and 0<=ids[6]<=LIMIT
             and stat.S_ISREG(ids[4]) and stat.S_IMODE(ids[4])==0o600 and rec['mountId']>0 and rec['sha256']==seal['sha256'])
    return value

def read_receipt(spec):
    path=canonical(spec['custodyFile']); parent=walk(path.parent,canonical(spec['sourceAnchor']),spec['custodyDirectories'])
    fd=None
    try:
        fd=child(parent,path.name,FILE); before=os.fstat(fd); rec=record(fd,True)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=LIMIT
             and (rec['uid'],rec['gid'],rec['mode'])==(0,spec['gid'],0o400 if spec['uid']==0 else 0o440)
             and not rec['acl'] and not rec['defaultAcl'])
        body=os.pread(fd,LIMIT+1,0); need(len(body)==before.st_size and identity(os.fstat(fd))==identity(before))
        def pairs(rows):
            result={}
            for key,value in rows: need(key not in result); result[key]=value
            return result
        value=json.loads(body,object_pairs_hook=pairs)
        receipt_shape(spec,value)
        again=child(parent,path.name,FILE)
        try: need(identity(os.fstat(again))==identity(before))
        finally: os.close(again)
        return value
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

class RootCopyCustodyRequired(ValueError):
    pass

def verify_existing(spec,target,anchor_fd,directory):
    try: proof=read_receipt(spec)
    except FileNotFoundError:
        raise RootCopyCustodyRequired('current-boot Root copy custody is not sealed; canonical Root sealing/disposition required') from None
    need(proof.get('runtimeAnchor')==dict(record(anchor_fd),mountId=_mount(anchor_fd))
         and proof.get('runtimeDirectory')==dict(directory,mountId=_mount(target))
         and set(proof.get('files',{}))==set(spec['files']))
    for name,seal in spec['files'].items():
        fd=child(target,name,FILE)
        try:
            _,actual=file_record(fd,spec['uid'],spec['gid'],seal['sha256'])
            need(dict(actual,mountId=_mount(fd),sha256=seal['sha256'])==proof['files'][name])
        finally: os.close(fd)
    return dict(status='completed',files=proof['files'],idempotent=True,activationAuthorized=False,readinessAuthorized=False)

def inspect_source(spec):
    need((_uid(),_gid())==(0,0))
    if not spec['files']:
        need(spec['store'] is None and not spec['sourceDirectories']); return dict(store=None,files={})
    source=canonical(spec['stateStore']); anchor=canonical(spec['sourceAnchor']); need(source==anchor/'runtime-env')
    parent=walk(source,anchor,spec['sourceDirectories'])
    try:
        need(record(parent)==portable(spec['store']) and _mount(parent)==spec['store']['mountId'])
        files={}
        for name,seal in spec['files'].items():
            fd=child(parent,name,FILE)
            try:
                _,actual=file_record(fd,spec['uid'],spec['gid'],seal['sha256'],seal)
                need(_mount(fd)==seal['mountId']); files[name]=dict(actual,mountId=_mount(fd),sha256=seal['sha256'])
            finally: os.close(fd)
        return dict(store=dict(record(parent),mountId=_mount(parent)),files=files)
    finally: os.close(parent)

def inspect_copy(spec):
    # Root read-only observation, used ONLY by the canonical Root issuer below.
    need((_uid(),_gid())==(0,0))
    uid,gid=spec['uid'],spec['gid']; handles=[]
    source=canonical(spec['stateStore']); source_anchor=canonical(spec['sourceAnchor'])
    need(source==source_anchor/'runtime-env')
    if uid:
        account=pwd.getpwuid(uid)
        need((account.pw_name,account.pw_gid)==(spec['user'],gid))
        anchor=HOST/'run/user'/str(uid)
    else: anchor=HOST/'run'
    need(spec['runtimeStore']==str(anchor/'webservices'))
    try:
        if spec['files']:
            source_fd=walk(source,source_anchor,spec['sourceDirectories']); handles.append(source_fd)
            need(record(source_fd)==portable(spec['store']))
            for name,seal in spec['files'].items():
                fd=child(source_fd,name,FILE); handles.append(fd)
                file_record(fd,uid,gid,seal['sha256'],seal)
        else: need(spec['store'] is None and not spec['sourceDirectories'])
        if uid:
            outer=walk(anchor.parent,HOST/'run'); handles.append(outer)
            anchor_fd=child(outer,anchor.name,PATH,False); handles.append(anchor_fd)
            rec=record(anchor_fd)
            need((rec['uid'],rec['gid'],rec['mode'])==(uid,gid,0o700) and not rec['acl'] and not rec['defaultAcl'])
        else:
            anchor_fd=walk(anchor,anchor); handles.append(anchor_fd)
        need(_tmpfs(anchor_fd))
        target=child(anchor_fd,'webservices',PATH); handles.append(target); directory=record(target)
        need((directory['uid'],directory['gid'],directory['mode'])==(uid,gid,0o700)
             and not directory['acl'] and not directory['defaultAcl'])
        files={}
        for name,seal in spec['files'].items():
            fd=child(target,name,FILE); handles.append(fd)
            _,actual=file_record(fd,uid,gid,seal['sha256'])
            files[name]=dict(actual,mountId=_mount(fd),sha256=seal['sha256'])
        return dict(receipt_base(spec),runtimeAnchor=dict(record(anchor_fd),mountId=_mount(anchor_fd)),
                    runtimeDirectory=dict(directory,mountId=_mount(target)),files=files)
    finally:
        for fd in reversed(handles): os.close(fd)

def restore(spec):
    need(isinstance(spec,dict) and spec.get('schemaVersion')==1 and spec.get('kind')=='exact-runtime-environment')
    uid,gid=spec['uid'],spec['gid']; need(type(uid) is int and type(gid) is int and (_uid(),_gid())==(uid,gid))
    role=spec['role']
    if role=='rootful':
        need(uid==gid==0 and spec['user']=='root')
        anchor=HOST/'run'; runtime=anchor/'webservices'
    else:
        names=('platform','apps','homeassistant','finance','ci-runner','workloads','test-runners')
        need(role.startswith('rootless-') and role[9:] in names)
        name=role[9:]; need(uid==780+names.index(name) and spec['user']=='webservices-lab-'+name)
        account=pwd.getpwuid(uid)
        need((account.pw_name,account.pw_uid,account.pw_gid,account.pw_dir)==(spec['user'],uid,gid,'/home/'+spec['user']))
        anchor=HOST/'run/user'/str(uid); runtime=anchor/'webservices'
    need(str(runtime)==spec['runtimeStore'])
    files=spec['files']; need(isinstance(files,dict) and len(files)<=10000)
    for name,seal in files.items():
        need(name.endswith('.env') and name[:-4] and all(c.isalnum() or c in '_-.' for c in name[:-4])
             and '/' not in name and isinstance(seal.get('sha256'),str) and len(seal['sha256'])==64)
    handles=[]; sources={}; payload={}; parent=None; target=None
    try:
        source=canonical(spec['stateStore']); source_anchor=canonical(spec['sourceAnchor'])
        need(source==source_anchor/'runtime-env')
        if files:
            need(spec['sourceDirectories'] and spec['store'] is not None)
            parent=walk(source,source_anchor,spec['sourceDirectories']); handles.append(parent)
            need(record(parent)==portable(spec['store']) and (record(parent)['uid'],record(parent)['gid'],record(parent)['mode'])==(uid,gid,0o700)
                 and not record(parent)['acl'] and not record(parent)['defaultAcl'])
            for name,seal in sorted(files.items()):
                fd=child(parent,name,FILE); handles.append(fd)
                body,pin=file_record(fd,uid,gid,seal['sha256'],seal)
                payload[name]=body; sources[name]=(fd,pin)
        else:
            need(spec['store'] is None and spec['sourceDirectories']=={})
        # Only logind's legitimate UID tmpfs boundary is allowed to cross.
        if uid:
            outer=walk(anchor.parent,HOST/'run'); handles.append(outer)
            anchor_fd=child(outer,anchor.name,PATH,False); handles.append(anchor_fd)
            rec=record(anchor_fd)
            need((rec['uid'],rec['gid'],rec['mode'])==(uid,gid,0o700) and not rec['acl'] and not rec['defaultAcl'])
        else:
            anchor_fd=walk(anchor,anchor); handles.append(anchor_fd)
        need(_tmpfs(anchor_fd))
        try: target_path=child(anchor_fd,'webservices',PATH)
        except FileNotFoundError:
            os.mkdir('webservices',0o700,dir_fd=anchor_fd)
            target_path=child(anchor_fd,'webservices',PATH)
        handles.append(target_path); rec=record(target_path)
        need((rec['uid'],rec['gid'],rec['mode'])==(uid,gid,0o700) and not rec['acl'] and not rec['defaultAcl'])
        target=child(anchor_fd,'webservices',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); handles.append(target)
        need(record(target)==rec)
        # An actor-authored stamp can NEVER authorize existing runtime files.
        present=[]
        for name in files:
            try: os.stat(name,dir_fd=target,follow_symlinks=False); present.append(name)
            except FileNotFoundError: pass
        need(not present or len(present)==len(files))
        def recheck():
            need(record(target)==rec)
            named=child(anchor_fd,'webservices',PATH)
            try: need(record(named)==rec)
            finally: os.close(named)
            if files:
                check=walk(source,source_anchor,spec['sourceDirectories'])
                try: need(record(check)==portable(spec['store']))
                finally: os.close(check)
            for name,(fd,pin) in sources.items():
                need(file_record(fd,uid,gid,files[name]['sha256'],files[name])[1]==pin)
                check=child(parent,name,FILE)
                try: need(file_record(check,uid,gid,files[name]['sha256'],files[name])[1]==pin)
                finally: os.close(check)
        if present:
            recheck()
            result=verify_existing(spec,target,anchor_fd,rec)
            recheck()
            return result
        published={}
        for name,body in sorted(payload.items()):
            recheck(); absent(target,name)
            stage='.runtime-env-'+secrets.token_hex(16)
            fd=os.open(stage,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=target); handles.append(fd)
            s=os.fstat(fd)
            need((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)==(uid,gid,0o600,1)
                 and _mount(fd)==_mount(target) and not _acl(fd,'system.posix_acl_access') and not _acl(fd,'system.posix_acl_default'))
            view=memoryview(body)
            while view:
                count=os.write(fd,view); need(count>0); view=view[count:]
            os.fsync(fd); staged=file_record(fd,uid,gid,files[name]['sha256'])[1]
            recheck(); absent(target,name)
            need(identity(os.stat(stage,dir_fd=target,follow_symlinks=False))==staged['identity'])
            rename(target,stage,name); os.fsync(target)
            actual_id=identity(os.stat(name,dir_fd=target,follow_symlinks=False))
            if actual_id[:-1]!=staged['identity'][:-1]:
                need(identity(os.stat(name,dir_fd=target,follow_symlinks=False))==actual_id)
                rename(target,name,stage); os.fsync(target)
                raise ValueError('foreign runtime stage restored without reading/adoption')
            check=child(target,name,FILE)
            try:
                _,actual=file_record(check,uid,gid,files[name]['sha256'])
                need(actual['identity'][:-1]==staged['identity'][:-1])
                published[name]=actual
            finally: os.close(check)
        recheck()
        return dict(status='completed',files=published,activationAuthorized=False,readinessAuthorized=False)
    finally:
        for fd in reversed(handles): os.close(fd)

if __name__=='__main__':
    try:
        need(len(sys.argv)==2)
        def pairs(rows):
            result={}
            for key,value in rows: need(key not in result); result[key]=value
            return result
        raw=base64.b64decode(sys.argv[1],validate=True); need(len(raw)<=4194304)
        restore(json.loads(raw,object_pairs_hook=pairs))
    except RootCopyCustodyRequired:
        print('current-boot Root copy custody is not sealed; canonical Root sealing/disposition required',file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('exact runtime environment restore refused; canonical disposition required',file=sys.stderr)
        sys.exit(1)
'''
_runtime = {'__name__': '_exact_runtime_restore'}
exec(compile(RUNTIME_PROGRAM, '<exact-runtime-env>', 'exec'), _runtime)
restore = _runtime['restore']


def render_unit(manifest):
    encoded = base64.b64encode(p.encoded(manifest)).decode('ascii')
    program = base64.b64encode(RUNTIME_PROGRAM.encode()).decode('ascii')
    command = "import base64;exec(compile(base64.b64decode('" + program + "'),'<exact-runtime-env>','exec'))"
    require(len(encoded) <= 96000 and len(command) <= 96000, 'exact restore unit argument exceeds safe kernel bound')
    return ('[Unit]\nDescription=Restore exact selected webservices environment files\n\n[Service]\n'
            'Type=oneshot\nWorkingDirectory=/\nExecStart=/usr/bin/python3 -I -B -c "' + command + '" "' + encoded +
            '"\nRemainAfterExit=yes\n').encode()


def render_dropin():
    return b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n'


def legacy_unit(source, runtime):
    # Reviewed owning SOURCE formula, never an import/eval of an old installer.
    return ("[Unit]\nDescription=Restore rendered webservices environment files\n\n[Service]\n"
            "Type=oneshot\nWorkingDirectory=/\nExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 " + runtime +
            '; for env_file in ' + source + '/*.env; do [ -e "$env_file" ] || continue; /usr/bin/install -m 0600 "$env_file" ' +
            runtime + "/; done'\nRemainAfterExit=yes\n").encode()


def check_stage(parent, name, expected, uid, gid, mode):
    fd = p.child_open(parent, name, FILE)
    try:
        require(m.regular(fd, uid, gid, mode, expected['sha256'])[1] == expected,
                'named/held fresh stage CAS changed before publication')
    finally: os.close(fd)


def check_published(parent, stage, name, staged, old):
    """Do not read/adopt a raced foreign stage; restore its original name."""
    actual = list(p.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
    if actual[:-1] == staged['identity'][:-1]: return
    if old is None:
        require(list(p.identity(os.stat(name, dir_fd=parent, follow_symlinks=False))) == actual,
                'foreign published stage raced again; retain names for disposition')
        m.rename(parent, name, stage)
    else:
        displaced = list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)))
        require(displaced[:-1] == old['identity'][:-1]
                and list(p.identity(os.stat(name, dir_fd=parent, follow_symlinks=False))) == actual,
                'foreign adjunct exchange raced again; retain names for disposition')
        m.rename(parent, stage, name, exchange=True)
    directory = os.open('.', DIR, dir_fd=parent)
    try: os.fsync(directory)
    finally: os.close(directory)
    raise Refused('foreign staged inode restored without reading/adoption; retained for disposition')


def environment_pin(seal):
    """Normalize the two EXISTING producer record shapes without dropping pins."""
    required = {'identity', 'mountId', 'sha256', 'mode', 'uid', 'gid', 'acl', 'defaultAcl'}
    require(isinstance(seal, dict) and required <= set(seal) <= required | {'dev', 'ino'}
            and isinstance(seal['identity'], list) and len(seal['identity']) == 9,
            'canonical environment producer pin shape differs')
    result = dict(seal, dev=seal['identity'][0], ino=seal['identity'][1])
    require(all(result[key] == value for key, value in seal.items()), 'environment producer inode pins disagree')
    return result


def verify_selected_files(observer):
    """Actual selected files, not an opaque completed JSON permission."""
    intent = observer.expected
    proof, custody = intent.get('nativeUnitFiles'), intent.get('nativeUnitFileCustody')
    require(isinstance(proof, dict) and isinstance(custody, dict)
            and proof.get('kind') == 'native-selected-unit-files' and proof.get('status') == 'completed'
            and proof.get('release') == str(observer.release) and proof.get('inputs') == intent['inputs']
            and proof.get('custodySha256') == p.sha(p.encoded(custody))
            and proof.get('activationAuthorized') is False and proof.get('readinessAuthorized') is False,
            'canonical selected unit file publication required before adjunct writer')
    expected = set()
    for scope, entry in n.inventory(observer.release).items():
        gid = 0 if scope == 'rootful' else observer.accounts[scope.removeprefix('rootless-')]['gid']
        for relative, seal in entry['files'].items():
            path = n.destination(scope, entry, relative); expected.add(str(path))
            parent = observer.open_host(path.parent, dict(entry, scope=scope))
            try:
                child = p.child_open(parent, path.name, FILE)
                try:
                    actual = m.regular(child, entry['uid'], gid, 0o644, seal['sha256'])[1]
                    require(actual == proof.get('files', {}).get(str(path)), 'actual selected unit file proof/inode/hash differs')
                finally: os.close(child)
            finally: os.close(parent)
    require(set(proof.get('files', {})) == expected, 'selected unit file proof namespace differs')


class Session:
    actor_directories = m.Session.actor_directories
    open_host = m.Session.open_host
    absent = m.Session.absent
    verify_overrides = m.Session.verify_overrides

    def __init__(self, root, release, intent):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.prior = n.strict(p.encoded(intent)); self.expected = self.prior
        self.fds = []; self.deadline = time.monotonic() + 120; self.closed = False
        self.record_pins = None; self.baseline = None; self.file_entries = {}; self.directory_entries = {}
        self.roles = {}; self.stages = {}; self.previous = None; self.old = None
        self.source_handles = {}; self.override_guards = {}
        try:
            require(os.geteuid() == 0 and self.prior.get('phase') == 'preparing'
                    and self.prior.get('release') == str(self.release) and self.release.parent == self.root / 'releases'
                    and 'nativeRuntimeEnvUnitCustody' not in self.prior and 'nativeRuntimeEnvUnits' not in self.prior,
                    'fresh exact preparing runtime-env adjunct transaction required')
            self.root_fd, self.root_chain = o.open_absolute(self.root); self.hold(self.root_fd)
            self.release_fd, self.release_chain = o.open_absolute(self.release); self.hold(self.release_fd)
            o.root_directory(os.fstat(self.root_fd), private=True); o.root_directory(os.fstat(self.release_fd), private=True)
            releases = self.hold(p.child_open(self.root_fd, 'releases', DIR))
            edge = self.hold(p.child_open(releases, self.release.name, DIR))
            require(p.custody_record(edge) == p.custody_record(self.release_fd), 'candidate NO_XDEV release edge differs')
            binding, observed = self.observe()
            self.metadata = binding['metadata']; self.rows = binding['rows']; self.ir = binding['ir']
            self.marker_sha = binding['markerSha256']
            self.accounts = {name: dict(uid=account.pw_uid, gid=account.pw_gid, user=account.pw_name)
                             for name, account in binding['accounts'].items()}
            scope, operator, marker = o.storage.authority(self.release)
            require(scope == binding['scope'] and marker == binding['marker'], 'canonical source provenance/marker differs')
            self.current = p.current_record(self.root_fd)
            old = observed.get('stop-only-previous-source')
            if old is not None:
                self.previous = p.canonical(old['release'])
                previous_fd, _ = o.open_absolute(self.previous); self.hold(previous_fd)
                snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
                try:
                    raw, _ = snap.root_file(previous_fd, 'installation-receipt.json')
                    self.old = n.strict(raw)
                finally: snap.close()
            self.plan = n.selection(self.release, self.previous)
            self.baseline = observed
            self.prepare_roles()
            verify_selected_files(self)
            self.prepare_files()
            self.prepare_overrides()
            self.check_stopped()
            self.custody = dict(schemaVersion=1, kind='native-runtime-env-unit-custody', release=str(self.release),
                inputs=self.expected['inputs'], current=self.current,
                stopOnlyPrevious=old, scopeMarkerSha256=binding['markerSha256'],
                roles={name: value['manifest'] for name, value in self.roles.items()},
                files={str(path): dict(sha256=p.sha(item['body']), uid=item['uid'], gid=item['gid'], mode=0o644,
                                      before=item['before'], stage=item['stage']) for path, item in self.file_entries.items()},
                activationAuthorized=False, readinessAuthorized=False, updaterOwned=False)
            self.verify()
        except BaseException:
            self.close(); raise

    def hold(self, fd):
        self.fds.append(fd); return fd

    def close(self):
        if not self.closed:
            for fd in reversed(self.fds): os.close(fd)
            self.fds = []; self.closed = True

    def observe(self):
        require(not self.closed and time.monotonic() < self.deadline, 'runtime-env unit custody expired')
        snap = v.Snapshot(self.root, self.release, self.expected, False, self.deadline)
        try:
            binding = snap.candidate_binding()
            observed_records = (binding['pin'], binding['rpin'])
            if self.record_pins is None: self.record_pins = observed_records
            require(self.record_pins == observed_records, 'root records inode CAS changed within preparing epoch')
            self.cas = p.sha(binding['raw'])
            observed = snap.sweep()
            excluded = {str(self.root / '.install-intent.json'), str(self.release / 'installation-receipt.json')}
            observed = {key: value for key, value in observed.items() if key not in excluded}
            # Snapshot descriptors close below; return only semantic data, not its FDs.
            return dict(metadata=binding['metadata'], rows=binding['rows'], ir=binding['ir'], accounts=binding['accounts'],
                        scope=binding['scope'], marker=binding['marker'], markerSha256=snap.marker_sha), observed
        finally: snap.close()

    def read_store(self, manifest):
        if not manifest['files']:
            require(manifest['store'] is None, 'empty role store must be absent authority')
            return
        ns = _runtime
        fd = ns['walk'](p.canonical(manifest['stateStore']), p.canonical(manifest['sourceAnchor']), manifest['sourceDirectories'])
        try:
            require(ns['record'](fd) == ns['portable'](manifest['store']), 'persistent role store identity differs')
            store_key = (manifest['role'], '')
            if store_key not in self.source_handles:
                self.source_handles[store_key] = self.hold(os.dup(fd))
            require(ns['record'](self.source_handles[store_key]) == ns['portable'](manifest['store']), 'held role source store changed')
            for name, seal in manifest['files'].items():
                child = p.child_open(fd, name, FILE)
                try:
                    _, rec = m.regular(child, manifest['uid'], manifest['gid'], 0o600, seal['sha256'])
                    require(rec == seal, 'canonical persistent environment file identity differs')
                    key = (manifest['role'], name)
                    if key not in self.source_handles:
                        self.source_handles[key] = self.hold(os.dup(child))
                    require(m.regular(self.source_handles[key], manifest['uid'], manifest['gid'], 0o600, seal['sha256'])[1] == seal,
                            'held role source environment inode differs')
                finally: os.close(child)
        finally: os.close(fd)

    def source_directories(self, store, anchor):
        # Root preparation can inspect all facts; the embedded ACTOR uses
        # O_PATH to traverse execute-only shared ancestors, never O_RDONLY.
        ns = _runtime; current = Path('/'); fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        result = {str(current): dict(ns['record'](fd), mountId=ns['_mount'](fd))}; anchored = False
        try:
            for part in store.parts[1:]:
                child = ns['child'](fd, part, ns['PATH'], anchored)
                os.close(fd); fd = child; current /= part
                result[str(current)] = dict(ns['record'](fd), mountId=ns['_mount'](fd))
                anchored |= current == anchor
            return result
        finally: os.close(fd)

    def prepare_roles(self):
        handoff = self.expected.get('rootfulEnvironmentStoreHandoff')
        custody = self.expected.get('rootfulEnvCustody')
        require(isinstance(handoff, dict) and isinstance(custody, dict)
                and handoff.get('kind') == 'rootful-persistent-environment' and handoff.get('status') == 'completed'
                and handoff.get('release') == str(self.release) and handoff.get('inputs') == self.expected['inputs']
                and handoff.get('stateStore') == str(self.root / 'runtime-env') and handoff.get('runtimeDeferred') is True
                and handoff.get('activationAuthorized') is False and handoff.get('readinessAuthorized') is False
                and handoff.get('sourceCustodySha256') == p.sha(p.encoded(custody)), 'canonical rootful environment handoff required')
        root_names = {name + '.env' for name, service in self.ir['services'].items()
                      if service.get('placement') == 'rootful' and p.declarations(service)}
        require(set(handoff.get('files', {})) == root_names
                and set(custody.get('files', {})) == root_names
                and all(rec['sha256'] == custody['files'][name]['sha256'] for name, rec in handoff['files'].items()),
                'rootful declaration/environment seal membership differs')
        specs = [('rootful', 0, 0, 'root', self.root, handoff)]
        for row in self.rows:
            actor = self.accounts[row['name']]
            proof = self.expected['domainRuntimeProjections'][row['name']]['environmentStoreHandoff']
            specs.append(('rootless-' + row['name'], row['uid'], actor['gid'], row['user'], p.canonical(row['stateRoot']), proof))
        for role, uid, gid, user, anchor, proof in specs:
            files = proof['files']; store = anchor / 'runtime-env'
            require(proof.get('stateStore') == str(store) and proof.get('runtimeDeferred') is True
                    and proof.get('status') == 'completed', 'canonical role environment handoff differs')
            custody_parent = self.release if uid == 0 else anchor / 'releases' / self.release.name
            manifest = dict(schemaVersion=1, kind='exact-runtime-environment', release=str(self.release), role=role, uid=uid, gid=gid, user=user,
                inputsSha256=p.sha(p.encoded(self.expected['inputs'])),
                scopeMarkerSha256=self.marker_sha,
                sourceCustodySha256=proof['sourceCustodySha256' if uid == 0 else 'custodySha256'],
                custodyFile=str(custody_parent / 'runtime-env-copy-custody.json'),
                custodyDirectories=self.source_directories(custody_parent, anchor),
                sourceAnchor=str(anchor), stateStore=str(store), store=proof['store'],
                sourceDirectories=self.source_directories(store, anchor) if files else {},
                files={name: environment_pin(seal) for name, seal in files.items()},
                runtimeStore=str(HOST / ('run/webservices' if uid == 0 else 'run/user/' + str(uid) + '/webservices')))
            self.read_store(manifest)
            folder = HOST / 'etc/systemd/system' if uid == 0 else HOST / 'home' / user / '.config/systemd/user'
            entry = dict(scope=role, uid=uid, user=user)
            self.roles[role] = dict(manifest=manifest, folder=folder, entry=entry, uid=uid, gid=gid)

    def old_bodies(self, role):
        if self.old is None: return set(), set()
        manifest = self.roles[role]['manifest']
        # Same-scope/account/source custody has already been validated by the
        # current canonical verifier's protected-current source binding.
        old_manifest = self.old.get('nativeRuntimeEnvUnitCustody', {}).get('roles', {}).get(role)
        allowed = {legacy_unit(manifest['stateStore'], manifest['runtimeStore'])}
        if old_manifest is not None:
            require(old_manifest.get('role') == role and old_manifest.get('uid') == manifest['uid']
                    and old_manifest.get('gid') == manifest['gid'] and old_manifest.get('stateStore') == manifest['stateStore']
                    and old_manifest.get('runtimeStore') == manifest['runtimeStore'], 'old exact runtime manifest role differs')
            allowed.add(render_unit(old_manifest))
        return allowed, {render_dropin()}

    def prepare_files(self):
        for role, spec in self.roles.items():
            folder = spec['folder']; entry = spec['entry']
            parent = self.hold(self.open_host(folder, entry))
            self.directory_entries[folder] = dict(fd=parent, pin=p.custody_record(parent), entry=entry, new=False)
            drop = folder / 'webservices.target.d'
            try: fd = p.child_open(parent, drop.name, DIR)
            except FileNotFoundError: fd = None
            if fd is not None:
                self.hold(fd); pin = p.custody_record(fd)
                require((pin['uid'], pin['gid']) == (spec['uid'], spec['gid']) and pin['mode'] in (0o700, 0o750, 0o755)
                        and not pin['acl'] and not pin['defaultAcl'], 'exact target drop-in directory custody differs')
                self.directory_entries[drop] = dict(fd=fd, pin=pin, entry=entry, new=False)
            else:
                self.directory_entries[drop] = dict(fd=None, pin=None, entry=entry, new=True)
            old_unit, old_drop = self.old_bodies(role)
            for path, body, allowed in ((folder / UNIT, render_unit(spec['manifest']), old_unit),
                                        (drop / DROPIN, render_dropin(), old_drop)):
                directory = self.directory_entries[path.parent]; before = None
                if directory['fd'] is not None:
                    try: child = p.child_open(directory['fd'], path.name, FILE)
                    except FileNotFoundError: child = None
                    if child is not None:
                        self.hold(child); existing, before = m.regular(child, spec['uid'], spec['gid'], 0o644)
                        require(existing in allowed, 'existing runtime helper/drop-in lacks exact old source authority')
                self.file_entries[path] = dict(body=body, before=before, uid=spec['uid'], gid=spec['gid'], role=role,
                    held=child if directory['fd'] is not None and before is not None else None,
                    stage='.runtime-env-unit-' + secrets.token_hex(16))

    def prepare_overrides(self):
        for role, spec in self.roles.items():
            folder, entry = spec['folder'], spec['entry']
            if not spec['uid']:
                roots = [HOST / name for name in ('etc/systemd/system', 'run/systemd/system',
                    'usr/lib/systemd/system', 'usr/local/lib/systemd/system', 'etc/systemd/system.control',
                    'run/systemd/system.control', 'run/systemd/transient')]
            else:
                home = HOST / 'home' / entry['user']; runtime = HOST / 'run/user' / str(entry['uid'])
                roots = [home / name for name in ('.config/systemd/user', '.config/systemd/user.control', '.local/share/systemd/user')]
                roots += [HOST / name for name in ('etc/systemd/user', 'run/systemd/user', 'usr/lib/systemd/user', 'usr/local/lib/systemd/user')]
                roots += [runtime / name for name in ('systemd/user', 'systemd/user.control', 'systemd/transient')]
            for parent in roots:
                if parent != folder:
                    self.absent(parent / UNIT, entry)
                    self.absent(parent / 'webservices.target.d', entry)
                for name in m.Session.dropin_names(UNIT): self.absent(parent / name, entry)

    def check_stopped(self):
        # All other selected units use the existing canonical gate unchanged.
        # The top target is checked separately so ONLY our independently
        # source-validated adjunct drop-in may appear in its DropInPaths.
        plan = n.strict(p.encoded(self.plan)); root = plan['scopes']['rootful']
        root['units'].remove('webservices.target')
        m.stopped(self.release, plan)
        allowed_drop = HOST / 'etc/systemd/system/webservices.target.d' / DROPIN
        import subprocess
        for unit in ('webservices.target', UNIT):
            result = subprocess.run(['systemctl', 'show', unit, '-p', 'Id', '-p', 'Names', '-p', 'ActiveState',
                '-p', 'MainPID', '-p', 'Job', '-p', 'LoadState', '-p', 'FragmentPath', '-p', 'SourcePath', '-p', 'DropInPaths'],
                capture_output=True, text=True, timeout=15)
            props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            expected_drop = str(allowed_drop) if self.file_entries[allowed_drop]['before'] is not None else ''
            require(result.returncode == 0 and props.get('Id') == unit and props.get('ActiveState') in ('inactive', 'failed')
                    and props.get('MainPID') in ('0', '') and props.get('Job') == ''
                    and props.get('LoadState') in ('not-found', 'loaded')
                    and set(props.get('Names', '').split()) <= {unit}
                    and props.get('DropInPaths') in ({'', expected_drop} if unit == 'webservices.target' else {''}),
                    'runtime helper/top target not canonically stopped or has foreign overrides')
            if props['LoadState'] == 'loaded':
                require(props.get('FragmentPath') == str(HOST / 'etc/systemd/system' / unit)
                        and props.get('SourcePath') == '' and props.get('Names') == unit, 'runtime adjunct loaded source differs')

    def verify(self):
        binding, observed = self.observe()
        require(observed == self.baseline and p.current_record(self.root_fd) == self.current,
                'invariant source/projection/marker/current custody changed')
        actual = n.selection(self.release, self.previous)
        wanted = n.strict(p.encoded(self.plan)); wanted['sources']['candidate']['receipt'] = dict(sha256=self.cas, phase='preparing')
        require(actual == wanted, 'runtime-env source selection changed')
        verify_selected_files(self)
        for role in self.roles.values(): self.read_store(role['manifest'])
        for path, directory in self.directory_entries.items():
            if directory['fd'] is None:
                parent = self.directory_entries[path.parent]['fd']
                try: os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: continue
                raise Refused('fresh target drop-in directory appeared')
            fd = self.open_host(path.parent, directory['entry']) if path.name == 'webservices.target.d' else self.open_host(path, directory['entry'])
            try:
                if path.name == 'webservices.target.d':
                    check = p.child_open(fd, path.name, DIR)
                    try: rec = p.custody_record(check)
                    finally: os.close(check)
                else: rec = p.custody_record(fd)
                require(rec == directory['pin'] == p.custody_record(directory['fd']), 'held/named adjunct parent changed')
            finally: os.close(fd)
        self.verify_overrides()
        for path, directory in self.directory_entries.items():
            if path.name == 'webservices.target.d' and directory['fd'] is not None:
                require(all(not name.endswith('.conf') or name == DROPIN for name in os.listdir(directory['fd'])),
                        'foreign affecting target drop-in preserved; owning disposition required')
        for path, item in self.file_entries.items():
            parent = self.directory_entries[path.parent]['fd']
            if parent is None: continue
            try: child = p.child_open(parent, path.name, FILE)
            except FileNotFoundError:
                require(item['before'] is None, 'selected adjunct disappeared'); continue
            try:
                _, pin = m.regular(child, item['uid'], item['gid'], 0o644)
                require(pin == item['before'], 'exact runtime adjunct inode/hash CAS changed')
                if item['held'] is not None:
                    require(m.regular(item['held'], item['uid'], item['gid'], 0o644)[1] == pin, 'held adjunct changed')
            finally: os.close(child)
        self.check_stopped()

    def publish(self, intent):
        value = n.strict(p.encoded(intent))
        require(value == dict(self.prior, nativeRuntimeEnvUnitCustody=self.custody), 'adjunct journal changed beyond exact custody')
        self.expected = value; self.record_pins = None
        self.verify()
        for path, directory in self.directory_entries.items():
            if not directory['new']: continue
            parent = self.directory_entries[path.parent]['fd']
            os.mkdir(path.name, 0o700, dir_fd=parent)
            fd = self.hold(p.child_open(parent, path.name, DIR)); rec = p.custody_record(fd)
            require((rec['uid'], rec['gid'], rec['mode']) == (0, 0, 0o700) and not rec['acl'] and not rec['defaultAcl'],
                    'fresh source-derived adjunct directory custody differs')
            require(os.listdir(fd) == [], 'new derived adjunct directory is not empty')
            os.fchown(fd, self.roles[directory['entry']['scope']]['uid'], self.roles[directory['entry']['scope']]['gid'])
            os.fsync(fd); os.fsync(parent)
            directory['fd'], directory['pin'], directory['new'] = fd, p.custody_record(fd), False
        published = {}
        for path, item in self.file_entries.items():
            self.verify(); parent = self.directory_entries[path.parent]['fd']; old = item['before']
            fd = self.hold(os.open(item['stage'], os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent))
            rec = p.custody_record(fd)
            require((rec['uid'], rec['gid'], rec['mode']) == (0, 0, 0o600) and not rec['acl'] and not rec['defaultAcl']
                    and os.fstat(fd).st_nlink == 1, 'fresh adjunct stage custody differs')
            view = memoryview(item['body'])
            while view:
                count = os.write(fd, view); require(count > 0, 'adjunct short write'); view = view[count:]
            os.fchown(fd, item['uid'], item['gid']); os.fchmod(fd, 0o644); os.fsync(fd)
            _, staged = m.regular(fd, item['uid'], item['gid'], 0o644, p.sha(item['body']))
            self.verify()
            check_stage(parent, item['stage'], staged, item['uid'], item['gid'], 0o644)
            m.rename(parent, item['stage'], path.name, exchange=old is not None)
            if old is not None:
                displaced_id = list(p.identity(os.stat(item['stage'], dir_fd=parent, follow_symlinks=False)))
                try:
                    require(displaced_id[:-1] == old['identity'][:-1], 'adjunct displaced inode differs')
                    displaced = p.child_open(parent, item['stage'], FILE)
                    try: _, removed = m.regular(displaced, item['uid'], item['gid'], 0o644, old['sha256'])
                    finally: os.close(displaced)
                    require(m.renamed(removed, old), 'adjunct displaced source CAS differs')
                except (ValueError, OSError):
                    current = list(p.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
                    require(current[:-1] == staged['identity'][:-1]
                            and list(p.identity(os.stat(item['stage'], dir_fd=parent, follow_symlinks=False))) == displaced_id,
                            'adjunct exchange raced again; both inodes retained')
                    m.rename(parent, item['stage'], path.name, exchange=True); os.fsync(parent)
                    raise Refused('adjunct foreign exchange restored without adoption; stage retained') from None
            check_published(parent, item['stage'], path.name, staged, old)
            actual = self.hold(p.child_open(parent, path.name, FILE))
            _, pin = m.regular(actual, item['uid'], item['gid'], 0o644, p.sha(item['body']))
            require(m.renamed(pin, staged), 'published adjunct inode differs')
            item['before'], item['held'] = pin, actual
            if old is not None:
                self.verify()
                check = p.child_open(parent, item['stage'], FILE)
                try: require(m.regular(check, item['uid'], item['gid'], 0o644, old['sha256'])[1] == removed, 'displaced adjunct changed')
                finally: os.close(check)
                os.unlink(item['stage'], dir_fd=parent)
            os.fsync(parent); published[str(path)] = pin
        self.verify()
        return dict(schemaVersion=1, kind='native-runtime-env-units', status='completed', release=str(self.release),
                    inputs=self.expected['inputs'], intentSha256=self.cas, receiptSha256=self.cas,
                    custodySha256=p.sha(p.encoded(self.custody)), files=published,
                    runtimeDeferred=True, updaterOwned=False, activationAuthorized=False, readinessAuthorized=False)


class PreparedUnits:
    """Read-only persistent/source/unit observer: no Session or runtime bypass.

    Actual Snapshot(False) preserves the caller's exact phase/dual records.
    No /run anchors, runtime files, service/socket/manager operations or writes.
    """
    actor_directories = m.Session.actor_directories
    open_host = m.Session.open_host

    def __init__(self, root, release, intent):
        self.root, self.release = p.canonical(str(root)), p.canonical(str(release))
        self.intent = n.strict(p.encoded(intent)); self.expected = self.intent
        self.deadline = time.monotonic() + 120; self.fds = []; self.closed = False
        self.record_pins = None; self.baseline = None; self.receipts = {}
        require(os.geteuid() == 0 and self.release.parent == self.root / 'releases'
                and self.intent.get('release') == str(self.release)
                and self.intent.get('phase') in ('preparing', 'units-selected', 'building', 'starting', 'active'),
                'Root copy issuer requires exact allowed canonical phase')
        self.custody = self.intent.get('nativeRuntimeEnvUnitCustody')
        self.proof = self.intent.get('nativeRuntimeEnvUnits')
        require(isinstance(self.custody, dict) and isinstance(self.proof, dict)
                and self.custody.get('kind') == 'native-runtime-env-unit-custody'
                and self.proof.get('kind') == 'native-runtime-env-units' and self.proof.get('status') == 'completed'
                and self.proof.get('release') == str(self.release) and self.proof.get('inputs') == self.intent.get('inputs')
                and self.proof.get('custodySha256') == p.sha(p.encoded(self.custody))
                and self.proof.get('activationAuthorized') is False and self.proof.get('readinessAuthorized') is False,
                'completed exact adjunct/source unit proof required before Root copy seal')
        self.roles = self.custody.get('roles')
        require(isinstance(self.roles, dict) and set(self.roles) == {'rootful'} | {'rootless-' + name for name in n.IDENTITIES},
                'all eight exact runtime copy manifests required')

    def hold(self, fd):
        self.fds.append(fd); return fd

    def close(self):
        if not self.closed:
            for fd in reversed(self.fds): os.close(fd)
            self.fds = []; self.closed = True

    def snapshot(self):
        return v.Snapshot(self.root, self.release, self.intent, False, self.deadline)

    def verify(self):
        require(not self.closed and time.monotonic() < self.deadline, 'Root source observer deadline exceeded')
        snap = self.snapshot()
        temporary = []
        try:
            binding = snap.candidate_binding()
            controls = (binding['pin'], binding['rpin'])
            if self.record_pins is None: self.record_pins = controls
            require(controls == self.record_pins, 'Root issuer record inode CAS changed')
            self.cas = p.sha(binding['raw'])
            observed = snap.sweep()
            scope, operator, marker = o.storage.authority(self.release)
            require(scope == binding['scope'] and marker == binding['marker'], 'Root issuer provenance/marker differs')
            self.accounts = {name: dict(uid=account.pw_uid, gid=account.pw_gid, user=account.pw_name)
                             for name, account in binding['accounts'].items()}
            verify_selected_files(self)
            rootful = self.intent.get('rootfulEnvironmentStoreHandoff')
            root_custody = self.intent.get('rootfulEnvCustody')
            require(isinstance(rootful, dict) and isinstance(root_custody, dict)
                    and rootful.get('schemaVersion') == 1
                    and rootful.get('status') == 'completed' and rootful.get('kind') == 'rootful-persistent-environment'
                    and rootful.get('release') == str(self.release) and rootful.get('inputs') == self.intent['inputs']
                    and rootful.get('stateStore') == str(self.root / 'runtime-env') and rootful.get('runtimeDeferred') is True
                    and rootful.get('sourceCustodySha256') == p.sha(p.encoded(root_custody))
                    and rootful.get('activationAuthorized') is False and rootful.get('readinessAuthorized') is False,
                    'Root issuer actual rootful environment proof differs')
            expected_files = set()
            for role, manifest in self.roles.items():
                uid = 0 if role == 'rootful' else n.IDENTITIES[role.removeprefix('rootless-')][0]
                account = None if uid == 0 else self.accounts[role.removeprefix('rootless-')]
                gid, user = (0, 'root') if account is None else (account['gid'], account['user'])
                row = None if uid == 0 else next(row for row in binding['rows'] if row['uid'] == uid)
                anchor = self.root if row is None else p.canonical(row['stateRoot'])
                source = rootful if row is None else self.intent['domainRuntimeProjections'][row['name']]['environmentStoreHandoff']
                parent = self.release if row is None else anchor / 'releases' / self.release.name
                runtime = HOST / ('run/webservices' if uid == 0 else 'run/user/' + str(uid) + '/webservices')
                require(manifest.get('schemaVersion') == 1 and manifest.get('kind') == 'exact-runtime-environment'
                        and (manifest.get('role'), manifest.get('uid'), manifest.get('gid'), manifest.get('user')) == (role, uid, gid, user)
                        and manifest.get('release') == str(self.release)
                        and manifest.get('inputsSha256') == p.sha(p.encoded(self.intent['inputs']))
                        and manifest.get('scopeMarkerSha256') == snap.marker_sha
                        and manifest.get('sourceCustodySha256') == source.get('sourceCustodySha256' if uid == 0 else 'custodySha256')
                        and manifest.get('sourceAnchor') == str(anchor)
                        and manifest.get('stateStore') == str(anchor / 'runtime-env')
                        and manifest.get('runtimeStore') == str(runtime)
                        and manifest.get('custodyFile') == str(parent / 'runtime-env-copy-custody.json')
                        and manifest.get('files') == {name: environment_pin(seal) for name, seal in source.get('files', {}).items()}
                        and manifest.get('store') == source.get('store'),
                        'Root issuer manifest role/source/current environment seal differs')
                declarations = {name + '.env' for name, service in binding['ir']['services'].items()
                    if (service.get('placement') == 'rootful' if uid == 0 else
                        service.get('placement') == 'rootless' and service.get('rootlessDomain') == row['name'])
                    and p.declarations(service)}
                require(set(manifest['files']) == declarations, 'Root issuer env name/IR declaration set differs')
                folder = HOST / 'etc/systemd/system' if uid == 0 else HOST / 'home' / user / '.config/systemd/user'
                entry = dict(scope=role, uid=uid, user=user)
                for path, body in ((folder / UNIT, render_unit(manifest)), (folder / 'webservices.target.d' / DROPIN, render_dropin())):
                    expected_files.add(str(path))
                    if path.name == DROPIN:
                        outer = self.open_host(folder, entry)
                        try: directory = p.child_open(outer, 'webservices.target.d', DIR)
                        finally: os.close(outer)
                        temporary.append(directory)
                        rec = p.custody_record(directory)
                        require(all(not name.endswith('.conf') or name == DROPIN for name in os.listdir(directory)),
                                'foreign target override preserved; owning disposition required')
                        require((rec['uid'], rec['gid']) == (uid, gid) and rec['mode'] in (0o700, 0o750, 0o755)
                                and not rec['acl'] and not rec['defaultAcl'], 'Root issuer drop-in parent custody differs')
                    else:
                        directory = self.open_host(folder, entry); temporary.append(directory)
                    fd = p.child_open(directory, path.name, FILE); temporary.append(fd)
                    _, actual = m.regular(fd, uid, gid, 0o644, p.sha(body))
                    require(actual == self.proof.get('files', {}).get(str(path)), 'Root issuer actual unit source/inode/hash differs')
                    observed[str(path)] = actual
                observed['persistent-store:' + role] = _runtime['inspect_source'](manifest)
            require(set(self.proof.get('files', {})) == expected_files, 'Root issuer unit proof exact namespace differs')
            if self.baseline is None: self.baseline = observed
            require(self.baseline == observed, 'prepared source/store/unit custody changed across sweeps')
            return observed
        finally:
            for fd in reversed(temporary): os.close(fd)
            snap.close()

    def old_receipt(self, parent, name, manifest):
        try: fd = p.child_open(parent, name, FILE)
        except FileNotFoundError: return None
        self.hold(fd); info = os.fstat(fd)
        mode = 0o400 if manifest['uid'] == 0 else 0o440
        _, rec = m.regular(fd, 0, manifest['gid'], mode)
        value = n.strict(os.pread(fd, n.LIMIT + 1, 0))
        _runtime['receipt_shape'](manifest, value, current_boot=False)
        return rec

    def cues(self):
        result = {}
        for role, manifest in self.roles.items():
            path = p.canonical(manifest['custodyFile'])
            parent = _runtime['walk'](path.parent, p.canonical(manifest['sourceAnchor']), manifest['custodyDirectories'])
            try: result[role] = self.old_receipt(parent, path.name, manifest)
            finally: os.close(parent)
        return result


class RunningSeal(PreparedUnits):
    """Post-restore Root issuer; actual runtime proof remains mandatory."""
    def __init__(self, root, release, intent):
        super().__init__(root, release, intent)
        self.runtime_baseline = None

    def snapshot(self):
        return v.Snapshot(self.root, self.release, self.intent,
                          self.intent['phase'] in ('starting', 'active'), self.deadline)

    def verify(self):
        super().verify()
        copies = {role: _runtime['inspect_copy'](manifest) for role, manifest in self.roles.items()}
        if self.runtime_baseline is None: self.runtime_baseline = copies
        require(self.runtime_baseline == copies, 'actual post-restore runtime/boot custody changed')
        return copies

    def check_role(self, role, original):
        # Whole-source/unit/role sweeps bracket the issuer. Each individual
        # receipt additionally has a fresh exact-root CAS and actual per-role
        # source/runtime observation, without an O(roles^2) full sweep loop.
        snap = v.Snapshot(self.root, self.release, self.intent,
                          self.intent['phase'] in ('starting', 'active'), self.deadline)
        try:
            binding = snap.candidate_binding()
            require((binding['pin'], binding['rpin']) == self.record_pins
                    and p.sha(binding['raw']) == self.cas, 'Root issuer per-role root CAS changed')
            require(_runtime['inspect_copy'](self.roles[role]) == original,
                    'Root issuer per-role source/runtime/boot custody changed')
        finally: snap.close()

    def issue(self):
        copies = self.verify()
        # Validate EVERY old receipt first; never partially overwrite a foreign one.
        for role, manifest in self.roles.items():
            path = p.canonical(manifest['custodyFile'])
            parent = _runtime['walk'](path.parent, p.canonical(manifest['sourceAnchor']), manifest['custodyDirectories'])
            self.hold(parent)
            old = self.old_receipt(parent, path.name, manifest)
            self.receipts[role] = dict(path=path, parent=parent, old=old, stage='.runtime-copy-seal-' + secrets.token_hex(16))
        self.verify()
        result = {}
        for role, manifest in self.roles.items():
            entry = self.receipts[role]; path, parent, old = entry['path'], entry['parent'], entry['old']
            self.check_role(role, copies[role])
            # Root can read a700 actor slot; obtain directory FD solely for fsync.
            directory = os.open('.', DIR, dir_fd=parent)
            self.hold(directory)
            require(_runtime['record'](directory) == _runtime['record'](parent), 'Root receipt parent FD differs')
            stage = entry['stage']; mode = 0o400 if manifest['uid'] == 0 else 0o440
            fd = self.hold(os.open(stage, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=parent))
            initial = p.custody_record(fd)
            require((initial['uid'], initial['gid'], initial['mode']) == (0, 0, 0o600)
                    and not initial['acl'] and not initial['defaultAcl'] and os.fstat(fd).st_nlink == 1,
                    'fresh Root copy receipt stage custody differs')
            body = p.encoded(copies[role]); view = memoryview(body)
            while view:
                count = os.write(fd, view); require(count > 0, 'Root receipt short write'); view = view[count:]
            os.fchown(fd, 0, manifest['gid']); os.fchmod(fd, mode); os.fsync(fd)
            _, staged = m.regular(fd, 0, manifest['gid'], mode, p.sha(body))
            actual_old = self.old_receipt(parent, path.name, manifest)
            require(actual_old == old, 'Root receipt pre-publication CAS differs')
            check_stage(parent, stage, staged, 0, manifest['gid'], mode)
            m.rename(parent, stage, path.name, exchange=old is not None)
            if old is not None:
                displaced_id = list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)))
                try:
                    require(displaced_id[:-1] == old['identity'][:-1], 'Root receipt displaced inode differs')
                    displaced = self.hold(p.child_open(parent, stage, FILE))
                    _, removed = m.regular(displaced, 0, manifest['gid'], mode, old['sha256'])
                    require(m.renamed(removed, old), 'Root receipt displaced custody differs')
                except (ValueError, OSError):
                    named_id = list(p.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
                    require(named_id[:-1] == staged['identity'][:-1]
                            and list(p.identity(os.stat(stage, dir_fd=parent, follow_symlinks=False))) == displaced_id,
                            'Root receipt exchange raced twice; both inodes retained')
                    m.rename(parent, stage, path.name, exchange=True); os.fsync(directory)
                    raise Refused('foreign Root receipt restored; stage retained') from None
            check_published(parent, stage, path.name, staged, old)
            published = self.hold(p.child_open(parent, path.name, FILE))
            _, record = m.regular(published, 0, manifest['gid'], mode, p.sha(body))
            require(m.renamed(record, staged), 'published Root receipt inode changed')
            self.check_role(role, copies[role])
            if old is not None:
                check = self.hold(p.child_open(parent, stage, FILE))
                require(m.regular(check, 0, manifest['gid'], mode, old['sha256'])[1] == removed, 'displaced Root receipt changed')
                os.unlink(stage, dir_fd=parent)
            os.fsync(directory)
            result[role] = dict(path=str(path), receipt=record, copy=copies[role])
        self.verify()
        return dict(schemaVersion=1, kind='root-runtime-copy-observation', status='completed', release=str(self.release),
                    inputs=self.intent['inputs'], intentSha256=self.cas, receiptSha256=self.cas,
                    copies=result, bootId=_runtime['_boot'](), activationAuthorized=False, readinessAuthorized=False,
                    resetAuthorized=False, journalWritten=False)


def verify_prepared_units(root, release, intent):
    observer = PreparedUnits(root, release, intent)
    try:
        source = observer.verify(); cues = observer.cues()
        require(source == observer.verify() and cues == observer.cues(), 'prepared persistent/unit/cue source changed')
        return dict(schemaVersion=1, kind='native-prepared-runtime-env-unit-observation', status='completed',
                    release=str(observer.release), inputs=observer.intent['inputs'], intentSha256=observer.cas,
                    receiptSha256=observer.cas, bindingSha256=p.sha(p.encoded(dict(source=source, cues=cues))),
                    sourceSha256=p.sha(p.encoded(source)), copyCustodySha256=p.sha(p.encoded(cues)),
                    selectionSourceSha256=p.sha(p.encoded({name: pin for name, pin in source.items()
                        if name not in {str(observer.root / '.install-intent.json'),
                                        str(observer.release / 'installation-receipt.json')}})),
                    runningEnvironmentChecked=False, journalWritten=False,
                    activationAuthorized=False, readinessAuthorized=False, resetAuthorized=False)
    finally: observer.close()


def verify_running_copies(root, release, intent):
    """Read ONLY actual source/copies and the already Root-issued observation.

    No issuance, restoration, publication or journal mutation. The original
    issuer CAS is historical evidence, not the current record CAS or a permit.
    Current private records and all physical source/copy/cue pins are freshly
    validated twice by the existing canonical observers under the held lock.
    """
    observer = RunningSeal(root, release, intent)
    prepared = None
    try:
        require(observer.intent.get('phase') in ('building', 'starting', 'active'),
                'running copy consumption requires selected building/starting/active source')
        proof = observer.intent.get('nativeRuntimeEnvironmentCopies')
        keys = {'schemaVersion', 'kind', 'status', 'release', 'inputs', 'intentSha256',
                'receiptSha256', 'copies', 'bootId', 'activationAuthorized', 'readinessAuthorized',
                'resetAuthorized', 'journalWritten'}
        require(isinstance(proof, dict) and set(proof) == keys
                and type(proof.get('schemaVersion')) is int and proof['schemaVersion'] == 1
                and proof.get('kind') == 'root-runtime-copy-observation' and proof.get('status') == 'completed'
                and proof.get('release') == str(observer.release)
                and p.encoded(proof.get('inputs')) == p.encoded(observer.intent.get('inputs'))
                and isinstance(proof.get('intentSha256'), str) and n.HEX.fullmatch(proof['intentSha256'])
                and proof.get('receiptSha256') == proof['intentSha256']
                and isinstance(proof.get('bootId'), str) and proof['bootId'] == _runtime['_boot']()
                and isinstance(proof.get('copies'), dict) and set(proof['copies']) == set(observer.roles)
                and all(proof.get(key) is False for key in
                        ('activationAuthorized', 'readinessAuthorized', 'resetAuthorized', 'journalWritten')),
                'exact typed current-boot Root runtime-copy observation required')
        prepared = PreparedUnits(root, release, observer.intent)
        source = prepared.verify()
        copies = observer.verify()
        cues = observer.cues()
        for role, manifest in observer.roles.items():
            entry = proof['copies'][role]
            cue = cues[role]
            require(isinstance(entry, dict) and set(entry) == {'path', 'copy', 'receipt'}
                    and entry.get('path') == manifest['custodyFile']
                    and isinstance(entry.get('copy'), dict) and isinstance(entry.get('receipt'), dict)
                    and isinstance(cue, dict)
                    and p.encoded(entry['copy']) == p.encoded(copies[role])
                    and p.encoded(entry['receipt']) == p.encoded(cue)
                    and cue.get('sha256') == p.sha(p.encoded(copies[role])),
                    'Root observation copy/path/original receipt differs from actual physical custody')
        require(source == prepared.verify() and copies == observer.verify() and cues == observer.cues()
                and prepared.cas == observer.cas and proof['bootId'] == _runtime['_boot'](),
                'current Root source/copy/cue/boot custody changed across read-only sweeps')
        # Legitimate phase publication rewrites precisely these two records.
        # Their current bytes/inodes/CAS remain mandatory above; only the stable
        # physical binding omits them, never an input, source, anchor or cue.
        records = {str(observer.root / '.install-intent.json'),
                   str(observer.release / 'installation-receipt.json')}
        physical_source = {name: pin for name, pin in source.items() if name not in records}
        return dict(schemaVersion=1, kind='root-runtime-copy-observation-verified', status='completed',
                    release=str(observer.release), inputs=observer.intent['inputs'],
                    intentSha256=observer.cas, receiptSha256=observer.cas, bootId=proof['bootId'],
                    bindingSha256=p.sha(p.encoded(dict(source=physical_source, copies=copies, cues=cues))),
                    sourceSha256=p.sha(p.encoded(source)), copyCustodySha256=p.sha(p.encoded(cues)),
                    selectionSourceSha256=p.sha(p.encoded(physical_source)),
                    runningEnvironmentChecked=True, activationAuthorized=False, readinessAuthorized=False,
                    resetAuthorized=False, journalWritten=False)
    finally:
        if prepared is not None: prepared.close()
        observer.close()


def seal_running_copies(root, release, intent):
    issuer = RunningSeal(root, release, intent)
    try: return issuer.issue()
    finally: issuer.close()


def prepare_custody(root, release, intent):
    key = str(root), str(release)
    require(key not in _sessions, 'unconsumed runtime-env unit custody exists')
    session = Session(root, release, intent); _sessions[key] = session
    return n.strict(p.encoded(session.custody))


def publish(root, release, intent):
    session = _sessions.pop((str(root), str(release)), None)
    require(session is not None, 'same-process retained runtime-env unit FDs required')
    try: return session.publish(intent)
    finally: session.close()


if __name__ == '__main__':
    raise SystemExit('in-process canonical Root installer API only')
