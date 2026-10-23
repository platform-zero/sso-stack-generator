#!/usr/bin/env python3
"""Prepare explicit fresh synthetic owner through native full realm import.

Private values arrive ONLY as six NUL-delimited stdin fields. No user/admin API,
account adoption, live database mutation, automatic restart or credential output.
Existing realms are never overwritten; native import skips them and subsequent
exact-subject verification must reject missing/different users.
"""
import argparse
import types
import json
import os
from pathlib import Path
import stat
import sys


def directory(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('noncanonical owner import directory')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def read_file(parent,name,limit):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit or info.st_mode&0o022:
            raise ValueError('unsafe owner import file')
        data=os.read(fd,limit+1)
        if len(data)>limit:raise ValueError('oversized owner import input')
        return data
    finally:os.close(fd)


def prepare(bundle,configs,fields):
    if len(fields)!=6 or any(not isinstance(v,str) or len(v)>1024 for v in fields):raise ValueError('invalid private owner input')
    mode,subject,username,email,password,finance=fields
    if mode not in ('existing','synthetic-new-owner'):raise ValueError('unsupported owner provisioning mode')
    if mode=='existing':
        if password:raise ValueError('existing owner provisioning cannot accept initial credential')
        return {'ownerImport':'existing-preserved','credentialOutput':False}
    bundle=Path(bundle);configs=Path(configs)
    if configs!=bundle/'runtime/configs':raise ValueError('synthetic owner import requires exact native runtime output')
    site=directory(bundle/'site')
    try:manifest=json.loads(read_file(site,'manifest.json',1024*1024))
    finally:os.close(site)
    if manifest.get('deploymentMode')!='standalone' or manifest.get('storageScope',{}).get('dataClass')!='synthetic':
        raise ValueError('new synthetic owner forbidden outside explicit synthetic installation')
    helper=bundle/'stack.config/keycloak/owner_import.py'
    parent=directory(helper.parent)
    try:source=read_file(parent,helper.name,65536)
    finally:os.close(parent)
    # Owning module is a pinned source input; never load a rendered helper that
    # might have had substitutions applied to Python source text.
    module=types.ModuleType('stack_explicit_owner_import')
    exec(compile(source,str(helper),'exec'),module.__dict__)
    realm_dir=directory(configs/'keycloak/realm')
    try:
        realm=json.loads(read_file(realm_dir,'webservices-realm.json',2*1024*1024))
        result=module.prepare_owner_import(realm,mode=mode,subject=subject,username=username,email=email,
                                          initial_password=password,finance_owner_subject=finance)
        data=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode()
        # Anonymous inode publication: no plaintext partial file after a crash.
        temp=os.open('/proc/self/fd/'+str(realm_dir),os.O_RDWR|os.O_TMPFILE,0o600)
        name='.owner-import-'+os.urandom(12).hex()
        try:
            with os.fdopen(temp,'wb',closefd=False)as stream:stream.write(data);stream.flush();os.fsync(temp)
            os.link('/proc/self/fd/'+str(temp),name,dst_dir_fd=realm_dir,follow_symlinks=True)
            os.replace(name,'webservices-realm.json',src_dir_fd=realm_dir,dst_dir_fd=realm_dir);os.fsync(realm_dir)
        finally:
            os.close(temp)
            try:os.unlink(name,dir_fd=realm_dir)
            except FileNotFoundError:pass
    finally:os.close(realm_dir)
    return {'ownerImport':'explicit-synthetic-full-realm-import','credentialOutput':False,'nativeExactSubjectProofRequired':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bundle',required=True,type=Path);parser.add_argument('--runtime-configs',required=True,type=Path);args=parser.parse_args()
    try:
        data=sys.stdin.buffer.read(8193)
        if len(data)>8192 or not data.endswith(b'\0'):raise ValueError('invalid private owner input framing')
        fields=[part.decode('utf-8')for part in data[:-1].split(b'\0')]
        print(json.dumps(prepare(args.bundle,args.runtime_configs,fields)))
    except (ValueError,OSError,KeyError,ImportError,TypeError):parser.exit(1,'explicit owner import refused; private values suppressed\n')
if __name__=='__main__':main()
