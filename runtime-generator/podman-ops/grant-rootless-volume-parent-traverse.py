#!/usr/bin/env python3
"""Give only a selected rootless domain execute access to its volume parent.

Fresh root-owned /mnt/stack/rootless is mode 0700. A child domain's owned
volume cannot be statfs'd through that parent without an exact per-UID ACL.
Never chmod the shared parent or replace any existing unrelated ACL.
"""
import argparse,os,pwd,re,stat,subprocess
from pathlib import Path

ROOTLESS_PARENT=Path('/mnt/stack/rootless')


def entries(path):
    result=subprocess.run(['getfacl','-cp','--',str(path)],capture_output=True,text=True,check=True,timeout=10)
    return {tuple(line.split(':',2)[:2]):line.split(':',2)[2]for line in result.stdout.splitlines()
            if line.startswith(('user:','group:','mask:','other:'))and line.count(':')>=2}


def grant(domain,user,volume_root):
    if os.geteuid()!=0 or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',domain)or user!='webservices-'+domain:
        raise ValueError('Exact selected rootless domain required')
    if volume_root!=ROOTLESS_PARENT/domain or volume_root.is_symlink() or ROOTLESS_PARENT.is_symlink():
        raise ValueError('Unexpected volume root authority')
    for path in (ROOTLESS_PARENT.parent,ROOTLESS_PARENT,volume_root):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode)or path.is_symlink()or info.st_mode&0o002:
            raise ValueError('Unsafe rootless volume ancestor')
    info=ROOTLESS_PARENT.lstat()
    if info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('Shared rootless parent must be root-controlled')
    pwd.getpwnam(user)
    before=entries(ROOTLESS_PARENT)
    existing=before.get(('user',user))
    if existing is not None:
        if 'x'not in existing:raise ValueError('Existing user ACL cannot be weakened or replaced')
        return False
    mask=before.get(('mask',''))
    if mask is not None and 'x'not in mask:
        raise ValueError('Existing ACL mask cannot be broadened implicitly')
    subprocess.run(['setfacl','-m','u:'+user+':--x','--',str(ROOTLESS_PARENT)],check=True,timeout=10)
    after=entries(ROOTLESS_PARENT)
    if after.get(('user',user))!='--x' or any(after.get(k)!=v for k,v in before.items()if k!=('mask','')):
        raise ValueError('Unexpected rootless ancestor ACL change')
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain',required=True)
    parser.add_argument('--user',required=True)
    parser.add_argument('--volume-root',type=Path,required=True)
    args=parser.parse_args()
    try:print('scoped rootless traverse granted'if grant(args.domain,args.user,args.volume_root)else'exact traverse already present')
    except (ValueError,OSError,subprocess.SubprocessError,KeyError):parser.exit(1,'rootless volume parent access refused\n')

if __name__=='__main__':main()
