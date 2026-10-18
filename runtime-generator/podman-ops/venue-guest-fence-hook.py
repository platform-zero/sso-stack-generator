#!/usr/bin/python3 -I
"""Native libvirt network start fence; no libvirt calls, guest or stack starts.

The versioned installer embeds one immutable policy into a root-owned copy.
Only that exact network's start/begin event is gated; unrelated networks and
stop events are not changed. Missing/changed inputs fail the selected start.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

POLICY = None


class Refusal(ValueError):
    pass


def json_fingerprint(value):
    def clean(item):
        if isinstance(item, dict):return {key:clean(val) for key,val in item.items() if key!='handle'}
        if isinstance(item, list):return [clean(val) for val in item if not isinstance(val,dict) or set(val)!={'metainfo'}]
        return item
    return hashlib.sha256(json.dumps(clean(value),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def xml_fingerprint(element):
    def clean(node):
        return [node.tag,sorted((k,v) for k,v in node.attrib.items() if not (node.tag=='network' and k=='connections')),
                (node.text or '').strip(),[clean(child) for child in node]]
    return hashlib.sha256(json.dumps(clean(element),separators=(',',':')).encode()).hexdigest()


def native(command, *, body=None):
    result=subprocess.run(command,input=body,capture_output=True,text=True,timeout=20)
    if result.returncode:raise Refusal('native fence operation failed; selected network must not start')
    return result.stdout


def protected_file(path,mode):
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=mode:
        raise Refusal('unprotected installed fence input')
    for parent in path.parents:
        item=parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(item.st_mode) or item.st_uid or item.st_mode&0o022:
            raise Refusal('unprotected fence ancestor')
    return info


def write_proof(path,document):
    parent=path.parent;info=parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid or stat.S_IMODE(info.st_mode)!=0o700:
        raise Refusal('private installed fence proof directory missing or changed')
    if os.path.lexists(path):
        protected_file(path,0o600);previous=json.loads(path.read_bytes())
        if not isinstance(previous,dict) or any(previous.get(key)!=document[key] for key in ('schemaVersion','namespace','networkUuid','hookSha256','nativeFenceFingerprint','networkXmlFingerprint')):
            raise Refusal('unreviewed existing boot proof; no overwrite')
    temporary=parent/('.network-fence-proof-'+str(os.getpid()))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as out:json.dump(document,out,sort_keys=True);out.write('\n');out.flush();os.fsync(out.fileno())
        os.replace(temporary,path)
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.lexists(temporary):temporary.unlink()


def guard(policy,arguments,xml, *, source=None):
    if not isinstance(policy,dict):raise Refusal('uninstalled network fence hook')
    if not arguments or arguments[0]!=policy['network']:return {'status':'unrelated-network'}
    if len(arguments)!=4:raise Refusal('invalid selected network hook arguments')
    if arguments[1:3]!=['start','begin']:return {'status':'non-start-event'}
    if os.geteuid()!=0:raise Refusal('network fence hook requires root')
    if len(xml)>2_000_000:raise Refusal('oversized native network description')
    root=ET.fromstring(xml);network=root.find('network') if root.tag=='hookData' else root
    if (network is None or network.tag!='network' or network.findtext('name')!=policy['network'] or
            network.findtext('uuid')!=policy['uuid'] or xml_fingerprint(network)!=policy['networkXmlFingerprint']):
        raise Refusal('selected native network identity/definition changed')
    file=Path(source or __file__);protected_file(file,0o755)
    if hashlib.sha256(policy['nftables'].encode()).hexdigest()!=policy['nftablesSha256']:
        raise Refusal('embedded source fence bytes changed')
    tables=json.loads(native(['/usr/sbin/nft','-j','list','tables']))
    present=any(row.get('table',{}).get('family')=='inet' and row.get('table',{}).get('name')==policy['table'] for row in tables['nftables'])
    if not present:
        native(['/usr/sbin/nft','-c','-f','-'],body=policy['nftables'])
        native(['/usr/sbin/nft','-f','-'],body=policy['nftables'])
    current=json.loads(native(['/usr/sbin/nft','-j','list','table','inet',policy['table']]))
    if json_fingerprint(current)!=policy['nativeFenceFingerprint']:
        raise Refusal('existing/native fence differs; no flush, replacement or network start')
    proof={'schemaVersion':1,'namespace':policy['namespace'],'network':policy['network'],'networkUuid':policy['uuid'],
           'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'event':'start/begin',
           'hookSha256':hashlib.sha256(file.read_bytes()).hexdigest(),'nativeFenceFingerprint':policy['nativeFenceFingerprint'],
           'networkXmlFingerprint':policy['networkXmlFingerprint'],'activationAuthorized':False}
    write_proof(Path(policy['proofPath']),proof)
    return {'status':'selected-network-fenced','activationAuthorized':False}


def main():
    try:guard(POLICY,sys.argv[1:],sys.stdin.read(2_000_001))
    except (Refusal,OSError,ValueError,KeyError,TypeError,ET.ParseError,subprocess.SubprocessError):
        print('Selected isolated network fence refused; no network/guest authority granted',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
