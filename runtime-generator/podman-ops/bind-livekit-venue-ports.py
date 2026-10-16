#!/usr/bin/env python3
"""Bind venue ICE advertised ports and private node IP after native rendering.

No container or network is started; reject mismatched authority before rewrite.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

class Refusal(ValueError):
    pass


def bind(bundle,config):
    bundle=Path(bundle);config=Path(config)
    venue=json.loads((bundle/'podman-domains.json').read_text()).get('venue')
    guest=json.loads((bundle/'site/agent-vm.json').read_text())
    if not isinstance(venue,dict) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',venue.get('unitPrefix','')):
        raise Refusal('Missing private Livekit venue')
    cfg=guest.get('networkConfig',{})
    address=ipaddress.ip_interface(cfg.get('address',''))
    if (address.version!=4 or str(address.network)!='192.168.140.0/24'
            or cfg.get('gateway')!='192.168.140.1' or cfg.get('nameservers')!=['192.168.140.1']):
        raise Refusal('Livekit bridge differs from site VM')
    mapping=venue.get('portMap',{})
    if (type(mapping.get('7881')) is not int or type(mapping.get('7882')) is not int or
            mapping['7881'] not in range(1024,65536) or mapping['7882'] not in range(1024,65536) or
            len({mapping['7881'],mapping['7882'],7881,7882})!=4):
        raise Refusal('Unbound or shared private ICE port identities')
    if not config.is_file() or config.is_symlink():
        raise Refusal('Missing regular rendered Livekit configuration')
    info=config.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>500_000 or info.st_mode & 0o022:
        raise Refusal('Unsafe rendered Livekit configuration')
    original=config.read_bytes()
    if original.count(b'node_ip: "192.168.140.1"')!=1 or original.count(b'port: 7880')!=1:
        raise Refusal('Livekit API or private ICE node identity differs')
    next_content=original
    for protocol,oldport in (('tcp',7881),('udp',7882)):
        old=f'  {protocol}_port: {oldport}'.encode()
        new=f'  {protocol}_port: {mapping[str(oldport)]}'.encode()
        if next_content.count(old)+next_content.count(new)!=1:
            raise Refusal('Unreviewed Livekit ICE socket or advertised port')
        next_content=next_content.replace(old,new)
    if next_content==original:
        return {'changed':False,'activationAuthorized':False}
    fd,name=tempfile.mkstemp(prefix='.p0-venue-livekit-',dir=config.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(next_content);out.flush();os.fsync(out.fileno())
        os.chmod(name,stat.S_IMODE(info.st_mode))
        os.replace(name,config)
    finally:
        Path(name).unlink(missing_ok=True)
    return {'changed':True,'activationAuthorized':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',required=True,type=Path)
    p.add_argument('--config',required=True,type=Path)
    a=p.parse_args()
    try:
        bind(a.bundle,a.config)
    except (Refusal,ValueError,KeyError,TypeError,OSError) as exc:
        raise SystemExit('private Livekit ICE configuration refused: '+str(exc)) from exc


if __name__=='__main__':main()
