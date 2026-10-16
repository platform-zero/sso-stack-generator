#!/usr/bin/env python3
"""Bind rendered isolated Caddy device API to the site-pinned new guest.

Fail closed before replacing the runtime Caddyfile; never writes to the
module source or to the selected original guest/host. Native render calls it
*after* template expansion, so rerenders cannot restore an old guest route.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile

OLD=b'reverse_proxy 192.168.122.235:24838'
HTTP_REDIRECT=b'\nhttp://{$DOMAIN}, http://*.{$DOMAIN} {\n\tredir https://{host}{uri} 308\n}\n'


class Refusal(ValueError):
    pass


def bind(bundle, caddyfile):
    bundle=Path(bundle);caddyfile=Path(caddyfile)
    metadata=json.loads((bundle/'podman-domains.json').read_text())
    venue=metadata.get('venue')
    guest=json.loads((bundle/'site/agent-vm.json').read_text())
    if not isinstance(venue,dict) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',venue.get('unitPrefix','')):
        raise Refusal('No reviewed isolated Caddy authority')
    if not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}-agents',guest.get('name','')):
        raise Refusal('No distinct new guest identity')
    cfg=guest.get('networkConfig',{})
    interface=ipaddress.ip_interface(cfg.get('address',''))
    if (interface.version!=4 or str(interface.network)!='192.168.140.0/24'
            or str(interface.ip)=='192.168.140.1' or str(interface.ip)=='192.168.122.235'
            or cfg.get('gateway')!='192.168.140.1' or cfg.get('nameservers')!=['192.168.140.1']):
        raise Refusal('Device API guest network differs from private bridge')
    mapping=venue.get('portMap',{})
    if (type(mapping.get('443')) is not int or mapping['443'] not in range(1024,65536)
            or type(mapping.get('7880')) is not int or mapping['7880'] not in range(1024,65536)
            or mapping['443']==mapping['7880']):
        raise Refusal('Caddy TLS and Livekit API venue ports not pinned')
    new=('reverse_proxy '+str(interface.ip)+':24838').encode()
    old_livekit=b'reverse_proxy host.containers.internal:7880'
    new_livekit=('reverse_proxy 127.0.0.1:'+str(mapping['7880'])).encode()
    if caddyfile.is_symlink() or not caddyfile.is_file():
        raise Refusal('Rendered Caddyfile must be a regular file')
    info=caddyfile.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>2_000_000 or info.st_mode & 0o022:
        raise Refusal('Unsafe rendered Caddyfile')
    body=caddyfile.read_bytes()
    if body.count(OLD)+body.count(new)!=1:
        raise Refusal('Unreviewed original/venue Caddy device API routes')
    if body.count(old_livekit)+body.count(new_livekit)!=1:
        raise Refusal('Unreviewed original/venue Caddy Livekit API routes')
    if body.count(HTTP_REDIRECT)>1 or (b'http://{$DOMAIN}' in body and HTTP_REDIRECT not in body):
        raise Refusal('Unreviewed Caddy HTTP redirect authority')
    if body.count(new)==1 and body.count(new_livekit)==1 and body.count(HTTP_REDIRECT)==1:
        return {'deviceApiGuest':str(interface.ip),'changed':False,'activationAuthorized':False}
    fd, name=tempfile.mkstemp(prefix='.p0-venue-caddy-',dir=caddyfile.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            next_body=body.replace(OLD,new).replace(old_livekit,new_livekit)
            if HTTP_REDIRECT not in next_body:
                next_body+=HTTP_REDIRECT
            out.write(next_body);out.flush();os.fsync(out.fileno())
        os.chmod(name,stat.S_IMODE(info.st_mode))
        os.replace(name,caddyfile)
    finally:
        Path(name).unlink(missing_ok=True)
    return {'deviceApiGuest':str(interface.ip),'changed':True,'activationAuthorized':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',required=True,type=Path)
    p.add_argument('--caddyfile',required=True,type=Path)
    args=p.parse_args()
    try:
        result=bind(args.bundle,args.caddyfile)
        print('bound isolated Caddy device API to '+result['deviceApiGuest'])
    except (Refusal,OSError,ValueError,KeyError,TypeError) as exc:
        raise SystemExit('isolated Caddy device API refused: '+str(exc)) from exc


if __name__=='__main__':main()
