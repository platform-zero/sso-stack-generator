#!/usr/bin/env python3
"""Classify FOUR isolated host-network Quadlets' static listener intent only.

Does not grant activation: runtime listeners, Caddy-generated HTTP/admin,
Podman namespace behavior and complete installer/fencing remain separate gates.
"""
import argparse
import json
from pathlib import Path
import re


class Refusal(ValueError):
    pass


def verify(bundle):
    bundle=Path(bundle)
    domains=json.loads((bundle/'podman-domains.json').read_text())
    venue=domains.get('venue')
    if not isinstance(venue,dict) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',venue.get('unitPrefix','')):
        raise Refusal('No isolated host listener authority')
    prefix=venue['unitPrefix']
    root=bundle/'quadlet'
    host_network=[]
    for path in sorted(root.glob('*/*.container')):
        lines=path.read_text().splitlines()
        if 'Network=host' in lines:
            if any(row.startswith('PublishPort=') for row in lines):
                raise Refusal('Host-network listener with unmatched Podman publisher')
            host_network.append(path)
    expected={f'{prefix}-{name}.container' for name in ('alloy','caddy','node-exporter','ntfy-native-auth')}
    if {p.name for p in host_network}!=expected or any(p.parent.name!='rootful' for p in host_network):
        raise Refusal('Unexpected host-network consumer, including rootless Livekit')
    by_name={p.name:p.read_text().splitlines() for p in host_network}
    if f'Exec="run" "--server.http.listen-addr=127.0.0.1:12345" "/etc/alloy/alloy.hcl"' not in by_name[f'{prefix}-alloy.container']:
        raise Refusal('Alloy UI/metrics listener is not pinned to host loopback')
    node=' '.join(by_name[f'{prefix}-node-exporter.container'])
    if '--web.listen-address=127.0.0.1:9100' not in node or '--web.listen-address=0.0.0.0' in node:
        raise Refusal('Node exporter listener not pinned to host loopback')
    native=bundle/'runtime/configs/caddy/ntfy-native-auth.py'
    if not native.is_file() or native.is_symlink() or native.read_text().count('ThreadingHTTPServer(("127.0.0.1", 25017), Handler)')!=1:
        raise Refusal('Ntfy native-auth listener is not pinned to host loopback')
    caddyfile=bundle/'runtime/configs/caddy/Caddyfile'
    if not caddyfile.is_file() or caddyfile.is_symlink() or caddyfile.read_text().count('{{CADDY_GLOBAL_OPTIONS}}')!=1:
        raise Refusal('Caddy runtime listener must still be rendered from bounded site authority')
    livekit=bundle/'quadlet/rootless-apps'/f'{prefix}-livekit.container'
    if not livekit.is_file() or 'Network=host' in livekit.read_text().splitlines():
        raise Refusal('Livekit must be isolated from host network')
    return {'schemaVersion':1,'scope':'static listener intent only, not runtime proof',
            'hostNetworkUnits':sorted(expected),'hostNetworkCount':4,
            'livekitHostNetwork':False,'activationAuthorized':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle',type=Path,required=True)
    a=p.parse_args()
    try: print(json.dumps(verify(a.bundle),sort_keys=True))
    except (Refusal,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('host listener intent refused: '+str(exc)) from exc


if __name__=='__main__':main()
