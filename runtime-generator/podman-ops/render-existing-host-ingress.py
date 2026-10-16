#!/usr/bin/env python3
"""Render only a *proposed* guest-facing TLS relay to loopback Caddy.

No unit install/enable/start, network definition, host listener, port forwarding
or activation authority. Caddy and every internal service must remain inaccessible
from the guest except through its own authenticated TLS sites; live listener and
CA checks are mandatory before a future installer may select these units.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

NETWORK = Path(__file__).with_name('render-existing-host-guest-network.py')
spec = importlib.util.spec_from_file_location('private_guest_network', NETWORK)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class Refusal(ValueError):
    pass


def render(bundle, selector):
    bundle=Path(bundle)
    _, net = network.render(bundle, selector)
    guest=selector.get('guest')
    domains=network.strict_json(bundle/'podman-domains.json')
    venue=domains.get('venue')
    if not isinstance(venue,dict) or not isinstance(guest,dict):
        raise Refusal('Missing isolated ingress authority')
    prefix=venue.get('unitPrefix')
    if not isinstance(prefix,str) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',prefix) or prefix!=selector.get('unitPrefix'):
        raise Refusal('Unbound Caddy/ingress unit namespace')
    ports=venue.get('portMap')
    if (not isinstance(ports,dict) or ports!=selector.get('ports') or set(guest.get('servicePorts',{}))!={'https','imap','smtp'}
            or ports.get('443')!=guest['servicePorts']['https'] or type(ports['443']) is not int
            or ports['443']==443 or ports['443'] not in range(1024,65536)):
        raise Refusal('Guest TLS transport differs from isolated Caddy map')
    if net['gateway']!='192.168.'+str(int(net['bridge'].removeprefix('virbr')))+'.1':
        raise Refusal('Guest bridge/gateway identity changed')
    caddy=bundle/'quadlet/rootful'/f'{prefix}-caddy.container'
    if not caddy.is_file() or caddy.is_symlink():
        raise Refusal('Missing exact isolated Caddy Quadlet')
    lines=caddy.read_text().splitlines()
    if (lines.count('Network=host')!=1 or any(row.startswith('PublishPort=') for row in lines)
            or f'ContainerName={prefix}-caddy' not in lines
            or 'Environment=CONTAINERS_STORAGE_CONF='+selector['rootful']['stateRoot']+'/containers-storage.conf' not in lines
            or 'Environment=CONTAINERS_CONF='+selector['rootful']['stateRoot']+'/containers.conf' not in lines):
        raise Refusal('Caddy container not bound to expected loopback host role')
    settings=bundle/'site/global.settings/stack.config.yaml'
    if not settings.is_file() or settings.is_symlink() or settings.stat().st_size>1_000_000:
        raise Refusal('Missing bounded Caddy site authority')
    content=settings.read_text()
    modes=re.findall(r'(?m)^  caddy_tls_mode: [^\n]+$',content)
    if len(modes)>1 or (modes and modes!=['  caddy_tls_mode: "local"'] and modes!=['  caddy_tls_mode: local']):
        raise Refusal('Isolated ingress requires synthetic local CA mode')
    # Two sockets are deliberately the only guest-facing Caddy endpoints:
    # 443 preserves standard-port OIDC URLs; the mapped port serves a separate
    # reviewed broker transport. Internal publishers remain on 127.0.0.1 only.
    bind=net['gateway']; https=ports['443']; http=ports.get('80'); unit=f'{prefix}-ingress-https'
    if type(http) is not int or http not in range(1024,65536) or http==https:
        raise Refusal('Unbound isolated Caddy HTTP redirect port')
    socket=(f'[Unit]\nDescription=Private {prefix} guest TLS ingress (Caddy only)\n'
            f'BindsTo={prefix}-caddy.service\nAfter={prefix}-caddy.service\n'
            f'[Socket]\nListenStream={bind}:443\nListenStream={bind}:{https}\n'
            f'BindToDevice={net["bridge"]}\nService={unit}.service\n'
            f'Accept=no\n[Install]\nWantedBy={prefix}.target\n')
    service=(f'[Unit]\nDescription=Private {prefix} guest TLS relay to loopback Caddy\n'
             f'Requires={prefix}-caddy.service\nBindsTo={prefix}-caddy.service\nAfter={prefix}-caddy.service\n'
             '[Service]\nType=notify\n'
             f'ExecStart=/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min 127.0.0.1:{https}\n'
             'NoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n'
             'RestrictAddressFamilies=AF_INET AF_UNIX\n')
    http_unit=f'{prefix}-ingress-http'
    http_socket=(f'[Unit]\nDescription=Private {prefix} guest HTTP redirect ingress\n'
                 f'BindsTo={prefix}-caddy.service\nAfter={prefix}-caddy.service\n'
                 f'[Socket]\nListenStream={bind}:80\nListenStream={bind}:{http}\n'
                 f'BindToDevice={net["bridge"]}\nService={http_unit}.service\n'
                 f'Accept=no\n[Install]\nWantedBy={prefix}.target\n')
    http_service=(f'[Unit]\nDescription=Private {prefix} HTTP redirect relay to loopback Caddy\n'
                  f'Requires={prefix}-caddy.service\nBindsTo={prefix}-caddy.service\nAfter={prefix}-caddy.service\n'
                  '[Service]\nType=notify\n'
                  f'ExecStart=/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min 127.0.0.1:{http}\n'
                  'NoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n'
                  'RestrictAddressFamilies=AF_INET AF_UNIX\n')
    return {'schemaVersion':1,'unit':unit,'socket':socket,'service':service,
            'httpUnit':http_unit,'httpSocket':http_socket,'httpService':http_service,
            'bridge':net['bridge'],'guestGateway':bind,'guestPorts':[443,https],
            'guestHttpPorts':[80,http], 'httpUpstream':'127.0.0.1:'+str(http),
            'upstream':'127.0.0.1:'+str(https),'caddyBoundaryPreserved':True,
            'networkDefined':False,'unitInstalled':False,'activationAuthorized':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--selector',type=Path,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(render(args.bundle,network.strict_json(args.selector)),sort_keys=True,indent=2))
    except (Refusal,network.Refusal,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('private guest ingress refused: '+str(exc)) from exc


if __name__=='__main__':main()
