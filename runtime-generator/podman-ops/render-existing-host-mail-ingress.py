#!/usr/bin/env python3
"""Propose two private mail TLS/IMAP guest relays; never install/start them.

SMTP/IMAP server authentication and synthetic mail egress fencing must be
proved independently. Port 25/465 remain host-loopback only in this venue.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('private_ingress',Path(__file__).with_name('render-existing-host-ingress.py'))
ingress=importlib.util.module_from_spec(spec);spec.loader.exec_module(ingress)


def render(bundle,selector):
    proposal=ingress.render(bundle,selector)
    prefix=selector['unitPrefix'];mapped=selector['ports']
    guest=selector['guest'];bridge=proposal['bridge'];gateway=proposal['guestGateway']
    for port in ('25','465','587','993'):
        if type(mapped.get(port)) is not int or mapped[port] not in range(1024,65536):
            raise ingress.Refusal('Unbound isolated mail published port')
    if (mapped['587']!=guest['servicePorts']['smtp'] or mapped['993']!=guest['servicePorts']['imap']
            or len({mapped[x] for x in ('25','465','587','993','443')})!=5):
        raise ingress.Refusal('Guest SMTP/IMAP port provenance differs from selected venue')
    quadlet=Path(bundle)/'quadlet/rootful'/f'{prefix}-mailserver.container'
    if not quadlet.is_file() or quadlet.is_symlink():
        raise ingress.Refusal('Missing isolated mailserver Quadlet')
    lines=quadlet.read_text().splitlines()
    expected={f'PublishPort=127.0.0.1:{mapped[port]}:{port}' for port in ('25','465','587','993')}
    declared={line for line in lines if line.startswith('PublishPort=')}
    if declared!=expected or len(declared)!=4 or 'Network=host' in lines or f'ContainerName={prefix}-mailserver' not in lines:
        raise ingress.Refusal('Mailserver publisher escapes exact loopback authority')
    units=[]
    for protocol,default,port in (('smtp',587,mapped['587']),('imap',993,mapped['993'])):
        unit=f'{prefix}-ingress-{protocol}'
        socket=(f'[Unit]\nDescription=Private {prefix} guest {protocol.upper()} transport\n'
                f'PartOf={prefix}.target\nAfter={prefix}-mailserver.service\n'
                f'[Socket]\nListenStream={gateway}:{default}\nListenStream={gateway}:{port}\n'
                f'Service={unit}.service\nAccept=no\n'
                f'[Install]\nWantedBy={prefix}.target\n')
        service=(f'[Unit]\nDescription=Private {prefix} guest {protocol.upper()} relay to loopback Mailserver\n'
                 f'PartOf={prefix}.target\n'
                 f'After={prefix}-mailserver.service\n[Service]\nType=notify\n'
                 f'ExecStart=/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=5min 127.0.0.1:{port}\n'
                 'NoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n'
                 'RestrictAddressFamilies=AF_INET AF_UNIX\n')
        units.append({'unit':unit,'socket':socket,'service':service,'guestPorts':[default,port],
                      'upstream':f'127.0.0.1:{port}'})
    return {'schemaVersion':1,'bridge':bridge,'guestGateway':gateway,'units':units,
            'unitInstalled':False,'activationAuthorized':False,'mailTlsProved':False,'mailSinkProved':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--selector',type=Path,required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(render(args.bundle,ingress.network.strict_json(args.selector)),sort_keys=True,indent=2))
    except (ingress.Refusal,ingress.network.Refusal,KeyError,TypeError,OSError,json.JSONDecodeError) as exc:
        raise SystemExit('private mail ingress refused: '+str(exc)) from exc


if __name__=='__main__':main()
