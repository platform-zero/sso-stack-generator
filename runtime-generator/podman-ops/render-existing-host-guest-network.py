#!/usr/bin/env python3
"""Render/read-only screen of a proposed private libvirt guest bridge.

No definition, start, network repair, firewall or resolver mutation. The
fresh-host venue installer must verify this exact artifact and provision its
own namespace later; source-only XML is not network or ingress proof.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


class Refusal(ValueError):
    pass


def strict_json(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 2_000_000:
        raise Refusal('Missing or unsafe network input')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise Refusal('Duplicate network authority key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def network_authority(bundle, selector):
    bundle = Path(bundle)
    vm = strict_json(bundle / 'site/agent-vm.json')
    venue = strict_json(bundle / 'podman-domains.json').get('venue')
    guest = selector.get('guest')
    if (not isinstance(venue, dict) or not isinstance(guest, dict)
            or set(guest) != {'name','network','networkConfig','servicePorts','diskRoot','controlCommit'}):
        raise Refusal('Missing site/selector venue authority')
    expected = {key: vm.get(key) for key in ('name','network','networkConfig','servicePorts','diskRoot')}
    expected['controlCommit'] = vm.get('runtime', {}).get('controlCommit')
    if guest != expected or guest.get('name') != guest.get('network','') + '-agents':
        raise Refusal('Guest authority differs from generated site')
    ports = guest['servicePorts']
    if (not isinstance(ports, dict) or set(ports) != {'https','imap','smtp'}
            or any(type(ports[k]) is not int or ports[k] != venue.get('portMap',{}).get(source)
                   for k,source in (('https','443'),('imap','993'),('smtp','587')))):
        raise Refusal('Guest ports differ from rendered host venue')
    if guest['diskRoot'] != '/mnt/lab_debian/agent_vm/' + guest['name']:
        raise Refusal('Guest disk root overlaps unknown ownership')
    try:
        interface = ipaddress.IPv4Interface(guest['networkConfig']['address'])
        gateway = ipaddress.IPv4Address(guest['networkConfig']['gateway'])
    except (ValueError, KeyError, TypeError) as exc:
        raise Refusal('Invalid private bridge address') from exc
    subnet = interface.network
    if (subnet.prefixlen != 24 or not subnet.is_private or not 140 <= subnet.network_address.packed[2] <= 199
            or gateway != subnet.network_address + 1 or interface.ip == gateway
            or guest['networkConfig'].get('nameservers') != [str(gateway)]
            or not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}', guest['network'])):
        raise Refusal('Guest network is not a distinct reviewed private /24')
    settings = bundle / 'site/global.settings/stack.config.yaml'
    caddy = bundle / 'runtime/configs/caddy/Caddyfile'
    if any(not p.is_file() or p.is_symlink() or p.stat().st_size > 1_000_000 for p in (settings,caddy)):
        raise Refusal('Missing bounded site domain/Caddy routing authority')
    domains = re.findall(r'(?m)^  domain: "([a-z][a-z0-9.-]{2,100})"$', settings.read_text())
    if len(domains) != 1 or domains[0] != 'datamancy.net':
        raise Refusal('Unreviewed guest DNS domain')
    labels = set(re.findall(r'([a-z][a-z0-9-]*)\.\{\$DOMAIN\}', caddy.read_text()))
    if (not {'keycloak','matrix','mail','control','ntfy','portal','search'}.issubset(labels)
            or not 40 <= len(labels) <= 100):
        raise Refusal('Incomplete generated private Caddy route DNS catalog')
    return guest, subnet, gateway, sorted({domains[0],*(name+'.'+domains[0] for name in labels)})


def screen_host(subnet, network_name, bridge_name, *, routes=None, network_names=None, links=None):
    """Read-only host collision screen; an absent name is not install authority."""
    if routes is None:
        routes = json.loads(subprocess.check_output(['ip','-j','-4','route','show'], text=True, timeout=10))
    if links is None:
        links = json.loads(subprocess.check_output(['ip','-j','link','show'], text=True, timeout=10))
    if network_names is None:
        network_names = subprocess.check_output(['virsh','-c','qemu:///system','net-list','--all','--name'], text=True, timeout=10).splitlines()
    if not isinstance(routes,list) or not isinstance(links,list) or not isinstance(network_names,list):
        raise Refusal('Unparseable host route/network authority')
    if network_name in network_names or bridge_name in {item.get('ifname') for item in links}:
        raise Refusal('Proposed private bridge/network already exists')
    for row in routes:
        destination=row.get('dst')
        if destination == 'default':
            continue
        try: occupied=ipaddress.ip_network(destination, strict=False)
        except (ValueError, TypeError) as exc: raise Refusal('Unparseable host route') from exc
        if subnet.overlaps(occupied):
            raise Refusal('Proposed guest subnet overlaps host route')
    return {'routeCollision':False,'existingNetworkCollision':False,'bridgeCollision':False}


def render(bundle, selector):
    guest, subnet, gateway, hostnames = network_authority(bundle, selector)
    bridge_name='virbr'+str(subnet.network_address.packed[2])
    root=ET.Element('network')
    ET.SubElement(root,'name').text=guest['network']
    ET.SubElement(root,'forward',{'mode':'nat'})
    ET.SubElement(root,'bridge',{'name':bridge_name,'stp':'on','delay':'0'})
    ET.SubElement(root,'domain',{'name':'datamancy.net','localOnly':'yes'})
    dns=ET.SubElement(root,'dns')
    host=ET.SubElement(dns,'host',{'ip':str(gateway)})
    for hostname in hostnames:
        ET.SubElement(host,'hostname').text=hostname
    ET.SubElement(root,'ip',{'address':str(gateway),'netmask':'255.255.255.0'})
    ET.indent(root)
    return ET.tostring(root,encoding='unicode')+'\n', {'network':guest['network'],'bridge':bridge_name,
        'subnet':str(subnet),'gateway':str(gateway),'dnsNameCount':len(hostnames),
        'guest':guest['name'],'diskRoot':guest['diskRoot'],'controlCommit':guest['controlCommit'],
        'defined':False,'activated':False,'ingressProven':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--selector',type=Path,required=True)
    parser.add_argument('--inspect-host',action='store_true',help='Read-only route/name/link collision check')
    args=parser.parse_args()
    try:
        xml,info=render(args.bundle,strict_json(args.selector))
        if args.inspect_host:
            info.update(screen_host(ipaddress.ip_network(info['subnet']),info['network'],info['bridge']))
        print(json.dumps(info,sort_keys=True),file=sys.stderr)
        print(xml,end='')
    except (Refusal,KeyError,TypeError,OSError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        raise SystemExit('private guest network refused: '+str(exc)) from exc


if __name__=='__main__':main()
