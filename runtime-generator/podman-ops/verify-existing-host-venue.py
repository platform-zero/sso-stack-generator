#!/usr/bin/env python3
"""Fail-closed *preflight* for a proposed same-host test selector; never grants activation.

The selected native installer has fixed webservices units/accounts/sockets and must
not be run on a live host merely because this path-level check passes. A later
reviewed installer must consume and revalidate a complete selector before mutation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import pwd
import ipaddress

class Refusal(ValueError):
    pass

def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or os.path.normpath(value) != value or '..' in Path(value).parts or value == '/':
        raise Refusal('noncanonical absolute path')
    return value

def exclusive(a, b):
    return a != b and not a.startswith(b.rstrip('/') + '/') and not b.startswith(a.rstrip('/') + '/')

def check(selector, ir, domains, protected, exists=os.path.lexists, required_ports=None):
    required = {'schemaVersion','rootful','domains','volumes','unitPrefix','socketRoot','storageRoots','ports'}
    if set(selector) not in (required, required | {'guest'}) or type(selector['schemaVersion']) is not int or selector['schemaVersion'] != 1:
        raise Refusal('selector schema or extra authority')
    if len(ir['services']) != 95 or len(ir['volumes']) != 65 or len(domains['domains']) != 7:
        raise Refusal('unexpected composition')
    venue = domains.get('venue')
    if (not isinstance(venue, dict) or set(venue) != {'schemaVersion','unitPrefix','rootfulStateRoot','rootfulRuntimeRoot','rootfulGraphRoot','rootfulRunRoot','rootfulVolumeRoot','pgSsdRoot','vectorDbsRoot','controlSocketRoot','logRoot','portMap'}
            or type(venue['schemaVersion']) is not int or venue['schemaVersion'] != 1
            or venue['unitPrefix'] != selector['unitPrefix']
            or venue['rootfulStateRoot'] != selector['rootful']['stateRoot']
            or venue['rootfulGraphRoot'] != selector['rootful']['graphRoot']
            or venue['rootfulRunRoot'] != selector['rootful']['runRoot']
            or venue['rootfulVolumeRoot'] != selector['rootful']['volumeRoot']
            or venue['controlSocketRoot'] != selector['socketRoot']
            or not isinstance(selector['storageRoots'],dict)
            or set(selector['storageRoots']) != {'pgSsdRoot','vectorDbsRoot','logRoot'}
            or any(venue[k] != selector['storageRoots'][k] for k in selector['storageRoots'])
            or venue['portMap'] != selector['ports']
            or venue['rootfulRuntimeRoot'] != '/run/' + selector['unitPrefix']):
        raise Refusal('generator did not bind the isolated unit/state/runtime authority')
    expected = set(ir['volumes'])
    if set(selector['volumes']) != expected:
        raise Refusal('missing or extra volume, including implicit Huly')
    if set(selector['domains']) != {d['name'] for d in domains['domains']}:
        raise Refusal('missing or extra domain')
    roots = []
    def take(value, allowed_parents=()):
        path = absolute(value)
        for prior in roots + protected:
            if prior in allowed_parents and path.startswith(prior.rstrip('/') + '/'):
                continue
            if not exclusive(path, prior):
                raise Refusal('overlapping selected or protected path')
        # Reject even existing *empty* roots; existence is not ownership.
        if exists(path):
            raise Refusal('existing path has no fresh ownership proof')
        parts = Path(path).parts
        for i in range(2, len(parts)):
            prefix = Path(*parts[:i])
            try: mode = prefix.lstat().st_mode
            except FileNotFoundError: break
            if stat.S_ISLNK(mode):
                raise Refusal('symlinked ancestor')
        roots.append(path)
    if 'guest' in selector:
        if not isinstance(selector['guest'],dict) or 'diskRoot' not in selector['guest']:
            raise Refusal('missing exclusive guest disk root')
        take(selector['guest']['diskRoot'])
    for key in ('stateRoot','graphRoot','volumeRoot','runRoot'):
        take(selector['rootful'][key])
    take(venue['rootfulRuntimeRoot'])
    for value in selector['storageRoots'].values():
        take(value)
    if set(selector['rootful']) != {'stateRoot','graphRoot','volumeRoot','runRoot'}:
        raise Refusal('rootful schema')
    users = set()
    for d in domains['domains']:
        entry = selector['domains'][d['name']]
        if set(entry) != {'user','uid','subuidStart','stateRoot','graphRoot','volumeRoot'}:
            raise Refusal('domain schema')
        user = entry['user']
        if not isinstance(user,str) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',user) or user in users or user != d['user']:
            raise Refusal('generated account mismatch or collision')
        users.add(user)
        if type(entry['uid']) is not int or type(entry['subuidStart']) is not int or entry['uid'] < 1000 or entry['subuidStart'] < 100000 or entry['uid'] != d['uid'] or entry['subuidStart'] != d['subuidStart']:
            raise Refusal('generated account identifiers mismatch')
        for key in ('stateRoot','graphRoot','volumeRoot'):
            if entry[key] != d[key]:
                raise Refusal('generated domain root mismatch')
            take(entry[key])
    if len({v['uid'] for v in selector['domains'].values()}) != 7 or len({v['subuidStart'] for v in selector['domains'].values()}) != 7:
        raise Refusal('duplicate account identifiers')
    ranges = sorted(v['subuidStart'] for v in selector['domains'].values())
    if any(b - a < 65536 for a,b in zip(ranges,ranges[1:])):
        raise Refusal('overlapping subordinate ranges')
    for name in sorted(expected):
        value = selector['volumes'][name]
        if 'hostPath' not in ir['volumes'][name]:
            # Podman named volumes live INSIDE the exclusively selected apps
            # graph. They are not separate host binds or independent roots.
            graph = selector['domains']['apps']['graphRoot']
            if value != graph + '/volumes/' + name + '/_data':
                raise Refusal('implicit volume does not match selected graph')
            take(value, allowed_parents=(graph,))
        else:
            if value != ir['volumes'][name]['hostPath']:
                raise Refusal('explicit generated hostPath mismatch')
            take(value, allowed_parents=(selector['rootful']['volumeRoot'],
                                         selector['storageRoots']['pgSsdRoot'],
                                         selector['storageRoots']['vectorDbsRoot']))
    take(selector['socketRoot'])
    prefix = selector['unitPrefix']
    if not isinstance(prefix,str) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}',prefix) or prefix == 'webservices':
        raise Refusal('unit namespace collision')
    ports = selector['ports']
    required = required_ports if required_ports is not None else {str(i) for i in range(25001,25010)} | {'9100'}
    if not isinstance(ports,dict) or set(ports) != required:
        raise Refusal('incomplete host port mapping')
    if any(type(v) is not int or v < 1024 or v > 65535 for v in ports.values()) or len(set(ports.values())) != len(ports) or any(int(k) == v for k,v in ports.items()):
        raise Refusal('port collision or invalid port')
    # Preflight alone cannot prove the candidate is wired through *all* unit,
    # quadlet, Caddy, socket, image, DNS, host-network and reset consumers.
    return {'pathPreflightPassed':True,'activationAuthorized':False,'checkedVolumes':len(expected),'checkedRoots':len(roots)}

def screen_guest_binding(bundle, selector):
    """Compare the proposed fresh guest to the materialized immutable site input.

    This proves a proposed address/port binding, not the actual bridge, DNS,
    routes, sockets, host controller or guest identity. Activation remains false.
    """
    guest = selector.get('guest')
    if not isinstance(guest, dict) or set(guest) != {'name','network','networkConfig','servicePorts','diskRoot','controlCommit'}:
        raise Refusal('missing dedicated guest authority in venue selector')
    vm_path = bundle / 'site/agent-vm.json'
    if not vm_path.is_file() or vm_path.is_symlink():
        raise Refusal('missing generated guest input')
    vm = json.loads(vm_path.read_text())
    try:
        expected = {k:vm[k] for k in ('name','network','networkConfig','servicePorts','diskRoot')}
        expected['controlCommit'] = vm['runtime']['controlCommit']
        net = ipaddress.ip_interface(guest['networkConfig']['address'])
        gateway = ipaddress.ip_address(guest['networkConfig']['gateway'])
    except (KeyError, ValueError, TypeError) as exc:
        raise Refusal('invalid guest endpoint authority') from exc
    if (guest != expected or guest['name'] != guest['network'] + '-agents'
            or guest['diskRoot'] != '/mnt/lab_debian/agent_vm/' + guest['name']
            or not isinstance(net, ipaddress.IPv4Interface)
            or gateway not in net.network or gateway == net.ip
            or not net.network.is_private or not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}',guest['network'])
            or any(guest['servicePorts'][name] != selector['ports'][source]
                   for name,source in (('https','443'),('imap','993'),('smtp','587')))):
        raise Refusal('guest authority differs from isolated host venue')
    return {'network':guest['network'],'gateway':str(gateway),'controlCommit':guest['controlCommit']}

def published_host_ports(bundle):
    """Collect *all* static Podman published host ports, not just cross-domain.

    Host-network processes need separate reviewed port bindings; the selected
    public Caddy and node-exporter fixed listeners are compulsory as well.
    """
    root = bundle / 'quadlet'
    if not root.is_dir():
        raise Refusal('missing Quadlet authority')
    ports = {'80','443','9100'}
    count = 0
    unbound = []
    rtc = []
    for path in root.glob('*/*.container'):
        for line in path.read_text().splitlines():
            if not line.startswith('PublishPort='):
                continue
            count += 1
            spec = line.split('=',1)[1]
            if spec.startswith('127.0.0.1:'):
                match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5}):[0-9]{1,5}',spec)
            elif path.name.endswith('-livekit.container'):
                match = re.fullmatch(r'192\.168\.140\.1:([0-9]{1,5}):([0-9]{1,5})/(tcp|udp)',spec)
                if match: rtc.append((int(match.group(1)),int(match.group(2)),match.group(3)))
            else:
                match = re.fullmatch(r'(?:127\.0\.0\.1:)?([0-9]{1,5}):[0-9]{1,5}',spec)
                unbound.append(path.name)
            if not match or not 1 <= int(match.group(1)) <= 65535:
                raise Refusal('unrecognized published port syntax')
            ports.add(str(int(match.group(1))))
    if count != 48 or len(ports) != 51:
        raise Refusal('unexpected selected published-port inventory')
    domains_path = bundle / 'podman-domains.json'
    domains = json.loads(domains_path.read_text()) if domains_path.is_file() else {}
    if 'venue' in domains:
        mapping = domains['venue'].get('portMap')
        if not isinstance(mapping, dict) or len(mapping) != 51:
            raise Refusal('generated venue has no complete original-port binding')
        if unbound or sorted(rtc)!=sorted([(mapping['7881'],mapping['7881'],'tcp'),
                                            (mapping['7882'],mapping['7882'],'udp')]):
            raise Refusal('isolated publisher escapes host loopback or private RTC ports')
        return set(mapping)
    return ports

def screen_quadlet_names(bundle, selector):
    """Require separate unit, network and container identities before activation."""
    prefix = selector['unitPrefix']
    paths = sorted((bundle / 'quadlet').glob('*/*'))
    if not paths:
        raise Refusal('missing rendered Quadlet units')
    for path in paths:
        if path.suffix not in ('.container', '.network', '.build', '.target'):
            raise Refusal('unclassified Quadlet member')
        if not path.name.startswith(prefix + '-') and path.name != prefix + '.target':
            raise Refusal('rendered unit retains non-venue name: ' + path.name)
        for line in path.read_text().splitlines():
            if '=' not in line or line.startswith('#'):
                continue
            key, value = line.split('=', 1)
            if key in ('ContainerName', 'NetworkName'):
                if not value.startswith(prefix + '-') and not value.startswith(prefix + '_'):
                    raise Refusal('rendered container or network name collides: ' + path.name)
            elif key == 'Network' and value != 'host' and not value.startswith(prefix + '-'):
                # Network=none is ONLY the three selected local-only build
                # units. It cannot authorize a container bridge/host escape.
                offline={prefix+'-'+name+'.build' for name in ('keycloak','onboarding','mastodon-rss-publisher')}
                if not (value=='none' and path.name in offline and
                        path.read_text().splitlines().count('Pull=never')==1):
                    raise Refusal('rendered network reference collides: ' + path.name)
            elif key in ('Requires', 'Wants', 'After', 'PartOf', 'WantedBy'):
                for name in value.split():
                    if name.startswith('webservices-') or name in ('webservices.target', 'webservices-runtime-env.service'):
                        raise Refusal('rendered unit references old stack: ' + path.name)
    return len(paths)


def screen_quadlet_mounts(bundle, selector, *, diagnostic_host_network=False):
    """Refuse rendered mounts outside the proposed venue, even if absent from IR.

    The IR volume map omits generated runtime/configuration paths, logging,
    socket mounts and module-specific hard-coded binds. A passing path-only
    selector must never be mistaken for proof that Quadlets use those paths.
    """
    root = bundle / 'quadlet'
    containers = sorted(root.glob('*/*.container'))
    if not containers:
        raise Refusal('missing rendered containers')
    explicit = set(selector['volumes'].values())
    private_roots = [selector['rootful']['stateRoot'], selector['rootful']['volumeRoot'],
                     selector['socketRoot'], *selector['storageRoots'].values()]
    for domain in selector['domains'].values():
        private_roots.extend((domain['stateRoot'], domain['volumeRoot']))
    os_readers = {'/', '/proc', '/sys', '/etc/localtime', '/etc/machine-id',
                  '/var/log/journal', '/run/log/journal'}
    checked = 0
    if diagnostic_host_network:
        # Diagnostic-only: never a live-listener or activation grant.
        expected_host = {selector['unitPrefix'] + '-' + name + '.container'
                         for name in ('alloy','caddy','node-exporter','ntfy-native-auth')}
        actual_host = {p.name for p in containers if 'Network=host' in p.read_text().splitlines()}
        if actual_host != expected_host:
            raise Refusal('unreviewed diagnostic host-network classification')
    for path in containers:
        authority = path.parent.name
        if authority != 'rootful' and authority.removeprefix('rootless-') not in selector['domains']:
            raise Refusal('unknown rendered Quadlet authority')
        for line in path.read_text().splitlines():
            if line == 'Network=host' and not diagnostic_host_network:
                raise Refusal('host-network container lacks isolated listener proof: ' + path.name)
            if not line.startswith('Volume='):
                continue
            checked += 1
            parts = line[7:].split(':')
            if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
                raise Refusal('unrecognized rendered volume declaration')
            source = parts[0]
            options = parts[2].split(',') if len(parts) == 3 else []
            if source in os_readers:
                if 'ro' not in options:
                    raise Refusal('host OS reader became writable: ' + source)
            elif source.startswith('%t/'):
                if authority == 'rootful' or source != '%t/podman/podman.sock':
                    raise Refusal('unreviewed runtime socket source')
            elif source.startswith('/'):
                if (source not in explicit and source != selector['socketRoot'] and
                        source not in selector['storageRoots'].values() and
                        source != selector['rootful']['volumeRoot'] and
                    not any(source.startswith(parent.rstrip('/') + '/') for parent in private_roots)):
                    raise Refusal('rendered bind escapes venue: ' + source)
                if os.path.normpath(source) != source or '..' in Path(source).parts:
                    raise Refusal('noncanonical rendered bind')
            elif source in selector['volumes'] and source.startswith('huly_'):
                if authority != 'rootless-apps':
                    raise Refusal('implicit Huly volume escaped apps authority')
            else:
                raise Refusal('unclassified rendered volume source')
    return checked


def screen_venue_volume_init(bundle, selector):
    """Venue volume-init cannot execute the legacy broad chmod/chown script."""
    prefix=selector['unitPrefix'];state=selector['rootful']['stateRoot']
    unit=bundle/'quadlet/rootful'/(prefix+'-volume-init.container')
    if not unit.is_file() or unit.is_symlink():raise Refusal('missing isolated volume-init gate')
    lines=unit.read_text().splitlines()
    marker=state+'/volume-ready-r1.txt'
    expected_mount='Volume='+marker+':/run/p0-venue-volume-ready.txt:ro'
    exec_lines=[line for line in lines if line.startswith('Exec=')]
    if (lines.count('AssertPathIsRegular='+marker)!=1 or
            [line for line in lines if line.startswith('Volume=')]!=[expected_mount] or
            lines.count('Entrypoint=/bin/sh')!=1 or len(exec_lines)!=1 or
            "grep -qx '"+prefix+"-volume-ready-v1' /run/p0-venue-volume-ready.txt" not in exec_lines[0] or
            any(token in exec_lines[0] for token in ('chmod','chown','mkdir',';','&&','||'))):
        raise Refusal('venue volume-init requires private host-installer ready marker; no broad mutation')
    return True

def screen_rootful_store_quadlets(bundle, selector):
    """Every rootful Podman unit must route to the venue's graph configuration."""
    root = bundle / 'quadlet/rootful'
    expected = 'Environment=CONTAINERS_STORAGE_CONF=' + selector['rootful']['stateRoot'] + '/containers-storage.conf'
    network = 'Environment=CONTAINERS_CONF=' + selector['rootful']['stateRoot'] + '/containers.conf'
    paths = sorted(p for p in root.iterdir() if p.suffix in ('.container', '.network', '.build'))
    if not paths:
        raise Refusal('missing rootful Podman units')
    for path in paths:
        lines = path.read_text().splitlines()
        values = [line for line in lines if line.startswith('Environment=CONTAINERS_STORAGE_CONF=')]
        if values != [expected] or [line for line in lines if line.startswith('Environment=CONTAINERS_CONF=')]!=[network] or '[Service]' not in lines:
            raise Refusal('rootful Quadlet not bound to isolated graph and netavark directory: ' + path.name)
    return len(paths)


def screen_rendered_ports(bundle, selector):
    """All 48 publishers: 46 loopback, two exact guest-only Livekit RTC."""
    expected = set(selector['ports'].values()) - {
        selector['ports'][original] for original in ('80', '443', '9100')
    }
    actual = []
    for path in (bundle / 'quadlet').glob('*/*.container'):
        for line in path.read_text().splitlines():
            if not line.startswith('PublishPort='):
                continue
            spec=line.split('=',1)[1]
            if path.name==selector['unitPrefix']+'-livekit.container' and spec.startswith('192.168.140.1:'):
                match=re.fullmatch(r'192\.168\.140\.1:([0-9]{1,5}):([0-9]{1,5})/(tcp|udp)',spec)
                if match and (int(match.group(1)),int(match.group(2)),match.group(3)) not in (
                        (selector['ports']['7881'],selector['ports']['7881'],'tcp'),
                        (selector['ports']['7882'],selector['ports']['7882'],'udp')):
                    raise Refusal('unreviewed guest RTC port identity')
            else:
                match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5}):[0-9]{1,5}(?:/(?:tcp|udp))?',spec)
            if not match:
                raise Refusal('unrecognized rendered published-port syntax')
            actual.append(int(match.group(1)))
    if len(actual) != 48 or len(set(actual)) != 48 or set(actual) != expected:
        raise Refusal('rendered published ports do not match isolated mapping')
    return len(actual)


def host_identity_port_screen(selector):
    occupied_uids = {p.pw_uid for p in pwd.getpwall()}
    occupied_names = {p.pw_name for p in pwd.getpwall()}
    occupied_subids = []
    for filename in ('/etc/subuid','/etc/subgid'):
        for line in Path(filename).read_text().splitlines():
            parts = line.split(':')
            if len(parts) != 3:
                raise Refusal('unparseable subordinate-id authority')
            try: start, length = int(parts[1]), int(parts[2])
            except ValueError as exc: raise Refusal('unparseable subordinate-id range') from exc
            occupied_subids.append((start,start+length))
    for entry in selector['domains'].values():
        if entry['user'] in occupied_names or entry['uid'] in occupied_uids:
            raise Refusal('existing account identity')
        low = entry['subuidStart']; high = low + 65536
        if any(low < end and start < high for start,end in occupied_subids):
            raise Refusal('existing subordinate-id range')
    port_screen(selector)


def port_screen(selector):
    """Recheck listeners after account provisioning without re-adopting users."""
    occupied_ports = set()
    for filename in ('/proc/net/tcp','/proc/net/tcp6','/proc/net/udp','/proc/net/udp6'):
        for line in Path(filename).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10: raise Refusal('unparseable socket table')
            # A closed outbound TCP connection can use a reserved number as
            # its ephemeral source port. TIME_WAIT with inode0 has no live
            # listener/owner; it must not masquerade as an installed service.
            # All live, UDP and unknown socket states remain conservative gates.
            if filename in ('/proc/net/tcp','/proc/net/tcp6') and fields[3]=='06' and fields[9]=='0':continue
            occupied_ports.add(int(fields[1].rsplit(':',1)[1],16))
    # Caddy's venue-only admin API is off; the other three host-network
    # local-only listeners have no Podman publisher. Reserve their actual
    # endpoints independently of unused mapped legacy port identities.
    host_network_local_ports = {9100, 12345, 25017}
    if occupied_ports.intersection(set(selector['ports'].values()) | host_network_local_ports):
        raise Refusal('port in use on host')

def protected_sources(inventory):
    if len(inventory) != 76:
        raise Refusal('incomplete selected inventory')
    root_binds = [m for row in inventory for m in row['mounts'] if m['Type']=='bind' and m['Source']=='/']
    if any(m['RW'] for m in root_binds):
        raise Refusal('writable host root bind')
    return {m['Source'] for row in inventory for m in row['mounts'] if m['Type']=='bind' and m['Source']!='/'}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--selector',required=True)
    ap.add_argument('--bundle',required=True)
    ap.add_argument('--protected-inventory',required=True)
    args = ap.parse_args()
    try:
        inventory = json.loads(Path(args.protected_inventory).read_text())
        # A read-only node-exporter host-/ reader is not a writable data
        # claim; a writable / bind is a hard refusal.
        protected = protected_sources(inventory)
        protected.update(('/var/lib/webservices','/etc/containers/systemd','/etc/systemd/system','/run/webservices','/mnt/stack/podman','/mnt/stack/rootless','/mnt/stack/volumes','/mnt/stack/vector-dbs','/mnt/stack/pg-ssd','/mnt/media','/mnt/lab_debian/agent_vm/clean-role'))
        selector = json.loads(Path(args.selector).read_text())
        result = check(selector,
                       json.loads((Path(args.bundle)/'stack.ir.json').read_text()),
                       json.loads((Path(args.bundle)/'podman-domains.json').read_text()),
                       sorted(absolute(p) for p in protected),
                       required_ports=published_host_ports(Path(args.bundle)))
        result['guestBinding'] = screen_guest_binding(Path(args.bundle), selector)
        host_identity_port_screen(selector)
        result['checkedQuadletUnits'] = screen_quadlet_names(Path(args.bundle), selector)
        result['checkedRootfulStoreUnits'] = screen_rootful_store_quadlets(Path(args.bundle), selector)
        result['checkedQuadletMounts'] = screen_quadlet_mounts(Path(args.bundle), selector)
        result['checkedPublishedPorts'] = screen_rendered_ports(Path(args.bundle), selector)
        print(json.dumps(result,sort_keys=True))
    except (Refusal, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit('venue preflight refused: '+str(exc)) from exc

if __name__ == '__main__': main()
