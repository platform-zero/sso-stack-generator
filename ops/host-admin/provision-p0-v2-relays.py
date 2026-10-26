#!/usr/bin/python3 -I
"""Prepare only fresh closed inactive P0 relay sources; no activation or evidence refresh."""
import sys
if __name__ == '__main__' and not sys.flags.isolated:
    sys.stdout.write('{"version":1,"refused":true,"reason":"isolated-python-required"}\n')
    raise SystemExit(2)

import argparse
import ctypes
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import selectors
import signal
import stat
import subprocess
import time



TARGET = Path('/mnt/stack/p0-v2')

SHARED = Path('/mnt/stack')

AUTHORITY = Path('/var/lib/p0-v2-namespace')

HOME = Path('/var/lib/p0-runtime')

LIMIT = 262144

HEX = re.compile(r'[0-9a-f]{64}')

UNIT = re.compile(r'p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*\.service')

UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')

class Refused(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Refused(code)

def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate-json-key')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('invalid-json')))

def identity(s):
    return {'device': s.st_dev, 'inode': s.st_ino}

def snapshot(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def strict_directory(path, owners=(0,), mode=None):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'directory-path')
    for part in (Path('/'), *reversed(path.parents[:-1]), path):
        s = part.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in owners and not s.st_mode & 0o022, 'directory-custody')
    if mode is not None:
        require(stat.S_IMODE(path.lstat().st_mode) == mode, 'directory-mode')

def read_exact(path, uid=0, mode=None, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_nlink == 1
                and not s.st_mode & 0o022 and s.st_size <= limit, 'file-custody')
        if mode is not None:
            require(stat.S_IMODE(s.st_mode) == mode, 'file-mode')
        raw = os.read(fd, limit + 1)
        require(len(raw) == s.st_size and snapshot(os.fstat(fd)) == snapshot(s), 'file-changed')
        return raw, snapshot(s)
    finally:
        os.close(fd)

def bounded_read(path, limit):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'observation-limit')
    return raw

def mountinfo(raw):
    """Parse only public kernel mount metadata, with duplicate/escape defenses."""
    result = []
    for line in raw.decode('ascii').splitlines():
        left, right = line.split(' - ')
        fields, tail = left.split(), right.split()
        require(len(fields) >= 6 and len(tail) == 3, 'mountinfo-schema')
        def unescape(s):
            s = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), s)
            require('\\' not in s, 'mountinfo-escape')
            return s
        result.append({'id': int(fields[0]), 'parent': int(fields[1]), 'device': fields[2],
                       'root': unescape(fields[3]), 'target': unescape(fields[4]),
                       'options': fields[5].split(','), 'optional': fields[6:],
                       'fsType': tail[0], 'source': unescape(tail[1])})
    require(len({m['id'] for m in result}) == len(result), 'mountinfo-duplicate')
    return result

def kernel():
    boot = bounded_read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    require(UUID.fullmatch(boot), 'boot-id')
    current = identity(os.stat('/proc/self/ns/mnt'))
    require(current == identity(os.stat('/proc/1/ns/mnt')), 'not-host-mount-namespace')
    return {'bootId': boot, 'mountNamespace': current,
            'mounts': mountinfo(bounded_read('/proc/self/mountinfo', 4 * 1024**2))}

def boundary_view(observation):
    # Independent mounts outside the owned boundary are not an activation gate.
    return {'bootId': observation['bootId'], 'mountNamespace': observation['mountNamespace'],
            'mounts': [m for m in observation['mounts'] if m['target'] in ('/', '/mnt', str(SHARED), str(TARGET))
                       or m['target'].startswith(str(TARGET) + '/')]}

def namespace(expected):
    """Anchor the existing inode; never follow an operator-replaced link."""
    strict_directory('/mnt')
    shared = SHARED.lstat()
    require(stat.S_ISDIR(shared.st_mode) and shared.st_uid == 1000 and shared.st_gid == 1000
            and stat.S_IMODE(shared.st_mode) == 0o2775, 'shared-parent-identity')
    parent = os.open(SHARED, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(identity(os.fstat(parent)) == identity(shared), 'shared-parent-changed')
        fd = os.open('p0-v2', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        s = os.fstat(fd)
        actual = dict(identity(s), filesystemId=os.fstatvfs(fd).f_fsid)
        require(actual == expected and s.st_uid == 0 and s.st_gid == 0
                and stat.S_IMODE(s.st_mode) == 0o711, 'namespace-identity')
        require(identity(TARGET.lstat()) == {k: expected[k] for k in ('device', 'inode')}, 'namespace-renamed')
        return fd
    except BaseException:
        os.close(fd)
        raise

def observed_mount(observation, expected, *, pinned):
    mounts = observation['mounts']
    parents = [m for m in mounts if m['target'] == str(SHARED)]
    require(len(parents) == 1, 'shared-parent-not-exact-mount')
    parent = parents[0]
    device = f"{os.major(expected['device'])}:{os.minor(expected['device'])}"
    require(parent['device'] == device, 'namespace-filesystem')
    require(not any(m['target'].startswith(str(TARGET) + '/') for m in mounts), 'namespace-submount')
    own = [m for m in mounts if m['target'] == str(TARGET)]
    require(len(own) <= 1, 'stacked-namespace-mount')
    if not pinned:
        require(not own, 'foreign-existing-mount')
        return None
    require(len(own) == 1, 'namespace-unpinned')
    own = own[0]
    root = parent['root'].rstrip('/') + '/p0-v2'
    require(own['parent'] == parent['id'] and own['device'] == device and own['root'] == root
            and own['fsType'] == parent['fsType'] and own['source'] == parent['source']
            and 'rw' in own['options'], 'foreign-namespace-mount')
    return own

def private_mount(own):
    require(not any(s.startswith(('shared:', 'master:', 'propagate_from:')) or s == 'unbindable'
                    for s in own['optional']), 'namespace-mount-not-private')

def same_mount_or_private_transition(saved, own):
    if saved == own:
        return True
    return (isinstance(saved, dict) and set(saved) == set(own) and isinstance(saved.get('optional'), list)
            and all(isinstance(v, str) and re.fullmatch(r'(shared|master|propagate_from):[1-9][0-9]*', v)
                    for v in saved['optional']) and own['optional'] == []
            and {k: v for k, v in own.items() if k != 'optional'}
                == {k: v for k, v in saved.items() if k != 'optional'})

def record_binding(record, expected):
    require(isinstance(record, dict) and set(record) == {'version', 'state', 'owner', 'evidenceSha256',
            'namespace', 'bootId', 'mountNamespace', 'mount', 'cloneMountId', 'integrity'}, 'marker-schema')
    require(isinstance(record['namespace'], dict) and set(record['namespace']) == {'device', 'inode', 'filesystemId'}
            and all(type(v) is int and v > 0 for v in record['namespace'].values()), 'marker-binding')
    fields = {k: v for k, v in record.items() if k != 'integrity'}
    digest = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(record['integrity'] == digest and type(record['version']) is int and record['version'] == 2
            and record['state'] in ('claimed', 'pinned') and isinstance(record['owner'], str)
            and re.fullmatch(r'[0-9a-f]{32}', record['owner'])
            and isinstance(record['evidenceSha256'], str) and HEX.fullmatch(record['evidenceSha256'])
            and record['namespace'] == expected and isinstance(record['bootId'], str) and UUID.fullmatch(record['bootId'])
            and isinstance(record['mountNamespace'], dict) and set(record['mountNamespace']) == {'device', 'inode'}
            and all(type(v) is int and v > 0 for v in record['mountNamespace'].values())
            and (record['mount'] is None or isinstance(record['mount'], dict))
            and (record['cloneMountId'] is None or (type(record['cloneMountId']) is int
                 and 0 < record['cloneMountId'] < 2**64)), 'marker-binding')

def verify_marker(record, observation, expected, *, allow_claimed=False):
    record_binding(record, expected)
    require(record['state'] == 'pinned' or (allow_claimed and record['state'] == 'claimed'), 'marker-binding')
    require(record['bootId'] == observation['bootId'] and record['mountNamespace'] == observation['mountNamespace'],
            'marker-stale-boot-or-namespace')
    own = observed_mount(observation, expected, pinned=True)
    private_mount(own)
    require(record['cloneMountId'] == own['id'], 'preclaimed-mount-id-changed')
    require(record['mount'] == own or (allow_claimed and record['state'] == 'claimed'
            and same_mount_or_private_transition(record['mount'], own)), 'marker-mount-changed')
    return own

def account():
    e = pwd.getpwnam('p0-runtime')
    require(e.pw_uid >= 1000 and e.pw_gid >= 1000 and e.pw_dir == str(HOME)
            and e.pw_shell == '/usr/sbin/nologin', 'actor-identity')
    g = grp.getgrgid(e.pw_gid)
    require(g.gr_name == 'p0-runtime' and not g.gr_mem
            and not any('p0-runtime' in x.gr_mem for x in grp.getgrall()), 'actor-groups')
    return e

def reserves():
    available = 0
    with open('/proc/meminfo', encoding='ascii') as stream:
        for line in stream:
            if line.startswith('MemAvailable:'):
                available = int(line.split()[1]) * 1024
    require(available >= 16 * 1024**3, 'ram-reserve')
    for path, floor in (('/', 50), ('/mnt/stack/p0-v2', 100), ('/var/lib', 1)):
        v = os.statvfs(path)
        require(v.f_bavail * v.f_frsize >= floor * 1024**3, 'disk-reserve')

def evidence(raw):
    value = strict_json(raw)
    require(isinstance(value, dict) and type(value.get('version')) is int
            and ((value['version'] == 1 and set(value) == {'version', 'namespace', 'units'})
                 or (value['version'] == 2 and set(value) == {'version', 'namespace', 'units', 'relays'})), 'evidence-schema')
    expected = value['namespace']
    require(isinstance(expected, dict) and set(expected) == {'device', 'inode', 'filesystemId'}
            and all(type(v) is int and v > 0 for v in expected.values()), 'evidence-identity')
    require(isinstance(value['units'], dict) and set(value['units']) == {'rootless', 'rootful'}, 'evidence-actors')
    for actor, units in value['units'].items():
        require(isinstance(units, list) and len(units) <= 256, 'evidence-units')
        seen = set()
        for entry in units:
            require(isinstance(entry, dict) and set(entry) in ({'name', 'sourceSha256'}, {'name', 'kind', 'sourceSha256'})
                    and entry.get('kind', 'container') in ('container', 'network', 'volume')
                    and isinstance(entry['name'], str) and UNIT.fullmatch(entry['name'])
                    and len(entry['name']) <= 128 and entry['name'] not in seen
                    and (actor != 'rootful' or entry['name'].startswith('p0-v2-'))
                    and isinstance(entry['sourceSha256'], str) and HEX.fullmatch(entry['sourceSha256']), 'evidence-unit')
            quadlet_name(entry)  # Bind native service suffix to its explicitly reviewed source kind.
            seen.add(entry['name'])
    relays = value.get('relays', [])
    require(isinstance(relays, list) and len(relays) <= 64, 'evidence-relays')
    names = {e['name'] for e in value['units']['rootful']}
    for relay in relays:
        relay_contract(relay)
        service, socket = relay_names(relay)
        require(service not in names, 'evidence-relay-collision')
        names.add(service)
    require(len(names) <= 256, 'evidence-units')
    return value

def quadlet_name(entry):
    kind = entry.get('kind', 'container')
    require(kind in ('container', 'network', 'volume'), 'evidence-unit-kind')
    suffix = '.service' if kind == 'container' else '-' + kind + '.service'
    require(entry['name'].endswith(suffix), 'evidence-unit-source-name')
    stem = entry['name'][:-len(suffix)]
    require(re.fullmatch(r'p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*', stem), 'evidence-unit-source-name')
    return stem + '.' + kind

def no_quadlet_dropins(source):
    # Quadlet's generic and dash-prefix drop-ins can override an unchanged source.
    stem, extension = source.stem, source.suffix
    names = {extension[1:] + '.d', source.name + '.d'}
    names.update(stem[:i + 1] + extension + '.d' for i, char in enumerate(stem) if char == '-')
    for name in names:
        try:
            (source.parent / name).lstat()
        except FileNotFoundError:
            continue
        raise Refused('quadlet-source-dropins')

RELAY_BASE = Path('/run/p0-v2-upstreams')

RELAY_UNITS = Path('/etc/systemd/system')

RELAY_PROXY = '/usr/lib/systemd/systemd-socket-proxyd'

NATIVE_UNIT_ROOTS = tuple(Path(p) for p in (
    '/etc/systemd/system.control', '/run/systemd/system.control', '/run/systemd/transient',
    '/run/systemd/generator.early', '/etc/systemd/system', '/etc/systemd/system.attached',
    '/run/systemd/system', '/run/systemd/system.attached', '/run/systemd/generator',
    '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system', '/run/systemd/generator.late'))

def relay_names(relay):
    name = 'p0-v2-' + relay['id']
    return name + '.service', name + '.socket'

def relay_contract(relay):
    require(isinstance(relay, dict) and set(relay) in (
        {'id', 'address', 'port', 'serviceSha256', 'socketSha256'},
        {'id', 'address', 'port', 'serviceSha256', 'socketSha256', 'resources'}), 'relay-schema')
    require(isinstance(relay['id'], str) and re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', relay['id'])
            and len(relay_names(relay)[0]) <= 128
            and len(str(RELAY_BASE / relay['id'] / 'http.sock').encode()) <= 107, 'relay-id')
    require(isinstance(relay['address'], str) and '%' not in relay['address'], 'relay-address')
    try:
        address = ipaddress.ip_address(relay['address'])
    except ValueError:
        raise Refused('relay-address') from None
    require(address.is_loopback and str(address) == relay['address'], 'relay-address')
    require(type(relay['port']) is int and 1 <= relay['port'] <= 65535
            and all(isinstance(relay[k], str) and HEX.fullmatch(relay[k]) for k in ('serviceSha256', 'socketSha256')), 'relay-binding')
    resources = relay.get('resources', {})
    require(isinstance(resources, dict) and set(resources) <= {'memoryMax', 'tasksMax'}
            and all(type(v) is int and 1 <= v < 2**63 for v in resources.values()), 'relay-resources')

def relay_sources(relay):
    # Independent closed Root contract. Never import core/service renderer code.
    relay_contract(relay)
    service, socket = relay_names(relay)
    address = ipaddress.ip_address(relay['address'])
    host = '[' + str(address) + ']' if address.version == 6 else str(address)
    prefix = '# Generated closed P0 HTTP socket relay; no auto-start.\n'
    sock = (prefix + '[Unit]\nDescription=P0 private upstream listener\n\n[Socket]\n'
            + f'ListenStream={RELAY_BASE / relay["id"] / "http.sock"}\nService={service}\n'
            + 'SocketUser=0\nSocketGroup=0\nSocketMode=0600\n'
            + 'DirectoryMode=0710\nRemoveOnStop=true\n')
    unit = (prefix + '[Unit]\nDescription=P0 fixed upstream forwarding\n\n[Service]\n'
            + f'ExecStart={RELAY_PROXY} --exit-idle-time=5min {host}:{relay["port"]}\n'
            + 'User=p0-runtime\nGroup=p0-runtime\nUMask=0077\nNoNewPrivileges=true\n'
            + 'CapabilityBoundingSet=\nAmbientCapabilities=\nPrivateTmp=true\nPrivateDevices=true\n'
            + 'ProtectSystem=strict\nProtectHome=true\nProtectKernelTunables=true\n'
            + 'ProtectKernelModules=true\nProtectControlGroups=true\n'
            + 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictSUIDSGID=true\n'
            + 'TimeoutStartSec=30\nTimeoutStopSec=30\nRestart=no\n')
    for key, directive in (('memoryMax', 'MemoryMax'), ('tasksMax', 'TasksMax')):
        if key in relay.get('resources', {}):
            unit += f'{directive}={relay["resources"][key]}\n'
    return {service: unit.encode(), socket: sock.encode()}

def no_native_dropins(name):
    stem, extension = name.rsplit('.', 1)
    names = {extension + '.d', name + '.d'}
    names.update(stem[:i + 1] + '.' + extension + '.d' for i, char in enumerate(stem) if char == '-')
    for root in NATIVE_UNIT_ROOTS:
        if root != RELAY_UNITS:
            try:
                (root / name).lstat()
            except FileNotFoundError:
                pass
            else:
                raise Refused('native-alternate-fragment')
        for directory in names:
            try:
                (root / directory).lstat()
            except FileNotFoundError:
                continue
            raise Refused('native-source-dropins')

def closed_relay_listener(relay, entry):
    require(identity(os.stat('/proc/self/ns/net')) == identity(os.stat('/proc/1/ns/net')), 'not-host-network-namespace')
    path = RELAY_BASE / relay['id'] / 'http.sock'
    if os.path.lexists(RELAY_BASE):
        strict_directory(RELAY_BASE)
    if os.path.lexists(path.parent):
        strict_directory(path.parent, mode=0o710)
        require(path.parent.lstat().st_gid == 0, 'relay-directory-custody')
    require(not os.path.lexists(path), 'relay-socket-path-remains')
    raw = bounded_read('/proc/net/unix', 4 * 1024**2).decode('ascii')
    lines = raw.splitlines()
    require(lines and lines[0].split() == ['Num', 'RefCount', 'Protocol', 'Flags', 'Type', 'St', 'Inode', 'Path'], 'unix-table-schema')
    for line in lines[1:]:
        parts = line.split(maxsplit=7)
        require(len(parts) in (7, 8), 'unix-table-schema')
        require(len(parts) == 7 or parts[7] != str(path), 'relay-kernel-socket-remains')

class Native:

    def __init__(self, entry):
        self.entry = entry

    def call(self, args, actor='rootful', pass_fds=()):
        require(actor in ('rootless', 'rootful') and (not pass_fds) and (not any(('/proc/self/fd/' in arg for arg in args))), 'native-fd-alias-refused')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}
        executable = args[0]
        if actor == 'rootless':
            args = ['/usr/bin/setpriv', '--reuid', str(self.entry.pw_uid), '--regid', str(self.entry.pw_gid), '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all'] + args
            env.update(HOME=str(HOME), XDG_RUNTIME_DIR=f'/run/user/{self.entry.pw_uid}')
        for executable in {executable, '/usr/bin/setpriv'} if actor == 'rootless' else {executable}:
            require(executable in ('/usr/bin/setpriv', '/usr/bin/systemctl'), 'native-executable')
            strict_directory(Path(executable).parent)
            read_exact(executable, limit=128 * 1024 ** 2)
            require(os.stat(executable).st_mode & 73, 'native-executable')
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd='/', pass_fds=pass_fds, start_new_session=True)
        data = bytearray()
        settled = False
        try:
            deadline = time.monotonic() + 30
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'native-timeout')
                    for key, _ in selector.select(min(remaining, 1)):
                        block = os.read(key.fileobj.fileno(), 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            data.extend(block)
                            require(len(data) <= LIMIT, 'native-output-limit')
            rc = p.wait(timeout=max(0.01, deadline - time.monotonic()))
            settled = True
            require(rc == 0, 'native-operation-uncertain')
            return bytes(data)
        finally:
            if not settled:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=5)
            p.stdout.close()

    def stopped_units(self, proof, owned=()):
        for actor, units in proof['units'].items():
            prefix = ['/usr/bin/systemctl'] + (['--user'] if actor == 'rootless' else [])
            relays = proof.get('relays', []) if actor == 'rootful' else []
            sockets = {relay_names(r)[1] for r in relays} | {name for name in owned if actor == 'rootful' and name.endswith('.socket')}
            expected = {entry['name'] for entry in units} | {relay_names(r)[0] for r in relays} | {name for name in owned if actor == 'rootful' and name.endswith('.service')}
            scope = 'p0-v2-' if actor == 'rootful' else 'p0-'
            require(all((name.startswith(scope) for name in expected)), 'unit-runtime-scope')
            for command in (['list-units', '--all', '--plain', '--no-legend', scope + '*.service'], ['list-unit-files', '--no-legend']):
                raw = self.call(prefix + command, actor)
                names = set()
                for line in raw.splitlines():
                    token = line.split()[0]
                    if not token.startswith(scope.encode('ascii')):
                        continue
                    name = token.decode('ascii')
                    if name in sockets:
                        continue
                    require(not name.endswith(('.timer', '.socket', '.path')), 'runtime-triggers-remain')
                    require(UNIT.fullmatch(name), 'unit-inventory-schema')
                    names.add(name)
                require(names <= expected, 'unreviewed-runtime-unit')
            triggers = [scope + '*' + suffix for suffix in ('.timer', '.socket', '.path')]
            for command in (['list-units', '--all', '--plain', '--no-legend'] + triggers,):
                raw = self.call(prefix + command, actor)
                require(all((line.split()[0].decode('ascii') in sockets for line in raw.splitlines())), 'runtime-triggers-remain')
            for entry in units:
                name = entry['name']
                source = (HOME / '.config/containers/systemd' if actor == 'rootless' else Path('/etc/containers/systemd')) / quadlet_name(entry)
                strict_directory(source.parent, (0, self.entry.pw_uid) if actor == 'rootless' else (0,))
                no_quadlet_dropins(source)
                raw, _ = read_exact(source, self.entry.pw_uid if actor == 'rootless' else 0)
                require(hashlib.sha256(raw).hexdigest() == entry['sourceSha256'], 'unit-source-binding')
                raw = self.call(prefix + ['show', name, '--no-pager', '--property=LoadState,ActiveState,MainPID,ControlGroup,Job,SourcePath,FragmentPath,DropInPaths,TriggeredBy'], actor)
                props = {}
                for line in raw.decode('utf-8').splitlines():
                    key, value = line.split('=', 1)
                    require(key not in props, 'unit-properties-schema')
                    props[key] = value
                generator = Path(f'/run/user/{self.entry.pw_uid}/systemd') if actor == 'rootless' else Path('/run/systemd')
                fragments = {str(generator / directory / name) for directory in ('generator', 'generator.early', 'generator.late')}
                require(set(props) == {'LoadState', 'ActiveState', 'MainPID', 'ControlGroup', 'Job', 'SourcePath', 'FragmentPath', 'DropInPaths', 'TriggeredBy'} and props['LoadState'] == 'loaded' and (props['ActiveState'] in ('inactive', 'failed')) and (props['MainPID'] == '0') and (props['ControlGroup'] == '') and (props['Job'] == '') and (props['SourcePath'] == str(source)) and (props['FragmentPath'] in fragments) and (props['DropInPaths'] == '') and (props['TriggeredBy'] == ''), 'runtime-unit-not-stopped')
        for relay in proof.get('relays', []):
            self.stopped_relay(relay)

    def stopped_relay(self, relay):
        service, socket = relay_names(relay)
        closed_relay_listener(relay, self.entry)
        for name, expected in relay_sources(relay).items():
            source = RELAY_UNITS / name
            strict_directory(source.parent)
            no_native_dropins(name)
            raw, initial = read_exact(source, 0)
            digest_key = 'serviceSha256' if name == service else 'socketSha256'
            require(hashlib.sha256(raw).hexdigest() == relay[digest_key] and raw == expected, 'relay-source-binding')
            common = {'LoadState', 'ActiveState', 'SubState', 'Job', 'ControlGroup', 'ControlPID', 'SourcePath', 'FragmentPath', 'DropInPaths', 'TriggeredBy', 'NeedDaemonReload'}
            fields = common | ({'MainPID', 'User', 'Group'} if name == service else {'Triggers'})
            raw = self.call(['/usr/bin/systemctl', 'show', name, '--no-pager', '--property=' + ','.join(sorted(fields))])
            props = {}
            for line in raw.decode('utf-8').splitlines():
                key, value = line.split('=', 1)
                require(key not in props, 'relay-properties-schema')
                props[key] = value
            require(set(props) == fields and props['LoadState'] == 'loaded' and (props['Job'] == props['ControlGroup'] == props['SourcePath'] == props['DropInPaths'] == '') and (props['ControlPID'] == '0') and (props['FragmentPath'] == str(source)) and (props['NeedDaemonReload'] == 'no'), 'relay-not-stopped')
            if name == service:
                require(props['ActiveState'] in ('inactive', 'failed') and props['SubState'] in ('dead', 'failed') and (props['MainPID'] == '0') and (props['User'] == props['Group'] == 'p0-runtime') and (props['TriggeredBy'] == socket), 'relay-not-stopped')
            else:
                require(props['ActiveState'] == 'inactive' and props['SubState'] == 'dead' and (props['TriggeredBy'] == '') and (props['Triggers'] == service), 'relay-not-stopped')
            require(read_exact(source, 0) == (expected, initial), 'relay-source-changed')
        closed_relay_listener(relay, self.entry)

class Marker:
    def __init__(self, base=AUTHORITY):
        self.base, self.fd, self.previous = Path(base), None, None

    def open(self, mutating, *, create=None):
        if create is None:
            create = mutating
        strict_directory(self.base.parent)
        if not os.path.lexists(self.base):
            if not create:
                return False
            self.base.mkdir(mode=0o700)
        strict_directory(self.base, mode=0o700)
        self.fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fcntl.flock(self.fd, (fcntl.LOCK_EX if mutating else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        self.directory_id = identity(os.fstat(self.fd))
        require(set(os.listdir(self.fd)) <= {'active.json'}, 'unknown-marker-entry')
        self.previous = self.current()
        return True

    def current(self):
        strict_directory(self.base, mode=0o700)
        require(identity(self.base.lstat()) == self.directory_id, 'marker-directory-changed')
        if not os.path.lexists(self.base / 'active.json'):
            return None
        return read_exact(self.base / 'active.json', 0, 0o400)

    def load(self):
        if self.previous is None:
            return None
        record = strict_json(self.previous[0])
        require(isinstance(record, dict), 'marker-schema')
        fields = {k: v for k, v in record.items() if k != 'integrity'}
        require(record.get('integrity') == hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'marker-integrity')
        return record

    def save(self, record):
        require(self.current() == self.previous, 'marker-cas')
        fields = {k: v for k, v in record.items() if k != 'integrity'}
        record['integrity'] = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        require(len(raw) <= LIMIT, 'marker-size')
        name = '.publish-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o400)
            require(os.write(fd, raw) == len(raw), 'marker-short-write')
            os.fsync(fd)
        finally:
            os.close(fd)
        require(self.current() == self.previous, 'marker-cas')
        os.replace(name, 'active.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.previous = self.current()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

RELAY_AUTHORITY = Path('/var/lib/p0-v2-relays')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def intent(raw):
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'version', 'relays'}
            and type(value['version']) is int and value['version'] == 1
            and isinstance(value['relays'], list) and 1 <= len(value['relays']) <= 64, 'intent-schema')
    seen = set()
    for relay in value['relays']:
        sources = relay_sources(relay)
        require(relay['id'] not in seen, 'intent-collision')
        seen.add(relay['id'])
        service, socket = relay_names(relay)
        require(sha(sources[service]) == relay['serviceSha256'] and sha(sources[socket]) == relay['socketSha256'], 'intent-source-hash')
    return value


class Authority:
    """Hold shared namespace lock; installer never refreshes its evidence."""
    def __init__(self, proof, digest):
        # Critical07:06 publication is paused, not authorized by old v2 binds.
        raise Refused('protected-view-v3-integration-required')

    def legacy_observation_init(self, proof, digest):
        """Uncalled legacy geometry for source comparison, NOT authority."""
        self.marker, self.fd = Marker(), None
        try:
            self.marker.open(False, create=False)
            self.record = self.marker.load()
            require(self.record is not None and self.record.get('evidenceSha256') == digest, 'namespace-evidence-changed')
            self.expected = proof['namespace']
            self.fd = namespace(self.expected)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        require(self.marker.current() == self.marker.previous, 'namespace-marker-changed')
        verify_marker(self.record, kernel(), self.expected)
        current = namespace(self.expected)
        try:
            require(identity(os.fstat(current)) == identity(os.fstat(self.fd)), 'namespace-changed')
        finally:
            os.close(current)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.marker.close()


def node_identity(s):
    return {'device': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid,
            'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode)}


class Anchor:
    def __init__(self, path):
        self.path = Path(path)
        strict_directory(self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.expected = node_identity(os.fstat(self.fd))
        try:
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        strict_directory(self.path)
        require(node_identity(os.fstat(self.fd)) == self.expected
                == node_identity(self.path.lstat()) and self.expected['gid'] == 0, 'target-parent-changed')
        v = os.fstatvfs(self.fd)
        require(v.f_bavail * v.f_frsize >= 1024**3, 'target-staging-reserve')

    def close(self):
        os.close(self.fd)


def plan(definition):
    result = {'base': {'path': RELAY_BASE, 'mode': 0o711, 'bytes': None}}
    for relay in definition['relays']:
        result[relay['id'] + '.dir'] = {'path': RELAY_BASE / relay['id'], 'mode': 0o710, 'bytes': None}
        for name, raw in relay_sources(relay).items():
            result[name] = {'path': RELAY_UNITS / name, 'mode': 0o400, 'bytes': raw}
    return result


class Files:
    def __init__(self, definition):
        self.plan, self.anchors = plan(definition), {}

    def parent(self, key):
        path = self.plan[key]['path'].parent
        if path not in self.anchors:
            self.anchors[path] = Anchor(path)
        self.anchors[path].check()
        return self.anchors[path]

    def temp(self, key, nonce):
        return '.p0-relay-' + nonce + '-' + key

    def probe(self, key, nonce, temporary=False):
        item = self.plan[key]
        name = self.temp(key, nonce) if temporary else item['path'].name
        if not os.path.lexists(item['path'].parent):
            return None
        parent = self.parent(key)
        try:
            s = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        directory = item['bytes'] is None
        require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1)
                and s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == item['mode'], 'target-custody')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
        fd = os.open(name, flags, dir_fd=parent.fd)
        try:
            require(node_identity(os.fstat(fd)) == node_identity(s), 'target-inode-changed')
            if not directory:
                require(s.st_size == len(item['bytes']) and os.read(fd, LIMIT + 1) == item['bytes']
                        and snapshot(os.fstat(fd)) == snapshot(s), 'target-source-changed')
            else:
                require(not temporary or not os.listdir(fd), 'prepared-directory-not-empty')
                require('system.posix_acl_default' not in os.listxattr(fd), 'target-default-acl')
            return node_identity(s)
        finally:
            os.close(fd)

    def prepare(self, key, nonce):
        item, parent = self.plan[key], self.parent(key)
        name = self.temp(key, nonce)
        require(self.probe(key, nonce) is None and self.probe(key, nonce, True) is None, 'target-exists')
        if item['bytes'] is None:
            os.mkdir(name, 0o700, dir_fd=parent.fd)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        else:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent.fd)
        try:
            os.fchown(fd, 0, 0)  # Only the inode just exclusively created above.
            os.fchmod(fd, item['mode'])  # Independent of caller umask; never existing data.
            if item['bytes'] is None:
                if 'system.posix_acl_default' in os.listxattr(fd):
                    os.removexattr(fd, 'system.posix_acl_default')
            else:
                require(os.write(fd, item['bytes']) == len(item['bytes']), 'source-short-write')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent.fd)
        parent.check()
        return self.probe(key, nonce, True)

    def publish(self, key, nonce):
        parent = self.parent(key)
        # Same-parent exact prepared inode, atomic exclusive publication. No fallback.
        api = ctypes.CDLL(None, use_errno=True)
        try:
            rename = api.renameat2
        except AttributeError:
            raise Refused('publication-api-unavailable') from None
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        require(rename(parent.fd, self.temp(key, nonce).encode(), parent.fd,
                       self.plan[key]['path'].name.encode(), 1) == 0, 'publication-indeterminate')
        os.fsync(parent.fd)
        parent.check()

    def inventory(self, rows, nonce, *, absent_directories=False):
        # /etc contains unrelated system units; only this private temp prefix is ours.
        for path in {RELAY_UNITS, RELAY_BASE, RELAY_BASE.parent}:
            if not os.path.lexists(path):
                continue
            anchor = self.anchors.get(path)
            if anchor is None:
                anchor = self.anchors[path] = Anchor(path)
            names = os.listdir(anchor.fd)
            allowed = {self.temp(k, nonce) for k in rows if self.plan[k]['path'].parent == path}
            require(len(names) <= 8192 and all(not n.startswith('.p0-relay-') or n in allowed for n in names), 'unknown-publication-entry')
            if path == RELAY_BASE:
                expected = {self.plan[k]['path'].name for k in rows if self.plan[k]['path'].parent == path} | allowed
                require(set(names) <= expected, 'foreign-relay-directory-entry')
        for key, row in rows.items():
            if key.endswith('.dir') and row['state'] == 'published':
                if absent_directories and not os.path.lexists(self.plan[key]['path']):
                    continue
                anchor = self.parent_for_directory(key)
                require(not os.listdir(anchor.fd), 'relay-directory-not-empty')

    def parent_for_directory(self, key):
        path = self.plan[key]['path']
        if path not in self.anchors:
            self.anchors[path] = Anchor(path)
        self.anchors[path].check()
        return self.anchors[path]

    def close(self):
        for anchor in self.anchors.values():
            anchor.close()
        self.anchors = {}


def validate_record(record, definition, digest):
    require(isinstance(record, dict) and set(record) == {'version', 'intentSha256', 'definition', 'owner',
            'namespace', 'namespaceOwner', 'evidenceSha256', 'bootId', 'nonce', 'phase', 'objects', 'previousBoots', 'integrity'}, 'relay-record-schema')
    require(type(record['version']) is int and record['version'] == 1 and record['intentSha256'] == digest
            and record['definition'] == definition and record['phase'] in ('pending', 'complete')
            and all(isinstance(record[k], str) and re.fullmatch(r'[0-9a-f]{32}', record[k]) for k in ('owner', 'nonce', 'namespaceOwner'))
            and isinstance(record['bootId'], str) and UUID.fullmatch(record['bootId'])
            and isinstance(record['evidenceSha256'], str) and HEX.fullmatch(record['evidenceSha256'])
            and sha(encoded({k: v for k, v in record.items() if k != 'integrity'})) == record['integrity'], 'relay-record-binding')
    require(isinstance(record['namespace'], dict) and set(record['namespace']) == {'device', 'inode', 'filesystemId'}
            and all(type(v) is int and v > 0 for v in record['namespace'].values()), 'relay-record-namespace')
    require(isinstance(record['previousBoots'], list) and len(record['previousBoots']) <= 8, 'relay-boot-history')
    for epoch in record['previousBoots']:
        require(isinstance(epoch, dict) and set(epoch) == {'bootId', 'nonce', 'directories'}
                and isinstance(epoch['bootId'], str) and UUID.fullmatch(epoch['bootId'])
                and isinstance(epoch['nonce'], str) and re.fullmatch(r'[0-9a-f]{32}', epoch['nonce'])
                and isinstance(epoch['directories'], dict)
                and set(epoch['directories']) == {k for k, p in plan(definition).items() if p['bytes'] is None}, 'relay-boot-history')
    require(isinstance(record['objects'], dict) and set(record['objects']) == set(plan(definition)), 'relay-record-objects')
    require(record['phase'] != 'complete' or all(r.get('state') == 'published' for r in record['objects'].values()
            if isinstance(r, dict)), 'relay-record-incomplete')
    for row in record['objects'].values():
        require(isinstance(row, dict) and set(row) == {'state', 'inode'} and row['state'] in (
            'planned', 'prepare-claimed', 'prepared', 'publish-claimed', 'published'), 'relay-record-state')
        value = row['inode']
        if row['state'] in ('planned', 'prepare-claimed'):
            require(value is None, 'relay-record-inode')
        else:
            require(isinstance(value, dict) and set(value) == {'device', 'inode', 'uid', 'gid', 'mode'}
                    and all(type(v) is int and v >= 0 for v in value.values())
                    and value['inode'] > 0 and value['uid'] == value['gid'] == 0, 'relay-record-inode')


def owned_unit(native, name):
    service = name.endswith('.service')
    pair = name.rsplit('.', 1)[0] + ('.socket' if service else '.service')
    fields = {'LoadState', 'ActiveState', 'ControlPID', 'ControlGroup', 'Job', 'SourcePath', 'FragmentPath',
              'DropInPaths', 'TriggeredBy', 'NeedDaemonReload'} | ({'MainPID', 'User', 'Group'} if service else {'Triggers'})
    raw = native.call(['/usr/bin/systemctl', 'show', name, '--no-pager', '--property=' + ','.join(sorted(fields))])
    props = {}
    for line in raw.decode('utf-8').splitlines():
        key, value = line.split('=', 1)
        require(key not in props, 'owned-unit-schema')
        props[key] = value
    require(set(props) == fields and props['LoadState'] == 'loaded' and props['ActiveState'] in ('inactive', 'failed')
            and props['ControlPID'] == '0' and props['ControlGroup'] == props['Job'] == props['SourcePath'] == props['DropInPaths'] == ''
            and props['FragmentPath'] == str(RELAY_UNITS / name) and props['NeedDaemonReload'] in ('yes', 'no'), 'owned-unit-not-stopped')
    if service:
        require(props['MainPID'] == '0' and props['User'] == props['Group'] == 'p0-runtime'
                and props['TriggeredBy'] in ('', pair), 'owned-unit-not-stopped')
    else:
        require(props['ActiveState'] == 'inactive' and props['TriggeredBy'] == '' and props['Triggers'] == pair, 'owned-unit-not-stopped')


class Supply:
    def __init__(self, store, files, authority, native, proof, evidence_digest):
        self.store, self.files, self.authority, self.native = store, files, authority, native
        self.proof, self.evidence_digest = proof, evidence_digest

    def verify_objects(self, record):
        owned = []
        for key, row in record['objects'].items():
            require(row['state'] != 'prepare-claimed', 'preparation-indeterminate')
            final = self.files.probe(key, record['nonce'])
            temporary = self.files.probe(key, record['nonce'], True)
            state, expected = row['state'], row['inode']
            if state == 'planned':
                require(final is None and temporary is None, 'foreign-target')
            elif state == 'prepared':
                require(final is None and temporary == expected, 'prepared-inode-changed')
            elif state == 'publish-claimed':
                require((temporary == expected and final is None) or (final == expected and temporary is None), 'publication-indeterminate')
            else:
                require(final == expected and temporary is None, 'published-inode-changed')
            if final is not None and key.endswith(('.service', '.socket')):
                owned.append(key)
        self.files.inventory(record['objects'], record['nonce'])
        return owned

    def gate(self, record):
        self.authority.check()
        require(record['namespace'] == self.authority.record['namespace']
                and record['namespaceOwner'] == self.authority.record['owner']
                and record['bootId'] == self.authority.record['bootId']
                and record['evidenceSha256'] == self.evidence_digest, 'relay-authority-changed')
        owned = self.verify_objects(record)
        self.native.stopped_units(self.proof, owned=owned)
        for name in owned:
            no_native_dropins(name)
            owned_unit(self.native, name)
        for relay in record['definition']['relays']:
            closed_relay_listener(relay, self.native.entry)
        self.authority.check()
        require(owned == self.verify_objects(record), 'relay-source-race')
        reserves()

    def reviewed_binding(self, record):
        require(record['namespace'] == self.authority.record['namespace']
                and record['namespaceOwner'] == self.authority.record['owner'], 'relay-authority-changed')
        current = {r['id']: r for r in self.proof.get('relays', [])}
        require(all(current.get(r['id']) == r for r in record['definition']['relays']), 'relay-current-evidence-required')

    def rematerialize(self, record):
        require(record['phase'] == 'complete' and record['bootId'] != self.authority.record['bootId']
                and len(record['previousBoots']) < 8, 'relay-rematerialize-not-new-complete-boot')
        self.reviewed_binding(record)
        for key, row in record['objects'].items():
            final = self.files.probe(key, record['nonce'])
            require(self.files.probe(key, record['nonce'], True) is None, 'old-publication-remains')
            if self.files.plan[key]['bytes'] is None:
                require(final is None, 'boot-directory-not-absent')
            else:
                require(final == row['inode'], 'published-inode-changed')
        self.files.inventory(record['objects'], record['nonce'], absent_directories=True)
        self.native.stopped_units(self.proof)
        self.authority.check()
        reserves()
        record['previousBoots'].append({'bootId': record['bootId'], 'nonce': record['nonce'],
            'directories': {k: dict(row) for k, row in record['objects'].items() if self.files.plan[k]['bytes'] is None}})
        record.update(bootId=self.authority.record['bootId'], evidenceSha256=self.evidence_digest,
                      nonce=secrets.token_hex(16), phase='pending')
        for key, row in record['objects'].items():
            if self.files.plan[key]['bytes'] is None:
                row.update(state='planned', inode=None)
        self.store.save(record)  # Explicit NEW boot directory epoch, not uncertain replay.

    def run(self, definition, digest, mode):
        record = self.store.load()
        if record is not None:
            validate_record(record, definition, digest)
        if mode == 'status':
            return {'version': 1, 'scope': 'p0-v2-relays', 'state': 'absent' if record is None else record['phase'],
                    'offline': True, 'installationCertified': False}
        require(mode in ('apply', 'resume', 'rematerialize'), 'relay-mode')
        self.authority.check()
        if record is None:
            require(mode == 'apply', 'relay-record-required')
            known = {e['name'] for e in self.proof['units']['rootful']} | {relay_names(r)[0] for r in self.proof.get('relays', [])}
            require(not any(relay_names(r)[0] in known for r in definition['relays']), 'relay-evidence-collision')
            record = {'version': 1, 'intentSha256': digest, 'definition': definition, 'owner': secrets.token_hex(16),
                      'namespace': self.authority.record['namespace'], 'namespaceOwner': self.authority.record['owner'],
                      'evidenceSha256': self.evidence_digest, 'bootId': self.authority.record['bootId'],
                      'nonce': secrets.token_hex(16), 'phase': 'pending', 'previousBoots': [],
                      'objects': {k: {'state': 'planned', 'inode': None} for k in self.files.plan}}
            self.gate(record)  # All fresh targets absent, no foreign manager units/listeners.
            self.store.save(record)  # Durable global claim BEFORE any target effect.
        else:
            require(record['phase'] == 'complete' or mode == 'resume', 'explicit-relay-resume-required')
        if mode == 'rematerialize':
            self.rematerialize(record)
        require(record['bootId'] == self.authority.record['bootId'], 'explicit-relay-rematerialize-required')
        if record['evidenceSha256'] != self.evidence_digest:
            require(mode == 'resume' and record['phase'] == 'complete', 'explicit-relay-evidence-review-required')
            self.reviewed_binding(record)
            self.verify_objects(record)
            self.native.stopped_units(self.proof)
            self.authority.check()
            record['evidenceSha256'] = self.evidence_digest
            self.store.save(record)
        for key in self.files.plan:  # Never let canonical JSON key ordering reorder parents.
            row = record['objects'][key]
            self.gate(record)
            if row['state'] == 'published':
                continue
            if row['state'] == 'planned':
                row['state'] = 'prepare-claimed'
                self.store.save(record)
                row['inode'] = self.files.prepare(key, record['nonce'])
                require(row['inode'] is not None, 'preparation-indeterminate')
                row['state'] = 'prepared'
                self.store.save(record)
            self.gate(record)
            if row['state'] == 'prepared':
                row['state'] = 'publish-claimed'
                self.store.save(record)
            final = self.files.probe(key, record['nonce'])
            if final is None:
                self.authority.check()
                self.files.publish(key, record['nonce'])
            require(self.files.probe(key, record['nonce']) == row['inode']
                    and self.files.probe(key, record['nonce'], True) is None, 'publication-indeterminate')
            row['state'] = 'published'
            self.store.save(record)
        self.gate(record)
        record['phase'] = 'complete'
        self.store.save(record)
        self.authority.check()
        return {'version': 1, 'scope': 'p0-v2-relays', 'state': 'needs-review-units',
                'priorEvidenceSha256': self.evidence_digest, 'daemonReloadRequired': True,
                'sources': [{'name': name, 'sha256': sha(item['bytes'])} for name, item in self.files.plan.items() if item['bytes'] is not None],
                'installationCertified': False, 'activationPerformed': False}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('cli-arguments')


def approved(path, digest, uid):
    require(uid >= 1000 and HEX.fullmatch(digest), 'approved-input-binding')
    path = Path(path)
    strict_directory(path.parent, (0, uid))
    raw, _ = read_exact(path, uid)
    require(sha(raw) == digest, 'approved-input-sha256')
    return raw


def main(argv=None):
    p = Parser(description=__doc__)
    p.add_argument('mode', choices=('apply', 'resume', 'rematerialize', 'status'))
    for name in ('helper-sha256', 'intent', 'intent-sha256', 'evidence', 'evidence-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--input-uid', required=True, type=int)
    p.add_argument('--parent-interlock-held', action='store_true')
    a = p.parse_args(argv)
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'root-required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = Path(__file__).absolute()
    require(source.is_relative_to('/var/lib') and source.parent != Path('/var/lib'), 'helper-staging')
    strict_directory(source.parent, mode=0o700)
    raw, _ = read_exact(source, 0, 0o400)
    require(HEX.fullmatch(a.helper_sha256) and sha(raw) == a.helper_sha256, 'helper-sha256')
    definition = intent(approved(a.intent, a.intent_sha256, a.input_uid))
    proof = evidence(approved(a.evidence, a.evidence_sha256, a.input_uid))
    mutating = a.mode != 'status'
    require(not mutating or a.parent_interlock_held, 'parent-interlock-required')
    store, authority, files = Marker(RELAY_AUTHORITY), None, None
    try:
        if mutating:
            reserves()
            authority = Authority(proof, a.evidence_sha256)
        store.open(mutating, create=mutating)
        files = Files(definition)
        native = Native(account()) if mutating else None
        result = Supply(store, files, authority, native, proof, a.evidence_sha256).run(definition, a.intent_sha256, a.mode)
    finally:
        if files is not None:
            files.close()
        store.close()
        if authority is not None:
            authority.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'version': 1, 'scope': 'p0-v2-relays', 'refused': True,
                          'reason': str(error) if isinstance(error, Refused) else 'operation-unavailable',
                          'installationCertified': False}))
        raise SystemExit(2)
