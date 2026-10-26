#!/usr/bin/python3 -I
"""Pin only the reviewed new P0 v2 namespace. No teardown or service activation."""
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
ROOTLESS = TARGET / 'rootless/engine'
ROOTFUL = TARGET / 'rootful/engine'
RUNFUL = Path('/run/p0-v2-rootful/engine')
NETWORK = Path('/var/lib/p0-v2-rootful/networks')
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
    for path, floor in (('/', 50), ('/mnt/stack', 100), ('/var/lib', 1)):
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
            + 'SocketUser=p0-runtime\nSocketGroup=p0-runtime\nSocketMode=0600\n'
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
        require(path.parent.lstat().st_gid == entry.pw_gid, 'relay-directory-custody')
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
        require(actor in ('rootless', 'rootful') and not pass_fds
                and not any('/proc/self/fd/' in arg for arg in args), 'native-fd-alias-refused')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}
        executable = args[0]
        if actor == 'rootless':
            args = ['/usr/bin/setpriv', '--reuid', str(self.entry.pw_uid), '--regid', str(self.entry.pw_gid),
                    '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all'] + args
            env.update(HOME=str(HOME), XDG_RUNTIME_DIR=f'/run/user/{self.entry.pw_uid}')
        # Validate only fixed native binaries; no caller-supplied executable paths.
        for executable in ({executable, '/usr/bin/setpriv'} if actor == 'rootless' else {executable}):
            require(executable in ('/usr/bin/setpriv', '/usr/bin/podman', '/usr/bin/systemctl'), 'native-executable')
            strict_directory(Path(executable).parent)
            read_exact(executable, limit=128 * 1024**2)
            require(os.stat(executable).st_mode & 0o111, 'native-executable')
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=env, cwd='/', pass_fds=pass_fds, start_new_session=True)
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
                # Kill before reaping: the unreaped leader reserves our group ID.
                # Only our new session/process group; never UID-global cleanup.
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=5)
            p.stdout.close()

    def engine(self, actor):
        # Literal persistent identity only. FD aliases are NOT native-compatible.
        require(actor in ('rootless', 'rootful'), 'engine-actor')
        graph = str(ROOTLESS if actor == 'rootless' else ROOTFUL)
        if actor == 'rootless':
            return ['/usr/bin/podman', '--root', graph, '--runroot',
                    f'/run/user/{self.entry.pw_uid}/containers', '--storage-driver', 'overlay']
        return ['/usr/bin/podman', '--root', graph, '--runroot', str(RUNFUL),
                '--storage-driver', 'overlay', '--network-config-dir', str(NETWORK)]

    def stopped(self, proof, fd, *, record, observation, repin=None):
        protected = inventory_authority(fd, proof, record, observation)
        if repin is not None:
            repin.verify(fd)
        fresh = fresh_rootful(fd, proof) if not protected and repin is None else None
        self.stopped_units(proof)
        # No Host Root Podman command may resolve an unpinned shared-ancestor path.
        # The sole pre-pin native store observer is the unprivileged fixed actor.
        for actor in ('rootless', 'rootful'):
            if actor == 'rootful':
                if not protected:
                    continue
                try:
                    anchor = EngineAnchor(fd, actor, self.entry)
                except FileNotFoundError:
                    # A claimed private pin can precede creation of new children.
                    # Only exact absence with no Rootful units permits provisioning.
                    require(fresh_rootful(fd, proof)[0] == 'absent', 'rootful-engine-missing')
                    continue
                else:
                    anchor.close()
            self.observe_empty_engine(actor, fd, proof, record, observation, repin=repin)
        require(inventory_authority(fd, proof, record, observation) == protected, 'inventory-authority-changed')
        if repin is not None:
            repin.verify(fd)
        if not protected and repin is None:
            require(fresh_rootful(fd, proof) == fresh, 'fresh-rootful-changed')

    def observe_empty_engine(self, actor, fd, proof, record, observation, *, repin=None):
        require(actor == 'rootless' or inventory_authority(fd, proof, record, observation), 'rootful-pin-required')
        check_actor_directories(self.entry, actor)
        anchor = EngineAnchor(fd, actor, self.entry)
        try:
            def guard():
                if repin is not None:
                    repin.verify(fd)
                protected = inventory_authority(fd, proof, record, observation)
                require(actor == 'rootless' or protected, 'rootful-pin-required')
                anchor.verify(fd)
                check_actor_directories(self.entry, actor)
            guard()
            prefix = self.engine(actor)
            store = strict_json(self.call(prefix + ['info', '--format', 'json'], actor)).get('store', {})
            guard()
            run = f'/run/user/{self.entry.pw_uid}/containers' if actor == 'rootless' else str(RUNFUL)
            require(store.get('graphRoot') == prefix[2] and store.get('runRoot') == run
                    and store.get('graphDriverName') == 'overlay', 'native-store-mismatch')
            guard()
            containers = strict_json(self.call(prefix + ['ps', '--all', '--external', '--format', 'json'], actor))
            guard()
            require(isinstance(containers, list) and not containers, 'engine-containers-remain')
        finally:
            anchor.close()

    def stopped_units(self, proof):
        for actor, units in proof['units'].items():
            prefix = ['/usr/bin/systemctl'] + (['--user'] if actor == 'rootless' else [])
            relays = proof.get('relays', []) if actor == 'rootful' else []
            sockets = {relay_names(r)[1] for r in relays}
            expected = {entry['name'] for entry in units} | {relay_names(r)[0] for r in relays}
            scope = 'p0-v2-' if actor == 'rootful' else 'p0-'
            require(all(name.startswith(scope) for name in expected), 'unit-runtime-scope')
            for command in (['list-units', '--all', '--plain', '--no-legend', scope + '*.service'],
                            ['list-unit-files', '--no-legend']):
                # Filter names in memory: filtered list-unit-files returns exit1
                # for no matches, indistinguishable from an operational failure.
                # Never reinterpret exit1/empty stdout as successful absence.
                raw = self.call(prefix + command, actor)
                names = set()
                for line in raw.splitlines():
                    token = line.split()[0]
                    if not token.startswith(scope.encode('ascii')):
                        continue  # Foreign manager scope, no stop/adoption authority.
                    name = token.decode('ascii')
                    if name in sockets:
                        continue  # Still must pass exact inactive source/kernel checks below.
                    require(not name.endswith(('.timer', '.socket', '.path')), 'runtime-triggers-remain')
                    require(UNIT.fullmatch(name), 'unit-inventory-schema')
                    names.add(name)
                require(names <= expected, 'unreviewed-runtime-unit')
            triggers = [scope + '*' + suffix for suffix in ('.timer', '.socket', '.path')]
            for command in (['list-units', '--all', '--plain', '--no-legend'] + triggers,):
                raw = self.call(prefix + command, actor)
                require(all(line.split()[0].decode('ascii') in sockets for line in raw.splitlines()), 'runtime-triggers-remain')
            for entry in units:
                name = entry['name']
                source = (HOME / '.config/containers/systemd' if actor == 'rootless'
                          else Path('/etc/containers/systemd')) / quadlet_name(entry)
                strict_directory(source.parent, (0, self.entry.pw_uid) if actor == 'rootless' else (0,))
                no_quadlet_dropins(source)
                raw, _ = read_exact(source, self.entry.pw_uid if actor == 'rootless' else 0)
                require(hashlib.sha256(raw).hexdigest() == entry['sourceSha256'], 'unit-source-binding')
                raw = self.call(prefix + ['show', name, '--no-pager',
                     '--property=LoadState,ActiveState,MainPID,ControlGroup,Job,SourcePath,FragmentPath,DropInPaths,TriggeredBy'], actor)
                props = {}
                for line in raw.decode('utf-8').splitlines():
                    key, value = line.split('=', 1)
                    require(key not in props, 'unit-properties-schema')
                    props[key] = value
                generator = Path(f'/run/user/{self.entry.pw_uid}/systemd') if actor == 'rootless' else Path('/run/systemd')
                fragments = {str(generator / directory / name) for directory in ('generator', 'generator.early', 'generator.late')}
                require(set(props) == {'LoadState', 'ActiveState', 'MainPID', 'ControlGroup', 'Job', 'SourcePath', 'FragmentPath', 'DropInPaths', 'TriggeredBy'}
                        and props['LoadState'] == 'loaded' and props['ActiveState'] in ('inactive', 'failed')
                        and props['MainPID'] == '0' and props['ControlGroup'] == '' and props['Job'] == ''
                        and props['SourcePath'] == str(source) and props['FragmentPath'] in fragments
                        and props['DropInPaths'] == '' and props['TriggeredBy'] == '', 'runtime-unit-not-stopped')

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
            common = {'LoadState', 'ActiveState', 'SubState', 'Job', 'ControlGroup', 'ControlPID',
                      'SourcePath', 'FragmentPath', 'DropInPaths', 'TriggeredBy', 'NeedDaemonReload'}
            fields = common | ({'MainPID', 'User', 'Group'} if name == service else {'Triggers'})
            raw = self.call(['/usr/bin/systemctl', 'show', name, '--no-pager', '--property=' + ','.join(sorted(fields))])
            props = {}
            for line in raw.decode('utf-8').splitlines():
                key, value = line.split('=', 1)
                require(key not in props, 'relay-properties-schema')
                props[key] = value
            require(set(props) == fields and props['LoadState'] == 'loaded'
                    and props['Job'] == props['ControlGroup'] == props['SourcePath'] == props['DropInPaths'] == ''
                    and props['ControlPID'] == '0' and props['FragmentPath'] == str(source)
                    and props['NeedDaemonReload'] == 'no', 'relay-not-stopped')
            if name == service:
                require(props['ActiveState'] in ('inactive', 'failed') and props['SubState'] in ('dead', 'failed')
                        and props['MainPID'] == '0' and props['User'] == props['Group'] == 'p0-runtime'
                        and props['TriggeredBy'] == socket, 'relay-not-stopped')
            else:
                require(props['ActiveState'] == 'inactive' and props['SubState'] == 'dead'
                        and props['TriggeredBy'] == '' and props['Triggers'] == service, 'relay-not-stopped')
            require(read_exact(source, 0) == (expected, initial), 'relay-source-changed')
        closed_relay_listener(relay, self.entry)

    def pin_namespace(self, fd, expected, *, claim_clone, before_attach, verify_attached):
        modern_private_pin(fd, expected, claim_clone=claim_clone,
                           before_attach=before_attach, verify_attached=verify_attached)

    def privatize_owned(self, fd, expected, mount_id, *, verify_attached):
        modern_privatize_owned(fd, expected, mount_id, verify_attached=verify_attached)


def directory_identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def owned_directory_fd(fd, uid, gid, mode=0o700):
    s = os.fstat(fd)
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid
            and stat.S_IMODE(s.st_mode) == mode, 'anchored-engine-custody')
    return directory_identity(s)


class EngineAnchor:
    """Hold only identity FDs; NEVER pass them as native store paths or to Podman."""
    def __init__(self, namespace_fd, actor, entry):
        require(actor in ('rootless', 'rootful'), 'engine-actor')
        self.actor, self.entry = actor, entry
        self.uid, self.gid = (entry.pw_uid, entry.pw_gid) if actor == 'rootless' else (0, 0)
        self.fds, self.identities = [], []
        parent = namespace_fd
        try:
            for name in (actor, 'engine'):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.fds.append(child)
                self.identities.append(owned_directory_fd(child, self.uid, self.gid))
                parent = child
        except BaseException:
            self.close()
            raise

    def verify(self, namespace_fd):
        for fd, observed in zip(self.fds, self.identities):
            require(owned_directory_fd(fd, self.uid, self.gid) == observed, 'engine-anchor-changed')
        current = EngineAnchor(namespace_fd, self.actor, self.entry)
        try:
            require(current.identities == self.identities, 'engine-identity-changed')
        finally:
            current.close()

    def close(self):
        for fd in self.fds:
            os.close(fd)
        self.fds = []


class RepinPermit:
    """Ephemeral held custody, NEVER permission for pre-pin Host Root native I/O.

    Marker v2 records namespace, not historical engine inode. Root-only descendants
    under that SAME namespace are trusted; compare their current held identities
    throughout this operation. Do not pretend prior store inode history exists.
    """
    def __init__(self, fd, proof, prior, observation, entry):
        record_binding(prior, proof['namespace'])
        require(prior['state'] == 'pinned' and prior['mount'] is not None
                and (prior['bootId'] != observation['bootId'] or prior['mountNamespace'] != observation['mountNamespace']),
                'prior-complete-pin-required')
        observed_mount(observation, proof['namespace'], pinned=False)
        # Validate the saved complete PRIVATE mount against the stable filesystem
        # geometry. Its old ID is NOT authority for any current mount.
        parent = dict(next(m for m in observation['mounts'] if m['target'] == str(SHARED)))
        saved = prior['mount']
        require(set(saved) == {'id', 'parent', 'device', 'root', 'target', 'options', 'optional', 'fsType', 'source'}
                and all(type(saved[k]) is int and 0 < saved[k] < 2**64 for k in ('id', 'parent'))
                and saved['id'] != saved['parent']
                and all(isinstance(saved[k], str) and 0 < len(saved[k]) <= 4096
                        for k in ('device', 'root', 'target', 'fsType', 'source'))
                and all(isinstance(saved[k], list) and len(saved[k]) <= 128
                        and all(isinstance(v, str) and 0 < len(v) <= 256 for v in saved[k])
                        for k in ('options', 'optional')), 'prior-mount-binding')
        parent['id'] = prior['mount']['parent']
        verify_marker(prior, {'bootId': prior['bootId'], 'mountNamespace': prior['mountNamespace'],
                              'mounts': [parent, prior['mount']]}, proof['namespace'])
        self.expected = dict(proof['namespace'])
        self.anchor = EngineAnchor(fd, 'rootful', entry)
        try:
            self.verify(fd)
        except BaseException:
            self.close()
            raise

    def verify(self, fd):
        owned_directory_fd(fd, 0, 0, 0o711)
        require(dict(identity(os.fstat(fd)), filesystemId=os.fstatvfs(fd).f_fsid) == self.expected,
                'repin-namespace-changed')
        current = namespace(self.expected)
        try:
            self.anchor.verify(current)
            self.anchor.verify(fd)
        finally:
            os.close(current)

    def close(self):
        self.anchor.close()


def fresh_rootful(fd, proof):
    """No native Root store access. Absence/empty directory is not an adoption API."""
    require(not proof['units']['rootful'] and not proof.get('relays'), 'rootful-unpinned-units-unsupported')
    fds, identities, parent = [], [], fd
    try:
        for name in ('rootful', 'engine'):
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                return ('absent', tuple(identities))
            fds.append(child)
            identities.append(owned_directory_fd(child, 0, 0))
            parent = child
        with os.scandir(parent) as entries:
            require(next(entries, None) is None, 'rootful-unpinned-existing-store-unsupported')
        return ('empty', tuple(identities))
    finally:
        for child in fds:
            os.close(child)


def inventory_authority(fd, proof, record, observation):
    """Return Rootful-native authority only from the current, private, owned pin."""
    expected = proof['namespace']
    owned_directory_fd(fd, 0, 0, 0o711)
    s = os.fstat(fd)
    require(dict(identity(s), filesystemId=os.fstatvfs(fd).f_fsid) == expected, 'namespace-anchor-changed')
    current_fd = namespace(expected)
    try:
        require(identity(os.fstat(current_fd)) == identity(s), 'namespace-renamed')
    finally:
        os.close(current_fd)
    current = kernel()
    require(boundary_view(current) == boundary_view(observation), 'namespace-observation-changed')
    mounted = any(m['target'] == str(TARGET) for m in current['mounts'])
    own = observed_mount(current, expected, pinned=mounted)
    if record is not None:
        record_binding(record, expected)
    if not mounted:
        if record is not None:
            same_boot = record['bootId'] == current['bootId'] and record['mountNamespace'] == current['mountNamespace']
            require(not same_boot or (record['state'] == 'claimed' and record['mount'] is None), 'owned-pin-lost')
        return False
    require(record is not None, 'unowned-namespace-mount')
    require(record['cloneMountId'] == own['id'], 'preclaimed-mount-id-changed')
    require(record['bootId'] == current['bootId'] and record['mountNamespace'] == current['mountNamespace'], 'marker-stale-boot-or-namespace')
    if record['mount'] is None:
        require(record['state'] == 'claimed', 'marker-binding')
        return False  # Bind outcome not yet recorded: only fresh-gated unprivileged observation.
    require(same_mount_or_private_transition(record['mount'], own), 'marker-mount-changed')
    is_private = not any(v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable' for v in own['optional'])
    if not is_private:
        require(record['state'] == 'claimed', 'namespace-mount-not-private')
        return False
    verify_marker(record, current, expected, allow_claimed=True)
    return True


# Linux UAPI: mount.h, asm/unistd_64.h, fcntl.h. No legacy mount(8)/mount(2)
# fd-symlink endpoints, arbitrary syscall selection, or pathname ABI fallback.
AT_EMPTY_PATH = 0x1000
OPEN_TREE_CLONE = 1
MOVE_MOUNT_EMPTY_PATHS = 0x04 | 0x40
MS_PRIVATE = 1 << 18
NR_OPEN_TREE, NR_MOVE_MOUNT, NR_MOUNT_SETATTR = 428, 429, 442


class MountAttr(ctypes.Structure):
    _fields_ = [('attr_set', ctypes.c_uint64), ('attr_clr', ctypes.c_uint64),
                ('propagation', ctypes.c_uint64), ('userns_fd', ctypes.c_uint64)]


def _mount_api():
    require(sys.platform == 'linux' and os.uname().machine == 'x86_64'
            and ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.sizeof(MountAttr) == 32, 'modern-mount-unsupported-abi')
    # Only the already-loaded trusted system libc; no caller library/symbol path.
    api = ctypes.CDLL(None, use_errno=True).syscall
    api.restype, api.argtypes = ctypes.c_long, [ctypes.c_long]
    return api


def fd_mount_id(fd):
    require(type(fd) is int and fd >= 0, 'mount-fd')
    raw = bounded_read(f'/proc/self/fdinfo/{fd}', 16384).decode('ascii')
    ids = [line.split(':', 1)[1].strip() for line in raw.splitlines() if line.startswith('mnt_id:')]
    require(len(ids) == 1 and re.fullmatch(r'[1-9][0-9]{0,19}', ids[0]), 'mount-fdinfo')
    result = int(ids[0])
    require(result < 2**64, 'mount-fdinfo')
    return result


def _open_tree(api, fd, *, clone):
    flags = AT_EMPTY_PATH | os.O_CLOEXEC | (OPEN_TREE_CLONE if clone else 0)
    tree = api(NR_OPEN_TREE, ctypes.c_int(fd), ctypes.c_char_p(b''), ctypes.c_uint(flags))
    require(tree >= 0, 'mount-open-tree-refused')
    return int(tree)


def _set_private(api, tree):
    attrs = MountAttr(0, 0, MS_PRIVATE, 0)
    result = api(NR_MOUNT_SETATTR, ctypes.c_int(tree), ctypes.c_char_p(b''),
                 ctypes.c_uint(AT_EMPTY_PATH), ctypes.byref(attrs), ctypes.c_size_t(ctypes.sizeof(attrs)))
    require(result == 0, 'mount-setattr-private-uncertain')


def _mount_deadline_start():
    # Synchronous in-process calls: no escaped child can attach later after this
    # helper releases its marker lock. Uninterruptible kernel waits can delay
    # signal delivery; exclusive custody remains locked until the call settles.
    require(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'mount-existing-deadline')
    def expired(signum, frame):
        raise Refused('modern-mount-deadline-uncertain')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 30)


def _mount_deadline_end():
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)


def modern_private_pin(fd, expected, *, claim_clone, before_attach, verify_attached):
    api, tree = _mount_api(), None
    _mount_deadline_start()
    try:
        owned_directory_fd(fd, 0, 0, 0o711)
        require(dict(identity(os.fstat(fd)), filesystemId=os.fstatvfs(fd).f_fsid) == expected, 'namespace-anchor-changed')
        tree = _open_tree(api, fd, clone=True)
        owned_directory_fd(tree, 0, 0, 0o711)
        require(dict(identity(os.fstat(tree)), filesystemId=os.fstatvfs(tree).f_fsid) == expected, 'clone-directory-changed')
        mount_id = fd_mount_id(tree)
        claim_clone(mount_id)  # Exact detached ID durable BEFORE move_mount.
        _set_private(api, tree)
        before_attach()
        require(fd_mount_id(tree) == mount_id, 'clone-mount-id-changed')
        result = api(NR_MOVE_MOUNT, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_int(fd),
                     ctypes.c_char_p(b''), ctypes.c_uint(MOVE_MOUNT_EMPTY_PATHS))
        require(result == 0, 'mount-move-uncertain')
        require(fd_mount_id(tree) == mount_id, 'clone-mount-id-changed')
        verify_attached(mount_id, require_private=False)
        # A shared parent can confer propagation on attach. Detached-private is
        # NOT sufficient. Affect only this SAME attached tree FD, not the old
        # covering directory FD/shared parent, then verify actual kernel state.
        _set_private(api, tree)
        require(fd_mount_id(tree) == mount_id, 'clone-mount-id-changed')
        verify_attached(mount_id, require_private=True)
    finally:
        if tree is not None:
            os.close(tree)  # Detached failure drops clone; attached mount remains.
        _mount_deadline_end()


def modern_privatize_owned(fd, expected, mount_id, *, verify_attached):
    api, tree = _mount_api(), None
    _mount_deadline_start()
    try:
        owned_directory_fd(fd, 0, 0, 0o711)
        require(dict(identity(os.fstat(fd)), filesystemId=os.fstatvfs(fd).f_fsid) == expected, 'namespace-anchor-changed')
        require(fd_mount_id(fd) == mount_id, 'covering-mount-fd-refused')
        tree = _open_tree(api, fd, clone=False)  # Reopen, never clone/rebind.
        owned_directory_fd(tree, 0, 0, 0o711)
        require(dict(identity(os.fstat(tree)), filesystemId=os.fstatvfs(tree).f_fsid) == expected, 'clone-directory-changed')
        require(fd_mount_id(tree) == mount_id, 'covering-mount-fd-refused')
        verify_attached(mount_id, require_private=False)
        _set_private(api, tree)
        require(fd_mount_id(tree) == mount_id, 'clone-mount-id-changed')
        verify_attached(mount_id, require_private=True)
    finally:
        if tree is not None:
            os.close(tree)
        _mount_deadline_end()


def owned_descendant(path, entry, uid=None, mode=None):
    """Only this helper's fixed namespace has the reviewed shared-ancestor exception."""
    path = Path(path)
    if path == TARGET or TARGET in path.parents:
        parts = (TARGET, *list(reversed(path.parents[:list(path.parents).index(TARGET)])), path) if path != TARGET else (TARGET,)
        for part in parts:
            s = part.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, entry.pw_uid) and not s.st_mode & 0o022, 'actor-directory')
    else:
        strict_directory(path, (0,) if uid == 0 else (0, entry.pw_uid))
    s = path.lstat()
    if uid is not None:
        require(s.st_uid == uid and s.st_gid == (entry.pw_gid if uid == entry.pw_uid else 0), 'actor-directory-owner')
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'actor-directory-mode')


def check_actor_directories(entry, actor):
    if actor == 'rootless':
        for path in (HOME, TARGET / 'rootless', ROOTLESS, Path(f'/run/user/{entry.pw_uid}/containers')):
            owned_descendant(path, entry, entry.pw_uid, 0o700)
        config = HOME / '.config/containers/storage.conf'
        strict_directory(config.parent, (0, entry.pw_uid))
        raw, _ = read_exact(config, entry.pw_uid, 0o600)
        expected = ('[storage]\ndriver = "overlay"\n'
                    f'runroot = "/run/user/{entry.pw_uid}/containers"\n'
                    f'graphroot = "{ROOTLESS}"\n').encode()
        require(raw == expected, 'actor-storage-config')
    else:
        for path in (TARGET / 'rootful', ROOTFUL, RUNFUL.parent, RUNFUL, NETWORK.parent, NETWORK):
            owned_descendant(path, entry, 0, 0o700)


def preflight_children(entry):
    check_actor_directories(entry, 'rootless')
    for path in (TARGET / 'rootful', ROOTFUL, RUNFUL.parent, RUNFUL, NETWORK.parent, NETWORK):
        if os.path.lexists(path):
            owned_descendant(path, entry, 0, 0o700)
        elif path.parent not in (TARGET / 'rootful', RUNFUL.parent, NETWORK.parent):
            if TARGET in path.parents:
                owned_descendant(path.parent, entry)
            else:
                strict_directory(path.parent)


def create_children(entry):
    # Parent already provisioned rootless identity/home/store; never repair them.
    check_actor_directories(entry, 'rootless')
    # Publish the empty new engine last, so a partial mkdir cannot leave an
    # engine requiring native inspection before its fixed auxiliary paths exist.
    for path in (TARGET / 'rootful', RUNFUL.parent, RUNFUL, NETWORK.parent, NETWORK, ROOTFUL):
        if os.path.lexists(path):
            owned_descendant(path, entry, 0, 0o700)
            continue
        # Rootful paths are created only AFTER the target is verified kernel-pinned.
        reserves()
        if TARGET not in path.parents:
            strict_directory(path.parent)
        else:
            owned_descendant(path.parent, entry)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o700)
                # Only the fresh inode, never the shared parent or existing data.
                if 'system.posix_acl_default' in os.listxattr(fd):
                    os.removexattr(fd, 'system.posix_acl_default')
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        finally:
            os.close(parent)


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


def pin(proof, digest, marker, native, entry, mode, *, previous_digest=None):
    expected = proof['namespace']
    fd = namespace(expected)
    repin = None
    try:
        observation = kernel()
        record = marker.load()
        require((mode == 'review-units' and isinstance(previous_digest, str) and HEX.fullmatch(previous_digest))
                or (mode != 'review-units' and previous_digest is None), 'previous-evidence-argument')
        if mode == 'review-units':
            require(record is not None and record.get('evidenceSha256') == previous_digest, 'previous-evidence-changed')
            verify_marker(record, observation, expected)
            before = json.loads(json.dumps(record))
            reserves()
            check_actor_directories(entry, 'rootless')
            check_actor_directories(entry, 'rootful')
            native.stopped(proof, fd, record=record, observation=observation)
            verify_marker(record, kernel(), expected)
            native.stopped(proof, fd, record=record, observation=kernel())
            verify_marker(record, kernel(), expected)
            require(record == before, 'review-marker-changed')
            reserves()
            record['evidenceSha256'] = digest
            marker.save(record)  # EX lock + exact prior byte/stat CAS; metadata only.
            verify_marker(record, kernel(), expected)
            require({k: v for k, v in record.items() if k not in ('evidenceSha256', 'integrity')}
                    == {k: v for k, v in before.items() if k not in ('evidenceSha256', 'integrity')}, 'review-marker-changed')
            return report(record, mode)
        if mode in ('status', 'check'):
            require(record is not None, 'marker-missing')
            require(record.get('evidenceSha256') == digest, 'namespace-evidence-changed')
            verify_marker(record, observation, expected)
            check_actor_directories(entry, 'rootless')
            check_actor_directories(entry, 'rootful')
            return report(record, mode)
        require(mode in ('apply', 'resume', 'recheck'), 'namespace-mode')
        reserves()
        if record is None:
            require(mode == 'apply', 'marker-required')
            observed_mount(observation, expected, pinned=False)
        else:
            record_binding(record, expected)
            same_boot = record['bootId'] == observation['bootId'] and record['mountNamespace'] == observation['mountNamespace']
            require(record['evidenceSha256'] == digest or (mode == 'recheck' and not same_boot), 'namespace-evidence-changed')
            if same_boot and record['state'] == 'pinned':
                verify_marker(record, observation, expected)
                # No effect or child repair from ordinary apply of a complete marker.
                require(mode != 'resume', 'no-partial-namespace')
                check_actor_directories(entry, 'rootless')
                check_actor_directories(entry, 'rootful')
                return report(record, mode)
            require(mode == ('resume' if same_boot else 'recheck'), 'explicit-namespace-recheck-required')
            if not same_boot:
                # A prior boot's mount ID is not authority for a new mount.
                observed_mount(observation, expected, pinned=False)
                require(record['state'] == 'pinned', 'prior-complete-pin-required')
                repin = RepinPermit(fd, proof, record, observation, entry)
            elif record['mount'] is not None:
                own = observed_mount(observation, expected, pinned=True)
                require(same_mount_or_private_transition(record['mount'], own), 'marker-mount-changed')
            else:
                exists = any(m['target'] == str(TARGET) for m in observation['mounts'])
                own = observed_mount(observation, expected, pinned=exists)
                if own is not None:
                    require(record['cloneMountId'] == own['id'], 'preclaimed-mount-id-changed')
                elif record['cloneMountId'] is not None:
                    # No background mount worker exists, but do not replace a
                    # durable preclaimed clone ID or erase uncertain evidence.
                    raise Refused('preclaimed-clone-absent-review-required')
        # No mount, marker claim, directory creation or ACL operation before these gates.
        preflight_children(entry)
        native.stopped(proof, fd, record=record, observation=observation, repin=repin)
        current = kernel()
        expected_inode = {k: expected[k] for k in ('device', 'inode')}
        require(boundary_view(current) == boundary_view(observation) and identity(TARGET.lstat()) == expected_inode
                and identity(os.fstat(fd)) == expected_inode
                and os.fstatvfs(fd).f_fsid == expected['filesystemId'], 'namespace-observation-changed')
        reserves()
        if marker.fd is None:
            marker.open(True)
            require(marker.load() is None, 'marker-created-concurrently')
        if record is None:
            record = {'version': 2, 'state': 'claimed', 'owner': secrets.token_hex(16), 'evidenceSha256': digest,
                      'namespace': expected, 'bootId': current['bootId'], 'mountNamespace': current['mountNamespace'],
                      'mount': None, 'cloneMountId': None}
        else:
            record.update(state='claimed', bootId=current['bootId'], mountNamespace=current['mountNamespace'], evidenceSha256=digest)
            if not same_boot:
                record['mount'], record['cloneMountId'] = None, None
        marker.save(record)  # Durable operation claim before any clone/effect.
        parent_before = next(m for m in current['mounts'] if m['target'] == str(SHARED))
        def verify_attached(mount_id, *, require_private):
            require(record['cloneMountId'] == mount_id, 'preclaimed-mount-id-changed')
            observed = kernel()
            own = observed_mount(observed, expected, pinned=True)
            require(own['id'] == mount_id, 'preclaimed-mount-id-changed')
            require(observed['bootId'] == record['bootId'] and observed['mountNamespace'] == record['mountNamespace']
                    and next(m for m in observed['mounts'] if m['target'] == str(SHARED)) == parent_before,
                    'namespace-observation-changed')
            checked = namespace(expected)
            os.close(checked)
            if require_private:
                private_mount(own)
            return own
        own = next((m for m in current['mounts'] if m['target'] == str(TARGET)), None)
        if own is None:
            def claim_clone(mount_id):
                require(record['cloneMountId'] is None and not any(m['id'] == mount_id for m in kernel()['mounts']),
                        'clone-id-not-fresh')
                record['cloneMountId'] = mount_id
                marker.save(record)  # Exact detached clone ID BEFORE move_mount.
            def before_attach():
                reserves()
                native.stopped(proof, fd, record=record, observation=observation, repin=repin)
            native.pin_namespace(fd, expected, claim_clone=claim_clone,
                                 before_attach=before_attach, verify_attached=verify_attached)
        else:
            require(record['cloneMountId'] == own['id'], 'preclaimed-mount-id-changed')
            if any(v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable' for v in own['optional']):
                # Only the preclaimed exact attached mount may be repaired. The
                # old namespace FD points to its covering mount, so reopen first.
                mounted_fd = namespace(expected)
                try:
                    reserves()
                    native.privatize_owned(mounted_fd, expected, record['cloneMountId'], verify_attached=verify_attached)
                finally:
                    os.close(mounted_fd)
        record['mount'] = verify_attached(record['cloneMountId'], require_private=True)
        marker.save(record)  # Claimed until children and canonical native gates pass.
        create_children(entry)
        # Changed authority, not a pathname fallback: the actual private pin and
        # durable Root claim now protect literal canonical Rootful store access.
        # Every native observation rechecks the pin and actual actor directories.
        current = kernel()
        native.stopped(proof, fd, record=record, observation=current, repin=repin)
        record['state'] = 'pinned'
        marker.save(record)
        verify_marker(record, kernel(), expected)
        return report(record, mode)
    finally:
        if repin is not None:
            repin.close()
        os.close(fd)


def report(record, mode):
    return {'version': 1, 'scope': 'p0-v2-namespace', 'mode': mode, 'state': record['state'],
            'namespace': record['namespace'], 'bootId': record['bootId'],
            'mountId': record['mount']['id'], 'owner': record['owner'],
            'authorityStrategy': 'canonical-after-verified-pin', 'existingRootfulRepinSupported': True, 'repinRequiresCompletePriorPin': True,
            'mountStrategy': 'open-tree-setattr-move-mount-setattr',
            'installationCertified': False}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('cli-arguments')


def main(argv=None):
    p = Parser(description=__doc__)
    p.add_argument('mode', choices=('apply', 'resume', 'recheck', 'review-units', 'status', 'check'))
    p.add_argument('--helper-sha256', required=True)
    p.add_argument('--evidence', required=True)
    p.add_argument('--evidence-sha256', required=True)
    p.add_argument('--evidence-uid', required=True, type=int)
    p.add_argument('--previous-evidence-sha256')
    a = p.parse_args(argv)
    require(os.geteuid() == 0, 'root-required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(HEX.fullmatch(a.helper_sha256) and HEX.fullmatch(a.evidence_sha256) and a.evidence_uid >= 1000, 'argument-binding')
    source = Path(__file__).absolute()
    require(source.is_relative_to('/var/lib') and source.parent != Path('/var/lib'), 'helper-staging')
    strict_directory(source.parent, mode=0o700)
    raw, _ = read_exact(source, 0, 0o400)
    require(hashlib.sha256(raw).hexdigest() == a.helper_sha256, 'helper-sha256')
    path = Path(a.evidence)
    strict_directory(path.parent, (0, a.evidence_uid))
    raw, _ = read_exact(path, a.evidence_uid)
    require(hashlib.sha256(raw).hexdigest() == a.evidence_sha256, 'evidence-sha256')
    proof = evidence(raw)
    entry = account()
    mutating = a.mode in ('apply', 'resume', 'recheck', 'review-units')
    if mutating:
        reserves()
    marker = Marker()
    try:
        marker.open(mutating, create=False)
        result = pin(proof, a.evidence_sha256, marker, Native(entry), entry, a.mode,
                     previous_digest=a.previous_evidence_sha256)
    finally:
        marker.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'version': 1, 'scope': 'p0-v2-namespace', 'refused': True,
                          'reason': str(error) if isinstance(error, Refused) else 'operation-unavailable',
                          'installationCertified': False}))
        raise SystemExit(2)
