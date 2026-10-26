#!/usr/bin/python3 -I
"""Bounded ordinary P0 machine credential custody; standalone stdlib only."""
import sys

# Check before importing filesystem-resolved stdlib modules. Parent must still
# verify the staged source hash BEFORE execution, not rely on this self-check.
if __name__ == '__main__' and not sys.flags.isolated:
    sys.stdout.write('{"version":1,"refused":true,"reason":"isolated-python-required"}\n')
    raise SystemExit(2)

import argparse
import base64
import fcntl
import grp
import hashlib
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

BASE = Path('/var/lib/p0-v2-machine-credentials')
HOME = Path('/var/lib/p0-runtime')
ROOTLESS = Path('/mnt/stack/p0-v2/rootless/engine')
ROOTFUL = Path('/mnt/stack/p0-v2/rootful/engine')
RUNFUL = Path('/run/p0-v2-rootful/engine')
NETWORK = Path('/var/lib/p0-v2-rootful/networks')
TARGET = Path('/mnt/stack/p0-v2')
SHARED = Path('/mnt/stack')
NAMESPACE_MARKER = Path('/var/lib/p0-v2-namespace')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
ACTORS = ('rootless', 'rootful')
LIMIT = 262144
HEX = re.compile(r'[0-9a-f]{64}')
OPAQUE = re.compile(r'[0-9a-f]{32}')
NATIVE_ID = re.compile(r'[a-zA-Z0-9]{12,64}')


class Refused(Exception):
    """Only fixed, public reason codes may cross the CLI boundary."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('invalid-json')))


def directory(path, owners=(0,), mode=None):
    """Every component must be a non-writable, non-symlink owned directory."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'unsafe-directory')
    at_boundary = path == TARGET or TARGET in path.parents
    if at_boundary:
        pinned_namespace()
    for part in (Path('/'), *reversed(path.parents[:-1]), path):
        if at_boundary and part == SHARED:
            continue  # Sole exception: independently verified kernel-pinned child.
        s = part.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in owners
                and not s.st_mode & 0o022, 'unsafe-directory')
    s = path.lstat()
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'directory-mode')
    return s


def identity(s):
    # Reading may update atime; it is not a custody identity field.
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_exact(path, uid, mode=None, max_bytes=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_nlink == 1
                and not s.st_mode & 0o022 and s.st_size <= max_bytes, 'unsafe-file')
        if mode is not None:
            require(stat.S_IMODE(s.st_mode) == mode, 'file-mode')
        raw = os.read(fd, max_bytes + 1)
        require(len(raw) == s.st_size and identity(os.fstat(fd)) == identity(s), 'file-changed')
        return raw, identity(s)
    finally:
        os.close(fd)


def bounded_read(path, limit):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'observation-limit')
    return raw


def mountinfo(raw):
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
    current = {'device': os.stat('/proc/self/ns/mnt').st_dev, 'inode': os.stat('/proc/self/ns/mnt').st_ino}
    host = {'device': os.stat('/proc/1/ns/mnt').st_dev, 'inode': os.stat('/proc/1/ns/mnt').st_ino}
    require(current == host, 'not-host-mount-namespace')
    return {'bootId': boot, 'mountNamespace': current,
            'mounts': mountinfo(bounded_read('/proc/self/mountinfo', 4 * 1024**2))}


def validate_namespace_marker(record, observation, expected):
    # Deliberately self-contained. NEVER import the namespace helper as Root.
    require(isinstance(record, dict) and set(record) == {'version', 'state', 'owner', 'evidenceSha256',
            'namespace', 'bootId', 'mountNamespace', 'mount', 'cloneMountId', 'integrity'}, 'marker-schema')
    fields = {k: v for k, v in record.items() if k != 'integrity'}
    digest = hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(record['integrity'] == digest and type(record['version']) is int and record['version'] == 2
            and record['state'] == 'pinned' and isinstance(record['owner'], str)
            and re.fullmatch(r'[0-9a-f]{32}', record['owner'])
            and isinstance(record['evidenceSha256'], str) and HEX.fullmatch(record['evidenceSha256'])
            and isinstance(record['namespace'], dict) and set(record['namespace']) == {'device', 'inode', 'filesystemId'}
            and all(type(v) is int and v > 0 for v in record['namespace'].values())
            and record['namespace'] == expected
            and isinstance(record['bootId'], str) and UUID.fullmatch(record['bootId'])
            and isinstance(record['mountNamespace'], dict) and set(record['mountNamespace']) == {'device', 'inode'}
            and all(type(v) is int and v > 0 for v in record['mountNamespace'].values()), 'marker-binding')
    require(record['bootId'] == observation['bootId'] and record['mountNamespace'] == observation['mountNamespace'],
            'marker-stale-boot-or-namespace')
    mounts = observation['mounts']
    parents = [m for m in mounts if m['target'] == str(SHARED)]
    require(len(parents) == 1, 'shared-parent-not-exact-mount')
    parent = parents[0]
    device = f"{os.major(expected['device'])}:{os.minor(expected['device'])}"
    require(parent['device'] == device, 'namespace-filesystem')
    require(not any(m['target'].startswith(str(TARGET) + '/') for m in mounts), 'namespace-submount')
    own = [m for m in mounts if m['target'] == str(TARGET)]
    require(len(own) == 1, 'namespace-unpinned-or-stacked')
    own = own[0]
    require(own['parent'] == parent['id'] and own['device'] == device
            and own['root'] == parent['root'].rstrip('/') + '/p0-v2'
            and own['fsType'] == parent['fsType'] and own['source'] == parent['source']
            and 'rw' in own['options'], 'foreign-namespace-mount')
    require(not any(s.startswith(('shared:', 'master:', 'propagate_from:')) or s == 'unbindable'
                    for s in own['optional']), 'namespace-mount-not-private')
    require(type(record['cloneMountId']) is int and 0 < record['cloneMountId'] < 2**64
            and record['cloneMountId'] == own['id'], 'preclaimed-mount-id-changed')
    require(record['mount'] == own, 'marker-mount-changed')
    return own


def pinned_namespace():
    # Native10 invalidates v2 canonical/private-bind custody across mount NSs.
    # Do not read a v2 marker as authority, even for info or preflight. Pending
    # independent v3 native-view + actual-unshare integration fails CLOSED.
    raise Refused('protected-view-v3-integration-required')


def legacy_pinned_namespace_observation():
    """Forensic geometry only; never used by credential authority or CLI."""
    directory('/mnt')
    shared = SHARED.lstat()
    require(stat.S_ISDIR(shared.st_mode) and shared.st_uid == 1000 and shared.st_gid == 1000
            and stat.S_IMODE(shared.st_mode) == 0o2775, 'shared-parent-identity')
    directory(NAMESPACE_MARKER, mode=0o700)
    raw, marker_identity = read_exact(NAMESPACE_MARKER / 'active.json', 0, 0o400)
    record = strict_json(raw)
    fd = os.open(TARGET, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        require(s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o711, 'namespace-identity')
        expected = {'device': s.st_dev, 'inode': s.st_ino, 'filesystemId': os.fstatvfs(fd).f_fsid}
        observation = kernel()
        mount = validate_namespace_marker(record, observation, expected)
        current = TARGET.lstat()
        require((current.st_dev, current.st_ino) == (s.st_dev, s.st_ino), 'namespace-renamed')
        return {'markerBytes': raw, 'markerIdentity': marker_identity, 'namespace': expected,
                'bootId': observation['bootId'], 'mountNamespace': observation['mountNamespace'],
                'mount': mount, 'parent': next(m for m in observation['mounts'] if m['target'] == str(SHARED))}
    finally:
        os.close(fd)


def policy(entry):
    result = entry.get('policy', {'encoding': 'base64url', 'entropyBytes': 48})
    require(isinstance(result, dict) and set(result) == {'encoding', 'entropyBytes'}
            and result['encoding'] in ('base64url', 'base64url-unpadded', 'hex') and type(result['entropyBytes']) is int
            and result['entropyBytes'] in (32, 48), 'resource-policy')
    return dict(result)


def intent(raw):
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'version', 'classification', 'resources'}
            and type(value['version']) is int and value['version'] == 1
            and value['classification'] == 'ordinary-service', 'intent-schema')
    resources = value['resources']
    require(isinstance(resources, list) and 1 <= len(resources) <= 64, 'intent-resources')
    names = set()
    for entry in resources:
        require(isinstance(entry, dict) and set(entry) in ({'name', 'actors'}, {'name', 'actors', 'policy'}), 'resource-schema')
        policy(entry)
        name = entry['name']
        require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', name)
                and len(name) <= 48 and name not in names, 'resource-name')
        require(not any(word in name for word in ('vault', 'keykeeper', 'bao', 'owner'))
                and name != 'postgres-admin', 'protected-resource')
        names.add(name)
        actors = entry['actors']
        require(isinstance(actors, list) and 1 <= len(actors) <= 2
                and all(isinstance(a, str) and a in ACTORS for a in actors)
                and len(set(actors)) == len(actors), 'resource-actors')
    return value


def reserves():
    available = 0
    with open('/proc/meminfo', encoding='ascii') as stream:
        for line in stream:
            if line.startswith('MemAvailable:'):
                available = int(line.split()[1]) * 1024
    require(available >= 16 * 1024**3, 'ram-reserve')
    for path, floor in (('/', 50), ('/mnt/stack/p0-v2', 100), ('/var/lib', 1)):
        data = os.statvfs(path)
        require(data.f_bavail * data.f_frsize >= floor * 1024**3, 'disk-reserve')


def actor_identity():
    entry = pwd.getpwnam('p0-runtime')
    require(entry.pw_uid >= 1000 and entry.pw_gid >= 1000
            and entry.pw_dir == str(HOME) and entry.pw_shell == '/usr/sbin/nologin', 'actor-identity')
    primary = grp.getgrgid(entry.pw_gid)
    require(primary.gr_name == 'p0-runtime' and not primary.gr_mem
            and not any('p0-runtime' in g.gr_mem for g in grp.getgrall()), 'actor-groups')
    return entry


def trusted_binary(path):
    directory(Path(path).parent)
    read_exact(path, 0, max_bytes=128 * 1024**2)
    require(os.stat(path).st_mode & 0o111, 'native-not-executable')


class Native:
    def __init__(self, entry):
        self.entry = entry
        self.authorities = {}

    def environment(self, actor):
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}
        if actor == 'rootless':
            env.update(HOME=str(HOME), XDG_RUNTIME_DIR=f'/run/user/{self.entry.pw_uid}')
        return env

    def prefix(self, actor):
        if actor == 'rootful':
            return ['/usr/bin/podman', '--root', str(ROOTFUL), '--runroot', str(RUNFUL),
                    '--storage-driver', 'overlay', '--network-config-dir', str(NETWORK)]
        return ['/usr/bin/setpriv', '--reuid', str(self.entry.pw_uid), '--regid',
                str(self.entry.pw_gid), '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all',
                '/usr/bin/podman', '--root', str(ROOTLESS), '--runroot',
                f'/run/user/{self.entry.pw_uid}/containers', '--storage-driver', 'overlay']

    def call(self, actor, args, payload=None):
        """Bounded pipe output, discarded stderr, 30s deadline; never surface native text."""
        self.check_authority(actor)
        p = subprocess.Popen(self.prefix(actor) + args, stdin=subprocess.PIPE if payload else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=self.environment(actor), cwd='/', start_new_session=True)
        output = bytearray()
        settled = False
        try:
            if payload:
                # Bounded generated ASCII payload (at most96 bytes) fits in one small pipe write.
                p.stdin.write(payload)
                p.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(p.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 30
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'native-timeout')
                    for key, _ in selector.select(min(remaining, 1)):
                        block = os.read(key.fileobj.fileno(), 8192)
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(block)
                            require(len(output) <= LIMIT, 'native-output-limit')
                rc = p.wait(timeout=max(0.01, deadline - time.monotonic()))
                settled = True
            self.check_authority(actor)
            return rc, bytes(output)
        finally:
            if not settled:
                # Signal only our own new session, before reaping its leader.
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait(timeout=5)
            p.stdout.close()
            if p.stdin and not p.stdin.closed:
                p.stdin.close()

    def layout(self, actor):
        e, observed = self.entry, []
        require(actor in ACTORS, 'native-actor')
        uid, gid = (e.pw_uid, e.pw_gid) if actor == 'rootless' else (0, 0)
        paths = ((HOME, ROOTLESS.parent, ROOTLESS, Path(f'/run/user/{e.pw_uid}/containers')) if actor == 'rootless'
                 else (ROOTFUL.parent, ROOTFUL, RUNFUL.parent, RUNFUL, NETWORK.parent, NETWORK))
        for path in paths:
            directory(path, (0, uid), mode=0o700)
            s = path.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid
                    and stat.S_IMODE(s.st_mode) == 0o700, 'actor-directory-owner')
            observed.append((str(path), (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))))
        if actor == 'rootless':
            config = HOME / '.config/containers/storage.conf'
            directory(config.parent, (0, uid))
            raw, config_identity = read_exact(config, uid, 0o600)
            expected = ('[storage]\ndriver = "overlay"\n'
                        f'runroot = "/run/user/{uid}/containers"\n'
                        f'graphroot = "{ROOTLESS}"\n').encode()
            require(raw == expected, 'actor-storage-config')
            observed.append((str(config), raw, config_identity))
        return tuple(observed)

    def check_authority(self, actor):
        require(actor in self.authorities, 'native-preflight-required')
        current = (pinned_namespace(), self.layout(actor))
        require(current == self.authorities[actor], 'native-authority-changed')

    def preflight(self, actors):
        require(actors and len(set(actors)) == len(actors) and all(a in ACTORS for a in actors), 'native-actors')
        self.authorities = {}
        boundary = pinned_namespace()  # Before ANY native or writable-ancestor exception.
        trusted_binary('/usr/bin/podman')
        if 'rootless' in actors:
            trusted_binary('/usr/bin/setpriv')
        for actor in actors:
            layout = self.layout(actor)
            require(pinned_namespace() == boundary, 'native-authority-changed')
            self.authorities[actor] = (boundary, layout)
        for actor in actors:
            rc, raw = self.call(actor, ['info', '--format', 'json'])
            require(rc == 0, 'native-info')
            store = strict_json(raw).get('store', {})
            graph = str(ROOTLESS if actor == 'rootless' else ROOTFUL)
            run = f'/run/user/{self.entry.pw_uid}/containers' if actor == 'rootless' else str(RUNFUL)
            require(store.get('graphRoot') == graph and store.get('runRoot') == run
                    and store.get('graphDriverName') == 'overlay', 'native-store-mismatch')

    def inspect(self, actor, name):
        rc, _ = self.call(actor, ['secret', 'exists', 'p0-' + name])
        require(rc in (0, 1), 'native-exists-uncertain')
        if rc == 1:
            return None
        rc, raw = self.call(actor, ['secret', 'inspect', 'p0-' + name])
        require(rc == 0, 'native-inspect-uncertain')
        items = strict_json(raw)
        require(isinstance(items, list) and len(items) == 1, 'native-metadata')
        item = items[0]
        spec = item.get('Spec', {})
        driver = spec.get('Driver', {})
        graph = ROOTLESS if actor == 'rootless' else ROOTFUL
        # Native Podman can materialize its default file-driver path in metadata.
        # Admit only that exact actor store, never caller paths/aliases/options.
        canonical_options = {'path': str(graph / 'secrets/filedriver')}
        require(spec.get('Name') == 'p0-' + name and isinstance(spec.get('Labels'), dict)
                and isinstance(driver, dict) and driver.get('Name') == 'file'
                and driver.get('Options') in (None, {}, canonical_options)
                and isinstance(item.get('ID'), str) and NATIVE_ID.fullmatch(item['ID']), 'native-metadata')
        return {'id': item['ID'], 'labels': spec['Labels']}

    def create(self, actor, name, labels, payload):
        args = ['secret', 'create', '--driver', 'file']
        for key, value in sorted(labels.items()):
            args += ['--label', key + '=' + value]
        rc, _ = self.call(actor, args + ['p0-' + name, '-'], payload)
        require(rc == 0, 'native-create-uncertain')


def labels(record, item):
    return {'p0.machine.owner': record['owner'], 'p0.machine.version': item['version'],
            'p0.machine.intent': record['intentSha256'], 'p0.machine.class': 'ordinary-service'}


def encode_value(raw, encoding):
    require(encoding in ('base64url', 'base64url-unpadded', 'hex'), 'resource-policy')
    if encoding == 'hex':
        return raw.hex()
    value = base64.urlsafe_b64encode(raw).decode('ascii')
    return value.rstrip('=') if encoding == 'base64url-unpadded' else value


def validate_value(value, selected):
    size, encoding = selected['entropyBytes'], selected['encoding']
    require(isinstance(value, str) and 1 <= len(value) <= 96, 'record-value-encoding')
    if encoding == 'hex':
        require(re.fullmatch(r'[0-9a-f]{' + str(2 * size) + '}', value), 'record-value-encoding')
        decoded = bytes.fromhex(value)
    else:
        expected_length = 4 * ((size + 2) // 3)
        if encoding == 'base64url-unpadded':
            expected_length -= (3 - size % 3) % 3
            require(re.fullmatch(r'[A-Za-z0-9_-]+', value), 'record-value-encoding')
        else:
            require(re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', value), 'record-value-encoding')
        require(len(value) == expected_length, 'record-value-encoding')
        padded = value + '=' * (-len(value) % 4) if encoding == 'base64url-unpadded' else value
        decoded = base64.b64decode(padded, altchars=b'-_', validate=True)
    require(len(decoded) == size and encode_value(decoded, encoding) == value, 'record-value-encoding')


def prepared(spec, digest):
    return {'version': 2, 'intentSha256': digest, 'owner': secrets.token_hex(16),
            'resources': {entry['name']: {'version': secrets.token_hex(16), 'policy': policy(entry),
                'value': encode_value(secrets.token_bytes(policy(entry)['entropyBytes']), policy(entry)['encoding']),
                'actors': {actor: {'state': 'prepared', 'id': None} for actor in entry['actors']}}
                for entry in spec['resources']}}


def record_integrity(record):
    # Internal corruption check, never reported. Root custody is the trust boundary,
    # not an assertion of resistance to an attacker already holding Root.
    fields = {k: v for k, v in record.items() if k != 'integrity'}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_record(record, spec, digest):
    require(isinstance(record, dict) and record.get('integrity') == record_integrity(record), 'record-integrity')
    require(set(record) == {'version', 'intentSha256', 'owner', 'resources', 'integrity'}
            and type(record['version']) is int and record['version'] == 2
            and record['intentSha256'] == digest and isinstance(record['owner'], str)
            and OPAQUE.fullmatch(record['owner']), 'record-binding')
    entries = {e['name']: e for e in spec['resources']}
    require(isinstance(record['resources'], dict) and set(record['resources']) == set(entries), 'record-resources')
    for name, item in record['resources'].items():
        require(isinstance(item, dict) and set(item) == {'version', 'value', 'actors', 'policy'}
                and isinstance(item['version'], str) and OPAQUE.fullmatch(item['version'])
                and isinstance(item['value'], str), 'record-schema')
        require(item['policy'] == policy(entries[name]), 'record-policy')
        validate_value(item['value'], policy({'policy': item['policy']}))
        require(isinstance(item['actors'], dict) and set(item['actors']) == set(entries[name]['actors']), 'record-actors')
        for state in item['actors'].values():
            require(isinstance(state, dict) and set(state) == {'state', 'id'}
                    and state['state'] in ('prepared', 'claimed', 'uncertain', 'complete'), 'record-state')
            require((state['state'] == 'complete' and isinstance(state['id'], str)
                     and NATIVE_ID.fullmatch(state['id'])) or
                    (state['state'] != 'complete' and state['id'] is None), 'record-id')


class Custody:
    """One locked active record. No adoption, credential rotation, or deletion API."""
    def __init__(self, base=BASE):
        self.base = Path(base)
        self.fd = None
        self.previous = None

    def open(self, apply, *, create=None):
        if create is None:
            create = apply
        directory(self.base.parent)
        if not os.path.lexists(self.base):
            if not create:
                return False
            self.base.mkdir(mode=0o700)
        directory(self.base, mode=0o700)
        self.fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fcntl.flock(self.fd, (fcntl.LOCK_EX if apply else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        self.identity = os.fstat(self.fd)
        require(set(os.listdir(self.fd)) <= {'active.json'}, 'unexpected-custody-entry')
        return True

    def current(self):
        directory(self.base, mode=0o700)
        s = self.base.lstat()
        require((s.st_dev, s.st_ino) == (self.identity.st_dev, self.identity.st_ino), 'custody-changed')
        path = self.base / 'active.json'
        if not os.path.lexists(path):
            return None
        return read_exact(path, 0, 0o400)

    def load(self):
        self.previous = self.current()
        return strict_json(self.previous[0]) if self.previous else None

    def save(self, record):
        require(self.current() == self.previous, 'record-cas')
        record['integrity'] = record_integrity(record)
        raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
        require(len(raw) <= LIMIT, 'record-size')
        temporary = '.publish-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o400)  # Only this freshly created inode; never repair existing custody.
            require(os.write(fd, raw) == len(raw), 'record-short-write')
            os.fsync(fd)
        finally:
            os.close(fd)
        require(self.current() == self.previous, 'record-cas')
        os.replace(temporary, 'active.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.previous = self.current()

    def catalog(self, spec):
        # Base record custody used by isolated source tests. Production uses the
        # bounded cross-intent authority below, never a legacy root active.json.
        pass

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class IntentCustody(Custody):
    """Independent intent records, serialized name claims under one Root authority."""
    def __init__(self, authority, digest):
        require(isinstance(digest, str) and HEX.fullmatch(digest), 'intent-directory')
        self.authority = Path(authority)
        self.digest = digest
        self.rootfd = None
        super().__init__(self.authority / 'intents' / digest)

    def open(self, apply, *, create=None):
        if create is None:
            create = apply
        directory(self.authority.parent)
        if not os.path.lexists(self.authority):
            if not create:
                return False
            self.authority.mkdir(mode=0o700)
        directory(self.authority, mode=0o700)
        self.rootfd = os.open(self.authority, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fcntl.flock(self.rootfd, (fcntl.LOCK_EX if apply else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        self.authority_id = os.fstat(self.rootfd)
        # A legacy global active.json is never adopted, repaired or auto-migrated.
        require(set(os.listdir(self.rootfd)) <= {'intents'}, 'unknown-credential-authority-entry')
        intents = self.authority / 'intents'
        if not os.path.lexists(intents):
            if not create:
                return False
            intents.mkdir(mode=0o700)
        directory(intents, mode=0o700)
        names = os.listdir(intents)
        require(len(names) <= 64 and all(HEX.fullmatch(n) for n in names), 'intent-catalog-bound')
        require(self.digest in names or len(names) < 64, 'intent-catalog-full')
        return super().open(apply, create=create)

    def catalog(self, spec):
        if self.rootfd is None:
            return
        directory(self.authority, mode=0o700)
        s = self.authority.lstat()
        require((s.st_dev, s.st_ino) == (self.authority_id.st_dev, self.authority_id.st_ino), 'credential-authority-changed')
        intents = self.authority / 'intents'
        if not os.path.lexists(intents):
            return
        directory(intents, mode=0o700)
        names = os.listdir(intents)
        require(len(names) <= 64 and all(HEX.fullmatch(n) for n in names), 'intent-catalog-bound')
        owners, count = {}, 0
        for digest in names:
            path = intents / digest
            directory(path, mode=0o700)
            entries = os.listdir(path)
            require(set(entries) <= {'active.json'}, 'unexpected-custody-entry')
            if not entries:
                continue
            raw, _ = read_exact(path / 'active.json', 0, 0o400)
            record = strict_json(raw)
            require(isinstance(record, dict) and isinstance(record.get('resources'), dict), 'catalog-record')
            resources = []
            for name, item in record['resources'].items():
                require(isinstance(item, dict) and isinstance(item.get('actors'), dict), 'catalog-record')
                resources.append({'name': name, 'actors': list(item['actors']), 'policy': item.get('policy')})
            other_spec = intent(json.dumps({'version': 1, 'classification': 'ordinary-service', 'resources': resources}).encode())
            validate_record(record, other_spec, digest)
            for name in record['resources']:
                require(name not in owners, 'cross-intent-name-collision')
                owners[name] = digest
                count += 1
        for entry in spec['resources']:
            name = entry['name']
            require(name not in owners or owners[name] == self.digest, 'cross-intent-name-collision')
            if name not in owners:
                count += 1
        require(count <= 512, 'aggregate-resource-bound')

    def close(self):
        super().close()
        if self.rootfd is not None:
            os.close(self.rootfd)
            self.rootfd = None


def supply(spec, digest, custody, native, mode):
    record = custody.load() if custody.fd is not None else None
    if record is not None:
        validate_record(record, spec, digest)
    custody.catalog(spec)
    if mode in ('status', 'dry-run'):
        return report(record, spec, mode)
    require(mode != 'resume' or record is not None, 'resume-record-required')
    actors = sorted({a for e in spec['resources'] for a in e['actors']})
    native.preflight(actors)
    if record is None:
        # Check every target before publishing fresh custody. Existing names are never adopted.
        for entry in spec['resources']:
            for actor in entry['actors']:
                require(native.inspect(actor, entry['name']) is None, 'foreign-existing-name')
        record = prepared(spec, digest)
        custody.save(record)
    elif mode == 'apply':
        require(all(s['state'] == 'complete' for item in record['resources'].values()
                    for s in item['actors'].values()), 'explicit-resume-required')
    # Validate ALL existing metadata before any create, including actors already completed.
    observations = {}
    for name, item in record['resources'].items():
        for actor, state in item['actors'].items():
            observation = native.inspect(actor, name)
            if observation is not None:
                require(observation['labels'] == labels(record, item), 'foreign-existing-name')
                require(state['state'] != 'prepared', 'unclaimed-native-name')
                require(state['id'] is None or state['id'] == observation['id'], 'native-id-changed')
            else:
                require(state['state'] not in ('complete', 'claimed', 'uncertain'), 'uncertain-absence-no-replay')
            observations[(name, actor)] = observation
    for name, item in record['resources'].items():
        for actor, state in item['actors'].items():
            observation = observations[(name, actor)]
            if observation is not None:
                if state['state'] != 'complete':
                    state.update(state='complete', id=observation['id'])
                    custody.save(record)
                continue
            reserves()  # Recheck floors immediately before each claimed mutation.
            state['state'] = 'claimed'
            custody.save(record)  # Durable claim precedes external effect.
            try:
                native.create(actor, name, labels(record, item), item['value'].encode('ascii'))
                observation = native.inspect(actor, name)
                require(observation is not None and observation['labels'] == labels(record, item), 'create-unconfirmed')
            except Exception:
                state['state'] = 'uncertain'
                custody.save(record)
                raise Refused('native-create-uncertain') from None
            state.update(state='complete', id=observation['id'])
            custody.save(record)
    return report(record, spec, mode)


def report(record, spec, mode):
    return {'version': 1, 'scope': 'ordinary-service', 'mode': mode, 'installationCertified': False,
            'owner': record['owner'] if record else None,
            'resources': [{'name': e['name'], 'version': record['resources'][e['name']]['version'] if record else None,
                           'actors': {a: dict(record['resources'][e['name']]['actors'][a]) if record else
                                      {'state': 'absent', 'id': None} for a in e['actors']}}
                          for e in spec['resources']]}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('cli-arguments')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('mode', choices=('apply', 'resume', 'status', 'dry-run'))
    parser.add_argument('--intent', required=True)
    parser.add_argument('--intent-sha256', required=True)
    parser.add_argument('--intent-uid', type=int, required=True)
    parser.add_argument('--helper-sha256', required=True)
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'root-required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(HEX.fullmatch(args.helper_sha256) and HEX.fullmatch(args.intent_sha256), 'invalid-sha256')
    source = Path(__file__).absolute()
    require(source.is_relative_to('/var/lib') and source.parent != Path('/var/lib'), 'helper-staging')
    directory(source.parent, mode=0o700)
    raw, _ = read_exact(source, 0, 0o400)
    require(hashlib.sha256(raw).hexdigest() == args.helper_sha256, 'helper-sha256')
    require(args.intent_uid >= 1000, 'intent-owner')
    path = Path(args.intent)
    directory(path.parent, (0, args.intent_uid))
    raw, _ = read_exact(path, args.intent_uid)
    require(hashlib.sha256(raw).hexdigest() == args.intent_sha256, 'intent-sha256')
    spec = intent(raw)
    entry = actor_identity()
    mutating = args.mode in ('apply', 'resume')
    if mutating:
        reserves()
    native = Native(entry)
    if mutating:
        # Refuse unexpected stores before even creating a custody directory.
        native.preflight(sorted({a for e in spec['resources'] for a in e['actors']}))
    custody = IntentCustody(BASE, args.intent_sha256)
    try:
        custody.open(mutating, create=args.mode == 'apply')
        result = supply(spec, args.intent_sha256, custody, native, args.mode)
    finally:
        custody.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never stringify exceptions, paths, native output, values, or fingerprints.
        code = str(error) if isinstance(error, Refused) else 'operation-unavailable'
        print(json.dumps({'version': 1, 'refused': True, 'reason': code,
                          'scope': 'ordinary-service', 'installationCertified': False}))
        raise SystemExit(2)
