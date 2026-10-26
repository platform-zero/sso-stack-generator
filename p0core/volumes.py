"""Fresh Rootless named-volume custody. No adoption, repair, reset or deletion.

Parent integrates the single bounded Runner and publication interlock. This code
must never be imported/executed as Host Root. NativeAdapter is not used by tests.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat

GRAPHROOT = Path('/mnt/stack/p0-v2/rootless/engine')
LIMIT = 262144
NAME = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')
STATES = ('claimed', 'bound', 'chmod-claimed', 'chmod-done', 'chown-claimed', 'prepared')


class VolumeError(RuntimeError):
    """Only fixed public refusal tags; never native output or data contents."""


def need(condition, reason):
    if not condition:
        raise VolumeError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def parse(raw):
    need(isinstance(raw, bytes) and len(raw) <= LIMIT, 'volume-json-bound')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'volume-json-duplicate')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(VolumeError('volume-json-constant')))
    except (ValueError, UnicodeError):
        raise VolumeError('volume-json-invalid') from None


def definition(resource, custody):
    need(isinstance(resource, str) and len(resource) <= 48 and NAME.fullmatch(resource), 'volume-resource')
    need(isinstance(custody, dict) and set(custody) == {'uid', 'gid', 'mode'}, 'volume-custody-schema')
    need(all(type(custody[k]) is int and 0 <= custody[k] <= 65535 for k in ('uid', 'gid'))
         and custody['mode'] in ('0700', '0750'), 'volume-custody-policy')
    return {'schemaVersion': 1, 'runtime': 'rootless', 'resource': resource, 'nativeName': 'p0-' + resource,
            'driver': 'local', 'options': {}, 'custody': dict(custody)}


def declared_custodies(services):
    """Pure catalog admission; no native lookup, permission or resource effect."""
    seen = {}
    for service in services:
        mounts = service.get('mounts', [])
        if not isinstance(mounts, list):
            continue  # Existing renderer owns unrelated malformed mount schemas.
        for mount in mounts:
            if not isinstance(mount, dict):
                continue
            supplied = 'custody' in mount
            need(not supplied or mount.get('kind') == 'volume', 'volume-custody-kind')
            if mount.get('kind') != 'volume':
                continue
            policy = None
            if supplied:
                need(service.get('runtime') == 'rootless', 'volume-custody-rootless-only')
                policy = definition(mount.get('source'), mount['custody'])['custody']
            source = mount.get('source')
            if not isinstance(source, str):
                continue  # Custodied sources were validated by definition above.
            key = (service.get('runtime'), source)
            if key in seen:
                need(seen[key] == policy, 'volume-shared-custody-conflict')
            else:
                seen[key] = policy
    return {source: dict(policy) for (runtime, source), policy in sorted(seen.items())
            if runtime == 'rootless' and policy is not None}


def labels(record):
    return {'io.platform-zero.managed': 'v2', 'io.platform-zero.volume.resource': record['definition']['resource'],
            'io.platform-zero.volume.intent': record['definitionSha256'],
            'io.platform-zero.volume.nonce': record['nonce']}


def inode(fd):
    s = os.fstat(fd)
    need(stat.S_ISDIR(s.st_mode), 'volume-not-directory')
    return {'device': s.st_dev, 'inode': s.st_ino}


def host_stat(fd):
    s = os.fstat(fd)
    return dict(inode(fd), uid=s.st_uid, gid=s.st_gid, mode=f'{stat.S_IMODE(s.st_mode):04o}')


def open_directory(path):
    """O_PATH permits immutable-stat recheck after ownership leaves Host UID.

    The fixed unshare program reopens '.' relative to this held inode to obtain
    its readable FD. No pathname chmod/chown or proc-FD mount/store aliases.
    """
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'volume-path')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def mapping(rows, namespace_id):
    need(isinstance(rows, list) and 1 <= len(rows) <= 64, 'volume-idmap')
    namespace_ranges, host_ranges, matches = [], [], []
    for row in rows:
        need(isinstance(row, list) and len(row) == 3 and all(type(x) is int for x in row), 'volume-idmap')
        start, outer, count = row
        need(start >= 0 and outer > 0 and count > 0 and start + count <= 2**32 - 1
             and outer + count <= 2**32 - 1, 'volume-idmap')
        need(not any(start < end and old < start + count for old, end in namespace_ranges)
             and not any(outer < end and old < outer + count for old, end in host_ranges), 'volume-idmap-overlap')
        namespace_ranges.append((start, start + count))
        host_ranges.append((outer, outer + count))
        if start <= namespace_id < start + count:
            matches.append(outer + namespace_id - start)
    need(len(matches) == 1, 'volume-id-unmapped')
    return matches[0]


# EXACT fixed stdlib program; source-owned, not a caller-supplied generator.
# Runs as namespace0 inside unprivileged Podman unshare, NEVER Host Root.
INODE_PROGRAM = r'''
import json, os, re, stat, sys
try:
    raw = sys.stdin.buffer.read(4097)
    assert len(raw) <= 4096
    request = json.loads(raw)
    assert set(request) == {'action','fd','identity','before','desired','fresh','resource','maps','protectedParent'}
    assert request['action'] in ('probe','chmod','chown')
    assert type(request['fd']) is int and request['fd'] >= 3
    assert type(request['fresh']) is bool and (request['fresh'] or request['action'] == 'probe')
    assert re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', request['resource']) and len(request['resource']) <= 48
    desired = request['desired']
    assert set(desired) == {'uid','gid','mode'}
    assert all(type(desired[k]) is int and 0 <= desired[k] <= 65535 for k in ('uid','gid'))
    assert desired['mode'] in ('0700','0750') and os.geteuid() == 0
    maps = {}
    for kind in ('uid','gid'):
        with open('/proc/self/' + kind + '_map', 'rb') as source:
            data = source.read(65537)
        assert len(data) <= 65536
        maps[kind + 'Map'] = [[int(x) for x in line.split()] for line in data.splitlines()]
        assert all(len(row) == 3 and row[1] > 0 for row in maps[kind + 'Map'])
    assert request['maps'] is None or maps == request['maps']
    assert request['action'] == 'probe' or request['maps'] is not None
    data_path = '/mnt/stack/p0-v2/rootless/engine/volumes/p0-' + request['resource'] + '/_data'
    def protected_parent():
        expected = request['protectedParent']
        assert set(expected) == {'device','inode'}
        assert all(type(expected[k]) is int and expected[k] > 0 for k in expected)
        current = os.open('/', os.O_PATH | os.O_DIRECTORY)
        try:
            for part in ('mnt','stack'):
                child = os.open(part,os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=current)
                os.close(current)
                current = child
            s = os.fstat(current)
            assert {'device':s.st_dev,'inode':s.st_ino} == expected
            assert stat.S_IMODE(s.st_mode) == 0o711
        finally:
            os.close(current)
    protected_parent()  # An OLD Podman pause mount namespace MUST refuse.
    def no_mounts():
        with open('/proc/self/mountinfo', 'rb') as source:
            mounts = source.read(4 * 1024**2 + 1)
        assert len(mounts) <= 4 * 1024**2
        for line in mounts.decode('ascii').splitlines():
            target = line.split()[4]
            target = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1],8)), target)
            assert target not in (data_path,data_path.rsplit('/',1)[0],data_path.rsplit('/',2)[0])
            assert not target.startswith(data_path + '/')
    no_mounts()
    fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=request['fd'])
    try:
        def observe():
            s = os.fstat(fd)
            assert stat.S_ISDIR(s.st_mode)
            actual = {'device':s.st_dev,'inode':s.st_ino}
            assert actual == request['identity']
            assert (s.st_dev,s.st_ino) == (os.fstat(request['fd']).st_dev,os.fstat(request['fd']).st_ino)
            if desired['mode'] == '0750':
                assert not {'system.posix_acl_access','system.posix_acl_default'}.intersection(os.listxattr(fd))
            if request['fresh']:
                with os.scandir(fd) as entries:
                    assert next(entries,None) is None
            return dict(actual,uid=s.st_uid,gid=s.st_gid,mode=format(stat.S_IMODE(s.st_mode),'04o'))
        def canonical_identity():
            current = os.open('/', os.O_PATH | os.O_DIRECTORY)
            try:
                for part in data_path.split('/')[1:]:
                    child = os.open(part,os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=current)
                    os.close(current)
                    current = child
                s = os.fstat(current)
                assert {'device':s.st_dev,'inode':s.st_ino} == request['identity']
            finally:
                os.close(current)
        canonical_identity()  # Child namespace canonical path MUST name held inode.
        before = observe()
        if request['action'] != 'probe':
            assert {k:before[k] for k in ('uid','gid','mode')} == request['before']
            if request['action'] == 'chmod':
                assert before['uid'] == before['gid'] == 0 and before['mode'] in ('0700','0755')
                os.fchmod(fd,int(desired['mode'],8))
            else:
                assert before['uid'] == before['gid'] == 0 and before['mode'] == desired['mode']
                os.fchown(fd,desired['uid'],desired['gid'])
        after = observe()
        canonical_identity()
        no_mounts()
        protected_parent()
        print(json.dumps(dict(maps,stat=after,empty=True if request['fresh'] else None)))
    finally:
        os.close(fd)
except BaseException:
    print('{"refused":true}')
    sys.exit(2)
'''


class NativeAdapter:
    """One Parent-owned bounded Runner, clean context and narrow pass_fds API."""
    def __init__(self, runtime):
        need(os.geteuid() == os.getuid() and os.getuid() >= 1000
             and pwd.getpwuid(os.getuid()).pw_name == 'p0-runtime', 'volume-rootless-only')
        self.runtime, self.actor_uid, self.actor_gid = runtime, os.getuid(), os.getgid()
        witness = runtime.verify_volume_context()
        need(isinstance(witness, dict) and witness.get('graphRoot') == str(GRAPHROOT)
             and witness.get('uid') == self.actor_uid and witness.get('gid') == self.actor_gid,
             'volume-runtime-context')
        self.witness = encoded(witness)
        parent = parse(self.witness).get('directories', {}).get('/mnt/stack', {})
        need(isinstance(parent, dict) and type(parent.get('uid')) is int and parent['uid'] == 0
             and type(parent.get('gid')) is int and parent['gid'] == 0
             and parent.get('mode') == '0711'
             and all(type(parent.get(k)) is int and parent[k] > 0 for k in ('device', 'inode')),
             'volume-protected-parent')
        self.protected_parent = {key: parent[key] for key in ('device', 'inode')}

    def call(self, arguments, *, input_bytes=None, pass_fds=()):
        need(encoded(self.runtime.verify_volume_context()) == self.witness, 'volume-context-changed')
        need(type(pass_fds) is tuple and len(pass_fds) <= 1 and all(type(x) is int and x >= 3 for x in pass_fds),
             'volume-pass-fds')
        if pass_fds or (arguments and arguments[0] == 'unshare'):
            need(arguments == ['unshare', '/usr/bin/python3', '-I', '-c', INODE_PROGRAM]
                 and len(pass_fds) == 1, 'volume-fd-command')
            inode(pass_fds[0])
        need(input_bytes is None or (isinstance(input_bytes, bytes) and len(input_bytes) <= 4096), 'volume-input-bound')
        prefix = ['/usr/bin/podman', '--root', str(GRAPHROOT), '--runroot',
                  f'/run/user/{self.actor_uid}/containers', '--storage-driver', 'overlay']
        try:
            raw = self.runtime.run(prefix + arguments, timeout=30, input_bytes=input_bytes, pass_fds=pass_fds)
        except Exception:
            raise VolumeError('volume-native-indeterminate') from None
        need(isinstance(raw, bytes) and len(raw) <= LIMIT, 'volume-native-output')
        need(encoded(self.runtime.verify_volume_context()) == self.witness, 'volume-context-changed')
        return raw

    def mountpoint(self, resource):
        return GRAPHROOT / 'volumes' / ('p0-' + resource) / '_data'

    def lookup(self, resource):
        name = 'p0-' + resource
        rows = parse(self.call(['volume', 'ls', '--format', 'json']))
        need(isinstance(rows, list) and len(rows) <= 512, 'volume-inventory')
        names = [row.get('Name') for row in rows if isinstance(row, dict)]
        need(len(names) == len(rows) and all(isinstance(n, str) for n in names)
             and len(set(names)) == len(names), 'volume-inventory')
        if name not in names:
            return None
        rows = parse(self.call(['volume', 'inspect', name]))
        need(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), 'volume-inspect')
        return rows[0]

    def create(self, record):
        args = ['volume', 'create', '--driver', 'local']
        for key, value in sorted(labels(record).items()):
            args += ['--label', key + '=' + value]
        raw = self.call(args + [record['definition']['nativeName']])
        need(raw.decode('ascii').strip() == record['definition']['nativeName'], 'volume-create-response')

    def no_mounts(self, path):
        with open('/proc/self/mountinfo', 'rb') as source:
            raw = source.read(4 * 1024**2 + 1)
        need(len(raw) <= 4 * 1024**2, 'volume-mountinfo-bound')
        for line in raw.decode('ascii').splitlines():
            parts = line.split()
            need(len(parts) >= 10, 'volume-mountinfo')
            target = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), parts[4])
            need(target not in (str(path), str(path.parent), str(path.parent.parent))
                 and not target.startswith(str(path) + '/'), 'volume-mounted')

    def no_users(self, resource):
        path, name = self.mountpoint(resource), 'p0-' + resource
        rows = parse(self.call(['ps', '--all', '--external', '--format', 'json']))
        need(isinstance(rows, list) and len(rows) <= 512, 'volume-users-unknown')
        checked_volumes = set()
        for row in rows:
            identity = row.get('Id') if isinstance(row, dict) else None
            need(isinstance(identity, str) and re.fullmatch('[a-f0-9]{12,64}', identity), 'volume-users-unknown')
            containers = parse(self.call(['container', 'inspect', identity]))
            need(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict)
                 and containers[0].get('Id') == identity
                 and isinstance(containers[0].get('Mounts'), list) and len(containers[0]['Mounts']) <= 128,
                 'volume-users-unknown')
            for mount in containers[0]['Mounts']:
                need(isinstance(mount, dict) and mount.get('Type') in ('volume', 'bind', 'tmpfs'), 'volume-users-unknown')
                if mount['Type'] == 'tmpfs':
                    continue
                # A bind source can alias the target through mounts or symlinks;
                # lexical non-overlap is not an absence-of-users proof. No
                # arbitrary host path traversal to make that proof here.
                need(mount['Type'] != 'bind', 'volume-users-unknown')
                source = mount.get('Source')
                need(isinstance(source, str) and source.startswith('/') and '..' not in Path(source).parts,
                     'volume-users-unknown')
                if mount['Type'] == 'volume':
                    need(isinstance(mount.get('Name'), str) and mount['Name'], 'volume-users-unknown')
                    need(mount['Name'] != name, 'volume-in-use')
                    other = mount['Name']
                    need(len(other) <= 51 and other.startswith('p0-') and NAME.fullmatch(other[3:]), 'volume-users-unknown')
                    expected = GRAPHROOT / 'volumes' / other / '_data'
                    need(source == str(expected), 'volume-users-unknown')
                    if other not in checked_volumes:
                        need(len(checked_volumes) < 512, 'volume-users-unknown')
                        metadata = parse(self.call(['volume', 'inspect', other]))
                        need(isinstance(metadata, list) and len(metadata) == 1 and isinstance(metadata[0], dict)
                             and metadata[0].get('Name') == other and metadata[0].get('Driver') == 'local'
                             and metadata[0].get('Options') == {} and metadata[0].get('Mountpoint') == source,
                             'volume-users-unknown')
                        self.no_mounts(expected)  # Reject a local bind alias as well as bind options.
                        checked_volumes.add(other)
                need(not (Path(source) == path or Path(source) in path.parents or path in Path(source).parents),
                     'volume-in-use')

    def probe(self, fd, record, *, fresh, action='probe', before=None):
        request = {'action': action, 'fd': fd, 'identity': inode(fd), 'fresh': fresh,
                   'desired': record['definition']['custody'], 'before': before,
                   'resource': record['definition']['resource'], 'maps': record['maps'],
                   'protectedParent': dict(self.protected_parent)}
        return parse(self.call(['unshare', '/usr/bin/python3', '-I', '-c', INODE_PROGRAM],
                               input_bytes=encoded(request), pass_fds=(fd,)))


def native_identity(raw, record, path, *, fresh):
    need(isinstance(raw, dict), 'volume-native-missing')
    required = {'Name', 'Driver', 'Options', 'Labels', 'Mountpoint', 'CreatedAt', 'MountCount'}
    need(required <= set(raw) and raw['Name'] == record['definition']['nativeName'] and raw['Driver'] == 'local'
         and raw['Options'] == {} and raw['Labels'] == labels(record) and raw['Mountpoint'] == str(path),
         'volume-native-binding')
    stamp = raw['CreatedAt']
    need(isinstance(stamp, str) and len(stamp) <= 64
         and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)', stamp),
         'volume-created-at')
    try:
        datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except ValueError:
        raise VolumeError('volume-created-at') from None
    need(type(raw['MountCount']) is int and raw['MountCount'] >= 0 and (not fresh or raw['MountCount'] == 0),
         'volume-native-mounted')
    # UID/GID options/native null fields are not physical custody evidence.
    return {k: raw[k] for k in sorted(required - {'MountCount'})}


def probe_identity(observed, fd, adapter, *, fresh):
    need(isinstance(observed, dict) and set(observed) == {'stat', 'empty', 'uidMap', 'gidMap'}, 'volume-probe-schema')
    s = observed['stat']
    need(isinstance(s, dict) and set(s) == {'device', 'inode', 'uid', 'gid', 'mode'}
         and all(type(s[k]) is int and s[k] >= 0 for k in ('device', 'inode', 'uid', 'gid'))
         and {k: s[k] for k in ('device', 'inode')} == inode(fd)
         and isinstance(s['mode'], str) and re.fullmatch('[0-7]{4}', s['mode']), 'volume-probe-identity')
    need(observed['empty'] is True if fresh else observed['empty'] is None, 'volume-not-empty')
    host = host_stat(fd)
    need(mapping(observed['uidMap'], 0) == adapter.actor_uid and mapping(observed['gidMap'], 0) == adapter.actor_gid,
         'volume-idmap-actor')
    need(host['uid'] == mapping(observed['uidMap'], s['uid']) and host['gid'] == mapping(observed['gidMap'], s['gid'])
         and host['mode'] == s['mode'], 'volume-host-readback')
    return {k: s[k] for k in ('uid', 'gid', 'mode')}


def file_snapshot(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class Records:
    """One preprovisioned private directory, exclusive flock and exact byte/stat CAS."""
    def __init__(self, root):
        self.root, self.fd, self.previous = Path(root), None, None

    def __enter__(self):
        need(self.root.is_absolute(), 'volume-record-path')
        for path in (Path('/'), *reversed(self.root.parents[:-1]), self.root):
            s = path.lstat()
            need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid()) and not s.st_mode & 0o022,
                 'volume-record-ancestor')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            s = os.fstat(self.fd)
            need(s.st_uid == os.getuid() and s.st_gid == os.getgid()
                 and stat.S_IMODE(s.st_mode) == 0o700, 'volume-record-directory')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            entries = os.listdir(self.fd)
            need(len(entries) <= 512 and all(len(n) <= 56 and re.fullmatch(r'p0-[a-z][a-z0-9]*(?:-[a-z0-9]+)*\.json', n)
                                           for n in entries), 'volume-record-inventory')
            for name in entries:
                s = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_gid == os.getgid() and s.st_nlink == 1
                     and stat.S_IMODE(s.st_mode) == 0o600, 'volume-record-custody')
                existing = parse(self.read(name)[0])
                need(isinstance(existing, dict) and isinstance(existing.get('definition'), dict)
                     and {'resource', 'custody'} <= set(existing['definition']), 'volume-record-schema')
                declared = definition(existing['definition']['resource'], existing['definition']['custody'])
                validate_record(existing, declared)
                need(name == declared['nativeName'] + '.json', 'volume-record-name-collision')
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def check_directory(self):
        current = open_directory(self.root)
        try:
            s = os.fstat(current)
            need(inode(current) == inode(self.fd) and s.st_uid == os.getuid() and s.st_gid == os.getgid()
                 and stat.S_IMODE(s.st_mode) == 0o700, 'volume-record-directory-changed')
        finally:
            os.close(current)

    def read(self, name):
        self.check_directory()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            s = os.fstat(fd)
            need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_gid == os.getgid() and s.st_nlink == 1
                 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= LIMIT, 'volume-record-custody')
            raw = os.read(fd, LIMIT + 1)
            need(len(raw) == s.st_size and file_snapshot(os.fstat(fd)) == file_snapshot(s), 'volume-record-changed')
            return raw, file_snapshot(s)
        finally:
            os.close(fd)

    def load(self, name):
        self.name = name
        self.previous = self.read(name)
        return parse(self.previous[0]) if self.previous else None

    def save(self, record):
        need(self.read(self.name) == self.previous, 'volume-record-cas')
        if self.previous is None:
            need(len(os.listdir(self.fd)) < 512, 'volume-record-limit')
        value = {k: v for k, v in record.items() if k != 'integrity'}
        record['integrity'] = digest(value)
        raw = encoded(record)
        need(len(raw) <= LIMIT, 'volume-record-bound')
        temporary = '.publish'  # Exclusive directory lock; stale publication is retained, never overwritten.
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o600)  # New private publication inode only.
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
        need(self.read(self.name) == self.previous, 'volume-record-cas')
        os.replace(temporary, self.name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.previous = self.read(self.name)

    def __exit__(self, *args):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def validate_record(record, desired):
    need(isinstance(record, dict) and set(record) == {'version', 'definition', 'definitionSha256', 'nonce',
         'state', 'native', 'inode', 'maps', 'initial', 'integrity'}, 'volume-record-schema')
    need(record['integrity'] == digest({k: v for k, v in record.items() if k != 'integrity'})
         and type(record['version']) is int and record['version'] == 1 and encoded(record['definition']) == encoded(desired)
         and record['definitionSha256'] == digest(desired) and isinstance(record['nonce'], str)
         and re.fullmatch('[a-f0-9]{32}', record['nonce']) and record['state'] in STATES, 'volume-record-binding')
    if record['state'] == 'claimed':
        need(all(record[k] is None for k in ('native', 'inode', 'maps', 'initial')), 'volume-record-state')
    else:
        need(isinstance(record['native'], dict)
             and set(record['native']) == {'Name', 'Driver', 'Options', 'Labels', 'Mountpoint', 'CreatedAt'}
             and record['native']['Name'] == desired['nativeName'] and record['native']['Driver'] == 'local'
             and record['native']['Options'] == {} and record['native']['Labels'] == labels(record)
             and isinstance(record['native']['Mountpoint'], str) and record['native']['Mountpoint'].startswith('/')
             and isinstance(record['native']['CreatedAt'], str) and len(record['native']['CreatedAt']) <= 64
             and isinstance(record['inode'], dict)
             and set(record['inode']) == {'device', 'inode'}
             and all(type(x) is int and x > 0 for x in record['inode'].values())
             and isinstance(record['maps'], dict) and set(record['maps']) == {'uidMap', 'gidMap'}
             and isinstance(record['initial'], dict) and set(record['initial']) == {'uid', 'gid', 'mode'}
             and type(record['initial']['uid']) is int and type(record['initial']['gid']) is int
             and record['initial']['uid'] == record['initial']['gid'] == 0
             and record['initial']['mode'] in ('0700', '0755'), 'volume-record-state')
        for key, target in (('uidMap', 'uid'), ('gidMap', 'gid')):
            mapping(record['maps'][key], desired['custody'][target])


class VolumeCustody:
    def __init__(self, private_state_directory, adapter):
        need(os.geteuid() != 0, 'volume-rootless-only')
        self.state, self.adapter = Path(private_state_directory), adapter

    def ensure(self, resource, custody, *, resume=False, prepared_only=False):
        try:
            need(type(prepared_only) is bool, 'volume-prepared-only-flag')
            return self._ensure(resource, custody, resume=resume, prepared_only=prepared_only)
        except VolumeError:
            raise
        except Exception:
            raise VolumeError('volume-operation-indeterminate') from None

    def _ensure(self, resource, custody, *, resume=False, prepared_only=False):
        desired = definition(resource, custody)
        custody = desired['custody']  # Snapshot policy; caller mutation is never an effect input.
        need(type(resume) is bool, 'volume-resume-flag')
        adapter, path = self.adapter, self.adapter.mountpoint(resource)
        with Records(self.state) as records:
            record = records.load(desired['nativeName'] + '.json')
            if prepared_only:
                need(record is not None and record.get('state') == 'prepared', 'volume-preparation-required')
            if record is None:
                need(not resume, 'volume-resume-claim-missing')
                need(adapter.lookup(resource) is None, 'volume-foreign-native')
                need(not os.path.lexists(path.parent), 'volume-partial-path')
                adapter.no_mounts(path)
                adapter.no_users(resource)
                record = {'version': 1, 'definition': desired, 'definitionSha256': digest(desired),
                          'nonce': secrets.token_hex(16), 'state': 'claimed', 'native': None,
                          'inode': None, 'maps': None, 'initial': None}
                records.save(record)  # Durable exact name/definition/nonce BEFORE native create.
                adapter.create(record)  # Never retried by any existing-claim path.
            else:
                validate_record(record, desired)
                need(record['state'] == 'prepared' or resume, 'volume-explicit-resume-required')
            fresh = record['state'] != 'prepared'
            raw = adapter.lookup(resource)
            need(raw is not None, 'volume-claim-native-absent-indeterminate')
            native = native_identity(raw, record, path, fresh=fresh)
            if record['native'] is not None:
                need(native == record['native'], 'volume-native-changed')
            adapter.no_mounts(path)
            fd = open_directory(path)
            try:
                if record['inode'] is not None:
                    need(inode(fd) == record['inode'], 'volume-inode-changed')
                def guard():
                    current = native_identity(adapter.lookup(resource), record, path, fresh=fresh)
                    need(current == native, 'volume-native-changed')
                    check = open_directory(path)
                    try:
                        need(inode(check) == inode(fd), 'volume-inode-changed')
                    finally:
                        os.close(check)
                    adapter.no_mounts(path)
                    if fresh:
                        adapter.no_users(resource)
                def probe():
                    guard()
                    result = adapter.probe(fd, record, fresh=fresh)
                    actual = probe_identity(result, fd, adapter, fresh=fresh)
                    guard()
                    maps = {k: result[k] for k in ('uidMap', 'gidMap')}
                    mapping(maps['uidMap'], custody['uid'])
                    mapping(maps['gidMap'], custody['gid'])
                    if record['maps'] is not None:
                        need(maps == record['maps'], 'volume-idmap-changed')
                    return actual, maps
                actual, maps = probe()
                if record['state'] == 'claimed':
                    need(actual['uid'] == actual['gid'] == 0 and actual['mode'] in ('0700', '0755'),
                         'volume-initial-custody')
                    record.update(native=native, inode=inode(fd), maps=maps, initial=actual, state='bound')
                    records.save(record)
                if not fresh:
                    need(actual == custody, 'volume-prepared-custody-changed')
                    return self.report(record)
                # Only known direct fresh transitions; no mode/owner normalization of data.
                initial, restricted = record['initial'], {'uid': 0, 'gid': 0, 'mode': custody['mode']}
                phase = record['state']
                allowed = ([initial] if phase == 'bound' else [initial, restricted] if phase == 'chmod-claimed'
                           else [restricted] if phase == 'chmod-done' else [restricted, custody])
                need(actual in allowed, 'volume-transition-unknown')
                for action, target, claim, done in (('chmod', restricted, 'chmod-claimed', 'chmod-done'),
                                                     ('chown', custody, 'chown-claimed', 'prepared')):
                    if action == 'chmod' and record['state'] in ('chmod-done', 'chown-claimed'):
                        continue
                    if actual != target:
                        record['state'] = claim
                        records.save(record)
                        guard()
                        result = adapter.probe(fd, record, fresh=True, action=action, before=actual)
                        readback = probe_identity(result, fd, adapter, fresh=True)
                        need(readback == target, 'volume-effect-readback')
                        need({k: result[k] for k in ('uidMap', 'gidMap')} == record['maps'], 'volume-idmap-changed')
                        guard()
                        actual, _ = probe()  # Independent namespace + explicit Host readback.
                        need(actual == target, 'volume-effect-readback')
                    record['state'] = done
                    records.save(record)
                return self.report(record)
            finally:
                os.close(fd)

    @staticmethod
    def report(record):
        return {'schemaVersion': 1, 'resource': record['definition']['resource'], 'nativeName': record['definition']['nativeName'],
                'state': record['state'], 'definitionSha256': record['definitionSha256'], 'labels': labels(record),
                'installationCertified': False}
