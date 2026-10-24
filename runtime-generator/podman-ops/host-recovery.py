#!/usr/bin/env python3
"""Selected synthetic stack recovery primitive, NOT an admission endpoint.

Integration API: Backend(root, expected_intent_sha256, age_binary, lease=None).plan(),
backup(archive, recipient, operation_id, authorize), restore(archive, archive_sha256,
identity_file, operation_id, authorize), recover(expected_recovery_sha256,
authorize). authorize(request) MUST consume/revalidate the existing root-approved
one-use operation and return that exact request. No default approval is provided.
The caller must also hold its existing typed-operation lease. We take the native
.install.lock (nonblocking); never replace/update installation intent or receipt.

Only the CLI `plan` is exposed, deliberately no standalone mutation/admission
CLI. All operations re-read native input pins, storage authority/marker and native
quarantine evidence. All restored payloads are staged before any rename. Recovery
journals retain displaced originals, including on success. No service starts,
account changes, graph/cache traversal, original-data adoption or pruning.

This is a cold, same-release, same-machine synthetic recovery contract. It fails
closed on links, foreign mounts, special files, payload ACLs/xattrs and unsupported bind sources;
it is not a logical database export or a production recovery claim. Plaintext is
held in a bounded, sealed anonymous memfd during authenticated decryption only;
no plaintext archive is written to a filesystem pathname.
"""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import errno
import subprocess
import tarfile
import tempfile
import threading

OWNER = 0
MAX_ENTRIES = 20000
MAX_BYTES = 4 * 1024 ** 3
MAX_MANIFEST = 8 * 1024 ** 2
MAX_JOURNAL = 3 * MAX_MANIFEST + 65536
MAX_ARCHIVE = MAX_BYTES + MAX_MANIFEST + MAX_ENTRIES * 2048 + 10240
MIN_FREE_BYTES = 1024 ** 3
PROCESS_TIMEOUT = 90
# Authentication must complete before extraction; never spill plaintext to disk.
# Cover the existing four-GiB payload contract, including the one-GiB acceptance
# fixture. Admission and each chunk retain the physical host memory reserve.
MAX_AUTHENTICATED_BYTES = MAX_ARCHIVE
MIN_AUTHENTICATION_FREE_BYTES = 16 * 1024 ** 3
HOME_ROOT = Path('/home')
CHUNK = 1024 * 1024


def load(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('recovery_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


journal = load('install-journal')
storage = load('grant-rootless-volume-parent-traverse')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise ValueError('Duplicate recovery JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def absolute(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path) == '/':
        raise ValueError('Noncanonical recovery path')
    return path


def chain(path):
    path = absolute(path)
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode): raise ValueError('Linked recovery ancestry')
    return path


def controlled(path, private=False):
    chain(path)
    for parent in path.parents:
        ancestor = parent.lstat()
        if (not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid not in (0, OWNER)
                or (ancestor.st_mode & 0o022 and not ancestor.st_mode & stat.S_ISVTX)):
            raise ValueError('Uncontrolled recovery directory ancestry')
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError('Recovery directory must be root-controlled')
    return info


def open_at(parent, name):
    # O_PATH never opens a device/FIFO. Reopen ONLY the kernel-pinned regular
    # inode/directory, not the original pathname (which could race a writer).
    pin = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        info = os.fstat(pin)
        if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ValueError('Linked/special recovery entry')
        flags = os.O_RDONLY | os.O_CLOEXEC
        if stat.S_ISDIR(info.st_mode): flags |= os.O_DIRECTORY
        return os.open('/proc/self/fd/' + str(pin), flags)
    finally: os.close(pin)


def nofollow_fd(path):
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return open_at(fd, path.name)
    finally: os.close(fd)


def file_fd(path, private=False, limit=MAX_ARCHIVE):
    controlled(path.parent)
    fd = nofollow_fd(path)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != OWNER
                or info.st_mode & (0o077 if private else 0o022) or info.st_size > limit):
            raise ValueError('Unsafe recovery authority file')
        return fd
    except BaseException:
        os.close(fd); raise


def read_file(path, limit=MAX_MANIFEST, private=False):
    fd = file_fd(path, private=private, limit=limit)
    with os.fdopen(fd, 'rb') as stream: return stream.read(limit + 1)


def file_sha(path):
    fd = file_fd(path)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        digest = hashlib.sha256(); remaining = info.st_size
        while remaining:
            block = stream.read(min(CHUNK, remaining))
            if not block: raise ValueError('Authority truncated during hashing')
            remaining -= len(block); digest.update(block)
        if stream.read(1) or stable(os.fstat(stream.fileno())) != stable(info):
            raise ValueError('Authority changed during hashing')
        return digest.hexdigest()


def capacity(path, needed):
    """Never recover space by pruning anything; admission may require more reserve."""
    value = os.statvfs(path)
    if value.f_bavail * value.f_frsize < needed + MIN_FREE_BYTES:
        raise ValueError('Insufficient selected recovery staging reserve')


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic(path, value):
    controlled(path.parent, private=True)
    if path.exists() or path.is_symlink(): read_file(path, limit=MAX_JOURNAL, private=True)
    body = canonical(value)
    if len(body) > MAX_JOURNAL: raise ValueError('Oversized bounded recovery journal')
    fd, temporary = tempfile.mkstemp(prefix='.recovery-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); sync_dir(path.parent)
    finally: Path(temporary).unlink(missing_ok=True)


def rename(source, destination, source_fd=-100, destination_fd=-100):
    """Linux exact no-replace rename: never overwrite a concurrently created path."""
    function = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if function is None: raise ValueError('Atomic no-replace rename is required')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def mount_points():
    # Runtime read-only native mount evidence; isolated tests inject fixture sets.
    result = set()
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if len(fields) < 6: raise ValueError('Invalid mount authority evidence')
        value = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        result.add(Path(value))
    return result


def identity(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode): raise ValueError('Recovery payload root is not a directory')
    return {'dev': info.st_dev, 'ino': info.st_ino}


def relative(name):
    if (not isinstance(name, str) or not name or len(name.encode()) > 240
            or name.startswith('/') or str(PurePosixPath(name)) != name
            or any(p in ('', '.', '..') for p in name.split('/'))
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError('Unsafe recovery archive path')
    return name


def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class HashedStream:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, count):
        block = self.stream.read(count)
        self.digest.update(block)
        return block


class ArchiveReader:
    """Bounded USTAR reader. Do not let tarfile process unbounded PAX/GNU headers."""
    def __init__(self, stream):
        self.stream, self.remaining = stream, 0

    def next(self):
        if self.remaining: raise ValueError('Unread archive body')
        block = self.stream.read(512)
        if len(block) != 512: raise ValueError('Truncated recovery archive')
        if block == b'\0' * 512:
            # Reject appended/concatenated data rather than silently ignoring it.
            for tail in iter(lambda: self.stream.read(CHUNK), b''):
                if tail.strip(b'\0'): raise ValueError('Unlisted trailing archive data')
            return None
        item = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        if (item.type not in (tarfile.REGTYPE, tarfile.DIRTYPE) or item.linkname
                or item.size < 0 or item.size > MAX_BYTES):
            raise ValueError('Unsupported/link/oversized archive header')
        self.remaining = item.size
        return item

    def blocks(self, item):
        while self.remaining:
            block = self.stream.read(min(CHUNK, self.remaining))
            if not block: raise ValueError('Truncated recovery member')
            self.remaining -= len(block)
            yield block
        padding = (-item.size) % 512
        if self.stream.read(padding) != b'\0' * padding:
            raise ValueError('Invalid archive member padding')


def mount_id(fd):
    with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as stream:
        rows = [line.split()[1] for line in stream if line.startswith('mnt_id:')]
    if len(rows) != 1: raise ValueError('Missing kernel FD mount identity')
    return int(rows[0])


def private_marker_acl(fd):
    """Preserve exact Root0600 marker ACL; mask0 makes latent entries inert."""
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or set(os.listxattr(fd)) - {'system.posix_acl_access'}):
        raise ValueError('Private Root marker metadata differs')
    try: raw = os.getxattr(fd, 'system.posix_acl_access')
    except OSError as error:
        if error.errno != errno.ENODATA: raise
        return ''
    undefined = 0xffffffff
    entries = ((1, 6, undefined), (2, 7, 1000), (4, 7, undefined), (16, 0, undefined), (32, 0, undefined))
    expected = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
    if raw != expected:
        raise ValueError('Only exact native Root marker operator1000/mask0 ACL supported')
    return raw.hex()


def tree_entries(root, prefix, budget, owners=None, expected_names=None, private_marker=False):
    """No-follow fd walk, bounded bytes/count, no mounts, ACL/xattr loss or links."""
    chain(root)
    root_dev = root.lstat().st_dev
    mounted = mount_points()
    if any(p == root or p.is_relative_to(root) for p in mounted):
        raise ValueError('Mounted selected payload is not safely swappable')
    result = []

    def walk(parent, name, archive_name):
        relative(archive_name)
        if expected_names is not None and archive_name not in expected_names:
            raise ValueError('Unclaimed configuration name; content not opened')
        fd = open_at(parent, name)
        try:
            info = os.fstat(fd)
            directory = stat.S_ISDIR(info.st_mode)
            metadata = os.listxattr(fd)
            if private_marker and archive_name == prefix:
                private_marker_acl(fd)  # Reference only: never restored or ACL-cleared.
                metadata = []
            if (not (directory or stat.S_ISREG(info.st_mode)) or info.st_dev != root_dev
                    or (not directory and info.st_nlink != 1) or info.st_mode & 0o7000
                    or mount_id(fd) != parent_mount or metadata):
                raise ValueError('Linked/mounted/special or extended-metadata payload')
            if owners is not None:
                check_owner(info.st_uid, info.st_gid, owners)
            budget[0] += 1
            budget[1] += 0 if directory else info.st_size
            if budget[0] > MAX_ENTRIES or budget[1] > MAX_BYTES:
                raise ValueError('Recovery payload exceeds bounded policy')
            row = {'name': archive_name, 'kind': 'dir' if directory else 'file',
                   'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
                   'size': 0 if directory else info.st_size, 'mtimeNs': info.st_mtime_ns}
            if not directory:
                digest = hashlib.sha256(); remaining = info.st_size
                while remaining:
                    block = os.read(fd, min(CHUNK, remaining))
                    if not block: raise ValueError('Payload truncated during inventory')
                    remaining -= len(block); digest.update(block)
                if os.read(fd, 1) or stable(os.fstat(fd)) != stable(info):
                    raise ValueError('Payload changed during inventory')
                row['sha256'] = digest.hexdigest()
            result.append(row)
            if directory:
                names = []
                with os.scandir(fd) as children:
                    for child in children:
                        names.append(child.name)
                        if len(names) + budget[0] > MAX_ENTRIES:
                            raise ValueError('Oversized recovery directory')
                for child in sorted(names):
                    walk(fd, child, archive_name + '/' + child)
                if stable(os.fstat(fd)) != stable(info): raise ValueError('Directory changed during inventory')
        finally: os.close(fd)

    parent = nofollow_fd(root.parent)
    try:
        parent_mount = mount_id(parent)
        walk(parent, root.name, prefix)
    finally: os.close(parent)
    return result


def selected_roots(release, scope, binding, allow_missing=False, classified=False):
    """Mirror generator resolvedVolumeSource; never scan stateRoot or graphRoot."""
    ir = strict(read_file(release / 'stack.ir.json'))
    services, volumes = ir['services'], ir['volumes']
    finance = load('verify-agent-vm-bundle').native_finance_reference(ir)
    if 'keycloak' not in services or not ({'postgres', 'postgres-ssd'} & set(services)):
        raise ValueError('Selected identity database composition not supported')
    domains = {r['name']: r for r in binding['domains']}
    # Owning standalone profile rewrites these two absolute sources. They are
    # selected data, not permission to traverse arbitrary scope/state binds.
    known_binds = {}
    if 'caddy' in services:
        ca = absolute(volumes['caddy_ca']['hostPath'])
        metadata = strict(read_file(release / 'podman-domains.json'))
        logs = ca.parent / '_logs/caddy'
        if metadata.get('caddyLogRoot') != str(logs):
            raise ValueError('Selected ingress log binding changed')
        known_binds[str(logs)] = (logs, False)
        if volumes['caddy_ca'].get('rootlessAccess') != 'read-only':
            raise ValueError('Public trust volume reader policy is missing')
        known_binds[str(ca / 'caddy-ca.crt')] = (ca, True)
    # Exact source-declared leaf data only; never archive a whole actor state,
    # graph, home or authentication store. These two generated binds are data.
    state_data = {}
    metadata = strict(read_file(release / 'podman-domains.json'))
    declared = {row['name']: row for row in metadata.get('domains', [])}
    for domain in binding['domains']:
        leaves = ('forgejo-runner-ssh',) if domain['name'] == 'ci-runner' else (
            ('test-runner/results',) if domain['name'] == 'test-runners' else ())
        data_root = declared.get(domain['name'], {}).get('dataRoot')
        if domain['name'] == 'ci-runner' and data_root:
            data = absolute(data_root)
            if (data == Path(domain['stateRoot']) or not data.is_relative_to(domain['stateRoot'])
                    or any(part.startswith('.') for part in data.relative_to(domain['stateRoot']).parts)):
                raise ValueError('CI dataRoot must be an exact separate selected data leaf')
            state_data[str(data)] = domain['name']
        for leaf in leaves:
            state_data[str(Path(domain['stateRoot']) / leaf)] = domain['name']
    roots = set()
    classification = []
    database_roots = set()
    for service_name, service in services.items():
        if service.get('placement') not in ('rootful', 'rootless'):
            raise ValueError('Unknown recovery placement')
        for mount in service.get('volumes', []):
            source = mount.split(':')[0] if isinstance(mount, str) else mount['source']
            if source in volumes:
                volume = volumes[source]
                strategy = volume.get('rootlessStrategy', 'copy')
                if strategy not in ('copy', 'shared', 'forbidden') or (service['placement'] == 'rootless' and strategy == 'forbidden'):
                    raise ValueError('Unsupported selected volume strategy')
                if service['placement'] == 'rootless' and strategy != 'shared':
                    path = Path(domains[service['rootlessDomain']]['volumeRoot']) / source
                else:
                    path = absolute(volume['hostPath'])
                if not path.is_relative_to(scope) or path == scope:
                    raise ValueError('Foreign selected data root')
                if not re.fullmatch(r'[A-Za-z0-9_-]+', source):
                    raise ValueError('Noncanonical selected volume')
                if service['placement'] == 'rootless':
                    for domain in domains.values():
                        if path.is_relative_to(domain['volumeRoot']) and domain['name'] != service['rootlessDomain']:
                            raise ValueError('Cross-domain selected private volume')
                roots.add(path)
                classification.append(dict(service=service_name, source=source, kind='named-data', path=str(path)))
                if service_name in ('postgres', 'postgres-ssd'): database_roots.add(path)
            elif source in known_binds:
                path, must_read_only = known_binds[source]
                read_only = ('ro' in {flag for option in mount.split(':')[2:] for flag in option.split(',')}
                             if isinstance(mount, str) else mount.get('read_only') is True)
                if must_read_only and not read_only:
                    raise ValueError('Selected public trust bind is writable')
                roots.add(path)
                classification.append(dict(service=service_name, source=source, kind='bind-data', path=str(path)))
            elif source in state_data:
                if service.get('placement') != 'rootless' or service.get('rootlessDomain') != state_data[source]:
                    raise ValueError('Selected state data bind belongs to another actor')
                path = absolute(source); roots.add(path)
                classification.append(dict(service=service_name, source=source, kind='state-data', path=str(path)))
            elif finance is not None and source == finance['source'] and service_name == finance['service']:
                classification.append(dict(service=service_name, source=source, path=source, kind='root-control-reference'))
            elif source == '%t/podman/podman.sock' or (service.get('placement') == 'rootless'
                    and service.get('rootlessDomain') in domains
                    and source == '/run/user/' + str(domains[service['rootlessDomain']]['uid']) + '/podman/podman.sock'):
                if service.get('placement') != 'rootless' or service.get('rootlessDomain') not in domains:
                    raise ValueError('Podman transport requires an exact selected rootless actor')
                classification.append(dict(service=service_name, source=source, kind='transport-not-archived'))
            elif (source.startswith('./configs/') or source.startswith('./build/')
                  or source.startswith('./stack.')):
                # Runtime config is included below; immutable build is pinned by
                # the native source receipt, not a mutable application data root.
                if '..' in Path(source).parts: raise ValueError('Escaped selected configuration')
                classification.append(dict(service=service_name, source=source, kind='immutable-source-reference'))
            else:
                raise ValueError('Unclassified selected bind/anonymous/cache mount for ' + service_name + ': ' + str(source))
    named = {row['source'] for row in classification if row['kind'] == 'named-data'}
    unconsumed = {name for name, volume in volumes.items()
                  if name not in named and absolute(volume['hostPath']) not in roots}
    if unconsumed:
        raise ValueError('Declared named data has no selected ownership/consumer: ' + ','.join(sorted(unconsumed)))
    if not roots or not database_roots:
        raise ValueError('Identity database storage is missing')
    reserved = [Path(r[k]) for r in binding['domains'] for k in ('stateRoot', 'graphRoot')]
    for root in roots:
        if not root.is_relative_to(scope) or root == scope:
            raise ValueError('Foreign selected data root')
        for domain in domains.values():
            volume_root = Path(domain['volumeRoot'])
            if root == volume_root or volume_root.is_relative_to(root):
                raise ValueError('Whole private volume ancestry is not a data root')
        for foreign in reserved:
            exact_state_leaf = str(root) in state_data and foreign == Path(domains[state_data[str(root)]]['stateRoot'])
            if not exact_state_leaf and (root.is_relative_to(foreign) or foreign.is_relative_to(root)):
                raise ValueError('Data root overlaps private state/cache')
        if any(root != other and (root.is_relative_to(other) or other.is_relative_to(root)) for other in roots):
            raise ValueError('Overlapping selected data roots')
        if not allow_missing or root.exists() or root.is_symlink(): chain(root)
    result = [release / 'runtime'] + sorted(roots)
    return (result, classification) if classified else result


def check_owner(uid, gid, owners):
    def allowed(value, kind):
        return value in owners[kind] or any(start <= value < start + count for start, count in owners['ranges'])
    if not allowed(uid, 'uids') or not allowed(gid, 'gids'):
        raise ValueError('Foreign/cross-domain recovery payload owner')


def custody_record(fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode): raise ValueError('Custody requires a directory')
    def acl(name):
        try: return os.getxattr(fd, name).hex()
        except OSError as error:
            if error.errno != errno.ENODATA: raise
            return ''
    if set(os.listxattr(fd)) - {'system.posix_acl_access', 'system.posix_acl_default'}:
        raise ValueError('Unsupported custody metadata')
    return dict(dev=info.st_dev, ino=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode), mountId=mount_id(fd),
                acl=acl('system.posix_acl_access'), defaultAcl=acl('system.posix_acl_default'))


def custody_permissions(row, uid, gid, actors=(), operator=False):
    if (row['uid'] != uid or row['gid'] != gid or row['defaultAcl']
            or row['mode'] not in ((0o700, 0o2770) if operator else (0o700,))):
        raise ValueError('Exact declared custody owner/group/mode required')
    raw = bytes.fromhex(row['acl'])
    if not raw: return
    if not operator or len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack('<I', raw[:4])[0] != 2:
        raise ValueError('Invalid custody ACL')
    entries = {}
    for offset in range(4, len(raw), 8):
        tag, rights, who = struct.unpack('<HHI', raw[offset:offset + 8])
        if (tag, who) in entries or rights > 7: raise ValueError('Ambiguous custody ACL')
        entries[tag, who] = rights
        if tag == 2:
            if who not in actors or rights != 1: raise ValueError('Only exact actor traversal ACLs are allowed')
        elif tag not in (1, 4, 16, 32) or who != 0xffffffff:
            raise ValueError('Foreign custody ACL')
    basic = {tag: rights for (tag, _), rights in entries.items() if tag != 2}
    if basic != {1: 7, 4: 7 if row['mode'] == 0o2770 else 0,
                 16: (row['mode'] >> 3) & 7, 32: 0}:
        raise ValueError('Unexpected custody ACL permissions')


class Custody:
    """Receipt/CAS-bound FD custody, not a new admission or owner inference path.

    recoveryCustody is recorded by the existing root installer in BOTH terminal
    receipt and intent, BEFORE this backend is called. lease.verify_recovery(req)
    must return None or raise, and revalidate that existing serialized stopped
    lease, closed triggers, all own/mapped processes, exact subuid/subgid hashes
    and allocations, and exclusive operator/group writer custody for the duration.
    It MUST NOT start a manager to inspect it or accept user-supplied proof JSON.

    Proof keys: schemaVersion=1, operatorUid/operatorGid, allocationSha256={subuid,
    subgid}, actors=[{name,user,uid,gid,start,count}], directories={absolute path:
    custody_record(fd)}, configurationRoots=[{domain,path,entriesSha256}]. Include
    each actor's .config AND stateRoot/releases/<selected>/runtime with source-
    validated content hashes (content_rows below), not hashes inferred from an
    unclaimed host tree. directories is EXACTLY scope, all actor private roots,
    their scope-relative ancestors, selected data parents, config parents and
    runtime ancestors. No cache contents are inventoried or touched.
    """
    def __init__(self, lease, pins, proof, binding, roots):
        self.fds, self.extra, self.records = {}, {}, {}
        self.lease, self.pins, self.proof = lease, dict(pins), proof
        self.configuration_roots, self.configs, self.owners = [], {}, {}
        try:
            if not callable(getattr(lease, 'verify_recovery', None)):
                raise ValueError('Authenticated existing stopped recovery lease adapter required')
            base_keys = {'schemaVersion', 'operatorUid', 'operatorGid', 'allocationSha256',
                         'actors', 'directories', 'configurationRoots'}
            if (set(proof) not in (base_keys, base_keys | {'native'})
                    or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
                    or any(type(proof[k]) is not int or proof[k] <= 0 for k in ('operatorUid', 'operatorGid'))
                    or proof['operatorUid'] == OWNER
                    or set(proof['allocationSha256']) != {'subuid', 'subgid'}
                    or any(not re.fullmatch('[a-f0-9]{64}', v) for v in proof['allocationSha256'].values())):
                raise ValueError('Exact root-receipted recovery custody required')
            domains = {row['name']: row for row in binding['domains']}
            metadata = strict(read_file(Path(pins['release']) / 'podman-domains.json'))
            declared = {row['name']: row for row in metadata.get('domains', [])}
            actors = {}
            for row in proof['actors']:
                domain = domains.get(row['name'])
                if (set(row) != {'name', 'user', 'uid', 'gid', 'start', 'count'} or domain is None
                        or row['name'] in actors or any(row[k] != domain[k] for k in ('user', 'uid'))
                        or any(type(row[k]) is not int or row[k] <= 0 for k in ('uid', 'gid', 'start', 'count'))
                        or row['count'] != 65536 or row['start'] + row['count'] > 2**32 - 1):
                    raise ValueError('Exact selected actor allocation required')
                if row['name'] in declared and 'subuidStart' in declared[row['name']]:
                    if declared[row['name']]['subuidStart'] != row['start']:
                        raise ValueError('Actor range differs from pinned selected metadata')
                actors[row['name']] = row
            if set(actors) != set(domains): raise ValueError('Incomplete selected actor allocation')
            ordered = sorted(actors.values(), key=lambda a: a['start'])
            if (any(b['start'] < a['start'] + 65536 for a, b in zip(ordered, ordered[1:]))
                    or any(a['start'] <= uid < a['start'] + 65536 for a in ordered
                           for uid in [OWNER, proof['operatorUid'], proof['operatorGid'],
                                       *[d[k] for d in ordered for k in ('uid', 'gid')]])):
                raise ValueError('Overlapping selected subordinate ranges')
            scope = Path(pins['scope']); release = Path(pins['release'])
            paths, private = {scope}, {}
            def below(node):
                while node != scope:
                    if not node.is_relative_to(scope): raise ValueError('Custody escaped selected scope')
                    paths.add(node); node = node.parent
            for name, domain in domains.items():
                for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                    node = absolute(domain[key])
                    if any(node.is_relative_to(other) or other.is_relative_to(node) for other in private):
                        raise ValueError('Overlapping selected private roots')
                    private[node] = actors[name]; below(node)
            for root in roots:
                if root != release / 'runtime': below(root.parent)
                else:
                    controlled(root.parent); paths.add(root.parent)
            seen_configs = set()
            for config in proof['configurationRoots']:
                if (set(config) != {'domain', 'path', 'entriesSha256'} or config['domain'] not in domains
                        or not re.fullmatch('[a-f0-9]{64}', config['entriesSha256'])):
                    raise ValueError('Invalid source-pinned actor configuration')
                actor = actors[config['domain']]; domain = domains[config['domain']]
                node = absolute(config['path'])
                home = HOME_ROOT / actor['user']
                runtime = Path(domain['stateRoot']) / 'releases' / release.name / 'runtime'
                if node not in (home / '.config', runtime) or node in seen_configs:
                    raise ValueError('Foreign/duplicate actor configuration root')
                seen_configs.add(node)
                if node == runtime: below(node.parent)
                else:
                    controlled(home.parent); paths.add(home); private[home] = actor
                self.configuration_roots.append(node); self.configs[str(node)] = config['entriesSha256']
            finance = (proof.get('native') or {}).get('financeReference')
            if finance is not None:
                node = Path('/var/lib/webservices-native-finance')
                if (finance.get('kind') != 'root-native-finance-reference-observation' or finance.get('status') != 'completed'
                        or finance['reference']['descriptor']['source'] != str(node)):
                    raise ValueError('Unknown native finance control reference')
                controlled(node.parent)
                parent = node
                while parent != Path('/'):
                    paths.add(parent); parent = parent.parent
                self.configuration_roots.append(node)
                self.configs[str(node)] = proof['native']['financeEntriesSha256']
            expected_configs = {HOME_ROOT / a['user'] / '.config' for a in actors.values()} | {
                Path(d['stateRoot']) / 'releases' / release.name / 'runtime' for d in domains.values()}
            if seen_configs != expected_configs: raise ValueError('All selected actor config/runtime roots are required')
            if set(proof['directories']) != {str(p) for p in paths}:
                raise ValueError('Custody must cover exact selected ancestry, no extra/unclaimed roots')
            self.check_lease()
            controlled(scope.parent)
            for node in sorted(paths, key=lambda p: (len(p.parts), str(p))):
                fd = nofollow_fd(node); self.fds[node] = fd
                row = custody_record(fd)
                if row != proof['directories'][str(node)]: raise ValueError('Custody inode/mount/ACL changed')
                actor = private.get(node)
                containing = next((a for p, a in private.items() if node.is_relative_to(p)), None)
                if proof.get('native') is not None:
                    # Reuse the exact canonical source custody policy, including
                    # reviewed operator defaults and mapped-root traversal. No
                    # legacy relaxation or inferred ownership is introduced.
                    self.lease.directory_custody(node, row, actor, containing)
                elif node == release:
                    controlled(node)
                elif actor or containing:
                    a = actor or containing
                    # Selected immutable projection parents may be root sealed.
                    custody_permissions(row, OWNER if row['uid'] == OWNER and not actor else a['uid'],
                                        row['gid'] if row['uid'] == OWNER and not actor else a['gid'])
                elif row['uid'] == OWNER and node != scope:
                    custody_permissions(row, OWNER, row['gid'])
                else:
                    custody_permissions(row, proof['operatorUid'], proof['operatorGid'],
                                        {a['uid'] for a in actors.values()}, operator=True)
                if node.is_relative_to(scope) and row['mountId'] != proof['directories'][str(scope)]['mountId']:
                    raise ValueError('Foreign mounted custody ancestry')
                self.records[node] = row
            ir = strict(read_file(release / 'stack.ir.json'))
            for root in roots + self.configuration_roots:
                owners = {'uids': [OWNER], 'gids': [OWNER], 'ranges': []}
                selected = []
                for name, domain in domains.items():
                    if (root.is_relative_to(domain['volumeRoot']) or root.is_relative_to(domain['stateRoot']) or root in (
                            HOME_ROOT / actors[name]['user'] / '.config',
                            Path(domain['stateRoot']) / 'releases' / release.name / 'runtime')):
                        selected.append(actors[name])
                for service in ir['services'].values():
                    if service.get('placement') != 'rootless': continue
                    for mount in service.get('volumes', []):
                        source = mount.split(':')[0] if isinstance(mount, str) else mount['source']
                        volume = ir['volumes'].get(source)
                        if volume and volume.get('rootlessStrategy') == 'shared' and Path(volume['hostPath']) == root:
                            access = volume.get('rootlessAccess', 'read-write')
                            if access not in ('read-only', 'read-write'):
                                raise ValueError('Unknown selected shared volume access')
                            # A read-only consumer is not a producer/owner claim.
                            if access == 'read-write': selected.append(actors[service['rootlessDomain']])
                for a in selected:
                    owners['uids'].append(a['uid']); owners['gids'].append(a['gid'])
                    owners['ranges'].append([a['start'], 65536])
                self.owners[str(root)] = owners
            self.configuration_roots.sort()
            self.verify()
        except BaseException:
            self.close(); raise

    def check_lease(self):
        request = dict(self.pins, allocationSha256=self.proof['allocationSha256'],
                       actors=self.proof['actors'], quiesced=True, exclusiveWriters=True, restart=False)
        if self.lease.verify_recovery(strict(canonical(request))) is not None:
            raise ValueError('Existing lease verifier must return None or raise, never an approval boolean')

    def verify(self, pins=None):
        if pins is not None and pins != self.pins: raise ValueError('Recovery selection custody changed')
        self.check_lease()
        for node, record in self.records.items():
            fd = nofollow_fd(node)
            try:
                if custody_record(fd) != record or custody_record(self.fds[node]) != record:
                    raise ValueError('Pinned selected ancestry moved or changed')
            finally: os.close(fd)
        for node, fd in self.extra.items():
            current = nofollow_fd(node)
            try:
                if custody_record(current) != custody_record(fd): raise ValueError('Staging custody changed')
            finally: os.close(current)

    def configuration(self, path, rows):
        if str(path) in self.configs and sha(canonical(content_rows(rows))) != self.configs[str(path)]:
            raise ValueError('Actor configuration differs from receipted source hashes')

    def pin_area(self, area):
        self.verify()
        fd = nofollow_fd(area)
        custody_permissions(custody_record(fd), OWNER, os.fstat(fd).st_gid)
        self.extra[area] = fd

    def rename(self, source, destination):
        self.verify()
        parents = self.fds | self.extra
        if source.parent not in parents or destination.parent not in parents:
            raise ValueError('Rename outside exact FD-pinned selected custody')
        rename(source.name, destination.name, parents[source.parent], parents[destination.parent])
        os.fsync(parents[source.parent]); os.fsync(parents[destination.parent])
        self.verify()

    def close(self):
        for fd in (*self.fds.values(), *self.extra.values()): os.close(fd)
        self.fds.clear(); self.extra.clear()


def content_rows(rows):
    """Source content pin excludes device/inode/time and archive payload index."""
    return [{k: (v.split('/', 2)[2] if k == 'name' and v.count('/') >= 2 else '.' if k == 'name' else v)
             for k, v in row.items() if k != 'mtimeNs'} for row in rows]


class Backend:
    def __init__(self, root, expected_intent_sha256, age_binary=Path('/usr/bin/age'), lease=None):
        self.root = absolute(root)
        self.expected = expected_intent_sha256
        self.age = absolute(age_binary)
        self.state = self.root / '.host-recovery'
        self.intent = self.state / 'intent.json'
        self.lease, self.custody = lease, None
        self.owners = {}
        self.references = []

    @contextlib.contextmanager
    def locked(self):
        if os.geteuid() != 0: raise ValueError('Root recovery authority required')
        controlled(self.root, private=True)
        # Native public controller retains the ACTUAL canonical flock OFD at
        # FD9. Never open/flock a second description (which would deadlock).
        native_lock = getattr(self.lease, 'native_lock', None)
        if native_lock is not None:
            try:
                with native_lock(self):
                    yield
            finally:
                if self.custody is not None:
                    self.custody.close(); self.custody = None
            return
        fd = os.open(self.root / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Unsafe native installation lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            if self.custody is not None:
                self.custody.close(); self.custody = None
            os.close(fd)

    def selection(self, allow_missing=False):
        if not re.fullmatch('[a-f0-9]{64}', self.expected): raise ValueError('Exact native CAS required')
        path = self.root / '.install-intent.json'
        read_file(path, private=True)
        value = journal.read(path)
        if not value or file_sha(path) != self.expected or value['phase'] not in ('active', 'retired-failed'):
            raise ValueError('Native installation intent changed or is not terminal')
        release = absolute(value['release'])
        if release.parent != self.root / 'releases': raise ValueError('Foreign selected release')
        controlled(release)
        # Only this pre-existing native metadata pointer is allowed to be a
        # symlink. Never follow it to open an archive or any payload.
        pointer = self.root / 'current'
        info = pointer.lstat()
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != OWNER or info.st_nlink != 1
                or os.readlink(pointer) not in (str(release), 'releases/' + release.name)):
            raise ValueError('Native selected release pointer changed')
        receipt = release / 'installation-receipt.json'
        read_file(receipt, private=True)
        if journal.read(receipt) != value: raise ValueError('Selected receipt mismatch')
        if set(value['inputs']) != set(journal.CORE_INPUTS + journal.PINNED_INPUTS):
            raise ValueError('Expanded canonical input pins required for recovery')
        for name, expected in value['inputs'].items():
            path = release / name
            if expected is None:
                if path.exists() or path.is_symlink(): raise ValueError('Absent input appeared')
            elif file_sha(path) != expected: raise ValueError('Canonical input hash changed')
        if journal.fingerprint(release) != value['inputs']:
            raise ValueError('Native input fingerprint changed')
        scope, operator, binding = storage.authority(release)
        manifest = strict(read_file(release / 'site/manifest.json'))
        if Path(manifest.get('installerStateRoot', '/var/lib/webservices')) != self.root:
            raise ValueError('Native metadata root differs from pinned site authority')
        storage.marker(scope, binding)
        if binding['scope']['dataClass'] != 'synthetic': raise ValueError('Only selected synthetic data is supported')
        marker = scope / storage.MARKER
        # Marker is root0600 even when its declared parent is operator2770.
        marker_fd = nofollow_fd(marker)
        try:
            info = os.fstat(marker_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
                raise ValueError('Unsafe exact scope marker')
            marker_body = os.read(marker_fd, 65537)
            if stable(os.fstat(marker_fd)) != stable(info): raise ValueError('Scope marker changed while reading')
            if strict(marker_body) != binding: raise ValueError('Exact scope marker mismatch')
        finally: os.close(marker_fd)
        roots, classified = selected_roots(release, scope, binding, allow_missing=allow_missing, classified=True)
        control_references = [row for row in classified if row['kind'] == 'root-control-reference']
        pins = {'nativeIntentSha256': self.expected, 'release': str(release),
                'receiptSha256': file_sha(receipt), 'scopeMarkerSha256': sha(marker_body),
                'scope': str(scope), 'inputs': value['inputs'], 'roots': [str(p) for p in roots]}
        proof = value.get('recoveryCustody')
        if proof is not None:
            pins['custodySha256'] = sha(canonical(proof))
            native = proof.get('native')
            original_roots = list(roots)
            if native is not None:
                if not callable(getattr(self.lease, 'native_lock', None)):
                    raise ValueError('Native custody requires its typed in-process operation lease')
                self.references = [release / 'runtime'] + [absolute(c['path']) for c in proof['configurationRoots']]
                if control_references:
                    observed = native.get('financeReference')
                    if (not isinstance(observed, dict) or observed.get('kind') != 'root-native-finance-reference-observation'
                            or observed.get('status') != 'completed' or len(control_references) != 1
                            or observed['reference']['descriptor']['source'] != control_references[0]['path']):
                        raise ValueError('Actual Root-issued finance reference observation required')
                    self.references.append(absolute(control_references[0]['path']))
                roots = roots[1:]
                pins['roots'] = [str(p) for p in roots]
                pins['referenceRoots'] = [str(p) for p in self.references]
            if self.custody is None:
                self.custody = Custody(self.lease, pins, proof, binding, original_roots)
            else:
                self.custody.verify(pins)
            if native is None:
                roots = roots + self.custody.configuration_roots
                pins['roots'] = [str(p) for p in roots]
            self.owners = self.custody.owners
        else:
            controlled(scope)
            for root in roots: controlled(root.parent)
            self.owners = {str(root): {'uids': [OWNER], 'gids': [OWNER], 'ranges': []} for root in roots}
        if control_references and (self.custody is None or self.custody.proof.get('native') is None):
            raise ValueError('Native finance reference cannot use historical recovery admission')
        journal.verify_quarantined(release)
        return pins, roots

    def inventory(self):
        pins, roots = self.selection()
        release = Path(pins['release'])
        files = [(release / name, 'inputs/' + name) for name, digest in sorted(pins['inputs'].items()) if digest is not None]
        files += [(release / 'installation-receipt.json', 'inputs/installation-receipt.json'),
                  (self.root / '.install-intent.json', 'inputs/install-intent.json'),
                  (Path(pins['scope']) / storage.MARKER, 'inputs/storage-marker.json')]
        entries, sources, budget = [], {}, [0, 0]
        for path, name in files:
            marker_reference = self.custody is not None and self.custody.proof.get('native') is not None and path == Path(pins['scope']) / storage.MARKER
            rows = tree_entries(path, name, budget, private_marker=marker_reference)
            if len(rows) != 1 or rows[0]['kind'] != 'file': raise ValueError('Input is not a file')
            entries.extend(rows); sources[name] = path
        for index, path in enumerate(self.references):
            prefix = 'reference/' + str(index)
            names = self.custody.proof['native'].get('configurationNamespaces', {}).get(str(path))
            allowed = None if names is None else {prefix if name == '.' else prefix + '/' + name for name in names}
            rows = tree_entries(path, prefix, budget, self.owners[str(path)], allowed)
            self.custody.configuration(path, rows)
            entries.extend(rows)
            for row in rows:
                sources[row['name']] = path.joinpath(*PurePosixPath(row['name']).parts[2:])
        for index, path in enumerate(roots):
            prefix = 'payload/' + str(index)
            rows = tree_entries(path, prefix, budget, self.owners[str(path)])
            if self.custody is not None:
                self.custody.configuration(path, rows)
            if rows[0]['kind'] != 'dir': raise ValueError('Missing selected payload directory')
            entries.extend(rows)
            for row in rows:
                sources[row['name']] = path.joinpath(*PurePosixPath(row['name']).parts[2:])
        manifest = {'schemaVersion': 1, 'kind': 'selected-synthetic-cold-recovery',
                    'selection': pins, 'entries': entries}
        if len(canonical(manifest)) > MAX_MANIFEST: raise ValueError('Oversized recovery manifest')
        if self.custody is not None: self.custody.verify()
        return manifest, sources

    def plan(self):
        with self.locked():
            manifest, _ = self.inventory()
            return {'selection': manifest['selection'], 'inventorySha256': sha(canonical(manifest)),
                    'entries': len(manifest['entries']), 'bytes': sum(r['size'] for r in manifest['entries']),
                    'authenticatedArchiveBytes': self.archive_bytes(manifest),
                    'maxAuthenticatedArchiveBytes': min(MAX_ARCHIVE, MAX_AUTHENTICATED_BYTES),
                    'backupWithinMemoryBound': self.archive_bytes(manifest) <= min(MAX_ARCHIVE, MAX_AUTHENTICATED_BYTES),
                    'installedAcceptance': False, 'restart': False}

    def prepare_state(self):
        if not self.state.exists(): self.state.mkdir(mode=0o700)
        controlled(self.state, private=True)
        if self.intent.exists() or self.intent.is_symlink():
            prior = strict(read_file(self.intent, limit=MAX_JOURNAL, private=True))
            if prior.get('phase') not in ('committed', 'originals-restored', 'staging-failed'):
                raise ValueError('Pending recovery requires exact recovery CAS, not replay')

    def request(self, kind, operation, manifest, archive_sha256):
        if not isinstance(operation, str) or not re.fullmatch('[a-f0-9]{32}', operation):
            raise ValueError('Exact recovery operation ID required')
        return {'schemaVersion': 1, 'kind': kind, 'operationId': operation,
                'selection': manifest['selection'], 'inventorySha256': sha(canonical(manifest)),
                'archiveSha256': archive_sha256, 'ageBinarySha256': self.trusted_age_hash(),
                'quiesced': True, 'restart': False}

    def trusted_age_hash(self):
        self.age_expected = file_sha(self.age)
        return self.age_expected

    @staticmethod
    def admit(authorize, request):
        # This callback is internal trusted controller code, NEVER serialized or
        # accepted from lane/user JSON. No CLI identity/boolean bypass exists.
        if not callable(authorize) or authorize(strict(canonical(request))) != request:
            raise ValueError('Exact consumed root recovery approval required')

    def subprocess(self, arguments, source=None, output=None, consume=None, pass_fds=()):
        controlled(self.age.parent)
        executable = file_fd(self.age)
        try:
            info = os.fstat(executable)
            with os.fdopen(os.dup(executable), 'rb') as stream:
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(CHUNK), b''): digest.update(block)
            if (not info.st_mode & stat.S_IXUSR or digest.hexdigest() != self.age_expected
                    or stable(os.fstat(executable)) != stable(info)):
                raise ValueError('Approved age executable/hash changed')
            process = subprocess.Popen(['/proc/self/fd/' + str(executable), *arguments],
                                       stdin=source if source is not None else subprocess.PIPE,
                                       stdout=output if output is not None else subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, pass_fds=(*pass_fds, executable), cwd='/',
                                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        finally: os.close(executable)
        timer = threading.Timer(PROCESS_TIMEOUT, process.kill)
        timer.start()
        try:
            if consume: consume(process)
            if process.wait(timeout=PROCESS_TIMEOUT): raise ValueError('Age authentication/encryption refused')
        except BaseException:
            process.kill(); process.wait(timeout=5); raise
        finally:
            timer.cancel()
            # Closing a killed producer pipe must not hide the original refusal.
            if process.stdin:
                with contextlib.suppress(OSError): process.stdin.close()
            if process.stdout:
                with contextlib.suppress(OSError): process.stdout.close()

    @staticmethod
    def archive_bytes(manifest):
        padded = lambda size: ((size + 511) // 512) * 512
        total = 512 + padded(len(canonical(manifest))) + sum(512 + padded(row['size']) for row in manifest['entries']) + 1024
        return ((total + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE

    def backup(self, archive, recipient, operation_id, authorize):
        archive = absolute(archive)
        if not isinstance(recipient, str) or not re.fullmatch('age1[023456789acdefghjklmnpqrstuvwxyz]{58}', recipient):
            raise ValueError('One explicit age recipient is required; retain identity separately')
        with self.locked():
            self.prepare_state()
            manifest, sources = self.inventory()
            if self.archive_bytes(manifest) > min(MAX_ARCHIVE, MAX_AUTHENTICATED_BYTES):
                raise ValueError('Backup would exceed supported authenticated-memory restore bound')
            self.external(archive, manifest['selection'])
            if archive.exists() or archive.is_symlink(): raise ValueError('Backup must not overwrite')
            request = self.request('backup', operation_id, manifest, None)
            # Destination and recipient are part of consumed approval too.
            request.update(archive=str(archive), recipient=recipient)
            self.admit(authorize, request)
            if self.custody is not None: self.custody.verify()
            capacity(archive.parent, sum(row['size'] for row in manifest['entries'])
                     + len(canonical(manifest)) + len(manifest['entries']) * 2048 + 10240)
            fd, temporary = tempfile.mkstemp(prefix='.encrypted-recovery-', dir=archive.parent)
            try:
                with os.fdopen(fd, 'wb') as output:
                    def produce(process):
                        with tarfile.open(fileobj=process.stdin, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                            body = canonical(manifest)
                            item = tarfile.TarInfo('manifest.json'); item.size = len(body); item.mode = 0o600
                            tar.addfile(item, io.BytesIO(body))
                            for row in manifest['entries']:
                                item = tarfile.TarInfo(row['name'])
                                item.mode, item.uid, item.gid = row['mode'], row['uid'], row['gid']
                                item.mtime = row['mtimeNs'] // 10**9
                                item.type = tarfile.DIRTYPE if row['kind'] == 'dir' else tarfile.REGTYPE
                                item.size = row['size']
                                if row['kind'] == 'dir': tar.addfile(item)
                                else:
                                    source_fd = nofollow_fd(sources[row['name']])
                                    with os.fdopen(source_fd, 'rb') as stream:
                                        info = os.fstat(stream.fileno())
                                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                                or (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns)
                                                != (row['mode'], row['uid'], row['gid'], row['size'], row['mtimeNs'])):
                                            raise ValueError('Backup stream metadata changed')
                                        hashed = HashedStream(stream); tar.addfile(item, hashed)
                                        if (hashed.digest.hexdigest() != row['sha256']
                                                or stable(os.fstat(stream.fileno())) != stable(info)):
                                            raise ValueError('Backup stream bytes changed')
                        process.stdin.close(); process.stdin = None
                    self.subprocess(['--encrypt', '--recipient', recipient], output=output, consume=produce)
                    output.flush(); os.fsync(output.fileno())
                again, _ = self.inventory()
                if again != manifest: raise ValueError('Selected stopped snapshot changed during encryption')
                # No replace and no hard-link publication. Parent is private,
                # root controlled and serialized by existing admission/lock.
                if archive.exists() or archive.is_symlink(): raise ValueError('Backup destination appeared')
                rename(temporary, archive); sync_dir(archive.parent)
                return {'archiveSha256': file_sha(archive), 'inventorySha256': sha(canonical(manifest)),
                        'encrypted': True, 'installedAcceptance': False, 'restart': False}
            finally: Path(temporary).unlink(missing_ok=True)

    def external(self, path, pins):
        controlled(path.parent, private=True)
        scope = Path(pins['scope'])
        if path.is_relative_to(scope) or path.is_relative_to(self.root):
            raise ValueError('Keys/archives must be outside selected data and native metadata')

    @staticmethod
    def authentication_capacity(remaining):
        if not isinstance(remaining, int) or remaining < 0:
            raise ValueError('Invalid authenticated-memory capacity request')
        rows = [line.split()[1:] for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:')]
        if (len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != 'kB'
                or not rows[0][0].isdigit()
                or int(rows[0][0]) * 1024 < MIN_AUTHENTICATION_FREE_BYTES + remaining):
            raise ValueError('Authenticated recovery would cross physical memory reserve')

    def decrypt(self, archive, key, destination):
        # Ciphertext is uncompressed age output; its length conservatively
        # budgets plaintext before any allocation. The independent plaintext
        # ceiling and live per-chunk reserve still apply to a hostile producer.
        self.authentication_capacity(min(archive.stat().st_size, MAX_ARCHIVE, MAX_AUTHENTICATED_BYTES))
        with contextlib.ExitStack() as cleanup:
            encrypted = cleanup.enter_context(os.fdopen(file_fd(archive, private=True), 'rb'))
            identity_fd = file_fd(key, private=True, limit=65536)
            cleanup.callback(os.close, identity_fd)
            output = destination
            def consume(process):
                total = 0
                for block in iter(lambda: process.stdout.read(CHUNK), b''):
                    total += len(block)
                    if total > min(MAX_ARCHIVE, MAX_AUTHENTICATED_BYTES):
                        raise ValueError('Decrypted archive exceeds bounded anonymous-memory policy')
                    self.authentication_capacity(len(block))
                    output.write(block)
            self.subprocess(['--decrypt', '--identity', '/proc/self/fd/' + str(identity_fd)],
                            source=encrypted, consume=consume, pass_fds=(identity_fd,))
            output.flush(); output.seek(0)
            # Freeze the anonymous archive after successful age authentication.
            fcntl.fcntl(output.fileno(), fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)

    def stage(self, plaintext, current, transaction, operation):
        """Manual extraction: exact names/types/sizes/hashes, never extractall."""
        with contextlib.nullcontext(plaintext) as archive_stream:
            archive_stream.seek(0)
            tar = ArchiveReader(archive_stream)
            first = tar.next()
            if (first is None or first.name != 'manifest.json' or not first.isreg()
                    or first.size > MAX_MANIFEST or first.pax_headers or first.linkname):
                raise ValueError('Missing bounded authenticated recovery manifest')
            manifest = strict(b''.join(tar.blocks(first)))
            if (set(manifest) != {'schemaVersion', 'kind', 'selection', 'entries'}
                    or manifest['schemaVersion'] != 1 or manifest['kind'] != current['kind']
                    or manifest['selection'] != current['selection']):
                raise ValueError('Foreign recovery selection/receipt/input binding')
            entries = manifest['entries']
            if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
                raise ValueError('Oversized archive entry set')
            seen, byte_count, input_rows, stages = set(), 0, {}, []
            roots = current['selection']['roots']
            for index, root in enumerate(roots):
                root = Path(root)
                staging = root.parent / ('.p0-recovery-' + operation + '-' + str(index))
                if staging.exists() or staging.is_symlink(): raise ValueError('Recovery staging already exists')
                capacity(root.parent, 0)
                if self.custody is not None:
                    self.custody.verify()
                    parent_fd = self.custody.fds[root.parent]
                    os.mkdir(staging.name, mode=0o700, dir_fd=parent_fd)
                    # Our exclusively-created ROOT-owned empty directory may
                    # inherit setgid/operator defaults. Normalize ONLY that
                    # held new inode, never the data parent or existing tree.
                    fresh = os.open(staging.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    try:
                        created = os.fstat(fresh)
                        if created.st_uid != OWNER or os.listdir(fresh):
                            raise ValueError('Fresh recovery stage substituted/nonempty; preserve')
                        os.fchown(fresh, OWNER, OWNER)
                        for name in ('system.posix_acl_access', 'system.posix_acl_default'):
                            try: os.removexattr(fresh, name)
                            except OSError as error:
                                if error.errno != errno.ENODATA: raise
                        os.fchmod(fresh, 0o700); os.fsync(fresh)
                        named = os.stat(staging.name, dir_fd=parent_fd, follow_symlinks=False)
                        if (named.st_dev, named.st_ino) != (created.st_dev, created.st_ino):
                            raise ValueError('Fresh recovery stage name changed; preserve')
                    finally: os.close(fresh)
                    self.custody.pin_area(staging)
                else:
                    staging.mkdir(mode=0o700); controlled(staging, private=True)
                sync_dir(staging.parent)
                stages.append({'root': str(root), 'area': str(staging), 'oldIdentity': identity(root),
                               'originalEntries': [r for r in current['entries'] if r['name'] == 'payload/' + str(index)
                                                   or r['name'].startswith('payload/' + str(index) + '/')]})
            for row in entries:
                if not isinstance(row, dict): raise ValueError('Invalid archive manifest row')
                name = relative(row.get('name'))
                kind = row.get('kind')
                required = {'name', 'kind', 'mode', 'uid', 'gid', 'size', 'mtimeNs'} | ({'sha256'} if kind == 'file' else set())
                if (set(row) != required or kind not in ('file', 'dir') or name in seen
                        or any(type(row[k]) is not int or row[k] < 0 for k in ('mode', 'uid', 'gid', 'size', 'mtimeNs'))
                        or row['mode'] > 0o777 or row['uid'] > 2**32-2 or row['gid'] > 2**32-2
                        or (kind == 'dir' and row['size'] != 0)
                        or (kind == 'file' and not re.fullmatch('[a-f0-9]{64}', row['sha256']))):
                    raise ValueError('Unsafe archive manifest metadata')
                seen.add(name); byte_count += row['size']
                if byte_count > MAX_BYTES: raise ValueError('Archive data exceeds bounded policy')
                item = tar.next()
                if (item is None or item.name.rstrip('/') != name or item.pax_headers or item.linkname
                        or item.type != (tarfile.DIRTYPE if kind == 'dir' else tarfile.REGTYPE)
                        or (item.mode, item.uid, item.gid, item.size, item.mtime)
                        != (row['mode'], row['uid'], row['gid'], row['size'], row['mtimeNs'] // 10**9)):
                    raise ValueError('Archive entry differs from exact manifest or is a link')
                parts = PurePosixPath(name).parts
                if parts[0] in ('inputs', 'reference'):
                    if parts[0] == 'inputs' and kind != 'file': raise ValueError('Unexpected input directory')
                    digest = hashlib.sha256()
                    for block in tar.blocks(item): digest.update(block)
                    if kind == 'file' and digest.hexdigest() != row['sha256']: raise ValueError('Archive input/reference hash mismatch')
                    input_rows[name] = row
                    continue
                if (len(parts) < 2 or parts[0] != 'payload' or not parts[1].isdigit()
                        or str(int(parts[1])) != parts[1] or int(parts[1]) >= len(roots)):
                    raise ValueError('Foreign archive root')
                index = int(parts[1])
                owner_root = roots[index]
                check_owner(row['uid'], row['gid'], self.owners[owner_root])
                target = self.stage_path(Path(stages[index]['area'])) / 'new'
                target = target.joinpath(*parts[2:])
                if len(parts) > 2 and '/'.join(parts[:-1]) not in seen:
                    raise ValueError('Archive parent missing/out of order')
                if kind == 'dir':
                    target.mkdir(mode=0o700)
                    list(tar.blocks(item))
                else:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as output:
                        digest = hashlib.sha256()
                        for block in tar.blocks(item):
                            capacity(target.parent, len(block))
                            digest.update(block); output.write(block)
                        if digest.hexdigest() != row['sha256']: raise ValueError('Archive payload hash mismatch')
                        output.flush(); os.fsync(output.fileno())
            if tar.next() is not None: raise ValueError('Unlisted archive member')
            if input_rows != {r['name']: r for r in current['entries'] if r['name'].startswith(('inputs/', 'reference/'))}:
                raise ValueError('Archived canonical inputs are not exactly the selected pins')
            # Apply metadata after children are complete, then prove staged bytes.
            for row in reversed(entries):
                parts = PurePosixPath(row['name']).parts
                if parts[0] != 'payload': continue
                target = (self.stage_path(Path(stages[int(parts[1])]['area'])) / 'new').joinpath(*parts[2:])
                os.chown(target, row['uid'], row['gid'], follow_symlinks=False)
                os.chmod(target, row['mode'], follow_symlinks=False)
                os.utime(target, ns=(row['mtimeNs'], row['mtimeNs']), follow_symlinks=False)
                fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try: os.fsync(fd)
                finally: os.close(fd)
            for index, stage in enumerate(stages):
                path = Path(stage['area']) / 'new'
                actual = tree_entries(path, 'payload/' + str(index), [0, 0], self.owners[roots[index]])
                expected = [r for r in entries if r['name'] == 'payload/' + str(index)
                            or r['name'].startswith('payload/' + str(index) + '/')]
                if actual != expected: raise ValueError('Staged payload set/hash differs')
                self.configuration_root_check(Path(roots[index]), actual)
                stage['newIdentity'] = identity(path); stage['newEntries'] = actual
            return manifest, stages

    def configuration_root_check(self, path, rows):
        if self.custody is not None: self.custody.configuration(path, rows)

    def stage_path(self, area):
        if self.custody is None: return area
        self.custody.verify()
        return Path('/proc/self/fd') / str(self.custody.extra[area])

    def swap(self, source, destination):
        if self.custody is None: rename(source, destination)
        else: self.custody.rename(source, destination)

    def record(self, value, transaction):
        atomic(transaction / 'receipt.json', value)
        atomic(self.intent, value)

    def restore(self, archive, archive_sha256, identity_file, operation_id, authorize):
        archive, key = absolute(archive), absolute(identity_file)
        with self.locked():
            self.prepare_state()
            current, _ = self.inventory()
            self.external(archive, current['selection']); self.external(key, current['selection'])
            if key.parent == archive.parent or key == archive:
                raise ValueError('Retain the recovery identity in a separate private directory')
            if not re.fullmatch('[a-f0-9]{64}', archive_sha256) or file_sha(archive) != archive_sha256:
                raise ValueError('Exact encrypted archive hash required')
            request = self.request('restore', operation_id, current, archive_sha256)
            request.update(archive=str(archive), identityFile=str(key), identitySha256=file_sha(key))
            self.admit(authorize, request)
            if self.custody is not None: self.custody.verify()
            transaction = self.state / operation_id
            transaction.mkdir(mode=0o700); sync_dir(self.state)
            row = {'schemaVersion': 1, 'phase': 'staging', 'request': request, 'stages': [], 'restart': False}
            self.record(row, transaction)
            plaintext = os.fdopen(os.memfd_create('authenticated-recovery', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING), 'w+b')
            try:
                self.decrypt(archive, key, plaintext)
                if file_sha(archive) != archive_sha256 or file_sha(key) != request['identitySha256']:
                    raise ValueError('Archive or separately retained key changed')
                manifest, stages = self.stage(plaintext, current, transaction, operation_id)
                row['stages'] = stages; row['snapshotInventorySha256'] = sha(canonical(manifest))
                row['phase'] = 'prepared'; self.record(row, transaction)
            except BaseException:
                # No selected rename is possible until staging has returned and
                # its complete journal is durable. Retain failed stages only.
                row['phase'] = 'staging-failed'; self.record(row, transaction)
                raise
            finally:
                # Anonymous memory only: no plaintext archive pathname, ever.
                plaintext.close()
            try:
                again, _ = self.inventory()
                if again != current: raise ValueError('Selected data changed before restore CAS')
                for stage in row['stages']:
                    root, area = Path(stage['root']), Path(stage['area'])
                    if identity(root) != stage['oldIdentity'] or identity(area / 'new') != stage['newIdentity']:
                        raise ValueError('Payload root changed before exact swap')
                    row['phase'] = 'swapping'; row['pendingRoot'] = str(root); self.record(row, transaction)
                    self.swap(root, area / 'original'); sync_dir(area); sync_dir(root.parent)
                    self.swap(area / 'new', root); sync_dir(area); sync_dir(root.parent)
                self.selection()
                for index, stage in enumerate(row['stages']):
                    if tree_entries(Path(stage['root']), 'payload/' + str(index), [0, 0]) != stage['newEntries']:
                        raise ValueError('Restored payload hash mismatch')
                row['phase'] = 'committed'; row.pop('pendingRoot', None); self.record(row, transaction)
                return {'restored': True, 'originalsRetained': True, 'restart': False,
                        'recoveryJournalSha256': file_sha(self.intent), 'installedAcceptance': False}
            except BaseException:
                # If rollback itself cannot prove exact inodes/hashes, do not
                # overwrite anything. Leave journal and originals for root CAS.
                self.rollback(row, transaction)
                raise

    def rollback(self, row, transaction):
        if self.custody is not None: self.custody.verify()
        for index in reversed(range(len(row['stages']))):
            stage = row['stages'][index]
            root, area = Path(stage['root']), Path(stage['area'])
            if self.custody is not None:
                if area not in self.custody.extra: self.custody.pin_area(area)
            else: controlled(area, private=True)
            original, new = area / 'original', area / 'new'
            if original.exists():
                if identity(original) != stage['oldIdentity']:
                    raise ValueError('Preserved original identity changed; recovery refused')
                if tree_entries(original, 'payload/' + str(index), [0, 0]) != stage['originalEntries']:
                    raise ValueError('Preserved original hash changed; recovery refused')
                if root.exists() or root.is_symlink():
                    if identity(root) != stage['newIdentity'] or new.exists() or new.is_symlink():
                        raise ValueError('Restore root drift; preserving both versions')
                    if tree_entries(root, 'payload/' + str(index), [0, 0]) != stage['newEntries']:
                        raise ValueError('Restored tree changed; preserving both versions')
                    self.swap(root, new); sync_dir(root.parent); sync_dir(area)
                self.swap(original, root); sync_dir(root.parent); sync_dir(area)
            elif identity(root) != stage['oldIdentity']:
                raise ValueError('Cannot prove unchanged original recovery root')
        row['phase'] = 'originals-restored'; row.pop('pendingRoot', None); self.record(row, transaction)

    def recover(self, expected_recovery_sha256, authorize):
        with self.locked():
            controlled(self.state, private=True)
            if (not re.fullmatch('[a-f0-9]{64}', expected_recovery_sha256)
                    or file_sha(self.intent) != expected_recovery_sha256):
                raise ValueError('Exact pending recovery CAS required')
            row = strict(read_file(self.intent, limit=MAX_JOURNAL, private=True))
            pins, roots = self.selection(allow_missing=True)
            if (row.get('schemaVersion') != 1 or row.get('phase') not in ('staging', 'staging-failed', 'prepared', 'swapping')
                    or row['request']['selection'] != pins or row.get('restart') is not False):
                raise ValueError('Pending recovery selection/phase mismatch; no replay')
            operation = row['request']['operationId']
            if not re.fullmatch('[a-f0-9]{32}', operation): raise ValueError('Invalid pending operation')
            transaction = self.state / operation
            controlled(transaction, private=True)
            receipt = strict(read_file(transaction / 'receipt.json', limit=MAX_JOURNAL, private=True))
            # intent.json is the single CAS authority. A power loss between its
            # atomic write and the historical receipt projection may leave only
            # the phase different; never reject recoverable inodes for that.
            staging_only = row['phase'] in ('staging', 'staging-failed')
            if (receipt.get('request') != row['request']
                    or (not staging_only and receipt.get('stages') != row['stages'])):
                raise ValueError('Recovery transaction/intent binding mismatch')
            if not staging_only and len(row['stages']) != len(roots):
                raise ValueError('Recovery root count mismatch')
            for index, stage in enumerate(row['stages']):
                if (stage['root'] != str(roots[index]) or stage['area'] != str(roots[index].parent /
                        ('.p0-recovery-' + operation + '-' + str(index)))):
                    raise ValueError('Foreign root in recovery journal')
            request = {'schemaVersion': 1, 'kind': 'recover-originals', 'operationId': operation,
                       'selection': pins, 'recoveryJournalSha256': expected_recovery_sha256, 'restart': False}
            self.admit(authorize, request)
            if file_sha(self.intent) != expected_recovery_sha256: raise ValueError('Recovery CAS changed')
            if staging_only:
                # No selected rename is possible before a durable prepared +
                # swapping intent. Prove originals are still the admitted tree;
                # retain any partial stage; no persistent raw spool exists.
                current, _ = self.inventory()
                if sha(canonical(current)) != row['request']['inventorySha256']:
                    raise ValueError('Originals changed during interrupted staging; preserve for review')
                # No persistent plaintext spool exists in this format.
                row['phase'] = 'originals-restored'; self.record(row, transaction)
            else:
                self.rollback(row, transaction)
            return {'originalsRestored': True, 'restart': False, 'installedAcceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan',))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expected-install-intent-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(Backend(args.root, args.expected_install_intent_sha256).plan(), sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
        parser.exit(1, 'Selected synthetic recovery refused; inspect protected scoped evidence\n')


if __name__ == '__main__': main()
