#!/usr/bin/env python3
"""Manager-free selected-image supply producer; NOT an operation authority.

Internal API (the existing privileged installer calls this IN PROCESS):
  export_selected(bundle, source_receipt, reviewed_sha256, output, *, lease,
                  storage=None, image_timeout=600, total_timeout=3600,
                  max_archive_bytes=8*GiB, max_total_bytes=32*GiB)

The receipt is root-sealed transport/CAS metadata, never approval. ``lease`` is
an authenticated adapter to the EXISTING journal lock/stopped operation. It must
implement these methods; all verification methods return None or raise:

* verify_export(request): re-read canonical operation/intent/receipt, inherited
  lock, frozen source, exact accounts AND exclusive operator/group writers,
  full subuid/subgid tables (including foreign overlaps), marker and source CAS.
  Require stopped/quiesced selected services, user managers, API sockets/jobs,
  no linger/boot activation and no foreign actor/mapped-ID processes throughout.
* read_leases(scope_fd, marker_fd, graph_fds, request): revalidate existing own
  storage leases using these pinned FDs, NOT paths or JSON approval booleans.
* check_reserves(request): existing operation's independent reserve/budget gate.
* export_process(plan, guard): context manager yielding a runner. runner.probe()
  returns namespace evidence, NOT admission. Only AFTER verify_namespace may
  runner.run() push, in that SAME retained/probed namespace. Main probes/execs:
  drop ALL supplementary groups, set exact UID/GID, empty environment, enforce
  CPU/address-space/file-size/deadline budgets and deny-all networking; enter namespacePrefix, verify
  namespace mapping/backend compatibility BEFORE executing command. No manager,
  D-Bus, Podman API, libpod DB edit, default-config fallback or graph copy. Refuse
  if installed Buildah/containers-storage cannot honor the exact source mapping
  with this fresh runroot. Use owned cgroup + subreaper (or equivalent): __exit__
  ALWAYS cancels/reaps ALL owned descendants, including a surviving unshare/
  pause helper after leader exit, bounded TERM then KILL, repeat-interrupt safe.
* verify_namespace(plan, evidence): verify actual observed map/backend/graph,
  explicit configuration, tool version compatibility and selected config bytes.
  Evidence keys are namespace, graphRoot, driver, storageOptions, configSha256
  (equal to plan), and compatibilitySha256 (existing root-reviewed tool/backend
  compatibility record; not a caller's assertion). No compatibility proof means
  refusal BEFORE push, never a protected-store or libpod DB fallback.
* verify_quiescent(request): independently prove all owned descendants are gone
  (not just the leader/process group) and original stopped/API/no-linger gates.

No adapter is loaded from a user path, token or CLI flag. No subprocess is run
here; Main owns the actual trusted executor and installed-tool compatibility
proof. CLI can describe frozen selection or rebind already-produced immutable
artifacts after complete recipe/COPY/OCI checks. That artifact-only mode never
accesses stores, exports an actor graph or substitutes for the lease. Synthetic tests are NOT namespace
compatibility, actual export or installation acceptance (complete acceptance 0/2).
Only new output/workspace children are written; source stores are never chowned,
pruned, copied or repaired. Failed output stays PENDING; no replay/promotion API.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

GIB = 1024**3
LIMIT = 8 * 1024**2
HEX = re.compile(r'[a-f0-9]{64}')
METHODS = ('verify_export', 'read_leases', 'check_reserves', 'export_process',
           'verify_namespace', 'verify_quiescent')


def load(name, filename):
    source = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    # Do not create bytecode in a protected installed helper directory.
    exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
    return module


package = load('_selected_export_package', 'package-release-images.py')
IDENTITIES = load('_selected_export_identities', 'native-selection.py').IDENTITIES


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def canonical(value):
    require(isinstance(value, (str, Path)), 'canonical absolute path required')
    value = str(value)
    path = Path(value)
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts
            and str(path) == value and re.fullmatch(r'/[A-Za-z0-9_./-]+', value),
            'canonical absolute path required')
    return path


def identity(info):
    # Directory link counts change when OUR new output children are created;
    # ownership/mode/ACL/inode remain pinned. Regular-file CAS adds nlink below.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def acl(fd, name):
    try:
        body = os.getxattr(fd, name)
    except OSError as error:
        import errno
        if error.errno == errno.ENODATA:
            return b''
        raise
    return body


def acl_rows(body):
    require(len(body) >= 4 and (len(body) - 4) % 8 == 0
            and struct.unpack('<I', body[:4])[0] == 2, 'invalid ACL')
    result = {}
    for offset in range(4, len(body), 8):
        tag, rights, who = struct.unpack('<HHI', body[offset:offset + 8])
        require((tag, who) not in result and rights <= 7, 'ambiguous ACL')
        result[tag, who] = rights
    return result


def mount_id(fd):
    with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as source:
        body = source.read(65537)
    values = [line.split()[1:] for line in body.splitlines() if line.startswith('mnt_id:')]
    require(len(body) <= 65536 and len(values) == 1 and len(values[0]) == 1
            and values[0][0].isdigit(), 'kernel FD mount identity unavailable')
    return int(values[0][0])


def custody(fd):
    info = os.fstat(fd)
    return identity(info), acl(fd, 'system.posix_acl_access'), acl(fd, 'system.posix_acl_default'), mount_id(fd)


def protected(fd, *, directory=False, uid=0, gid=0, private=False):
    info = os.fstat(fd)
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == uid and info.st_gid == gid
            and not info.st_mode & (0o077 if private else 0o022)
            and (directory or info.st_nlink == 1), 'unprotected owner/type/link/mode')
    require(not acl(fd, 'system.posix_acl_default')
            and not acl(fd, 'system.posix_acl_access'), 'unexpected private/root ACL')


def no_foreign_writers(fd, operator):
    """Operator-only writers, INCLUDING default ACL. Group membership is leased."""
    info = os.fstat(fd)
    require(info.st_uid in (0, operator.pw_uid) and info.st_gid in (0, operator.pw_gid)
            and not info.st_mode & 0o002, 'foreign parent writer')
    for body in (acl(fd, 'system.posix_acl_access'), acl(fd, 'system.posix_acl_default')):
        if not body:
            continue
        for (tag, who), rights in acl_rows(body).items():
            if not rights & 2 or tag == 16:
                continue
            allowed = ((tag == 1 and info.st_uid in (0, operator.pw_uid))
                       or (tag == 2 and who in (0, operator.pw_uid))
                       or (tag == 4 and info.st_gid in (0, operator.pw_gid))
                       or (tag == 8 and who in (0, operator.pw_gid)))
            require(allowed, 'foreign access/default ACL writer')


class Pins:
    """No-follow FD custody plus path re-open/CAS; never reopen through a symlink."""
    def __init__(self):
        self.dirs, self.files = {}, {}

    def close(self):
        for fd, _ in self.dirs.values():
            os.close(fd)
        for fd, _ in self.files.values():
            os.close(fd)
        self.dirs.clear(); self.files.clear()

    def directory(self, path, check):
        path = Path(path)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        nodes = []
        try:
            nodes.append((Path('/'), os.dup(fd)))
            current = Path('/')
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child; current /= part
                nodes.append((current, os.dup(fd)))
            for node, opened in nodes:
                check(node, opened)
                record = custody(opened)
                if node in self.dirs:
                    require(self.dirs[node][1] == record, 'directory custody changed')
                else:
                    self.dirs[node] = (os.dup(opened), record)
            return fd
        except BaseException:
            os.close(fd)
            raise
        finally:
            for _, opened in nodes:
                os.close(opened)

    def file(self, path, *, uid=0, gid=0, private=True, limit=LIMIT):
        path = canonical(path)
        require(path.parent in self.dirs, 'file parent not pinned')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=self.dirs[path.parent][0])
        try:
            protected(fd, uid=uid, gid=gid, private=private)
            require(mount_id(fd) == mount_id(self.dirs[path.parent][0]), 'mounted metadata path escape')
            require(os.fstat(fd).st_size <= limit, 'oversized source metadata')
            before = file_cas(fd, max_bytes=limit)
            if path in self.files:
                require(self.files[path][1] == before, 'source file CAS changed')
                os.close(fd)
                return self.files[path][0]
            self.files[path] = (fd, before)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def document(self, path, **kwargs):
        fd = self.file(path, **kwargs)
        os.lseek(fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(fd), 'rb') as source:
            result = package.strict_json(source)
        require(file_cas(fd) == self.files[Path(path)][1], 'JSON source CAS changed')
        return result

    def check(self):
        for path, (fd, before) in self.dirs.items():
            require(custody(fd) == before, 'pinned directory custody changed')
            # A pinned inode alone cannot detect replacement of the named path.
            fresh = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in path.parts[1:]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fresh)
                    os.close(fresh); fresh = child
                require(custody(fresh) == before, 'directory path replaced')
            finally:
                os.close(fresh)
        for path, (fd, before) in self.files.items():
            fresh = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=self.dirs[path.parent][0])
            try:
                require(file_cas(fd) == before == file_cas(fresh), 'source full-inventory/file CAS changed')
            finally:
                os.close(fresh)


def file_cas(fd, *, max_bytes=package.MAX_ARCHIVE, guard=lambda: None):
    before = os.fstat(fd)
    mount = mount_id(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'linked/nonregular file')
    require(before.st_size <= max_bytes, 'oversized CAS input')
    digest = hashlib.sha256(); offset = 0
    while True:
        guard()
        block = os.pread(fd, 1024**2, offset)
        if not block:
            break
        digest.update(block); offset += len(block)
        require(offset <= max_bytes, 'growing CAS input exceeds budget')
    after = os.fstat(fd)
    record = lambda s: (*identity(s), s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(record(before) == record(after) and mount == mount_id(fd), 'file changed while hashing')
    return (*record(after), mount, digest.hexdigest())


def root_check(path, fd):
    protected(fd, directory=True)


def source_check(scope, operator, storage, owners):
    scope_mount = None
    def check(path, fd):
        nonlocal scope_mount
        if path == scope:
            observed = mount_id(fd)
            require(scope_mount is None or scope_mount == observed, 'scope mount changed')
            scope_mount = observed
        elif path.is_relative_to(scope):
            require(scope_mount is not None and mount_id(fd) == scope_mount, 'nested source mount/path escape')
        if path == Path('/mnt/stack') and scope.is_relative_to(path):
            info = os.fstat(fd)
            require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                    (1000, 1000, 0o2775) and operator.pw_uid == operator.pw_gid == 1000,
                    'unsupported external operator ancestor')
            no_foreign_writers(fd, operator)
        elif path == scope or path.is_relative_to(scope):
            owner = next((row for root, row in owners.items() if path == root or path.is_relative_to(root)), None)
            if owner:
                protected(fd, directory=True, uid=owner['uid'], gid=owner['gid'], private=True)
            else:
                # Reuse the canonical storage authority's gate, bracketed by FD identity.
                before = custody(fd)
                storage.safe_parent(path, operator)
                require(custody(fd) == before and identity(path.lstat()) == before[0],
                        'storage safe_parent path/FD drift')
                no_foreign_writers(fd, operator)
        else:
            protected(fd, directory=True)
    return check


def verify_receipt(document, binding, selected, bundle, output):
    keys = {'schemaVersion', 'purpose', 'binding', 'imageAuthorities', 'operation',
            'scope', 'scopeMarkerSha256', 'allocationSha256', 'sources'}
    require(isinstance(document, dict) and set(document) == keys
            and type(document['schemaVersion']) is int and document['schemaVersion'] == 1
            and document['purpose'] == 'selected-actor-image-export'
            and document['binding'] == binding and document['imageAuthorities'] == selected,
            'source receipt frozen selection mismatch')
    operation = document['operation']
    require(isinstance(operation, dict) and set(operation) == {'journalRoot', 'release', 'operationId'}
            and canonical(operation['release']) == bundle
            and bundle.parent == canonical(operation['journalRoot']) / 'releases'
            and isinstance(operation['operationId'], str)
            and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', operation['operationId']),
            'existing journal operation binding required')
    require(set(document['allocationSha256']) == {'subuid', 'subgid'}
            and all(isinstance(v, str) and HEX.fullmatch(v) for v in
                    [document['scopeMarkerSha256'], *document['allocationSha256'].values()]),
            'exact allocation/marker hash binding required')
    scope = canonical(document['scope'])
    require(not output.is_relative_to(scope) and not scope.is_relative_to(output)
            and not output.is_relative_to(bundle) and not bundle.is_relative_to(output),
            'supply output must be disjoint from source authority/release')
    sources = document['sources']
    require(isinstance(sources, list) and len(sources) == 8, 'exact seven actors plus rootful required')
    require({row['authority'] for row in sources} == {'root', *[v[1] for v in IDENTITIES.values()]},
            'exact selected source accounts required')
    metadata = package.read_document(bundle / 'podman-domains.json')
    declared = {row['name']: row for row in metadata['domains']}
    require(set(declared) == set(IDENTITIES), 'exact frozen seven-actor metadata required')
    ranges = []; roots = []
    for row in sources:
        require(set(row) == {'authority', 'domain', 'uid', 'gid', 'subuidStart', 'subgidStart',
                            'subidCount', 'graphRoot', 'driver', 'storageOptions', 'namespace',
                            'markerSha256', 'inventories', 'images'}, 'exact source authority schema required')
        require(row['driver'] == 'overlay' and row['storageOptions'] in ([], ['overlay.mount_program=/usr/bin/fuse-overlayfs'])
                and all(type(row[k]) is int for k in ('uid', 'gid', 'subuidStart', 'subgidStart', 'subidCount')),
                'unsupported backend or numeric source identity')
        graph = canonical(row['graphRoot'])
        require(graph != scope and graph.is_relative_to(scope), 'graph escapes selected scope')
        require(all(not graph.is_relative_to(other) and not other.is_relative_to(graph) for other in roots),
                'overlapping selected graphs')
        roots.append(graph)
        if row['authority'] == 'root':
            require(row['domain'] == 'rootful' and row['uid'] == row['gid'] == 0
                    and row['subuidStart'] == row['subgidStart'] == row['subidCount'] == 0,
                    'rootful source identity differs')
            expected_map = {'uidMap': [[0, 0, 4294967295]], 'gidMap': [[0, 0, 4294967295]]}
        else:
            require(row['domain'] in IDENTITIES and
                    (row['uid'], row['authority']) == IDENTITIES[row['domain']]
                    and row['gid'] > 0 and row['subidCount'] == 65536,
                    'canonical actor account/range differs')
            frozen = declared[row['domain']]
            require((frozen['user'], frozen['uid'], frozen['graphRoot']) ==
                    (row['authority'], row['uid'], str(graph)), 'frozen actor graph/identity differs')
            for key in ('subuidStart', 'subgidStart'):
                require(65536 <= row[key] and row[key] + 65536 < 2**32
                        and (key not in frozen or frozen[key] == row[key]), 'invalid frozen subordinate range')
            ranges.append(row)
            expected_map = {'uidMap': [[0, row['uid'], 1], [1, row['subuidStart'], 65536]],
                            'gidMap': [[0, row['gid'], 1], [1, row['subgidStart'], 65536]]}
        require(row['namespace'] == expected_map, 'incompatible source namespace mapping')
        require(isinstance(row['markerSha256'], str) and HEX.fullmatch(row['markerSha256']), 'marker hash required')
        require(row['images'] == sorted(image for image, users in selected.items() if row['authority'] in users),
                'exact per-authority selected IDs required')
        inventories = row['inventories']
        require(isinstance(inventories, dict) and set(inventories) == {
            'overlay-images/images.json', 'overlay-layers/layers.json', 'overlay-containers/containers.json'}
            and all(isinstance(v, str) and HEX.fullmatch(v) for v in inventories.values()),
            'complete image/layer/container inventory CAS required')
    require(len({row['gid'] for row in ranges}) == 7
            and all(row['gid'] not in (0, 1000) for row in ranges), 'disjoint actor groups required')
    for key in ('subuidStart', 'subgidStart'):
        ordered = sorted(ranges, key=lambda row: row[key])
        require(all(a[key] + 65536 <= b[key] for a, b in zip(ordered, ordered[1:])), 'overlapping actor ranges')
        require(all(not row[key] <= value < row[key] + 65536 for row in ordered
                    for value in [0, 1000, *[v[k] for v in ranges for k in ('uid', 'gid')]]),
                'subordinate range overlaps account identity')
    return scope, sources


def floor_reserves():
    for path, floor in (('/', 50 * GIB), ('/mnt/stack', 100 * GIB)):
        info = os.statvfs(path)
        require(info.f_bavail * info.f_frsize >= floor, 'independent filesystem reserve floor')
    with open('/proc/meminfo', encoding='ascii') as source:
        values = [int(line.split()[1]) * 1024 for line in source if line.startswith('MemAvailable:')]
    require(len(values) == 1 and values[0] >= 16 * GIB, 'independent memory reserve floor')


def workspace_parent_check(path, fd):
    root_check(path, fd)
    # Actors must traverse paths, without granting them read/write to output.
    # Choose a root-protected public-x export parent, NOT installer-private root.
    require(os.fstat(fd).st_mode & 0o001, 'workspace ancestry lacks actor traversal')


def owned_bytes(fd, *, max_file, max_total):
    """Bound only our new output/workspace; no symlink/mount/path following."""
    device, mount = os.fstat(fd).st_dev, mount_id(fd)
    count = 0
    def walk(parent):
        nonlocal count
        total = 0
        for name in os.listdir(parent):
            count += 1
            require(count <= 20000, 'owned workspace node budget exceeded')
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(info.st_dev == device, 'workspace mount escape')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    require(identity(os.fstat(child)) == identity(info) and mount_id(child) == mount,
                            'workspace directory replaced/mounted')
                    total += walk(child)
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'linked/nonregular partial output')
                child = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    require(identity(os.fstat(child)) == identity(info) and mount_id(child) == mount,
                            'workspace file replaced/mounted')
                finally:
                    os.close(child)
                require(info.st_size <= max_file, 'oversized partial output')
                total += info.st_size
            require(total <= max_total, 'aggregate partial output budget exceeded')
        return total
    return walk(fd)


def validate_probe(plan, evidence):
    keys = {'namespace', 'graphRoot', 'driver', 'storageOptions', 'configSha256'}
    require(isinstance(evidence, dict) and set(evidence) == keys | {'compatibilitySha256'}
            and all(evidence[key] == plan[key] for key in keys)
            and isinstance(evidence['compatibilitySha256'], str)
            and HEX.fullmatch(evidence['compatibilitySha256']), 'source namespace/backend probe mismatch')


def new_file(parent, name, body, uid=0, gid=0):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchown(fd, uid, gid)  # ONLY this fresh inode, never source/config/store.
        with os.fdopen(os.dup(fd), 'wb') as target:
            target.write(body); target.flush(); os.fsync(target.fileno())
    finally:
        os.close(fd)


def json_bytes(body):
    return (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()


def make_plan(work_parent, work_path, row, image, timeout, max_bytes):
    """Only the trusted executor may run this plan; no implicit tool fallback."""
    name = ('rootful' if row['authority'] == 'root' else row['domain']) + '-' + image[7:]
    os.mkdir(name, 0o700, dir_fd=work_parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=work_parent)
    path = work_path / name
    try:
        # A root-controlled traversal parent prevents actor substitution of the
        # workspace; only exact private children/files belong to the actor.
        os.fchmod(fd, 0o711)
        for child in ('runtime', 'runroot', 'scratch', 'home', 'transfer'):
            os.mkdir(child, 0o700, dir_fd=fd)
            sub = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: os.fchown(sub, row['uid'], row['gid'])
            finally: os.close(sub)
        options = '\nmount_program = "/usr/bin/fuse-overlayfs"' if row['storageOptions'] else ''
        storage_body = ('[storage]\ndriver = "overlay"\ngraphroot = ' + json.dumps(row['graphRoot']) +
                        '\nrunroot = ' + json.dumps(str(path / 'runroot')) +
                        '\n[storage.options]\nadditionalimagestores = []\n'
                        '[storage.options.overlay]' + options + '\n').encode()
        for filename, body in (('storage.conf', storage_body), ('containers.conf', b'[engine]\n'),
                               ('auth.json', b'{"auths":{}}\n')):
            # Actor read only; root-controlled parent and source hash pinned.
            new_file(fd, filename, body)
            config = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try: os.fchmod(config, 0o644)
            finally: os.close(config)
        base = ['/usr/bin/buildah', '--root', row['graphRoot'], '--runroot', str(path / 'runroot'),
                '--storage-driver', row['driver']]
        for option in row['storageOptions']:
            base += ['--storage-opt', option]
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(path / 'home'),
               'XDG_RUNTIME_DIR': str(path / 'runtime'), 'XDG_CONFIG_HOME': str(path / 'home'),
               'TMPDIR': str(path / 'scratch'), 'CONTAINERS_STORAGE_CONF': str(path / 'storage.conf'),
               'CONTAINERS_CONF': str(path / 'containers.conf'),
               'REGISTRY_AUTH_FILE': str(path / 'auth.json')}
        return {'authority': row['authority'], 'uid': row['uid'], 'gid': row['gid'],
                'supplementaryGroups': [], 'image': image, 'graphRoot': row['graphRoot'],
                'driver': row['driver'], 'storageOptions': row['storageOptions'],
                'namespace': row['namespace'], 'namespacePrefix': [] if row['uid'] == 0 else base + ['unshare'],
                'command': base + ['push', '--format', 'oci', '--authfile', str(path / 'auth.json'),
                                   image, 'oci-archive:' + str(path / 'transfer/image.tar')],
                'environment': env, 'workspace': str(path), 'archive': str(path / 'transfer/image.tar'),
                'configSha256': {name: hashlib.sha256(body).hexdigest() for name, body in
                    [('storage.conf', storage_body), ('containers.conf', b'[engine]\n'), ('auth.json', b'{"auths":{}}\n')]},
                'limits': {'wallSeconds': timeout, 'cpuSeconds': timeout, 'addressSpaceBytes': 16 * GIB,
                           'archiveBytes': max_bytes, 'processes': 64},
                'networkPolicy': 'deny-all',
                'requiredIsolation': 'owned-descendant-lifetime-with-namespace-preexec-check'}
    finally:
        os.close(fd)


def checked(lease, method, *args):
    require(getattr(lease, method)(*args) is None, 'trusted lease verifier must return None, not approval JSON')


def export_selected(bundle, source_receipt, reviewed_sha256, output, *, lease, storage=None,
                    image_timeout=600, total_timeout=3600, max_archive_bytes=8 * GIB,
                    max_total_bytes=32 * GIB):
    require(all(callable(getattr(lease, name, None)) for name in METHODS), 'existing trusted stopped lease adapter required')
    require(os.geteuid() == 0, 'root supply custody required')
    require(type(image_timeout) is int and 1 <= image_timeout <= 3600
            and type(total_timeout) is int and 1 <= total_timeout <= 3600
            and type(max_archive_bytes) is int and 1 <= max_archive_bytes <= package.MAX_ARCHIVE
            and type(max_total_bytes) is int and max_archive_bytes <= max_total_bytes <= package.MAX_ARCHIVE,
            'bounded export budgets required')
    bundle, source_receipt, output = map(canonical, (bundle, source_receipt, output))
    require(isinstance(reviewed_sha256, str) and HEX.fullmatch(reviewed_sha256), 'reviewed source receipt hash required')
    binding, selected, bundle_proof = package.bundle_selection(bundle)
    storage = storage or load('_selected_export_storage', 'grant-rootless-volume-parent-traverse.py')
    pins = Pins(); output_fd = work_fd = None; started = completed = False
    deadline = time.monotonic() + total_timeout
    request = None
    try:
        fd = pins.directory(source_receipt.parent, root_check); os.close(fd)
        document = pins.document(source_receipt)
        require(pins.files[source_receipt][1][-1] == reviewed_sha256, 'source receipt review hash mismatch')
        scope, sources = verify_receipt(document, binding, selected, bundle, output)
        request = {'binding': binding, 'imageAuthorities': selected, 'sourceReceiptSha256': reviewed_sha256,
                   'operation': document['operation'], 'scope': str(scope), 'sources': sources,
                   'allocationSha256': document['allocationSha256'], 'deadlineMonotonic': deadline}
        checked(lease, 'verify_export', request)  # BEFORE any source store access.
        actual_scope, operator, marker = storage.authority(bundle)
        require(actual_scope == scope, 'storage authority scope differs')
        owners = {Path(row['graphRoot']): row for row in sources}
        check = source_check(scope, operator, storage, owners)
        fd = pins.directory(scope, check); os.close(fd)
        marker_path = scope / storage.MARKER
        pins.document(marker_path)
        require(pins.files[marker_path][1][-1] == document['scopeMarkerSha256'], 'scope marker CAS differs')
        storage.marker(scope, marker)
        graph_fds = {}
        # All authority/receipt/mapping checks precede inventory access.
        for row in sources:
            graph = Path(row['graphRoot'])
            fd = pins.directory(graph, check); os.close(fd)
            graph_fds[row['authority']] = pins.dirs[graph][0]
            marker_file = graph / '.selected-image-source.json'
            source_marker = pins.document(marker_file)
            require(pins.files[marker_file][1][-1] == row['markerSha256'] and source_marker == {
                'schemaVersion': 1, 'purpose': 'selected-image-source', 'binding': binding,
                'operation': document['operation'], 'authority': row['authority'], 'graphRoot': str(graph)},
                'source graph marker identity differs')
        checked(lease, 'read_leases', pins.dirs[scope][0], pins.files[marker_path][0], graph_fds, request)
        for row in sources:
            graph = Path(row['graphRoot'])
            for relative, expected in row['inventories'].items():
                path = graph / relative
                fd = pins.directory(path.parent, check); os.close(fd)
                content = pins.document(path, uid=row['uid'], gid=row['gid'], private=False)
                require(pins.files[path][1][-1] == expected and isinstance(content, list), 'full inventory CAS differs')
                if relative == 'overlay-images/images.json':
                    require(all(isinstance(r, dict) and isinstance(r.get('id'), str) and HEX.fullmatch(r['id']) for r in content)
                            and len({r['id'] for r in content}) == len(content)
                            and {image[7:] for image in row['images']} <= {r['id'] for r in content},
                            'selected source immutable image absent')
                elif relative == 'overlay-containers/containers.json':
                    require(not content, 'source has retained storage containers; compatibility unproven')
        parent_fd = pins.directory(output.parent, workspace_parent_check)
        try:
            # Exclusive mkdir: never adopt, clear, resume or overwrite old output.
            work_path = output.parent / (output.name + '.export-work')
            require(not work_path.exists() and not work_path.is_symlink(), 'workspace must be a new child')
            image_deadline = deadline
            allowed_output = {'PENDING'}
            def guard():
                require(time.monotonic() < min(deadline, image_deadline), 'export deadline exceeded')
                floor_reserves(); checked(lease, 'check_reserves', request)
                checked(lease, 'verify_export', request)
                checked(lease, 'read_leases', pins.dirs[scope][0], pins.files[marker_path][0], graph_fds, request)
                package.assert_unchanged(bundle_proof); pins.check()
                if output_fd is not None:
                    require(set(os.listdir(output_fd)) <= allowed_output, 'unselected output entry')
                    total = sum(owned_bytes(fd, max_file=max_archive_bytes, max_total=max_total_bytes)
                                for fd in (output_fd, work_fd) if fd is not None)
                    require(total <= max_total_bytes, 'aggregate partial output budget exceeded')
            guard()
            os.mkdir(output.name, 0o700, dir_fd=parent_fd)
            output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            new_file(output_fd, 'PENDING', b'Incomplete selected image supply; never import or resume.\n')
            os.fsync(output_fd); os.fsync(parent_fd)
            fd = pins.directory(output, root_check); os.close(fd)
            os.mkdir(work_path.name, 0o711, dir_fd=parent_fd)
            work_fd = os.open(work_path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.fchmod(work_fd, 0o711)
            rows = {}; evidence_rows = []; output_cas = {}
            for row in sorted(sources, key=lambda row: row['authority']):
                for image in row['images']:
                    guard()
                    image_deadline = min(deadline, time.monotonic() + image_timeout)
                    plan = make_plan(work_fd, work_path, row, image,
                                     min(image_timeout, max(1, int(deadline - time.monotonic()))), max_archive_bytes)
                    started = True
                    try:
                        with lease.export_process(plan, guard) as runner:
                            evidence = runner.probe()
                            validate_probe(plan, evidence)
                            checked(lease, 'verify_namespace', plan, evidence)
                            guard()
                            require(runner.run() is None, 'trusted exporter must complete without approval payload')
                    finally:
                        # Even after leader exit/exception: no publish if any owned helper survives.
                        checked(lease, 'verify_quiescent', request)
                    guard()
                    archive = Path(plan['archive'])
                    # Anchor actor output; copy to root-private single-link inode
                    # BEFORE interpreting OCI bytes. No actor-owned input is supply.
                    fd = pins.directory(archive.parent, lambda path, fd: None)
                    try:
                        src = os.open(archive.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    finally:
                        os.close(fd)
                    try:
                        protected(src, uid=row['uid'], gid=row['gid'], private=True)
                        require(mount_id(src) == mount_id(pins.dirs[archive.parent][0]), 'mounted actor archive escape')
                        before = file_cas(src, max_bytes=max_archive_bytes, guard=guard)
                        require(0 < os.fstat(src).st_size <= max_archive_bytes, 'invalid actor archive size')
                        filename = image[7:] + '.oci.tar' if image not in rows else row['domain'] + '-' + image[7:] + '.oci.tar'
                        allowed_output.add(filename)
                        dst = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=output_fd)
                        try:
                            offset = 0
                            while True:
                                guard()
                                block = os.pread(src, 1024**2, offset)
                                if not block: break
                                require(offset + len(block) <= max_archive_bytes, 'growing actor archive exceeds budget')
                                pending = memoryview(block)
                                while pending:
                                    written = os.write(dst, pending)
                                    require(written > 0, 'short root archive write')
                                    pending = pending[written:]
                                offset += len(block)
                            os.fsync(dst)
                            require(before == file_cas(src, max_bytes=max_archive_bytes, guard=guard),
                                    'actor archive copy CAS changed')
                            proof = package.verify_oci(Path('/proc/self/fd') / str(dst), image, guard)
                            copied = file_cas(dst, max_bytes=max_archive_bytes, guard=guard)
                            require(copied[-1] == before[-1], 'root copy differs from actor output')
                            os.fchmod(dst, 0o400)
                        finally:
                            os.close(dst)
                    finally:
                        os.close(src)
                    output_cas[output / filename] = package.snapshot(output / filename)
                    evidence_rows.append({'authority': row['authority'], 'image': image,
                                          'archiveFilename': filename, 'archiveSha256': copied[-1],
                                          'archiveBytes': offset, 'oci': proof, 'namespaceEvidence': evidence})
                    rows.setdefault(image, {'image': image, 'archiveFilename': filename,
                                           'archiveSha256': copied[-1], 'archiveBytes': offset})
            image_deadline = deadline
            checked(lease, 'verify_quiescent', request)
            guard(); package.assert_unchanged(output_cas)
            supply = {'schemaVersion': 1, 'purpose': 'release-image-supply', 'binding': binding,
                      'imageAuthorities': selected, 'images': [rows[image] for image in sorted(rows)]}
            require(set(rows) == set(selected), 'incomplete exact selected supply')
            supply_body = json_bytes(supply)
            receipt = {'schemaVersion': 1, 'purpose': 'selected-image-supply-proof', 'binding': binding,
                       'imageAuthorities': selected, 'sourceReceiptSha256': reviewed_sha256,
                       'sameSourceCAS': {str(path): record[-1] for path, (_, record) in pins.files.items()},
                       'sourceCustody': {str(path): {'device': record[0][0], 'inode': record[0][1],
                           'uid': record[0][2], 'gid': record[0][3], 'mode': stat.S_IMODE(record[0][4]),
                           'accessAclSha256': hashlib.sha256(record[1]).hexdigest(),
                           'defaultAclSha256': hashlib.sha256(record[2]).hexdigest(), 'mountId': record[3]}
                           for path, (_, record) in pins.dirs.items() if path == scope or path.is_relative_to(scope)},
                       'operation': document['operation'], 'exporterSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       'supplySha256': hashlib.sha256(supply_body).hexdigest(),
                       'evidence': evidence_rows, 'activationAuthorized': False, 'acceptedIntegratedInstalls': 0}
            allowed_output.update(('supply.json.partial', 'export-proof.json.partial', 'supply.json', 'export-proof.json'))
            new_file(output_fd, 'supply.json.partial', supply_body)
            new_file(output_fd, 'export-proof.json.partial', json_bytes(receipt))
            guard(); package.assert_unchanged(output_cas)
            os.rename('supply.json.partial', 'supply.json', src_dir_fd=output_fd, dst_dir_fd=output_fd)
            os.rename('export-proof.json.partial', 'export-proof.json', src_dir_fd=output_fd, dst_dir_fd=output_fd)
            for name in ('supply.json', 'export-proof.json'):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=output_fd)
                try:
                    os.fchmod(fd, 0o400); os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(output_fd)
            guard(); package.assert_unchanged(output_cas)
            checked(lease, 'verify_quiescent', request)
            require(set(os.listdir(output_fd)) == {'PENDING', 'supply.json', 'export-proof.json',
                    *[row['archiveFilename'] for row in evidence_rows]}, 'incomplete/unselected publication entries')
            os.unlink('PENDING', dir_fd=output_fd); os.fsync(output_fd); os.fsync(parent_fd)
            completed = True
            return {'supply': str(output / 'supply.json'), 'supplySha256': receipt['supplySha256'],
                    'proof': str(output / 'export-proof.json'),
                    'proofSha256': hashlib.sha256(json_bytes(receipt)).hexdigest()}
        finally:
            os.close(parent_fd)
    finally:
        try:
            if started and not completed:
                checked(lease, 'verify_quiescent', request)
        finally:
            if output_fd is not None: os.close(output_fd)
            if work_fd is not None: os.close(work_fd)
            pins.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--describe-selection', action='store_true',
                      help='read-only; store export requires existing in-process installer lease')
    mode.add_argument('--rebind-qualified-artifacts', action='store_true',
                      help='artifact-only source/COPY/OCI rebind; never accesses stores or admits operations')
    for name in ('source-bundle', 'public-build', 'producer-record', 'producer-sha256',
                 'image-inputs', 'image-inputs-sha256', 'output'):
        parser.add_argument('--' + name)
    parser.add_argument('--archive-source', help='opaque archive DATA only; code/controls must remain Root-protected')
    parser.add_argument('--package-output', action='store_true', help='use existing packager in one copy, not intermediate supply')
    parser.add_argument('--reference-qualified-archives', action='store_true',
                        help='protected controls reference verified opaque archive data without copying; requires qualified package output')
    args = parser.parse_args()
    values = [getattr(args, name) for name in ('source_bundle', 'public_build', 'producer_record',
              'producer_sha256', 'image_inputs', 'image_inputs_sha256', 'output')]
    if args.rebind_qualified_artifacts:
        if any(value is None for value in values):
            parser.error('artifact rebind requires every explicit source/hash/output argument')
        owner = load('_qualified_image_supply', 'qualified-image-supply.py')
        result = owner.rebind(canonical(args.bundle), *values,
                              archive_source=args.archive_source, package_output=args.package_output,
                              reference_archives=args.reference_qualified_archives)
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if (any(value is not None for value in values) or args.archive_source is not None
                or args.package_output or args.reference_qualified_archives):
            parser.error('selection description does not accept artifact arguments')
        binding, selected, _ = package.bundle_selection(canonical(args.bundle))
        print(json.dumps({'binding': binding, 'imageAuthorities': selected,
                          'execution': 'existing-installer-lease-required', 'acceptedIntegratedInstalls': 0}, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('selected image artifact operation interrupted; incomplete output retained', file=sys.stderr)
        raise SystemExit(130) from None
    except Exception as error:
        frames = []; trace = error.__traceback__
        allowed = {'export-selected-images.py', 'qualified-image-supply.py', 'package-release-images.py'}
        while trace:
            code = trace.tb_frame.f_code
            if Path(code.co_filename).name in allowed:
                frames.append(Path(code.co_filename).name + ':' + str(trace.tb_lineno) + ':' + code.co_name)
            trace = trace.tb_next
        if frames:
            print('guard: ' + ' > '.join(frames[-12:]), file=sys.stderr)
        print('selected image artifact operation refused; verify exact source/hash/custody arguments', file=sys.stderr)
        raise SystemExit(1) from None
