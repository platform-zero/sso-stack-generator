#!/usr/bin/env python3
"""Empty node-exporter views, subordinate to the serialized native installer.

prepare(bundle) creates ONLY two absent view trees and a separate 0600 proof.
validate(bundle, expected=None) observes them, never repairs/adopts/chowns them.
The caller MUST retain the canonical installer lock/selected-scope custody and
bind the returned proof in its existing journal readiness metadata. Pass that
journal-bound proof as expected before/after active commit. Neither this helper
nor its proof authorizes activation. No environment, secret, service or cache is
read/mutated. There is deliberately no test-root/ownership override in the CLI.

probe accepts a projected metrics FILE, not a URL. snapshot/compare_metrics are
also available to the native caller to bracket its existing metrics projection.
Those APIs read host procfs/statvfs only when explicitly called at runtime.
"""
import argparse
from functools import lru_cache
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import shlex
import sys

OWNER = 0  # patched only in isolated tests; not configurable by operator/env
VOLUME = 'node-exporter-stack-filesystem-view'
DESCRIPTOR = 'node-exporter/host-metrics-view.json'
PROOF = '.host-metrics-views.json'
IMAGE = 'prom/node-exporter:v1.10.2@sha256:3ac34ce007accad95afed72149e0d2b927b7e42fd1c866149b945b84737c62c3'
# Exact owning descriptor bytes, not a caller-provided policy to interpret.
DESCRIPTOR_SHA = '13aee8f9cbf50291dceac3ede8ad848a21c1d3903f0a34f73b48af1363e08fb9'
FIELDS = dict(placement='rootful', hostNetwork=True, pidMode='host', user='65534:65534',
              capDrop=['ALL'], securityOpt=['no-new-privileges:true'], readOnly=True)
COMMAND = ['--web.listen-address=127.0.0.1:9100', '--path.rootfs=/host',
           '--collector.filesystem.mount-points-include=^(/|/mnt/stack)$$']
MOUNTS = ['./configs/node-exporter/rootfs-view:/host:ro', VOLUME + ':/host/mnt/stack:ro']
HEALTH = dict(test=['CMD', 'wget', '--quiet', '--tries=1', '-O', '/dev/null',
                    'http://localhost:9100/metrics'], interval='60s', timeout='10s',
              retries=3, start_period='10s')
SERVICE_IDENTITY = dict(containerName='node-exporter', lifecycle='daemon', restart='unless-stopped',
                        ports=['127.0.0.1:9100:9100'], networks=['monitoring'], health=HEALTH)
PHASES = ('preparing', 'units-selected', 'building', 'starting', 'active')
REQUIRED = {'bundle.json', 'stack.ir.json', 'source-provenance.json',
            'podman-domains.json', 'site/manifest.json'}
FS_METRICS = ('size_bytes', 'free_bytes', 'avail_bytes', 'files', 'files_free',
              'readonly', 'device_error')


class Refusal(ValueError):
    pass


@lru_cache(maxsize=None)
def load(name):
    path = Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location('host_metrics_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    # Source-only imports must not create/refresh an unrelated __pycache__ in
    # the immutable release. Canonical authority's nested imports are similarly
    # suppressed below; use python3 -B for the CLI's standard-library imports.
    source = spec.loader.get_source(spec.name)
    exec(compile(source, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def sha(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def strict(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal('duplicate proof/input key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=pairs)


def canonical(value):
    if (not isinstance(value, str) or not value.startswith('/') or value == '/'
            or str(Path(value)) != value or any(p in ('', '.', '..') for p in value.split('/')[1:])):
        raise Refusal('noncanonical selected path')
    return Path(value)


def fact(fd):
    """No names resolved through /proc/self/fd; metadata only."""
    return load('project-domain-runtime').custody_record(fd)


def mounts():
    # Native host namespace required; collector reads PID 1, never a host bind.
    return (Path('/proc/1/mountinfo').read_bytes(), Path('/proc/self/mountinfo').read_bytes())


def host_devices():
    result = {}
    for path in ('/', '/mnt/stack'):
        s = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(s.st_mode):
            raise Refusal('native host mountpoint is linked or not a directory')
        result[path] = dict(dev=s.st_dev, ino=s.st_ino)
    return result


def unescape(value):
    return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)


def parse_mounts(body):
    result = []
    for line in body.decode().splitlines():
        left, sep, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if not sep or len(fields) < 6 or len(tail) != 3:
            raise Refusal('invalid native mountinfo')
        result.append(dict(id=int(fields[0]), parent=int(fields[1]), device=fields[2],
                           root=unescape(fields[3]), path=unescape(fields[4]),
                           options=fields[5].split(','), fstype=tail[0],
                           source=unescape(tail[1]), superOptions=tail[2].split(',')))
    if len({r['id'] for r in result}) != len(result):
        raise Refusal('duplicate mount identity')
    return result


def selected_mounts(body):
    rows = parse_mounts(body)
    selected = {}
    for path in ('/', '/mnt/stack'):
        found = [row for row in rows if row['path'] == path]
        if len(found) != 1 or found[0]['root'] != '/' or found[0]['fstype'] in ('overlay', 'proc', 'sysfs'):
            raise Refusal('exact native root/stack filesystem unavailable')
        selected[path] = found[0]
        # v1.10.2 joins option map entries without separators. Any multi-option
        # ro set needs another option set exactly 'ro' to be supported. Map
        # iteration order is random, but cannot repair missing separators.
        row = found[0]
        real_ro = 'ro' in row['options'] or 'ro' in row['superOptions']
        pinned_ro = row['options'] == ['ro'] or row['superOptions'] == ['ro']
        if real_ro != pinned_ro:
            raise Refusal('pinned exporter cannot prove exact native readonly options')
    return selected


class Anchors:
    """Retain and rewalk every directory FD; no resolve()/symlink containment."""
    def __init__(self, roles=None):
        self.fds, self.roles = {}, roles or {}

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        for fd in self.fds.values():
            os.close(fd)

    def permissions(self, path, fd):
        s, record = os.fstat(fd), fact(fd)
        if not stat.S_ISDIR(s.st_mode):
            raise Refusal('non-directory ancestor')
        if path in self.roles:
            operator, gid, actors = self.roles[path]
            if record['uid'] == OWNER and not record['mode'] & 0o022:
                load('project-domain-runtime').custody_permissions(record, OWNER, record['gid'], actors, root_ancestor=True)
            else:
                load('project-domain-runtime').custody_permissions(record, operator, gid, actors, operator=True)
        elif s.st_uid != OWNER or s.st_mode & 0o022 or record['defaultAcl']:
            raise Refusal('uncontrolled ancestor')
        elif record['acl']:
            # Only exact selected actor execute ACLs, never foreign read/write.
            load('project-domain-runtime').custody_permissions(
                record, OWNER, s.st_gid, self.actors, root_ancestor=True)
        return record

    @property
    def actors(self):
        return set().union(*(r[2] for r in self.roles.values()))

    def open(self, path):
        path = Path(path)
        if path in self.fds:
            return self.fds[path]
        if path == Path('/'):
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent = self.open(path.parent)
            fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            self.permissions(path, fd)
        except BaseException:
            os.close(fd)
            raise
        self.fds[path] = fd
        return fd

    def read(self, path, private=False):
        parent = self.open(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != OWNER or s.st_nlink != 1
                    or s.st_mode & 0o022 or s.st_size > 32 * 1024 * 1024
                    or (private and stat.S_IMODE(s.st_mode) != 0o600)):
                raise Refusal('unsafe selected regular file')
            before = (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            with os.fdopen(os.dup(fd), 'rb') as source:
                body = source.read(32 * 1024 * 1024 + 1)
            after = os.fstat(fd)
            if (before != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or len(body) > 32 * 1024 * 1024):
                raise Refusal('selected file changed while reading')
            return body
        finally:
            os.close(fd)

    def records(self):
        return {str(path): self.permissions(path, fd) for path, fd in self.fds.items()}

    def verify(self, records):
        for path, fd in self.fds.items():
            if fact(fd) != records[str(path)]:
                raise Refusal('held directory changed')
            fresh = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) if path == Path('/') else os.open(
                path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fds[path.parent])
            try:
                if fact(fresh) != records[str(path)]:
                    raise Refusal('directory renamed or replaced')
            finally:
                os.close(fresh)

    def mkdir(self, path):
        parent = self.open(path.parent)
        os.mkdir(path.name, mode=0o755, dir_fd=parent)
        created = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        fd = self.open(path)
        opened = os.fstat(fd)
        if ((created.st_dev, created.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_uid != OWNER or os.listdir(fd)):
            raise Refusal('new scaffold changed before initialization')
        # Set mode ONLY on this just-created inode, never an existing view.
        # A canonical 2770 stack-group parent propagates setgid; remove that
        # bit on our new scaffold, retaining its GID (the descriptor pins UID0).
        # Default/access ACLs are never removed or rewritten.
        if stat.S_IMODE(opened.st_mode) != 0o755:
            os.fchmod(fd, 0o755)
        exact_view(fd)
        os.fsync(self.fds[path.parent])
        return fd


def exact_view(fd):
    row = fact(fd)
    if (row['uid'] != OWNER or row['mode'] != 0o755 or row['acl'] or row['defaultAcl']):
        raise Refusal('view is not exact UID0 0755 without ACLs')
    return row


def role_authority(bundle):
    """Reuse canonical manifest/marker/account validation, not a new scope plan."""
    storage = load('grant-rootless-volume-parent-traverse')
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        scope, operator, marker = storage.authority(bundle)
    finally:
        sys.dont_write_bytecode = previous
    # A stack-group writable scope is canonical; arbitrary writable groups are
    # NOT. The marker is still a root-private FILE, not an all-root ancestor test.
    stack = grp.getgrnam('stack')
    if operator.pw_uid != OWNER and operator.pw_gid != stack.gr_gid and operator.pw_name not in stack.gr_mem:
        raise Refusal('scope operator lacks canonical stack group role')
    actors = {row['uid'] for row in marker['domains']}
    roles = {scope: (operator.pw_uid, stack.gr_gid, actors),
             scope / 'volumes': (operator.pw_uid, stack.gr_gid, actors)}
    # Private 0700 operator ancestors may use their primary group instead.
    for path in roles:
        s = path.lstat()
        if stat.S_IMODE(s.st_mode) == 0o700:
            roles[path] = (operator.pw_uid, s.st_gid, actors)
    return scope, marker, roles


def binding(bundle, anchors, scope, marker):
    receipt_body = anchors.read(bundle / 'installation-receipt.json', private=True)
    receipt = strict(receipt_body)
    metadata = strict(anchors.read(bundle / 'podman-domains.json'))
    root = canonical(metadata.get('installerStateRoot'))
    intent_body = anchors.read(root / '.install-intent.json', private=True)
    if (bundle.parent != root / 'releases' or receipt_body != intent_body
            or receipt.get('schemaVersion') != 1 or receipt.get('release') != str(bundle)
            or receipt.get('phase') not in PHASES
            or receipt.get('steps') != list(PHASES[:PHASES.index(receipt['phase']) + 1])):
        raise Refusal('exact live installer receipt/intent CAS required')
    inputs = receipt.get('inputs', {})
    if not REQUIRED <= set(inputs) <= load('project-domain-runtime').INPUTS:
        raise Refusal('missing or unknown canonical input pins')
    for name, digest in inputs.items():
        if digest is None:
            try:
                anchors.read(bundle / name)
            except FileNotFoundError:
                continue
            raise Refusal('pinned absent input appeared')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest) or sha(anchors.read(bundle / name)) != digest:
            raise Refusal('release input pin changed')
    marker_body = anchors.read(scope / '.stack-installation.json', private=True)
    if strict(marker_body) != marker:
        raise Refusal('canonical storage marker changed')
    ir = strict(anchors.read(bundle / 'stack.ir.json'))
    service = ir['services'].get('node-exporter')
    if not isinstance(service, dict):
        raise Refusal('node-exporter is not selected')
    if (any(service.get(k) != v for k, v in (FIELDS | SERVICE_IDENTITY).items()) or service.get('image') != IMAGE
            or service.get('hostMetricsView') != './configs/' + DESCRIPTOR
            or service.get('volumes') != MOUNTS or service.get('command') != COMMAND):
        raise Refusal('unsupported node-exporter IR')
    for key in ('privileged', 'capAdd', 'devices', 'groupAdd', 'userns', 'entrypoint',
                'build', 'tmpfs', 'ephemeralImageVolumes', 'sysctls', 'environment', 'rootlessDomain'):
        if service.get(key):
            raise Refusal('undeclared exporter privilege or input')
    stack_view = scope / 'volumes' / VOLUME
    volume = ir.get('volumes', {}).get(VOLUME)
    if volume != {'hostPath': str(stack_view), 'rootlessStrategy': 'shared'}:
        raise Refusal('unselected stack view volume')
    for name, other in ir['services'].items():
        if name == 'node-exporter':
            continue
        # Resolve named-volume aliases too. Parent binds expose the view too.
        for mount in other.get('volumes', []):
            source = mount.split(':', 1)[0] if isinstance(mount, str) else mount.get('source', '')
            resolved = ir.get('volumes', {}).get(source, {}).get('hostPath', source)
            if (source == VOLUME or 'rootfs-view' in source
                    or (resolved.startswith('/') and (stack_view.is_relative_to(resolved)
                        or Path(resolved).is_relative_to(stack_view)))
                    or (source.startswith('./configs') and './configs/node-exporter'.startswith(source.rstrip('/')))):
                raise Refusal('view has an undeclared consumer')
    descriptor = anchors.read(bundle / 'stack.config' / DESCRIPTOR)
    if (sha(descriptor) != DESCRIPTOR_SHA
            or anchors.read(bundle / 'runtime/configs' / DESCRIPTOR) != descriptor):
        raise Refusal('view descriptor source/rendered hash differs')
    # Quadlet is the active backend, not merely an IR declaration.
    unit = anchors.read(bundle / 'quadlet/rootful/webservices-node-exporter.container').decode()
    if check_unit(unit, root) != str(stack_view):
        raise Refusal('selected unit stack source escapes exact scope')
    return dict(release=str(bundle), inputs=inputs, selectedScope=str(scope),
                scopeMarkerSha256=sha(marker_body), runtimeIrSha256=inputs['stack.ir.json'],
                releaseSha256=sha(encoded({'release': str(bundle), 'inputs': inputs})),
                descriptorSha256=sha(descriptor), selectedUnitSha256=sha(unit.encode()),
                initialReceiptSha256=sha(receipt_body)), receipt


def check_unit(unit, installer_root):
    section, fields, sections = None, {}, set()
    for raw in unit.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            if line not in ('[Unit]', '[Container]', '[Service]', '[Install]') or line in sections:
                raise Refusal('unsupported/repeated selected unit section')
            section = line
            sections.add(line)
            continue
        key, sep, value = line.partition('=')
        if not sep or line.endswith('\\'):
            raise Refusal('unsupported selected unit syntax')
        if section == '[Container]':
            fields.setdefault(key, []).append(value)
        elif section == '[Service]':
            if key == 'Environment':
                if value not in ('CONTAINERS_STORAGE_CONF=' + str(installer_root / 'containers-storage.conf'),
                                 'CONTAINERS_CONF=' + str(installer_root / 'containers.conf'),
                                 'DISABLE_HC_SYSTEMD=true'):
                    raise Refusal('unselected exporter service environment')
            elif key not in ('Restart', 'RestartSec', 'TimeoutStartSec', 'TimeoutStopSec',
                             'MemoryMax', 'CPUQuota', 'TasksMax'):
                raise Refusal('undeclared exporter service execution/authority')
        elif section == '[Unit]':
            if key not in ('Description', 'Requires', 'After', 'PartOf'):
                raise Refusal('unsupported exporter unit authority')
        elif section != '[Install]' or key != 'WantedBy':
            raise Refusal('unsupported selected unit directive')
    exact = dict(Pid=['host'], User=['65534:65534'], ReadOnly=['true'],
                 DropCapability=['ALL'], NoNewPrivileges=['true'], Network=['host'],
                 Image=['docker.io/' + IMAGE], ContainerName=['node-exporter'])
    for key, value in exact.items():
        if fields.get(key) != value:
            raise Refusal('selected exporter unit security/identity differs')
    root_source = str(installer_root / 'current/runtime/configs/node-exporter/rootfs-view')
    stack_source = None
    for mount in fields.get('Volume', []):
        if mount == root_source + ':/host:ro':
            continue
        if mount.endswith('/' + VOLUME + ':/host/mnt/stack:ro'):
            stack_source = mount.rsplit(':', 2)[0]
            continue
        raise Refusal('undeclared exporter unit mount')
    if (len(fields.get('Volume', [])) != 2 or not stack_source
            or fields['Volume'].count(root_source + ':/host:ro') != 1):
        raise Refusal('missing selected exporter view mounts')
    allowed = set(exact) | {'Volume', 'Exec', 'PodmanArgs', 'HealthCmd', 'HealthInterval',
                           'HealthTimeout', 'HealthRetries', 'HealthStartPeriod', 'LogDriver',
                           'Pull'}
    if set(fields) - allowed or any(len(values) != 1 for key, values in fields.items() if key != 'Volume'):
        raise Refusal('unsupported exporter unit privilege/input')
    if len(fields.get('Exec', [])) != 1 or shlex.split(fields['Exec'][0]) != COMMAND:
        raise Refusal('selected exporter unit argv differs')
    args = fields.get('PodmanArgs', [])
    if len(args) != 1 or shlex.split(args[0]) not in (['--image-volume=ignore'],
            ['--image-volume=ignore', '--sdnotify=healthy']):
        raise Refusal('unsupported exporter engine arguments')
    return stack_source


def topology(anchors, root, stack, native, devices):
    host, own = native
    selected = selected_mounts(host)
    local = selected_mounts(own)
    if selected != local:
        raise Refusal('installer is not in native host mount namespace')
    records = {}
    for path in (root, root / 'mnt', root / 'mnt/stack', stack):
        records[str(path)] = exact_view(anchors.open(path))
    for path, names in ((root, ['mnt']), (root / 'mnt', ['stack']),
                        (root / 'mnt/stack', []), (stack, [])):
        if sorted(os.listdir(anchors.open(path))) != names:
            raise Refusal('foreign content in view scaffold')
    root_record, stack_record = records[str(root)], records[str(stack)]
    for path in (root, root / 'mnt', root / 'mnt/stack'):
        r = records[str(path)]
        if r['dev'] != root_record['dev'] or r['mountId'] != selected['/']['id']:
            raise Refusal('root view crosses mount boundary')
    volume_record = fact(anchors.open(stack.parent))
    if (root_record['dev'] != devices['/']['dev']
            or stack_record['dev'] != devices['/mnt/stack']['dev']
            or root_record['dev'] != os.makedev(*map(int, selected['/']['device'].split(':')))
            or stack_record['dev'] != volume_record['dev']
            or stack_record['dev'] != os.makedev(*map(int, selected['/mnt/stack']['device'].split(':')))
            or stack_record['mountId'] != selected['/mnt/stack']['id']
            or volume_record['mountId'] != selected['/mnt/stack']['id']):
        raise Refusal('view device differs from actual host root/stack filesystem')
    for row in parse_mounts(own):
        if any(Path(row['path']) == p or Path(row['path']).is_relative_to(p) for p in (root, stack)):
            raise Refusal('view has an unexpected mount or submount')
    if len({(r['dev'], r['ino']) for r in records.values()}) != len(records):
        raise Refusal('aliased view inodes')
    return dict(views=records, directories=anchors.records(), hostMountinfoSha256=sha(host),
                selfMountinfoSha256=sha(own), nativeMounts=selected, nativeDevices=devices)


def proof_value(authority, topology_proof):
    body = dict(schemaVersion=1, contract='node-exporter-empty-host-view-v1',
                authority=authority, **topology_proof)
    return dict(body, proofSha256=sha(encoded(body)))


def check_expected(actual, expected):
    if isinstance(expected, str):
        if not re.fullmatch('[0-9a-f]{64}', expected) or actual['proofSha256'] != expected:
            raise Refusal('journal-bound view proof digest changed')
    elif expected is not None and encoded(actual) != encoded(expected):
        raise Refusal('journal-bound view proof CAS changed')


def run(bundle, create, expected=None):
    if os.geteuid() != 0:
        raise Refusal('root serialized installer required')
    bundle = canonical(str(bundle))
    scope, marker, roles = role_authority(bundle)
    root = bundle / 'runtime/configs/node-exporter/rootfs-view'
    stack = scope / 'volumes' / VOLUME
    with Anchors(roles) as a:
        authority, receipt = binding(bundle, a, scope, marker)
        native, devices = mounts(), host_devices()
        a.open(root.parent)
        a.open(stack.parent)
        # Preflight devices BEFORE any mkdir. In particular a separate /var
        # filesystem is not host /; there is no fallback view outside the release.
        selected = selected_mounts(native[0])
        if selected != selected_mounts(native[1]):
            raise Refusal('installer host root/stack mount namespace differs')
        if (fact(a.open(root.parent))['mountId'] != selected['/']['id']
                or fact(a.open(stack.parent))['mountId'] != selected['/mnt/stack']['id']):
            raise Refusal('view parent is a bind alias or separate mount')
        if (fact(a.open(root.parent))['dev'] != devices['/']['dev']
                or fact(a.open(stack.parent))['dev'] != devices['/mnt/stack']['dev']
                or devices['/']['dev'] != os.makedev(*map(int, selected['/']['device'].split(':')))
                or devices['/mnt/stack']['dev'] != os.makedev(*map(int, selected['/mnt/stack']['device'].split(':')))):
            raise Refusal('release/volume parent on unsupported filesystem')
        try:
            saved = strict(a.read(bundle / PROOF, private=True))
        except FileNotFoundError:
            saved = None
        if saved is None:
            if not create or receipt['phase'] != 'preparing':
                raise Refusal('view preparation proof absent')
            for path in (root, stack):
                try:
                    os.stat(path.name, dir_fd=a.open(path.parent), follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Refusal('unclaimed existing view; no adoption')
            for path in (root, root / 'mnt', root / 'mnt/stack', stack):
                a.mkdir(path)
            result = proof_value(authority, topology(a, root, stack, native, devices))
        else:
            initial = saved['authority']['initialReceiptSha256']
            authority['initialReceiptSha256'] = initial
            result = proof_value(authority, topology(a, root, stack, native, devices))
            check_expected(result, saved)
        check_expected(result, expected)
        records = a.records()
        # Repeat live bindings, file hashes, topology and mountinfo after all
        # directory creation/inspection. No proof may bless a raced replacement.
        again, _ = binding(bundle, a, scope, marker)
        again['initialReceiptSha256'] = result['authority']['initialReceiptSha256']
        if (again != authority or mounts() != native or host_devices() != devices
                or topology(a, root, stack, native, devices) != {k: result[k] for k in
                    ('views', 'directories', 'hostMountinfoSha256', 'selfMountinfoSha256', 'nativeMounts', 'nativeDevices')}):
            raise Refusal('view/input custody changed')
        a.verify(records)
        if saved is None:
            fd = os.open(PROOF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=a.open(bundle))
            try:
                with os.fdopen(os.dup(fd), 'wb') as output:
                    output.write(encoded(result)); output.flush(); os.fsync(output.fileno())
            finally:
                os.close(fd)
            os.fsync(a.open(bundle))
        return result


def prepare(bundle):
    return run(bundle, True)


def validate(bundle, expected=None):
    return run(bundle, False, expected)


def snapshot():
    """Runtime only. Caller brackets a fresh projected scrape with two snapshots."""
    start = time.monotonic()
    devices = host_devices()
    body = Path('/proc/1/mountinfo').read_bytes()
    selected = selected_mounts(body)
    filesystems = {}
    for path, row in selected.items():
        if devices[path]['dev'] != os.makedev(*map(int, row['device'].split(':'))):
            raise Refusal('native host path device differs from native mountinfo')
        s = os.statvfs(path)
        if bool(s.f_flag & os.ST_RDONLY) != bool('ro' in row['options'] or 'ro' in row['superOptions']):
            raise Refusal('native statvfs readonly differs from native mount options')
        filesystems[path] = dict(device=row['source'], fstype=row['fstype'],
            major=row['device'].split(':')[0], minor=row['device'].split(':')[1],
            size_bytes=s.f_blocks * s.f_frsize, free_bytes=s.f_bfree * s.f_frsize,
            avail_bytes=s.f_bavail * s.f_frsize, files=s.f_files, files_free=s.f_ffree,
            readonly=int('ro' in row['options'] or 'ro' in row['superOptions']), device_error=0)
    memory = Path('/proc/meminfo').read_text()
    match = re.search(r'(?m)^MemTotal:\s+(\d+) kB$', memory)
    if not match:
        raise Refusal('native memory counter unavailable')
    cpus, tick = {}, os.sysconf('SC_CLK_TCK')
    modes = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal')
    for line in Path('/proc/stat').read_text().splitlines():
        fields = line.split()
        if fields and re.fullmatch(r'cpu\d+', fields[0]):
            values = list(map(int, fields[1:]))
            if len(values) < 8:
                raise Refusal('incomplete native CPU counters')
            # Linux /proc/stat user/nice include guest; procfs.Stat matches it.
            cpus[fields[0][3:]] = dict(zip(modes, (v / tick for v in values[:8])))
    if not cpus:
        raise Refusal('native CPU counters unavailable')
    return dict(start=start, end=time.monotonic(), mountinfoSha256=sha(body),
                nativeDevices=devices, filesystems=filesystems, memTotalBytes=int(match[1]) * 1024, cpus=cpus)


def metric_rows(text):
    if len(text.encode()) > 32 * 1024 * 1024:
        raise Refusal('projected metrics exceed bound')
    result = {}
    label = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\[\\"n])*)"(?:,|$)')
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        m = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)', line)
        if not m:
            raise Refusal('invalid projected exposition')
        labels, pos = {}, 0
        for item in label.finditer(m[2] or ''):
            if item.start() != pos or item[1] in labels:
                raise Refusal('ambiguous metric labels')
            labels[item[1]] = json.loads('"' + item[2].replace('\\n', '\\n') + '"')
            pos = item.end()
        if pos != len(m[2] or ''):
            raise Refusal('invalid metric labels')
        value = float(m[3])
        if not math.isfinite(value):
            raise Refusal('nonfinite projected metric')
        key = (m[1], tuple(sorted(labels.items())))
        if key in result:
            raise Refusal('duplicate projected metric')
        result[key] = value
    return result


def compare_metrics(projected, before, after):
    """Fail-closed bounded real-host comparison; no relabeling or metric hiding.

    Root/stack labels, readonly, size and inode totals are exact. Dynamic free
    bytes/inodes use bracketing values plus fixed maximum drift (64MiB/4096).
    CPU uses bracket values +/- 1 tick, max 10s collection window. Samples must
    be a direct fresh exporter projection, without Prometheus-added labels.
    """
    if (not before['start'] <= before['end'] <= after['start'] <= after['end']
            or after['end'] - before['start'] > 10
            or before['mountinfoSha256'] != after['mountinfoSha256']
            or before['nativeDevices'] != after['nativeDevices']
            or before['memTotalBytes'] != after['memTotalBytes']
            or set(before['cpus']) != set(after['cpus'])):
        raise Refusal('host comparison window/identity changed')
    rows = metric_rows(projected)
    consumed = set()
    def exact(name, labels):
        key = (name, tuple(sorted(labels.items())))
        if key not in rows:
            raise Refusal('missing exact host metric/labels')
        consumed.add(key)
        return rows[key]
    for path in ('/', '/mnt/stack'):
        a, b = before['filesystems'][path], after['filesystems'][path]
        for k in ('device', 'fstype', 'major', 'minor', 'readonly', 'size_bytes', 'files'):
            if a[k] != b[k]:
                raise Refusal('filesystem identity/geometry/options changed')
        labels = dict(device=a['device'], fstype=a['fstype'], mountpoint=path, device_error='')
        for suffix in FS_METRICS:
            v = exact('node_filesystem_' + suffix, labels)
            delta = 64 * 1024 * 1024 if suffix in ('free_bytes', 'avail_bytes') else (4096 if suffix == 'files_free' else 0)
            if v < 0 or not min(a[suffix], b[suffix]) - delta <= v <= max(a[suffix], b[suffix]) + delta:
                raise Refusal('filesystem value differs from native host')
        if exact('node_filesystem_mount_info', dict(device=a['device'], major=a['major'], minor=a['minor'], mountpoint=path)) != 1:
            raise Refusal('native mount identity metric differs')
        # v1.10.2 may emit the common collector's zero Linux purgeable field.
        key = ('node_filesystem_purgeable_bytes', tuple(sorted(labels.items())))
        if key in rows and exact(key[0], labels) != 0:
            raise Refusal('unsupported native purgeable byte value')
    if exact('node_memory_MemTotal_bytes', {}) != before['memTotalBytes']:
        raise Refusal('memory is not the native host total')
    for cpu, modes in before['cpus'].items():
        for mode, low in modes.items():
            high = after['cpus'][cpu][mode]
            value = exact('node_cpu_seconds_total', dict(cpu=cpu, mode=mode))
            if high < low or not low - 0.01 <= value <= high + 0.01:
                raise Refusal('CPU counter not within native host bracket')
    for key in rows:
        if (key[0].startswith('node_filesystem_') or key[0] in ('node_cpu_seconds_total', 'node_memory_MemTotal_bytes')) and key not in consumed:
            raise Refusal('unexpected host filesystem/CPU/memory labels or metric')
    return dict(checked=True, proof='real-runtime-comparison-only', mountpoints=['/', '/mnt/stack'],
                cpuCount=len(before['cpus']), maxWindowSeconds=10, maxFreeByteDrift=64 * 1024 * 1024,
                maxFreeInodeDrift=4096)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('prepare', 'validate'):
        cmd = sub.add_parser(command)
        cmd.add_argument('--bundle', type=Path, required=True)
        if command == 'validate':
            cmd.add_argument('--expected-proof', type=Path)
    cmd = sub.add_parser('probe')
    cmd.add_argument('--metrics', type=Path, required=True)
    cmd.add_argument('--before', type=Path, required=True)
    cmd.add_argument('--after', type=Path, required=True)
    sub.add_parser('snapshot')
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            result = prepare(args.bundle)
        elif args.command == 'validate':
            expected = strict(args.expected_proof.read_bytes()) if args.expected_proof else None
            result = validate(args.bundle, expected)
        elif args.command == 'snapshot':
            result = snapshot()
        else:
            result = compare_metrics(args.metrics.read_text(), strict(args.before.read_bytes()), strict(args.after.read_bytes()))
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        parser.exit(1, 'host metrics view/probe refused; no activation authorized\n')


if __name__ == '__main__':
    main()
