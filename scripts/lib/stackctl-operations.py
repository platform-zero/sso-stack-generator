#!/usr/bin/env python3
"""Exact-selection native start/stop/verify, not application acceptance.

Only the marker-bound standalone host profile is supported. Managed roles,
lanes and experimental venues are deliberately not adopted. `verify` emits CAS
proof even when native health is false; pass all four proof fields explicitly
on start/stop. Failed/pending installs can be stopped but never started here:
recovery/approval remains with the canonical installer and journal tooling.
"""
import argparse
from contextlib import contextmanager, nullcontext
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time

# Dynamic journal/role imports must not create root-owned interpreter caches.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 8 * 1024 * 1024
COMMON_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Job', 'FragmentPath',
                     'SourcePath', 'DropInPaths', 'UnitFileState', 'Requires', 'Wants',
                     'BindsTo', 'ConsistsOf', 'BoundBy', 'PropagatesStopTo', 'RefuseManualStart')
SERVICE_PROPERTIES = ('Result', 'Type', 'ExecMainStatus', 'ExecMainCode',
                      'ExecMainStartTimestampMonotonic')
PROPERTIES = COMMON_PROPERTIES + SERVICE_PROPERTIES


def journal_module():
    spec = importlib.util.spec_from_file_location('stackctl_operations_journal',
        ROOT / 'runtime-generator/podman-ops/install-journal.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def info(path):
    return path.lstat()


@contextmanager
def opened_directory(path, owner=0, storage=None):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute canonical authority required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        parts = path.parts[1:]
        for index in range(len(parts) + 1):
            value = os.fstat(fd)
            final = index == len(parts)
            # Root-owned sticky ancestors permit isolated temp fixtures,
            # never a writable authority directory itself. Walking dirfds
            # with O_NOFOLLOW prevents ancestor replacement/link races.
            sticky = not final and value.st_uid == 0 and value.st_mode & stat.S_ISVTX
            component = Path('/', *parts[:index])
            if storage is not None and component in storage.parents:
                storage.check_parent(fd, component, value)
            elif (not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, owner)
                    or (value.st_mode & 0o022 and not sticky)
                    or (final and value.st_uid != owner)):
                raise ValueError('Untrusted authority ancestor')
            if storage is not None and component in storage.private:
                uid, gid = storage.private[component]
                if (value.st_uid != uid or value.st_gid != gid
                        or stat.S_IMODE(value.st_mode) != 0o700):
                    raise ValueError('Private actor root ownership drift')
            if not final:
                child = os.open(parts[index], flags, dir_fd=fd)
                os.close(fd)
                fd = child
        yield fd
    finally:
        os.close(fd)


def chain(path, owner=0, storage=None):
    with opened_directory(path, owner, storage):
        pass


def body(path, owner=0, private=False, ancestor_owner=None, storage=None):
    with opened_directory(path.parent, owner if ancestor_owner is None else ancestor_owner, storage) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            value = os.fstat(fd)
            if (not stat.S_ISREG(value.st_mode) or value.st_uid != owner
                    or value.st_nlink != 1 or value.st_mode & 0o022
                    or (private and stat.S_IMODE(value.st_mode) != 0o600)
                    or value.st_size > LIMIT):
                raise ValueError('Untrusted authority file')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                result = source.read(LIMIT + 1)
            if len(result) > LIMIT:
                raise ValueError('Oversized authority file')
            return result
        finally:
            os.close(fd)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def decode(value):
    def pairs(rows):
        result = {}
        for key, item in rows:
            if key in result:
                raise ValueError('Duplicate authority key')
            result[key] = item
        return result
    result = json.loads(value, object_pairs_hook=pairs)
    if not isinstance(result, dict):
        raise ValueError('Authority object required')
    return result


def load(path, owner=0, private=False):
    return decode(body(path, owner, private))


@contextmanager
def installer_lock(root):
    if os.geteuid() != 0:
        raise ValueError('Root required')
    # Existing lock only: verify does not create state. Same inode/flock as
    # install-podman-bundle.sh, with hardlinks additionally forbidden.
    with opened_directory(root) as parent:
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise ValueError('Private metadata root required')
        fd = os.open('.install.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0
                or stat.S_IMODE(value.st_mode) != 0o600 or value.st_nlink != 1):
            raise ValueError('Untrusted installer lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if info(root / '.install.lock').st_ino != value.st_ino:
            raise ValueError('Installer lock replaced')
        yield (value.st_dev, value.st_ino, fd)
        selected_lock = info(root / '.install.lock')
        if (selected_lock.st_dev, selected_lock.st_ino) != (value.st_dev, value.st_ino):
            raise ValueError('Installer lock replaced during operation')
    finally:
        os.close(fd)


def pointer(path, expected, owner=0, storage=None):
    # current is the sole intentional symlink exception, never an authority
    # file. Its literal target must name the exact immutable release.
    with opened_directory(path.parent, owner, storage) as parent:
        fd = os.open(path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            value = os.fstat(fd)
            if (not stat.S_ISLNK(value.st_mode) or value.st_uid not in (0, owner)
                    or value.st_nlink != 1 or os.readlink(path.name, dir_fd=parent) not in (str(expected), 'releases/' + expected.name)):
                raise ValueError('Selected pointer mismatch')
        finally:
            os.close(fd)
    chain(expected, owner, storage)


def acl_entries(fd):
    """Read the pinned inode's numeric access ACL, never a substituted pathname."""
    result = subprocess.run(['/usr/bin/getfacl', '-cpn', '--', '/proc/self/fd/' + str(fd)],
        capture_output=True, text=True, timeout=10, pass_fds=(fd,), cwd='/',
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    if result.returncode or len(result.stdout) > LIMIT:
        raise ValueError('Storage ACL proof unavailable')
    entries = {}
    for line in result.stdout.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        if (len(fields) != 3 or fields[0] not in ('user', 'group', 'mask', 'other')
                or (fields[1] and not fields[1].isdigit())
                or not re.fullmatch(r'[r-][w-][x-]', fields[2])
                or tuple(fields[:2]) in entries):
            raise ValueError('Unknown/default/duplicate storage ACL')
        entries[tuple(fields[:2])] = fields[2]
    return entries


class StorageAuthority:
    """Narrow marker-bound traversal exception, not ownership of scope contents.

    Root-controlled ancestors remain mandatory above scope. Only exact parents
    of selected private roots may retain operator/group write and execute ACLs.
    App data (including root/mapped owners and public trust files) is not read.
    """
    def __init__(self, binding):
        self.scope = Path(binding['scope']['root'])
        if (not self.scope.is_absolute() or '..' in self.scope.parts
                or str(self.scope) != binding['scope']['root'] or self.scope == Path('/')):
            raise ValueError('Noncanonical selected scope')
        self.parents, self.private, self.pins = {self.scope: set()}, {}, {}
        self.required_users = {}
        owner = info(self.scope).st_uid
        operator = pwd.getpwuid(owner)
        self.operator = owner
        self.groups = {0, operator.pw_gid}
        # The declared operator-owned lab scope may use the dedicated stack
        # group rather than the operator's primary group. This is not a grant
        # to arbitrary supplementary/foreign groups; canonical binding above
        # must also admit the same explicit authority.
        try:
            self.groups.add(grp.getgrnam('stack').gr_gid)
        except KeyError:
            pass
        for row in binding['domains']:
            account = pwd.getpwnam(row['user'])
            if account.pw_uid != row['uid'] or account.pw_uid == owner:
                raise ValueError('Storage actor identity drift')
            # Existing journal helper validates exact, disjoint UID/GID ranges.
            start = journal_module().offline_subordinate_start(row['user'])
            for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
                path = Path(row[key])
                if (not path.is_relative_to(self.scope) or path == self.scope
                        or '..' in path.parts or str(path) != row[key]):
                    raise ValueError('Private root escaped selected scope')
                if path in self.private:
                    raise ValueError('Duplicate private storage root')
                self.private[path] = (account.pw_uid, account.pw_gid)
                for parent in path.parents:
                    if not parent.is_relative_to(self.scope):
                        break
                    users = self.parents.setdefault(parent, set())
                    users.add(str(account.pw_uid))
                    self.required_users.setdefault(parent, set()).add(str(account.pw_uid))
                    if key == 'graphRoot':
                        users.add(str(start))
        roots = list(self.private)
        if (set(binding['roots']) != {str(path) for path in roots}
                or any(a != b and a.is_relative_to(b) for a in roots for b in roots)
                or set(self.private) & set(self.parents)):
            raise ValueError('Overlapping/unclaimed private storage roots')
        for path, (uid, _) in self.private.items():
            with opened_directory(path, uid, self) as fd:
                value = os.fstat(fd)
                self.pins[str(path)] = [value.st_dev, value.st_ino, value.st_uid,
                                       value.st_gid, stat.S_IMODE(value.st_mode)]

    def check_parent(self, fd, path, value):
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid not in (0, self.operator)
                or value.st_gid not in self.groups or value.st_mode & 0o007
                or value.st_mode & (stat.S_ISVTX | stat.S_ISUID)
                or not value.st_mode & stat.S_IRUSR or not value.st_mode & stat.S_IXUSR):
            raise ValueError('Untrusted selected storage parent')
        acl = acl_entries(fd)
        base = {('user', ''), ('group', ''), ('other', '')}
        if not base.issubset(acl) or acl[('other', '')] != '---':
            raise ValueError('Storage base ACL drift')
        if any(key not in base | {('mask', '')} and
               (key[0] != 'user' or key[1] not in self.parents[path] or permissions != '--x')
               for key, permissions in acl.items()):
            raise ValueError('Foreign or broadened storage ACL')
        if acl[('group', '')] not in ('---', '--x', 'r-x', 'rwx') or acl[('user', '')] != 'rwx':
            raise ValueError('Storage owner/group ACL drift')
        named = {key[1] for key in acl if key[0] == 'user' and key[1]}
        if not self.required_users.get(path, set()).issubset(named):
            raise ValueError('Missing selected actor traversal ACL')
        if named and ('x' not in acl.get(('mask', ''), '')
                      or (acl[('group', '')] == 'rwx' and acl.get(('mask', '')) != 'rwx')):
            raise ValueError('Storage traversal ACL mask drift')
        # Pin ownership, mode, inode and complete ACL to lifecycle CAS.
        self.pins[str(path)] = [value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                               stat.S_IMODE(value.st_mode), sorted(':'.join(k) + ':' + v for k, v in acl.items())]


def selected(root, journal):
    chain(root / 'releases')
    intent_bytes = body(root / '.install-intent.json', private=True)
    intent = decode(intent_bytes)
    release = Path(intent.get('release', ''))
    if (release.parent != root / 'releases' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', release.name)
            or intent.get('schemaVersion') != 1 or intent.get('phase') not in journal.PHASES):
        raise ValueError('Unrecognized selected installation')
    pointer(root / 'current', release)
    receipt_bytes = body(release / 'installation-receipt.json', private=True)
    if receipt_bytes != intent_bytes or decode(receipt_bytes) != intent:
        raise ValueError('Receipt and intent differ')
    pins = intent.get('inputs')
    if not isinstance(pins, dict) or set(pins) != set(journal.CORE_INPUTS + journal.PINNED_INPUTS):
        raise ValueError('Expanded immutable input pins required')
    for name, expected in pins.items():
        path = release / name
        if expected is None:
            if path.exists() or path.is_symlink():
                raise ValueError('Absent pinned input appeared')
            # A missing file does not excuse a linked parent directory.
            parent = path.parent
            while not parent.exists() and not parent.is_symlink():
                parent = parent.parent
            chain(parent)
        elif not isinstance(expected, str) or sha(body(path)) != expected:
            raise ValueError('Immutable input pin changed')
    metadata = load(release / 'podman-domains.json')
    manifest = load(release / 'site/manifest.json')
    if (type(metadata.get('schemaVersion')) is not int or metadata['schemaVersion'] != 1
            or metadata.get('deploymentMode') != 'standalone' or 'venue' in metadata
            or manifest.get('deploymentMode') != 'standalone'
            or metadata.get('installerStateRoot') != str(root)
            or manifest.get('installerStateRoot', '/var/lib/webservices') != str(root)
            or 'agentVmSpec' in manifest):
        raise ValueError('Only explicit standalone host installation supported')
    binding = journal.standalone_binding(release)  # Existing marker/role/ACL gate, read-only.
    if (binding.get('scope') != metadata.get('storageScope')
            or binding.get('scope') != manifest.get('storageScope')):
        raise ValueError('Selected storage marker mismatch')
    storage = StorageAuthority(binding)
    marker = Path(binding['scope']['root']) / '.stack-installation.json'
    marker_bytes = body(marker, private=True, storage=storage)
    if decode(marker_bytes) != binding:
        raise ValueError('Storage marker changed')
    return release, intent, metadata, binding, {
        'selectedRelease': release.name, 'intentSha256': sha(intent_bytes),
        'receiptSha256': sha(receipt_bytes), 'markerSha256': sha(marker_bytes)}, storage


def command_for(account):
    return ['/usr/sbin/runuser', '-u', account.pw_name, '--', '/usr/bin/env', '-i',
            'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C', 'LC_ALL=C', 'HOME=' + account.pw_dir, 'XDG_RUNTIME_DIR=/run/user/' + str(account.pw_uid),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(account.pw_uid) + '/bus',
            '/usr/bin/systemctl', '--user']


def runtime_env_unit(source_dir, runtime_dir):
    """Exact install_runtime_env_unit template; never inspect environment data."""
    return ('[Unit]\nDescription=Restore rendered webservices environment files\n\n'
            '[Service]\nType=oneshot\nWorkingDirectory=/\n'
            f"ExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 {runtime_dir}; "
            f'for env_file in {source_dir}/*.env; do [ -e "$env_file" ] || continue; '
            f'/usr/bin/install -m 0600 "$env_file" {runtime_dir}/; done\'\n'
            'RemainAfterExit=yes\n').encode()


RUNTIME_DROPIN = b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n'


def runtime_api(release):
    """Execute only the protected selected-release, fully pinned ops closure.

    Missing historical ops pins are NOT authority to import repository code or
    to fall back to an installer template for a cold restart.
    """
    pins = load(release / 'bundle.json').get('liveOps')
    if not isinstance(pins, dict) or not pins:
        raise ValueError('Selected runtime operations pins unavailable; cold restart unsupported')
    sources = {}
    for name, digest in sorted(pins.items()):
        if (not isinstance(name, str) or not re.fullmatch(r'ops/[A-Za-z0-9_.-]+', name)
                or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)):
            raise ValueError('Unknown selected operations pin')
        data = body(release / name)
        if sha(data) != digest:
            raise ValueError('Selected operations source drift')
        sources[name] = data
    chain(release / 'ops')
    if {'ops/' + path.name for path in (release / 'ops').iterdir()} != set(sources):
        raise ValueError('Unpinned selected operations closure')
    name = 'ops/native-runtime-env-units.py'
    if name not in sources:
        raise ValueError('Canonical runtime unit source unavailable')
    path = release / name
    spec = importlib.util.spec_from_file_location('stackctl_selected_runtime_units', path)
    module = importlib.util.module_from_spec(spec)
    # Compile the verified bytes, not a second unpinned pathname/pyc read.
    exec(compile(sources[name], str(path), 'exec'), module.__dict__)
    for name, data in sources.items():
        if body(release / name) != data:
            raise ValueError('Selected operations closure changed during import')
    return module


def plans(root, release, metadata, binding, storage=None, runtime_owner=None, custody=None):
    """Enumerate exact generated names; never discover by a live wildcard."""
    if storage is None:
        storage = StorageAuthority(binding)
    storage = storage or StorageAuthority(binding)
    rows = metadata.get('domains')
    if not isinstance(rows, list) or not rows:
        raise ValueError('Missing selected domains')
    bound = {row['name']: row for row in binding['domains']}
    if len(bound) != len(rows):
        raise ValueError('Marker domain count mismatch')
    actors = [('rootful', ['/usr/bin/systemctl'], 0, Path('/etc/containers/systemd'),
               Path('/etc/systemd/system'), release)]
    names, users, uids = set(), set(), set()
    for row in rows:
        name, user, uid = row['name'], row['user'], row['uid']
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name)
                or not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                or type(uid) is not int or uid <= 0
                or name in names or user in users or uid in uids):
            raise ValueError('Invalid selected domain')
        names.add(name); users.add(user); uids.add(uid)
        if {key: row[key] for key in bound[name]} != bound[name]:
            raise ValueError('Marker identity mismatch')
        account = pwd.getpwnam(user)
        if account.pw_uid != uid or account.pw_dir != '/home/' + user:
            raise ValueError('Selected account identity drift')
        actor_release = Path(row['stateRoot']) / 'releases' / release.name
        pointer(Path(row['stateRoot']) / 'current', actor_release, uid, storage)
        home = Path(account.pw_dir)
        actors.append(('rootless-' + name, command_for(account), uid,
                       home / '.config/containers/systemd', home / '.config/systemd/user', actor_release))
    ir = load(release / 'stack.ir.json')
    services = ir.get('services')
    if not isinstance(services, dict) or not services:
        raise ValueError('Missing selected service metadata')
    result = []
    for label, command, uid, quadlet_dir, systemd_dir, actor_release in actors:
        source = release / 'quadlet' / label
        chain(source)
        units = {}
        for path in sorted(source.iterdir()):
            suffix = path.suffix
            # The owning generator emits these four kinds only. In particular
            # do not invent volume-unit stop semantics that could delete data.
            if suffix not in ('.container', '.build', '.network', '.target'):
                raise ValueError('Unknown selected quadlet artifact')
            data = body(path)
            if not re.fullmatch(r'webservices(?:-[a-zA-Z0-9_.@-]+)?', path.stem):
                raise ValueError('Unowned selected unit namespace')
            unit = path.stem + {'.container': '.service', '.build': '-build.service',
                '.network': '-network.service', '.target': '.target'}[suffix]
            if unit in units:
                raise ValueError('Duplicate generated unit identity')
            installed = (systemd_dir if suffix == '.target' else quadlet_dir) / path.name
            if body(installed, uid) != data:
                raise ValueError('Installed selected unit differs from immutable source')
            if suffix in ('.container', '.build'):
                service = services.get(path.stem.removeprefix('webservices-'))
                expected_label = ('rootless-' + service['rootlessDomain']
                                  if service and service.get('rootlessDomain') else 'rootful')
                if not service or expected_label != label:
                    raise ValueError('Unit service/role metadata mismatch')
                lifecycle = service.get('lifecycle', 'daemon') if suffix == '.container' else 'producer'
                if lifecycle not in ('daemon', 'oneshot', 'on-demand', 'producer'):
                    raise ValueError('Unknown native service lifecycle')
                if suffix == '.build' and service.get('frozenBuildImage') is not None:
                    frozen = service['frozenBuildImage']
                    if (not isinstance(frozen, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', frozen)
                            or b'[Unit]\nRefuseManualStart=yes\n' not in data):
                        raise ValueError('Frozen producer lacks its canonical inert gate')
                    lifecycle = 'inert-producer'
            else:
                lifecycle = 'target' if suffix == '.target' else 'resource'
            units[unit] = {'lifecycle': lifecycle, 'sourcePath': str(installed),
                           'sha256': sha(data), 'generated': suffix != '.target'}
        if 'webservices.target' not in units:
            raise ValueError('Missing exact selected target')
        # These are canonical installer-owned adjuncts, not guessed patterns.
        runtime = systemd_dir / 'webservices-runtime-env.service'
        runtime_data = body(runtime, uid)
        source_dir = actor_release.parent.parent / 'runtime-env'
        runtime_dir = '/run/webservices' if uid == 0 else '/run/user/' + str(uid) + '/webservices'
        if custody is None:
            expected_runtime = runtime_env_unit(source_dir, runtime_dir)
        else:
            manifest = custody.get('roles', {}).get(label)
            if not isinstance(manifest, dict):
                raise ValueError('Selected runtime manifest missing exact role')
            expected_runtime = runtime_owner.render_unit(manifest)
            dropin = systemd_dir / 'webservices.target.d/10-runtime-env.conf'
            data = body(dropin, uid)
            if data != runtime_owner.render_dropin() or data != RUNTIME_DROPIN:
                raise ValueError('Selected runtime target dependency drift')
            units['webservices.target']['dropInSha256'] = sha(data)
        if runtime_data != expected_runtime:
            raise ValueError('Runtime restore service differs from canonical selected source')
        units[runtime.name] = {'lifecycle': 'oneshot', 'sourcePath': str(runtime),
                              'sha256': sha(runtime_data), 'generated': False}
        updater_absence = None
        if label == 'rootful':
            if custody is not None:
                # Emitted historical artifacts do not grant installed ownership.
                # New native installations own NO legacy updater/timer/wrapper.
                updater_absence = unconfigured_updaters(systemd_dir)
            else:
                for name in LEGACY_UPDATERS:
                    data = body(release / 'ops' / name)
                    if body(systemd_dir / name) != data:
                        raise ValueError('Selected activation trigger drift')
                    units[name] = {'lifecycle': 'trigger' if name.endswith('.timer') else 'on-demand',
                                  'sourcePath': str(systemd_dir / name), 'sha256': sha(data), 'generated': False}
        else:
            # Dedicated marker-bound accounts only. Never the operator's API.
            for name in ('podman.socket', 'podman.service'):
                path = Path('/usr/lib/systemd/user') / name
                units[name] = {'lifecycle': 'trigger' if name.endswith('.socket') else 'on-demand',
                              'sourcePath': str(path), 'sha256': sha(body(path)), 'generated': False}
        configuration = {}
        if uid != 0:
            row = next(row for row in rows if row['uid'] == uid)
            configs = {
                'storage.conf': f'[storage]\ndriver = "overlay"\ngraphroot = "{row["graphRoot"]}"\n',
                'containers.conf': '[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n'}
            for name, expected in configs.items():
                path = quadlet_dir.parent / name
                data = body(path, uid, private=True)
                if data != expected.encode():
                    raise ValueError('Selected actor runtime configuration drift')
                configuration[str(path)] = sha(data)
        plan = {'role': label, 'command': command, 'uid': uid, 'units': units, 'configuration': configuration}
        if updater_absence is not None:
            plan['unconfiguredLegacyUpdaters'] = updater_absence
        result.append(plan)
    # Every ordinary managed service must have exactly one generated container.
    actual = {name for plan in result for name, unit in plan['units'].items()
              if unit['lifecycle'] in ('daemon', 'oneshot', 'on-demand')
              and unit['generated']}
    expected = {'webservices-' + name + '.service' for name, service in services.items()
                if service.get('lifecycle') != 'on-demand' or service.get('quadletManaged') is True or 'build' in service}
    if actual != expected:
        raise ValueError('Selected service coverage incomplete')
    return result


def run(command):
    # No inherited shell, arbitrary executable, environment inspection, or app
    # calls; output is parsed in memory and never printed (may contain paths).
    result = subprocess.run(command, cwd='/', capture_output=True, text=True, timeout=30,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
             'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'})
    if result.returncode or len(result.stdout) > LIMIT:
        raise ValueError('Exact native command failed')
    return result.stdout


LEGACY_UPDATERS = ('webservices-auto-update.timer', 'webservices-auto-update.service')
ABSENT_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Job', 'FragmentPath',
                     'SourcePath', 'DropInPaths', 'UnitFileState')


def unconfigured_updaters(systemd_dir):
    wrapper = Path('/usr/local/sbin/webservices-auto-update')
    for path in [systemd_dir / name for name in LEGACY_UPDATERS] + [wrapper]:
        chain(path.parent)
        try:
            info(path)
        except FileNotFoundError:
            continue
        raise ValueError('Native updater namespace already occupied; owning disposition required')
    text = run(['/usr/bin/systemctl', 'show', *LEGACY_UPDATERS,
                *sum((['-p', p] for p in ABSENT_PROPERTIES), [])])
    result = {}
    for block in text.strip().split('\n\n'):
        pairs = [line.split('=', 1) for line in block.splitlines()]
        if (any(len(row) != 2 for row in pairs) or len(pairs) != len(ABSENT_PROPERTIES)
                or {row[0] for row in pairs} != set(ABSENT_PROPERTIES)):
            raise ValueError('Incomplete updater absence observation')
        row = dict(pairs); name = row['Id']
        if (name not in LEGACY_UPDATERS or name in result or row['LoadState'] != 'not-found'
                or row['ActiveState'] != 'inactive' or row['SubState'] != 'dead'
                or row['Job'] not in ('', '0') or row['FragmentPath'] or row['SourcePath']
                or row['DropInPaths'] or row['UnitFileState'] not in ('', 'not-found')):
            raise ValueError('Native updater is configured/active/unknown; no ownership adopted')
        result[name] = row
    if set(result) != set(LEGACY_UPDATERS):
        raise ValueError('Incomplete updater absence scope')
    return result


def states(plan):
    names = sorted(plan['units'])
    text = run(plan['command'] + ['show', '--all', *names, *sum((['-p', p] for p in PROPERTIES), [])])
    result = {}
    for block in text.strip().split('\n\n'):
        row = {}
        for line in block.splitlines():
            if '=' not in line:
                raise ValueError('Malformed native unit state')
            key, value = line.split('=', 1)
            if key in row or key not in PROPERTIES:
                raise ValueError('Duplicate/unknown native property')
            row[key] = value
        name = row.get('Id')
        if name not in plan['units'] or name in result:
            raise ValueError('Foreign/duplicate native unit state')
        required = set(COMMON_PROPERTIES)
        if name.endswith('.service'):
            required.update(SERVICE_PROPERTIES)
        elif name.endswith(('.socket', '.timer')):
            required.add('Result')
        if not required.issubset(row):
            raise ValueError('Incomplete native unit state')
        # Service-only D-Bus properties do not exist on targets/sockets/timers;
        # missing service properties are NOT tolerated for actual services.
        row = dict.fromkeys(PROPERTIES, '') | row
        unit = plan['units'][name]
        if row['LoadState'] != 'loaded':
            raise ValueError('Selected unit not loaded')
        if row['DropInPaths']:
            # Only the installer target/runtime-env dependency drop-in exists
            # without a separate receipt. Its bytes are included in plan CAS.
            expected = str(Path(unit['sourcePath']).parent / 'webservices.target.d/10-runtime-env.conf')
            if name != 'webservices.target' or row['DropInPaths'] != expected:
                raise ValueError('Unreceipted native unit override')
            dropin = body(Path(expected), plan['uid'])
            if dropin != RUNTIME_DROPIN:
                raise ValueError('Runtime dependency override differs from installer')
            unit['dropInSha256'] = sha(dropin)
        if unit['generated']:
            if row['SourcePath'] != unit['sourcePath']:
                raise ValueError('Native source path differs from selected unit')
            generator = (Path('/run/systemd/generator') if plan['uid'] == 0 else
                         Path('/run/user') / str(plan['uid']) / 'systemd/generator')
            if row['FragmentPath'] != str(generator / name):
                raise ValueError('Native generated fragment escaped manager')
            unit['fragmentSha256'] = sha(body(generator / name, plan['uid']))
        elif row['FragmentPath'] != unit['sourcePath'] or row['SourcePath']:
            raise ValueError('Native unit fragment differs from selected authority')
        # Reverse stop propagation may not affect any unselected unit; forward
        # activation may only include selected units or inert manager targets.
        for prop in ('ConsistsOf', 'BoundBy', 'PropagatesStopTo'):
            if set(row[prop].split()) - set(names):
                raise ValueError('Stop would propagate outside selected scope')
        for prop in ('Requires', 'Wants', 'BindsTo'):
            external = set(row[prop].split()) - set(names)
            if external - {'basic.target', 'sysinit.target', 'sockets.target',
                           'network-online.target', 'network.target', 'local-fs.target',
                           'system.slice', 'app.slice', 'user.slice'}:
                raise ValueError('Activation dependency outside selected scope')
        result[name] = row
    if set(result) != set(names):
        raise ValueError('Native unit count mismatch')
    return result


def healthy(unit, row):
    if row['LoadState'] != 'loaded' or row['Job'] not in ('', '0'):
        return False
    kind = unit['lifecycle']
    success = row['Result'] in ('', 'success')
    if kind == 'inert-producer':
        return row['ActiveState'] == 'inactive' and success and row['RefuseManualStart'] == 'yes'
    if kind == 'trigger' and unit['sourcePath'].endswith('.socket'):
        return row['ActiveState'] == 'active' and row['SubState'] == 'listening' and success
    if kind in ('trigger', 'on-demand'):
        return row['ActiveState'] in ('active', 'inactive') and success
    if kind == 'daemon':
        return (row['ActiveState'] == 'active' and row['SubState'] == 'running'
                and row['Type'] in ('simple', 'exec', 'forking', 'notify', 'notify-reload', 'dbus', 'idle')
                and success)
    if kind in ('oneshot', 'producer') or (kind == 'resource' and row['Type'] == 'oneshot'):
        # Inactive/success alone is the initial, never-executed oneshot state.
        return (row['Type'] == 'oneshot' and row['ActiveState'] in ('active', 'inactive')
                and row['Result'] == 'success' and row['ExecMainStatus'] == '0'
                and row['ExecMainCode'] == '1'
                and row['ExecMainStartTimestampMonotonic'].isdigit()
                and int(row['ExecMainStartTimestampMonotonic']) > 0)
    return row['ActiveState'] == 'active' and success


def snapshot(root, journal, transition=None):
    release, intent, metadata, binding, proof, storage = selected(root, journal)
    custody = intent.get('nativeRuntimeEnvUnitCustody')
    runtime = runtime_api(release) if custody is not None else None
    selected_plans = plans(root, release, metadata, binding, storage, runtime, custody)
    observed = []
    for plan in selected_plans:
        actor = journal.offline_actor(release, plan['role'])
        plan['offlineManagerStopped'] = actor is not None
        if actor is not None:
            expected_actor = next(row for row in binding['domains']
                                  if 'rootless-' + row['name'] == plan['role'])
            if any(actor.get(key) != value for key, value in expected_actor.items()):
                raise ValueError('Offline actor differs from selected marker')
            journal.verify_offline_actor(actor, plan['command'])
            # Do not query a stopped manager or fabricate loaded/healthy unit
            # state. Canonical proof covers no linger, closed target/API,
            # exact actor/mapped processes and pending manager jobs.
            observed.append({name: dict.fromkeys(PROPERTIES, '') | {
                'LoadState': 'unobserved', 'ActiveState': 'unobserved',
                'UnitFileState': 'unobserved'} for name in plan['units']})
        else:
            observed.append(states(plan))
    lock = info(root / '.install.lock')
    authority = {'plans': selected_plans, 'storageAuthority': storage.pins,
                 'markerSha256': proof['markerSha256'],
                 'lockIdentity': [lock.st_dev, lock.st_ino],
                 'selectedPointer': os.readlink(root / 'current')}
    proof['planSha256'] = sha(json.dumps(authority, sort_keys=True, separators=(',', ':')).encode())
    if transition is not None:
        comparison = dict(authority, plans=transition.normalize(selected_plans))
        transition.comparison_sha = sha(json.dumps(comparison, sort_keys=True, separators=(',', ':')).encode())
    return release, intent, proof, selected_plans, observed


def check_expected(proof, expected):
    for key in ('selectedRelease', 'intentSha256', 'receiptSha256', 'planSha256'):
        if not expected.get(key) or expected[key] != proof[key]:
            raise ValueError('Exact selected release/receipt/plan CAS required')


def seal_failure(root, release, intent, journal):
    # Use the existing journal, never a parallel operation daemon or approval
    # record. A terminal safety failure is not startable through this backend.
    current = load(root / '.install-intent.json', private=True)
    if (current != intent or load(release / 'installation-receipt.json', private=True) != intent):
        raise ValueError('Safety failure journal CAS changed')
    pointer(root / 'current', release)
    if intent['phase'] not in ('failed', 'retired-failed'):
        failed = dict(intent, phase='failed', steps=intent.get('steps', []) + ['failed'])
        journal.write(release / 'installation-receipt.json', failed)
        journal.write(root / '.install-intent.json', failed)


def checked_snapshot(root, journal, proof, transition=None):
    fresh = snapshot(root, journal, transition)
    comparison = fresh[2] if transition is None else dict(fresh[2], planSha256=transition.comparison_sha)
    check_expected(comparison, proof)
    return fresh


@contextmanager
def canonical_lock_fd(fd):
    """Lend the actual flock-owning open file description, NOT a fresh open."""
    installed = False
    try:
        if fd != 9:
            # Atomic lowest-free allocation: unlike check+dup2 this can NEVER
            # overwrite a descriptor that appeared between observation/use.
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 9)
            if duplicate != 9:
                os.close(duplicate)
                raise ValueError('Canonical FD9 occupied; refusing to replace caller descriptor')
            installed = True
        if (os.fstat(9).st_dev, os.fstat(9).st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
            raise ValueError('Canonical inherited lock descriptor differs')
        yield
    finally:
        if installed:
            os.close(9)


class ManagerTransition:
    """One-way exact selected UID transition, never a generic plan rebase."""
    def __init__(self, selected_plans):
        self.before = {p['role']: decode(json.dumps(p).encode()) for p in selected_plans
                       if p['offlineManagerStopped']}
        self.allowed = set()
        self.online = {}
        self.comparison_sha = None

    def normalize(self, selected_plans):
        result = []
        for plan in selected_plans:
            role = plan['role']
            if role not in self.before or role not in self.allowed:
                result.append(plan)
                continue
            before = self.before[role]
            if plan['offlineManagerStopped']:
                if role in self.online:
                    raise ValueError('Selected manager stopped again during restart')
                result.append(plan)
                continue
            candidate = decode(json.dumps(plan).encode())
            candidate['offlineManagerStopped'] = True
            for name, unit in candidate['units'].items():
                # ONLY newly generated runtime fragments may appear. Installed
                # sources, drop-ins, configs, command/UID and graph stay exact.
                if unit['generated']:
                    unit.pop('fragmentSha256', None)
            if candidate != before:
                raise ValueError('Source or scope changed across selected manager transition')
            if role in self.online and self.online[role] != plan:
                raise ValueError('Regenerated selected fragment drift')
            self.online[role] = decode(json.dumps(plan).encode())
            result.append(before)
        return result


MANAGER_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Job',
                      'Result', 'FragmentPath', 'DropInPaths', 'ControlGroup')


LOGIN_BARRIER_PATH = '/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf'
LOGIN_BARRIER_SHA256 = '1c1452839b609b0609cccaba3c648d780372df6f244deb487da6da5ee002a993'
LOGIN_BARRIER_BODY = b'''#  SPDX-License-Identifier: LGPL-2.1-or-later
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

[Unit]
# Make sure user instances are started after logins are allowed. However this
# is not desirable for user@0.service since root should be able to log in
# earlier during the boot process especially if something goes wrong.
After=systemd-user-sessions.service
'''


def manager_source(path, expected_sha=None):
    """Pin a fixed root package source through held/named no-follow FDs.

    Caller paths are fixed reviewed constants, never discovered drop-ins. Full
    file and /usr ancestor pins make replacement, chmod/body ABA and races
    visible to the manager source-profile CAS, not merely its content hash.
    """
    package_root = Path('/usr')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def pin(fd, node, leaf=False):
        value = os.fstat(fd)
        packaged = node == package_root or node.is_relative_to(package_root)
        sticky = not leaf and not packaged and node != path.parent and value.st_mode & stat.S_ISVTX
        if (value.st_uid != 0 or value.st_gid != 0
                or (value.st_mode & 0o022 and not sticky)
                or value.st_mode & (stat.S_ISUID | stat.S_ISGID | (stat.S_ISVTX if packaged else 0))
                or (leaf and (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1
                              or stat.S_IMODE(value.st_mode) != 0o644 or value.st_size > LIMIT))
                or (not leaf and not stat.S_ISDIR(value.st_mode))):
            raise ValueError('Manager package source custody differs')
        for name in ('system.posix_acl_access', 'system.posix_acl_default'):
            try:
                os.getxattr(fd, name)
            except OSError as error:
                if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                    raise
            else:
                raise ValueError('Manager package source ACL present')
        result = [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink]
        if leaf or node == package_root or node.is_relative_to(package_root):
            result.extend((value.st_size, value.st_mtime_ns, value.st_ctime_ns))
        return result

    handles = []
    def capture():
        fd = os.open('/', flags); handles.append(fd)
        nodes = [(fd, Path('/'), False)]
        parent = Path('/')
        for part in path.parent.parts[1:]:
            # Validate the held parent BEFORE traversing each next edge.
            pin(fd, parent)
            fd = os.open(part, flags, dir_fd=fd); handles.append(fd)
            parent /= part
            nodes.append((fd, parent, False))
        pin(fd, parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        handles.append(fd); nodes.append((fd, path, True))
        return fd, nodes, [[str(node), pin(held, node, leaf)] for held, node, leaf in nodes]

    try:
        fd, nodes, original = capture()
        data = os.pread(fd, LIMIT + 1, 0)
        if len(data) != os.fstat(fd).st_size or len(data) > LIMIT:
            raise ValueError('Manager package source read changed')
        digest = sha(data)
        if expected_sha is not None and (digest != expected_sha or data != LOGIN_BARRIER_BODY):
            raise ValueError('Reviewed login barrier content differs')
        _, _, named = capture()
        if named != original or original != [[str(node), pin(held, node, leaf)] for held, node, leaf in nodes]:
            raise ValueError('Manager package source held/named/ancestry CAS changed')
        return {'path': str(path), 'sha256': digest, 'pins': original}
    finally:
        for fd in reversed(handles):
            os.close(fd)


def manager_state(uid):
    name = 'user@' + str(uid) + '.service'
    text = run(['/usr/bin/systemctl', 'show', name, *sum((['-p', p] for p in MANAGER_PROPERTIES), [])])
    pairs = [line.split('=', 1) for line in text.splitlines()]
    if (any(len(row) != 2 for row in pairs) or len(pairs) != len(MANAGER_PROPERTIES)
            or {row[0] for row in pairs} != set(MANAGER_PROPERTIES)):
        raise ValueError('Incomplete selected manager observation')
    row = dict(pairs)
    if (row['Id'] != name or row['LoadState'] != 'loaded'
            or row['FragmentPath'] != '/usr/lib/systemd/system/user@.service'
            or row['DropInPaths'] not in ('', LOGIN_BARRIER_PATH)):
        raise ValueError('Unowned selected manager template/override')
    template = manager_source(Path('/usr/lib/systemd/system/user@.service'))
    dropins = []
    if row['DropInPaths']:
        dropins.append(manager_source(Path(LOGIN_BARRIER_PATH), LOGIN_BARRIER_SHA256))
    row['templateSha256'] = template['sha256']
    row['sourceProfile'] = {'profile': 'systemd-user-login-barrier-v1' if dropins else 'systemd-user-no-dropins-v1',
                            'template': template, 'dropins': dropins}
    return row


def no_actor_logins(uid):
    sessions = json.loads(run(['/usr/bin/loginctl', 'list-sessions', '--json=short', '--no-pager']))
    if (not isinstance(sessions, list) or any(not isinstance(row, dict)
            or type(row.get('uid')) is not int or not isinstance(row.get('session'), str)
            or row['uid'] == uid for row in sessions)):
        raise ValueError('Selected actor login scope is not idle')


def offline_manager(row):
    if (row['ActiveState'] != 'inactive' or row['SubState'] != 'dead'
            or row['MainPID'] != '0' or row['Job'] not in ('', '0')
            or row['Result'] != 'success' or row['ControlGroup']):
        raise ValueError('Cold restart requires clean stopped manager, not failed boot/recovery')


def running_manager(row, uid):
    return (row['ActiveState'] == 'active' and row['SubState'] == 'running'
            and row['MainPID'].isdigit() and int(row['MainPID']) > 0
            and row['Job'] in ('', '0') and row['Result'] == 'success'
            and row['ControlGroup'] == '/user.slice/user-' + str(uid) + '.slice/user@' + str(uid) + '.service')


def boot_identity():
    value = body(Path('/proc/sys/kernel/random/boot_id')).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
        raise ValueError('Unknown selected boot identity')
    return value


def offline_boot_units(plan, journal):
    # Read-only offline unit-file inventory, NOT an all-unit lifecycle command.
    # Canonical stop disabled target/API already. Any remaining enabled unit
    # could run at user@ bootstrap before we can observe its live graph.
    text = run(journal.offline_control(plan['command']) + ['list-unit-files',
        '--state=enabled,enabled-runtime', '--no-legend', '--no-pager', '--plain'])
    if text.strip():
        raise ValueError('Unselected enabled actor boot units; cold shape unsupported')


BOOT_UNITS = ('default.target', 'basic.target', 'sockets.target', 'paths.target',
              'timers.target', 'dbus.socket', 'dbus.service')
BOOT_PROPERTIES = ('Id', 'LoadState', 'FragmentPath', 'SourcePath', 'DropInPaths', 'Requires', 'Wants', 'BindsTo')


def manager_boot_closure(plan):
    text = run(plan['command'] + ['show', *BOOT_UNITS, *sum((['-p', p] for p in BOOT_PROPERTIES), [])])
    result = {}
    allowed = set(BOOT_UNITS) | {'dbus-broker.service'} | set(plan['units'])
    for block in text.strip().split('\n\n'):
        pairs = [line.split('=', 1) for line in block.splitlines()]
        if (any(len(row) != 2 for row in pairs) or len(pairs) != len(BOOT_PROPERTIES)
                or {row[0] for row in pairs} != set(BOOT_PROPERTIES)):
            raise ValueError('Incomplete fixed manager boot closure')
        row = dict(pairs); name = row['Id']
        # The sole supported alias is the package-owned D-Bus implementation.
        canonical = 'dbus.service' if name == 'dbus-broker.service' else name
        if canonical not in BOOT_UNITS or canonical in result:
            raise ValueError('Foreign/duplicate manager boot identity')
        if (row['LoadState'] != 'loaded' or row['SourcePath'] or row['DropInPaths']
                or row['FragmentPath'] != '/usr/lib/systemd/user/' + name
                or any(set(row[key].split()) - allowed for key in ('Requires', 'Wants', 'BindsTo'))):
            raise ValueError('Unknown manager boot source/dependency/override')
        row['sha256'] = sha(body(Path(row['FragmentPath'])))
        result[canonical] = row
    if set(result) != set(BOOT_UNITS):
        raise ValueError('Incomplete fixed manager boot unit inventory')
    return result


class PreparedLifecycle:
    """Consume canonical full-source observations, never JSON start permits."""
    def __init__(self, root, release, intent, api):
        self.root, self.release, self.intent, self.api = root, release, intent, api
        self.boot = boot_identity()
        raw = body(root / '.install-intent.json', private=True)
        if decode(raw) != intent or body(release / 'installation-receipt.json', private=True) != raw:
            raise ValueError('Private lifecycle dual records differ')
        self.intent_sha = sha(raw)
        self.baseline = None
        self.managers = {}
        self.boot_closures = {}
        self.plans = {}
        if not callable(getattr(api, 'verify_prepared_units', None)):
            raise ValueError('Canonical pre-start runtime source observation API unavailable')
        self.verify_source()

    def verify_source(self, issued_copies=None):
        if boot_identity() != self.boot:
            raise ValueError('Boot changed during selected lifecycle')
        observed = self.api.verify_prepared_units(self.root, self.release, self.intent)
        # Fresh canonical filesystem observations, not stored start permits.
        if (not isinstance(observed, dict) or observed.get('schemaVersion') != 1
                or observed.get('kind') != 'native-prepared-runtime-env-unit-observation'
                or observed.get('status') != 'completed' or observed.get('release') != str(self.release)
                or observed.get('inputs') != self.intent['inputs']
                or observed.get('intentSha256') != self.intent_sha or observed.get('receiptSha256') != self.intent_sha
                or any(not isinstance(observed.get(key), str) or not re.fullmatch(r'[a-f0-9]{64}', observed[key])
                       for key in ('sourceSha256', 'copyCustodySha256', 'bindingSha256'))
                or any(observed.get(key) is not False for key in ('runningEnvironmentChecked', 'journalWritten',
                       'activationAuthorized', 'readinessAuthorized', 'resetAuthorized'))):
            raise ValueError('Canonical prepared source observation missing/incompatible')
        if self.baseline is None:
            self.baseline = decode(json.dumps(observed).encode())
        if issued_copies is not None:
            # The only permitted custody change is the actual Root issuer's
            # receipt publication. Keep the entire independent source/record
            # observation fixed; NEVER rebase source to accommodate cue writes.
            cues = {role: row['receipt'] for role, row in issued_copies.items()}
            cue_sha = sha((json.dumps(cues, sort_keys=True, separators=(',', ':')) + '\n').encode())
            stable = lambda row: {k: v for k, v in row.items() if k not in ('copyCustodySha256', 'bindingSha256')}
            if stable(observed) != stable(self.baseline) or observed['copyCustodySha256'] != cue_sha:
                raise ValueError('Root receipt publication changed source or differs from issued copies')
            self.baseline = decode(json.dumps(observed).encode())
        if observed != self.baseline:
            raise ValueError('Canonical prepared source custody changed')

    def admit_running(self, plan, current=None):
        uid = plan['uid']
        current = current or manager_state(uid)
        if not running_manager(current, uid):
            raise ValueError('Selected manager is not stably running')
        no_actor_logins(uid)
        self.managers[uid] = current
        self.plans[uid] = plan
        self.boot_closures[uid] = manager_boot_closure(plan)

    def guard(self):
        self.verify_source()
        for uid, expected in self.managers.items():
            no_actor_logins(uid)
            if manager_state(uid) != expected:
                raise ValueError('Selected manager PID/template/namespace closure changed')
            if manager_boot_closure(self.plans[uid]) != self.boot_closures[uid]:
                raise ValueError('Selected manager boot closure changed')

    def seal(self, proof, selected_plans):
        self.guard()
        observed = self.api.seal_running_copies(self.root, self.release, self.intent)
        if (not isinstance(observed, dict) or observed.get('schemaVersion') != 1
                or observed.get('kind') != 'root-runtime-copy-observation'
                or observed.get('status') != 'completed' or observed.get('release') != str(self.release)
                or observed.get('inputs') != self.intent['inputs'] or observed.get('bootId') != self.boot
                or observed.get('intentSha256') != proof['intentSha256']
                or observed.get('receiptSha256') != proof['receiptSha256']
                or not isinstance(observed.get('copies'), dict)
                or set(observed['copies']) != {p['role'] for p in selected_plans}
                or any(observed.get(key) is not False for key in
                       ('activationAuthorized', 'readinessAuthorized', 'resetAuthorized', 'journalWritten'))):
            raise ValueError('Fresh canonical Root runtime-copy observation differs')
        self.verify_source(issued_copies=observed['copies'])
        self.guard()
        return observed


def resume_managers(root, journal, proof, selected_plans, transition, lifecycle, deadline):
    offline = [p for p in selected_plans if p['offlineManagerStopped']]
    # Validate ALL exact actors before the first manager mutation. Failure is
    # not authority to repair/adopt an account or replay any previous source.
    initial = {}
    for plan in offline:
        checked_snapshot(root, journal, proof, transition)
        lifecycle.guard()
        no_actor_logins(plan['uid'])
        initial[plan['uid']] = manager_state(plan['uid'])
        offline_manager(initial[plan['uid']])
        offline_boot_units(plan, journal)
    for plan in offline:
        checked_snapshot(root, journal, proof, transition)
        lifecycle.guard()
        no_actor_logins(plan['uid'])
        if manager_state(plan['uid']) != initial[plan['uid']]:
            raise ValueError('Stopped manager drift before exact bootstrap')
        offline_boot_units(plan, journal)
        transition.allowed.add(plan['role'])
        # systemd owns user-runtime-dir/XDG regeneration through user@'s normal
        # dependency. No linger, enable, arbitrary UID, installer or shell.
        run(['/usr/bin/systemctl', 'start', 'user@' + str(plan['uid']) + '.service'])
        while True:
            lifecycle.verify_source()
            current = manager_state(plan['uid'])
            if (current['templateSha256'] != initial[plan['uid']]['templateSha256']
                    or current['sourceProfile'] != initial[plan['uid']]['sourceProfile']):
                raise ValueError('Selected manager template/source profile changed while starting')
            if running_manager(current, plan['uid']):
                lifecycle.admit_running(plan, current)
                break
            if (current['ActiveState'] not in ('activating', 'active')
                    or current['Result'] not in ('success', '') or time.monotonic() >= deadline):
                raise ValueError('Selected manager bootstrap failed or timed out')
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        fresh = checked_snapshot(root, journal, proof, transition)
        rows = next(rows for selected_plan, rows in zip(fresh[3], fresh[4])
                    if selected_plan['role'] == plan['role'])
        if (any(row['ActiveState'] != 'inactive' or row['Job'] not in ('', '0') for row in rows.values())
                or any(rows[name]['UnitFileState'] not in ('disabled', 'masked')
                       for name, unit in plan['units'].items()
                       if name == 'webservices.target' or unit['lifecycle'] == 'trigger')):
            raise ValueError('Selected units auto-activated or boot triggers escaped cold quarantine')
        lifecycle.guard()


def stop_selected(root, journal, proof, selected_plans, transition=None):
    failures = False
    for plan in selected_plans:
        checked_snapshot(root, journal, proof, transition)
        if plan['offlineManagerStopped']:
            # Already quarantined by the canonical journal proof; no user
            # manager/API/socket start and no blind offline file mutation.
            continue
        triggers = sorted(name for name, unit in plan['units'].items()
                          if unit['lifecycle'] == 'trigger')
        try:
            run(plan['command'] + ['disable', 'webservices.target', *triggers])
        except (OSError, ValueError, subprocess.SubprocessError):
            failures = True
        # A failed disable must not prevent a safe exact stop of this or the
        # other selected manager. Authority/CAS failure, in contrast, stops ALL
        # dispatch: it could now name somebody else's installation.
        checked_snapshot(root, journal, proof, transition)
        try:
            run(plan['command'] + ['stop', *sorted(plan['units'])])
        except (OSError, ValueError, subprocess.SubprocessError):
            failures = True
    if failures:
        raise ValueError('Exact selected stop/activation quarantine incomplete')


def stopped(selected_plans, observed):
    return all(plan['offlineManagerStopped'] or (
        all(row['ActiveState'] in ('inactive', 'failed') and row['Job'] in ('', '0')
            for row in rows.values())
        and all(rows[name]['UnitFileState'] in ('disabled', 'masked')
                for name, unit in plan['units'].items()
                if name == 'webservices.target' or unit['lifecycle'] == 'trigger'))
        for plan, rows in zip(selected_plans, observed))


def operate(action, root, expected=None, journal=None, wait_seconds=120):
    if action not in ('start', 'stop', 'verify'):
        raise ValueError('Unknown operation')
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 120:
        raise ValueError('Native wait must be between 0 and 120 seconds')
    journal = journal or journal_module()
    with installer_lock(root) as locked:
        release, intent, proof, selected_plans, observed = snapshot(root, journal)
        selected_lock = info(root / '.install.lock')
        if (selected_lock.st_dev, selected_lock.st_ino) != locked[:2]:
            raise ValueError('Selected installer lock identity changed')
        if action != 'verify':
            check_expected(proof, expected or {})
            if action == 'start' and (intent['phase'] != 'active'
                    or intent.get('steps') != list(journal.PHASES[:5])):
                raise ValueError('Start requires compatible active receipt; use installer recovery')
            cold = action == 'start' and any(p['offlineManagerStopped'] for p in selected_plans)
            canonical = action == 'start' and 'nativeRuntimeEnvUnitCustody' in intent
            if cold and not canonical:
                raise ValueError('Cold/historical runtime restore lacks canonical custody; installer recovery required')
            transition = ManagerTransition(selected_plans) if cold else None
            lifecycle = None
            try:
                deadline = time.monotonic() + wait_seconds
                with canonical_lock_fd(locked[2]) if canonical else nullcontext():
                    if canonical:
                        lifecycle = PreparedLifecycle(root, release, intent, runtime_api(release))
                        for plan in selected_plans:
                            if plan['uid'] and not plan['offlineManagerStopped']:
                                lifecycle.admit_running(plan)
                    if action == 'stop':
                        stop_selected(root, journal, proof, selected_plans)
                    else:
                        if cold:
                            resume_managers(root, journal, proof, selected_plans, transition, lifecycle, deadline)
                        if lifecycle is not None:
                            # Restore ALL exact runtime manifests before application
                            # targets or APIs, then obtain a fresh ROOT-issued copy
                            # observation. An old actor stamp cannot authorize this.
                            for plan in selected_plans:
                                checked_snapshot(root, journal, proof, transition)
                                lifecycle.guard()
                                run(plan['command'] + ['start', 'webservices-runtime-env.service'])
                            checked_snapshot(root, journal, proof, transition)
                            lifecycle.seal(proof, selected_plans)
                        for plan in selected_plans:
                            checked_snapshot(root, journal, proof, transition)
                            if lifecycle is not None:
                                lifecycle.guard()
                            # Exact actor API only; never enable updater/linger.
                            sockets = sorted(name for name in plan['units'] if name.endswith('.socket'))
                            if sockets:
                                run(plan['command'] + ['start', *sockets])
                                checked_snapshot(root, journal, proof, transition)
                                if lifecycle is not None:
                                    lifecycle.guard()
                            run(plan['command'] + ['start', 'webservices.target'])
                    # Wants= targets may finish before their services do. Poll
                    # native outcomes only, not real application acceptance.
                    while True:
                        after = checked_snapshot(root, journal, proof, transition)
                        observed = after[4]
                        selected_plans = after[3]
                        if lifecycle is not None:
                            lifecycle.guard()
                        if action == 'stop':
                            done = stopped(selected_plans, observed)
                        else:
                            done = all(healthy(unit, rows[name]) for plan, rows in zip(selected_plans, observed)
                                       for name, unit in plan['units'].items())
                        if done:
                            # Return the actual post-transition CAS, never the
                            # normalized comparison used inside this transaction.
                            proof = after[2]
                            break
                        if time.monotonic() >= deadline:
                            raise ValueError('Selected native lifecycle outcome did not converge')
                        time.sleep(min(1, max(0, deadline - time.monotonic())))
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                if action == 'start':
                    # Best-effort exact quarantine, never broad kill/reset or
                    # previous-release replay. If authority changed, dispatch
                    # nothing else. Persist terminal failure even if a native
                    # manager cannot be reached for cleanup.
                    try:
                        fresh = checked_snapshot(root, journal, proof, transition)
                        stop_selected(root, journal, proof, fresh[3], transition)
                    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                        pass
                seal_failure(root, release, intent, journal)
                raise
        domains = [{'role': plan['role'], 'offlineManagerStopped': plan['offlineManagerStopped'], 'units': [
            {'name': name, 'lifecycle': unit['lifecycle'], 'activeState': rows[name]['ActiveState'],
             'nativeHealthy': healthy(unit, rows[name])}
            for name, unit in sorted(plan['units'].items())]}
            for plan, rows in zip(selected_plans, observed)]
        native = intent['phase'] == 'active' and all(unit['nativeHealthy'] for domain in domains for unit in domain['units'])
        return {'schemaVersion': 1, 'operation': action, **proof, 'domains': domains,
                'nativeHealthy': native, 'nativeStopped': stopped(selected_plans, observed),
                'applicationAcceptance': 'unproven', 'acceptedIntegratedInstalls': 0,
                'containerRuntimeDirectlyInvoked': False,
                'nativeServiceMutationsPerformed': action != 'verify', 'journalPhase': intent['phase']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for action in ('start', 'stop', 'verify'):
        command = commands.add_parser(action)
        command.add_argument('--state-root', required=True, type=Path)
        command.add_argument('--json', action='store_true')
        if action != 'verify':
            command.add_argument('--wait-seconds', type=int, default=120)
            command.add_argument('--expected-release', required=True)
            command.add_argument('--expected-intent-sha256', required=True)
            command.add_argument('--expected-receipt-sha256', required=True)
            command.add_argument('--expected-plan-sha256', required=True)
    args = parser.parse_args(argv)
    expected = None if args.command == 'verify' else {
        'selectedRelease': args.expected_release, 'intentSha256': args.expected_intent_sha256,
        'receiptSha256': args.expected_receipt_sha256, 'planSha256': args.expected_plan_sha256}
    try:
        result = operate(args.command, args.state_root, expected,
                         wait_seconds=getattr(args, 'wait_seconds', 0))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('stackctl: native operation refused; inspect exact selected authority and installer journal', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if args.command == 'stop' or result['nativeHealthy'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
