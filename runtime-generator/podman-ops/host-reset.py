#!/usr/bin/env python3
"""Internal exact synthetic-data reset backend; deliberately has no CLI.

Integration API: review(root, intent_sha256) -> {plan, planSha256};
reset(root, intent_sha256, plan_sha256) -> completion evidence. Both acquire the
EXISTING installer .install.lock (nonblocking). Call only from the existing
installer/lifecycle authority, after its authorization gate. No service stopping,
trigger disabling, account/range changes, cache cleanup or installation occurs.

Resolve persistent app roots with the generator's per-service/domain rules.
Marker-bound actor roots, exact allocated subordinate IDs and private installed
configuration are supported, not adopted. Metadata/state/graph roots, caches,
keys, receipts and earlier evidence survive: this is DATA reset, NOT a complete
clean counted reset. App symlinks are unlinked as inert entries, never read or
followed; linked roots, hardlinks, mounts and foreign ownership fail closed.
The installer's root-owned `current` pointer must name the receipted release.
"""
import contextlib
import contextvars
import errno
import grp
import importlib.util
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import uuid


class Refusal(ValueError):
    pass


CORE = ('bundle.json', 'stack.ir.json', 'source-provenance.json')
PINS = CORE + ('podman-domains.json', 'site/agent-vm.json',
               'site/agent-vm.provenance.json', 'site/manifest.json',
               'site/components.lock.json', 'site/global.settings/registry-image-ids.json',
               'site/global.settings/webservices.sops.json',
               'site/global.settings/build-base-image-ids.json')
REQUIRED = set(CORE + ('podman-domains.json', 'site/manifest.json'))
SHA = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[a-z][a-z0-9-]{0,63}')
UNIT = re.compile(r'webservices(?:-[A-Za-z0-9_.@-]+)?\.(?:service|target|timer|socket)')
MARKER = '.stack-installation.json'
MAX_NODES = 100000
OWNERSHIP = contextvars.ContextVar('reset_ownership', default=None)


@contextlib.contextmanager
def ownership_session():
    token = OWNERSHIP.set({'paths': {}, 'files': {}, 'missing': set()})
    try: yield
    finally: OWNERSHIP.reset(token)


def access_acl(fd):
    """Read ACL bytes on the anchored inode, never an external path/tool."""
    try: raw = os.getxattr(fd, 'system.posix_acl_access')
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.ENOTSUP): return []
        raise
    if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack('<I', raw[:4])[0] != 2:
        raise Refusal('Malformed storage ACL')
    rows = [list(struct.unpack('<HHI', raw[i:i + 8])) for i in range(4, len(raw), 8)]
    if len({(r[0], r[2]) for r in rows}) != len(rows) or any(r[1] > 7 for r in rows):
        raise Refusal('Ambiguous storage ACL')
    return sorted(rows)


def data_permissions(info, acl, owners):
    if info.st_mode & 0o002: return False
    access = owners.get('sharedAccess', {}) if isinstance(owners, dict) else {}
    if not access: return not info.st_mode & 0o022
    # Shared ACL mask bits may look group-writable. Permit ONLY the exact
    # selected per-domain grant emitted by grant_shared_access; no foreign
    # named group/user or world writer is adopted.
    for tag, rights, who in acl:
        if tag == 2:
            maximum = 5 if access.get(str(who)) == 'read-only' else 7
            if str(who) not in access or rights & ~maximum: return False
        elif tag == 4:
            if rights & 2 and not permitted(info.st_gid, owners, 'gids'): return False
        elif tag == 32:
            if rights & 2: return False
        elif tag not in (1, 16): return False
    return not info.st_mode & 0o020 or bool(acl)


def directory_authority(fd, selected):
    info = os.fstat(fd); policy = OWNERSHIP.get()
    acl = access_acl(fd)
    allowed = info.st_uid == 0 and not info.st_mode & 0o022
    if policy and 'scope' in policy:
        scope = policy['scope']; domains = policy['domains']
        private = next((d for d in domains if any(selected == path(d[k]) for k in
                        ('stateRoot', 'graphRoot', 'volumeRoot'))), None)
        home = next((d for d in domains if selected.is_relative_to('/home/' + d['user'])), None)
        app = next((r for r in policy.get('apps', []) if selected.is_relative_to(r[0])), None)
        if private and info.st_uid == private['uid']:
            allowed = stat.S_IMODE(info.st_mode) == 0o700 and info.st_gid == policy['actorGids'][private['user']]
        elif app:
            allowed = (permitted(info.st_uid, app[1], 'uids') and permitted(info.st_gid, app[1], 'gids')
                       and data_permissions(info, acl, app[1]))
        elif home and info.st_uid == home['uid']:
            # Only the exact configuration ancestors used for selected sources.
            base = Path('/home/' + home['user'])
            allowed = selected in (base, base / '.config', base / '.config/containers',
                                  base / '.config/containers/systemd', base / '.config/systemd',
                                  base / '.config/systemd/user',
                                  base / '.config/systemd/user/webservices.target.d') and not info.st_mode & 0o022
        elif selected == scope or (selected.is_relative_to(scope) and any(
                path(d[k]).is_relative_to(selected) for d in domains for k in ('stateRoot', 'graphRoot', 'volumeRoot'))):
            if info.st_uid == 1000:
                allowed = (info.st_gid == grp.getgrnam('stack').gr_gid and
                           stat.S_IMODE(info.st_mode) in (0o2770, 0o700, 0o750))
            # Only exact selected execute ACLs; no foreign reader/writer grant.
            actors = {d['uid'] for d in domains}
            actors.update(a['start'] for a in policy.get('allocations', {}).get('actors', []))
            for tag, rights, who in acl:
                if tag == 2:
                    if who not in actors or rights != 1: allowed = False
                elif tag not in (1, 4, 16, 32) or (tag == 32 and rights): allowed = False
        if selected.is_relative_to(scope) and acl and (private or app):
            # Private app/actor parents may not carry hidden named ACL grants.
            if (not app or not app[1].get('sharedAccess')) and any(r[0] in (2, 8) for r in acl): allowed = False
    if not allowed: raise Refusal('Foreign or writable directory authority')
    if policy:
        proof = {'identity': identity(info), 'acl': acl}
        old = policy['paths'].setdefault(str(selected), proof)
        if old != proof: raise Refusal('Directory ownership/ACL changed during operation')


def identity_ids():
    import pwd
    return [p.pw_uid for p in pwd.getpwall()] + [g.gr_gid for g in grp.getgrall()]


def read_allocation_files():
    return {name: read_file(Path('/etc') / name, limit=1024 * 1024) for name in ('subuid', 'subgid')}


def allocations(domains):
    files = read_allocation_files(); tables = {}
    for name, raw in files.items():
        rows = []
        for line in raw.decode('ascii').splitlines():
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
                raise Refusal('Malformed subordinate allocation')
            start, count = map(int, parts[1:])
            if start <= 0 or count <= 0 or start + count > 2**32 - 1:
                raise Refusal('Invalid subordinate interval')
            rows.append((parts[0], start, count))
        tables[name] = rows
    actors = []; host_ids = identity_ids()
    for domain in domains:
        found = []
        for rows in tables.values():
            matches = [r for r in rows if r[0] in (domain['user'], str(domain['uid']))]
            if len(matches) != 1 or matches[0][2] != 65536:
                raise Refusal('Exact single selected subordinate allocation required')
            owner, start, count = matches[0]
            if any(r != matches[0] and start < r[1] + r[2] and r[1] < start + count for r in rows):
                raise Refusal('Overlapping subordinate allocation')
            if any(start <= uid < start + count for uid in host_ids + [d['uid'] for d in domains]):
                raise Refusal('Subordinate allocation overlaps actor identity')
            found.append(start)
        if len(found) != 2 or found[0] != found[1]: raise Refusal('Subordinate UID/GID disagreement')
        actors.append({'user': domain['user'], 'uid': domain['uid'], 'start': found[0], 'count': 65536})
    for index, actor in enumerate(actors):
        if any(actor['start'] < other['start'] + 65536 and other['start'] < actor['start'] + 65536
               for other in actors[index + 1:]): raise Refusal('Cross-domain subordinate overlap')
    return {'files': {n: sha(v) for n, v in files.items()}, 'actors': actors}


def permitted(value, owners, kind):
    if isinstance(owners, list): return value in owners  # legacy internal test helper
    return value in owners[kind] or any(start <= value < start + count for start, count in owners['ranges'])


def journal_offline(release, row, command):
    """Reuse canonical journal stopped/no-linger/process/trigger authority.

    Native calls are exclusively read proofs. Never start a manager to query it.
    The caller has already FD/hash-bound the metadata and exact subid tables.
    """
    spec = importlib.util.spec_from_file_location('reset_install_journal', Path(__file__).with_name('install-journal.py'))
    # Pin helper bytes as authority, and suppress import cache writes (including
    # the journal's subordinate-ID helper import). No replacement admission.
    journal_bytes = read_file(Path(__file__).with_name('install-journal.py'))
    read_file(Path(__file__).with_name('grant-rootless-volume-parent-traverse.py'))
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        journal = importlib.util.module_from_spec(spec)
        # Execute the FD-read/hash-pinned bytes, not a potentially stale pyc.
        exec(compile(journal_bytes, str(Path(__file__).with_name('install-journal.py')), 'exec'), journal.__dict__)
        actor = journal.offline_actor(release, 'rootless-' + row['name'])
        if actor is None: return False
        if any(actor.get(k) != row[k] for k in ('name', 'user', 'uid', 'stateRoot', 'graphRoot', 'volumeRoot')):
            raise Refusal('Journal actor proof differs from selected marker')
        journal.verify_offline_actor(actor, command)
        return True
    finally:
        sys.dont_write_bytecode = previous


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def path(value):
    if (not isinstance(value, (str, Path)) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(value))
            or str(value) == '/' or str(Path(value)) != str(value)
            or any(p in ('.', '..') for p in str(value).split('/')[1:])):
        raise Refusal('Noncanonical absolute path')
    return Path(value)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_gid]


def regular(info, private=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or (private and stat.S_IMODE(info.st_mode) != 0o600) or info.st_mode & 0o022):
        raise Refusal('Foreign, linked or writable authority file')


@contextlib.contextmanager
def directory(value):
    """Open every absolute component with NOFOLLOW; trust no resolved paths."""
    value = path(value)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        selected = Path('/')
        for part in value.parts[1:]:
            selected = selected / part
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
            directory_authority(fd, selected)
        yield fd
    finally:
        os.close(fd)


def read_file(value, private=False, limit=16 * 1024 * 1024, actor=None):
    with directory(value.parent) as parent:
        fd = os.open(value.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if actor is None: regular(before, private)
            elif (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, actor)
                  or before.st_nlink != 1 or before.st_mode & 0o022):
                raise Refusal('Foreign or linked installed actor configuration')
            if before.st_size > limit:
                raise Refusal('Oversized authority file')
            chunks = []
            while True:
                data = os.read(fd, min(65536, limit + 1))
                if not data: break
                chunks.append(data)
                if sum(map(len, chunks)) > limit:
                    raise Refusal('Authority file grew during review')
            after = os.fstat(fd)
            if snapshot_stat(before) != snapshot_stat(after):
                raise Refusal('Authority changed while reading')
            raw = b''.join(chunks)
            policy = OWNERSHIP.get()
            if policy is not None:
                proof = {'stat': snapshot_stat(after), 'sha256': sha(raw), 'actor': actor}
                previous = policy['files'].setdefault(str(value), proof)
                if previous != proof: raise Refusal('Authority file identity/hash changed during operation')
            return raw
        finally:
            os.close(fd)


def strict(data):
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out: raise Refusal('Duplicate JSON key')
            out[key] = value
        return out
    def invalid(_): raise Refusal('Nonfinite JSON value')
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict): raise Refusal('Expected JSON object')
    return value


def absent(value):
    with directory(value.parent) as fd:
        try: os.stat(value.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: return True
        return False


@contextlib.contextmanager
def locked(root):
    if os.geteuid() != 0: raise Refusal('Root-owned installer authority required')
    with directory(root) as parent:
        # Never create a substitute lock or truncate installer state.
        fd = os.open('.install.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd); regular(info, True)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.stat('.install.lock', dir_fd=parent, follow_symlinks=False)
            if identity(current) != identity(info): raise Refusal('Installer lock identity changed')
            if OWNERSHIP.get() is not None: OWNERSHIP.get()['lock'] = identity(info)
            yield parent
        finally:
            os.close(fd)


def selection(root, expected):
    if not isinstance(expected, str) or not SHA.fullmatch(expected): raise Refusal('Exact journal SHA required')
    raw = read_file(root / '.install-intent.json', True)
    if sha(raw) != expected: raise Refusal('Installation journal CAS changed')
    receipt = strict(raw)
    if receipt.get('schemaVersion') != 1 or receipt.get('phase') not in ('active', 'failed', 'retired-failed'):
        raise Refusal('Only terminal selected installations can be reviewed')
    release = path(receipt.get('release'))
    if release.parent != root / 'releases': raise Refusal('Receipt release escaped installer root')
    with directory(root) as fd:
        pointer = os.stat('current', dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISLNK(pointer.st_mode) or pointer.st_uid != 0 or pointer.st_nlink != 1
                or os.readlink('current', dir_fd=fd) != str(release)):
            raise Refusal('Selected pointer differs from canonical receipt')
    if read_file(release / 'installation-receipt.json', True) != raw:
        raise Refusal('Selected release receipt differs from journal')
    inputs = receipt.get('inputs')
    if (not isinstance(inputs, dict) or not REQUIRED.issubset(inputs) or not set(inputs).issubset(PINS)
            or any(not isinstance(inputs[n], str) or not SHA.fullmatch(inputs[n]) for n in REQUIRED)):
        raise Refusal('Incomplete installation input authority')
    docs = {}
    for name, expected_hash in inputs.items():
        item = release / name
        if expected_hash is None:
            # Optional absent parent directories are legal; no link traversal.
            try:
                missing = absent(item)
            except FileNotFoundError:
                missing = True
            if not missing: raise Refusal('Previously absent input appeared')
            continue
        if not isinstance(expected_hash, str) or not SHA.fullmatch(expected_hash):
            raise Refusal('Malformed installation input hash')
        content = read_file(item)
        if sha(content) != expected_hash: raise Refusal('Selected input hash changed')
        if name in REQUIRED: docs[name] = strict(content)
    bundle, ir, provenance = (docs[n] for n in CORE)
    manifest = docs['site/manifest.json']; metadata = docs['podman-domains.json']
    if (bundle.get('backend') != 'podman' or bundle.get('irSha256') != inputs['stack.ir.json']
            or bundle.get('sourceProvenanceSha256') != inputs['source-provenance.json']
            or provenance.get('manifestSha256') != inputs['site/manifest.json']):
        raise Refusal('Bundle provenance binding differs')
    scope_config = manifest.get('storageScope')
    if (manifest.get('deploymentMode') != 'standalone' or metadata.get('deploymentMode') != 'standalone'
            or 'venue' in metadata or 'agentVmSpec' in manifest
            or not isinstance(scope_config, dict) or set(scope_config) != {'root', 'dataClass'}
            or scope_config.get('dataClass') != 'synthetic' or metadata.get('storageScope') != scope_config
            or manifest.get('installerStateRoot', '/var/lib/webservices') != str(root)
            or metadata.get('installerStateRoot', '/var/lib/webservices') != str(root)):
        raise Refusal('Not an exact synthetic host-only installation')
    scope = path(scope_config['root'])
    if scope == root or scope.is_relative_to(root) or root.is_relative_to(scope):
        raise Refusal('Storage scope overlaps installer metadata')
    rows = metadata.get('domains')
    if not isinstance(rows, list) or not rows: raise Refusal('Missing selected domains')
    domains = []; names = set(); users = set(); uids = set()
    for row in rows:
        if not isinstance(row, dict): raise Refusal('Malformed selected domain')
        name, user, uid = row.get('name'), row.get('user'), row.get('uid')
        if (not isinstance(name, str) or not NAME.fullmatch(name) or name in names
                or not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                or user in users or type(uid) is not int or uid <= 0 or uid in uids):
            raise Refusal('Foreign or duplicate domain identity')
        names.add(name); users.add(user); uids.add(uid)
        entry = {'name': name, 'user': user, 'uid': uid}
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            p = path(row.get(key))
            if p == scope or not p.is_relative_to(scope): raise Refusal('Domain root escapes scope')
            entry[key] = str(p)
        domains.append(entry)
    roots = sorted({d[k] for d in domains for k in ('stateRoot', 'graphRoot', 'volumeRoot')})
    if len(roots) != len(domains) * 3: raise Refusal('Duplicate private domain root')
    for i, a in enumerate(roots):
        if any(Path(a).is_relative_to(b) or Path(b).is_relative_to(a) for b in roots[i + 1:]):
            raise Refusal('Overlapping domain roots')
    expected_marker = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': manifest.get('site'),
                       'scope': scope_config, 'domains': sorted(domains, key=lambda d: d['name']), 'roots': roots}
    policy = OWNERSHIP.get()
    if policy is None: raise Refusal('Ownership session required')
    import pwd
    selected_allocations = allocations(domains)
    for row in rows:
        if 'subuidStart' in row:
            expected_start = row['subuidStart']
            actual_start = next(a['start'] for a in selected_allocations['actors'] if a['user'] == row['user'])
            if type(expected_start) is not int or expected_start != actual_start:
                raise Refusal('Receipted subordinate allocation drift')
    policy.update(scope=scope, domains=domains, allocations=selected_allocations,
                  actorGids={d['user']: pwd.getpwnam(d['user']).pw_gid for d in domains})
    marker_raw = read_file(scope / MARKER, True, 65536)
    if strict(marker_raw) != expected_marker: raise Refusal('Scoped ownership marker differs')
    # Revalidate ACLs now that execute-only namespace-root grants are known.
    with directory(scope): pass
    for d in domains:
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            with directory(path(d[key])): pass
    return release, ir, domains, scope, sha(marker_raw), identity(pointer)


def source_authority(source, installed):
    try: raw = read_file(source)
    except FileNotFoundError: return None
    return {'source': str(installed), 'sha256': sha(raw)}


def native_podman_source(unit):
    # The installer enables this API ONLY for its selected domain accounts.
    # Never select or mutate another user's socket or a shared graph. Package
    # bytes are root-owned and pinned into the reviewed plan, not trusted from
    # an environment override or a manager's free-form FragmentPath.
    source = Path('/usr/lib/systemd/user') / unit
    return source_authority(source, source)


def runtime_env_authority(unit_dest, state, runtime):
    # Exact bytes emitted by install_runtime_env_unit, not arbitrary installed
    # drop-in adoption. No env/key file is read or changed.
    raw = ('[Unit]\nDescription=Restore rendered webservices environment files\n\n'
           '[Service]\nType=oneshot\nWorkingDirectory=/\n'
           "ExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 " + runtime +
           '; for env_file in ' + state + '/runtime-env/*.env; do [ -e "$env_file" ] || continue; '
           '/usr/bin/install -m 0600 "$env_file" ' + runtime +
           "/; done'\nRemainAfterExit=yes\n").encode()
    dropin = b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n'
    return ({'source': str(unit_dest / 'webservices-runtime-env.service'), 'sha256': sha(raw)},
            {'source': str(unit_dest / 'webservices.target.d/10-runtime-env.conf'), 'sha256': sha(dropin)})


def selected_units(release, domains):
    """Exact selected generated units, including all timers and sockets."""
    result = []
    suffixes = {'.container': '.service', '.build': '-build.service', '.network': '-network.service',
                '.volume': '-volume.service', '.target': '.target', '.service': '.service',
                '.timer': '.timer', '.socket': '.socket'}
    managers = [('rootful', ['/usr/bin/systemctl'], Path('/etc/containers/systemd'), Path('/etc/systemd/system'))]
    for row in domains:
        # No NSS/account adoption. The system account must still be the pinned UID.
        import pwd
        account = pwd.getpwnam(row['user'])
        if account.pw_uid != row['uid'] or account.pw_dir != '/home/' + row['user']:
            raise Refusal('Selected account identity changed')
        home = Path(account.pw_dir)
        managers.append(('rootless-' + row['name'], ['/usr/sbin/runuser', '-u', row['user'], '--',
                         '/usr/bin/env', '-i', 'HOME=' + str(home), 'XDG_RUNTIME_DIR=/run/user/' + str(row['uid']),
                         'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(row['uid']) + '/bus',
                         '/usr/bin/systemctl', '--user'], home / '.config/containers/systemd', home / '.config/systemd/user'))
    for label, command, quadlet_dest, unit_dest in managers:
        source = release / 'quadlet' / label
        units = {}
        with directory(source) as fd:
            for filename in sorted(os.listdir(fd)):
                item = Path(filename)
                if item.suffix not in suffixes: raise Refusal('Unclassified selected unit source')
                name = item.stem + suffixes[item.suffix]
                if not UNIT.fullmatch(name) or name in units: raise Refusal('Foreign or duplicate selected unit')
                raw = read_file(source / filename)
                installed = (quadlet_dest if item.suffix in ('.container', '.build', '.network', '.volume') else unit_dest) / filename
                units[name] = {'source': str(installed), 'sha256': sha(raw)}
        if 'webservices.target' not in units: raise Refusal('Missing selected target source')
        if label == 'rootful':
            # These exact two implicit sources are installed by the ordinary
            # installer from the selected release's ops tree.
            for unit in ('webservices-auto-update.timer', 'webservices-auto-update.service'):
                units.setdefault(unit, source_authority(release / 'ops' / unit, unit_dest / unit))
        else:
            for unit in ('podman.socket', 'podman.service'):
                units[unit] = native_podman_source(unit)
        if label == 'rootful':
            state, runtime = str(release.parent.parent), '/run/webservices'
        else:
            actor = next(d for d in domains if label == 'rootless-' + d['name'])
            state, runtime = actor['stateRoot'], '/run/user/' + str(actor['uid']) + '/webservices'
        env_unit, dropin = runtime_env_authority(unit_dest, state, runtime)
        if 'webservices-runtime-env.service' in units: raise Refusal('Conflicting canonical environment unit')
        units['webservices-runtime-env.service'] = env_unit
        manager = {'manager': label, 'command': command, 'units': units,
                   'dropins': {'webservices.target': dropin}}
        if label != 'rootful':
            actor = next(d for d in domains if label == 'rootless-' + d['name'])
            manager.update(actor=actor, release=str(release), offline=journal_offline(release, actor, command))
        result.append(manager)
    return result


def run_read(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=15,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def verify_inactive(managers):
    for manager in managers:
        command, units = manager['command'], manager['units']
        if manager.get('offline'):
            if not journal_offline(path(manager['release']), manager['actor'], command):
                raise Refusal('Stopped selected manager became active')
            # Query disk unit-file state without contacting/reviving the manager.
            offline = command[:-2] + ['SYSTEMD_OFFLINE=1', *command[-2:], '--no-reload']
            triggers = [u for u in units if u.endswith(('.target', '.socket', '.timer'))]
            result = run_read(offline + ['is-enabled', *triggers])
            states = result.stdout.splitlines()
            if (result.returncode not in (0, 1, 4) or len(states) != len(triggers)
                    or any(s not in ('disabled', 'masked', 'not-found') for s in states)):
                raise Refusal('Stopped actor selected boot/API trigger remains')
            for authority in [*units.values(), *manager.get('dropins', {}).values()]:
                if authority is None: continue
                source = path(authority['source'])
                actor_uid = manager['actor']['uid'] if source.is_relative_to('/home/' + manager['actor']['user'] + '/.config') else None
                try: raw = read_file(source, actor=actor_uid)
                except FileNotFoundError:
                    OWNERSHIP.get()['missing'].add(str(source))
                    continue
                if sha(raw) != authority['sha256']: raise Refusal('Offline actor source hash differs')
            continue
        for unit, authority in units.items():
            fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'FragmentPath',
                      'SourcePath', 'Job', 'TriggeredBy', 'Triggers', 'Names', 'DropInPaths',
                      'NeedDaemonReload', 'Transient')
            args = [arg for key in fields for arg in ('-p', key)]
            result = run_read(command + ['show', unit, *args, '--no-pager'])
            props = {}
            for line in result.stdout.splitlines():
                if '=' not in line: raise Refusal('Malformed unit proof')
                key, value = line.split('=', 1)
                if key in props or key not in fields: raise Refusal('Ambiguous unit proof')
                props[key] = value
            if (result.returncode or set(props) != set(fields) or props['Id'] != unit
                    or props['Names'].split() not in ([unit], [])
                    or props['ActiveState'] != 'inactive' or props['SubState'] != 'dead'
                    or props['NeedDaemonReload'] != 'no' or props['Transient'] != 'no'
                    or props['Job'] not in ('', '0')
                    or any(u not in units for k in ('TriggeredBy', 'Triggers') for u in props[k].split())):
                raise Refusal('Selected unit inactivity/trigger proof incomplete')
            dropin = manager.get('dropins', {}).get(unit)
            if props['DropInPaths']:
                if (not dropin or props['DropInPaths'].split() != [dropin['source']]
                        or sha(read_file(path(dropin['source']), actor=manager.get('actor', {}).get('uid'))) != dropin['sha256']):
                    raise Refusal('Foreign or changed selected drop-in')
            if props['LoadState'] == 'not-found':
                if props['DropInPaths'] or props['FragmentPath'] or props['SourcePath'] or props['UnitFileState'] not in ('', 'not-found'):
                    raise Refusal('Ambiguous absent unit')
            elif (props['LoadState'] != 'loaded' or authority is None
                  or props['UnitFileState'] not in ('disabled', 'masked', 'static')
                  or (unit.endswith(('.timer', '.socket', '.target')) and props['UnitFileState'] == 'static')):
                raise Refusal('Selected unit not fenced or lacks source authority')
            else:
                actual = props['SourcePath'] or props['FragmentPath']
                actor = manager.get('actor', {}).get('uid')
                if actual != authority['source'] or sha(read_file(path(actual), actor=actor)) != authority['sha256']:
                    raise Refusal('Installed unit source differs from selected release')
        jobs = run_read(command + ['list-jobs', '--no-legend', '--no-pager', '--plain'])
        # Stronger than name filtering: any manager job prevents deletion. No
        # unrelated job is cancelled, stopped or otherwise mutated.
        if jobs.returncode or jobs.stdout.strip(): raise Refusal('Manager jobs remain or job proof unavailable')


def mount_views():
    """All readable process mount namespaces; any unavailable view refuses."""
    proc = Path('/proc')
    views = [read_mountinfo(proc / 'self/mountinfo')]
    for entry in sorted(proc.iterdir()):
        if entry.name.isdecimal(): views.append(read_mountinfo(entry / 'mountinfo'))
    if len(views) < 2: raise Refusal('Process mount proof unavailable')
    return views


def read_mountinfo(filename):
    # proc files are intentionally not filesystem ownership markers.
    return filename.read_text().splitlines()


def mounts(lines):
    out = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or '-' not in fields or not re.fullmatch(r'\d+:\d+', fields[2]):
            raise Refusal('Malformed mount proof')
        def decode(value):
            value = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
            if not value.startswith('/') or '\x00' in value: raise Refusal('Malformed mount path')
            return Path(value)
        out.append((fields[2], decode(fields[3]), decode(fields[4])))
    if not out: raise Refusal('Empty mount proof')
    return out


def verify_unmounted(paths):
    views = [mounts(v) for v in mount_views()]
    if len(views) < 2: raise Refusal('Insufficient process mount proof')
    for selected in paths:
        parents = [r for r in views[0] if selected.is_relative_to(r[2])]
        if not parents: raise Refusal('Selected filesystem not proved')
        base = max(parents, key=lambda r: len(r[2].parts))
        if selected == base[2] or any(r[2].is_relative_to(selected) for r in views[0]):
            raise Refusal('Selected root or child is mounted')
        fs_path = base[1] / selected.relative_to(base[2])
        with directory(selected) as fd:
            dev = os.fstat(fd).st_dev
            if base[0] != str(os.major(dev)) + ':' + str(os.minor(dev)):
                raise Refusal('Mount/device identity differs')
        for view in views:
            for device, fs_root, mountpoint in view:
                if device != base[0]: continue
                if (fs_root.is_relative_to(fs_path)
                        or (fs_path.is_relative_to(fs_root) and fs_root != base[1])):
                    raise Refusal('Selected data mounted in a process namespace')


def snapshot_stat(info):
    return identity(info) + [info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]


def tree(fd, owners, device, count):
    result = []
    for name in sorted(os.listdir(fd)):
        count[0] += 1
        if count[0] > MAX_NODES: raise Refusal('Reset inventory exceeds bounded scope')
        if name in (MARKER, '.install-intent.json', 'installation-receipt.json', '.host-reset'):
            raise Refusal('Journal/marker evidence found inside app data')
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (info.st_dev != device or not permitted(info.st_uid, owners, 'uids')
                or not permitted(info.st_gid, owners, 'gids')
                or (not stat.S_ISLNK(info.st_mode) and info.st_mode & (0o002 if isinstance(owners, dict) and owners.get('sharedAccess') else 0o022))):
            raise Refusal('Foreign, writable or mounted app data')
        entry = {'name': name, 'stat': snapshot_stat(info)}
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if snapshot_stat(os.fstat(child)) != entry['stat']: raise Refusal('Directory open CAS changed')
                if not data_permissions(info, access_acl(child), owners): raise Refusal('Foreign shared directory ACL')
                entry['children'] = tree(child, owners, device, count)
            finally: os.close(child)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                if snapshot_stat(os.fstat(child)) != entry['stat']: raise Refusal('File open CAS changed')
                if not data_permissions(info, access_acl(child), owners): raise Refusal('Foreign shared file ACL')
                digest = hashlib.sha256()
                while True:
                    data = os.read(child, 65536)
                    if not data: break
                    digest.update(data)
                if snapshot_stat(os.fstat(child)) != entry['stat']: raise Refusal('File read CAS changed')
                entry['sha256'] = digest.hexdigest()
            finally: os.close(child)
        elif stat.S_ISLNK(info.st_mode) and info.st_nlink == 1:
            # lstat/CAS and unlink only. Do not readlink, open or inspect target.
            entry['inertSymlink'] = True
        else: raise Refusal('Hardlinked or special app data')
        result.append(entry)
    return result


def app_roots(ir, domains, scope, root):
    """Mirror resolvedVolumeSource in stack-generator.main.kts, not hostPath alone."""
    import pwd
    volumes, services = ir.get('volumes'), ir.get('services')
    if not isinstance(volumes, dict) or not volumes or not isinstance(services, dict):
        raise Refusal('No explicit synthetic app data')
    by_name = {d['name']: d for d in domains}; resolved = {}
    for name, volume in volumes.items():
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name)
                or not isinstance(volume, dict) or not volume.get('hostPath')):
            raise Refusal('Unmapped or malformed named volume')
        declared = path(volume['hostPath'])
        if declared == scope or not declared.is_relative_to(scope): raise Refusal('Declared volume escapes selected scope')
    for service in services.values():
        if not isinstance(service, dict): raise Refusal('Malformed service placement')
        placement = service.get('placement', 'rootful')
        if placement not in ('rootful', 'rootless'): raise Refusal('Unknown service placement')
        domain = None
        if placement == 'rootless':
            domain = by_name.get(service.get('rootlessDomain'))
            if domain is None: raise Refusal('Unknown selected volume domain')
        for mount in service.get('volumes', []):
            source = mount.split(':', 1)[0] if isinstance(mount, str) else mount.get('source')
            if not isinstance(source, str): raise Refusal('Malformed volume source')
            if source not in volumes:
                if (source.startswith('./configs/') or source.startswith('./build/')
                        or source == './repos' or source.startswith('./repos/') or source.startswith('./stack.')
                        or source.startswith('${')):
                    continue  # generator runtimeBindPath; never app reset authority
                if source.startswith('/'):
                    direct = path(source)
                    if direct.is_relative_to(scope) and not any(direct.is_relative_to(d[k]) for d in domains for k in ('stateRoot', 'graphRoot')):
                        raise Refusal('Persistent direct bind needs explicit named-volume ownership')
                    continue
                raise Refusal('Unmapped service named volume')
            volume = volumes[source]; strategy = volume.get('rootlessStrategy', 'copy')
            if strategy not in ('copy', 'shared', 'forbidden') or (domain and strategy == 'forbidden'):
                raise Refusal('Unsupported rootless volume policy')
            p = path(volume['hostPath']) if not domain or strategy == 'shared' else path(domain['volumeRoot']) / source
            if p == scope or not p.is_relative_to(scope): raise Refusal('App root escapes scope')
            protected = [root] + [path(d[k]) for d in domains for k in ('stateRoot', 'graphRoot')]
            if any(p.is_relative_to(q) or q.is_relative_to(p) for q in protected):
                raise Refusal('App root overlaps journal/state/cache authority')
            if any(p == path(d['volumeRoot']) or path(d['volumeRoot']).is_relative_to(p) for d in domains):
                raise Refusal('Cannot empty a whole volume/cache parent')
            containing = next((d for d in domains if p.is_relative_to(d['volumeRoot'])), None)
            if domain and containing and containing['name'] != domain['name']:
                raise Refusal('Cross-domain app root')
            allowed = resolved.setdefault(p, {'uids': [0], 'gids': [0], 'ranges': [], 'sharedAccess': {}})
            if domain and strategy == 'shared':
                access = volume.get('rootlessAccess', 'read-write')
                if access not in ('read-only', 'read-write'): raise Refusal('Unknown selected shared access')
                allowed['sharedAccess'][str(domain['uid'])] = access
            # A legacy explicit private hostPath still belongs only to its own
            # selected actor, never to every actor sharing the outer scope.
            owner = domain or containing
            if owner:
                account = pwd.getpwnam(owner['user'])
                allocation = next(a for a in OWNERSHIP.get()['allocations']['actors'] if a['user'] == owner['user'])
                allowed['uids'] = sorted(set(allowed['uids'] + [owner['uid']]))
                allowed['gids'] = sorted(set(allowed['gids'] + [account.pw_gid]))
                allowed['ranges'] = sorted({tuple(r) for r in allowed['ranges']} | {(allocation['start'], 65536)})
                allowed['ranges'] = [list(r) for r in allowed['ranges']]
    selected = sorted(resolved.items(), key=lambda r: str(r[0]))
    if not selected: raise Refusal('No resolved persistent app roots')
    for i, (p, _) in enumerate(selected):
        if any(p.is_relative_to(q) or q.is_relative_to(p) for q, _ in selected[i + 1:]):
            raise Refusal('Overlapping app roots')
    OWNERSHIP.get()['apps'] = selected
    return selected


def plan_locked(root, expected):
    release, ir, domains, scope, marker_sha, pointer = selection(root, expected)
    managers = selected_units(release, domains)
    selected = app_roots(ir, domains, scope, root)
    verify_inactive(managers)
    verify_unmounted([p for p, _ in selected])
    inventory = []; count = [0]
    for p, owners in selected:
        with directory(p) as fd:
            info = os.fstat(fd)
            inventory.append({'path': str(p), 'identity': identity(info), 'owners': owners,
                              'children': tree(fd, owners, info.st_dev, count)})
    authority_directories = {}
    for selected_path in (root, release, scope):
        with directory(selected_path) as fd:
            authority_directories[str(selected_path)] = identity(os.fstat(fd))
    plan = {'schemaVersion': 1, 'kind': 'exact-synthetic-app-reset', 'root': str(root),
            'release': str(release), 'intentSha256': expected, 'markerSha256': marker_sha,
            'selectedPointer': pointer, 'authorityDirectories': authority_directories,
            'managers': managers, 'directories': inventory,
            'subordinateAllocations': OWNERSHIP.get()['allocations'],
            'ownershipPaths': dict(OWNERSHIP.get()['paths']),
            'authorityFiles': dict(OWNERSHIP.get()['files']),
            'absentSources': sorted(OWNERSHIP.get()['missing']),
            'installerLock': OWNERSHIP.get()['lock'],
            'resetClass': 'engineering-data-only-not-complete-clean'}
    return plan


def verify_binding(root, expected, plan):
    release, _, domains, _, marker_sha, pointer = selection(root, expected)
    if (str(release) != plan['release'] or marker_sha != plan['markerSha256']
            or pointer != plan['selectedPointer'] or selected_units(release, domains) != plan['managers']):
        raise Refusal('Selected reset authority changed after intent')
    if (OWNERSHIP.get()['allocations'] != plan['subordinateAllocations']
            or OWNERSHIP.get()['lock'] != plan['installerLock']):
        raise Refusal('Subordinate allocation or installer lock changed after review')
    for filename, proof in plan['authorityFiles'].items():
        raw = read_file(path(filename), actor=proof['actor'])
        if OWNERSHIP.get()['files'][filename] != proof or sha(raw) != proof['sha256']:
            raise Refusal('Reviewed authority file identity/hash changed')
    for filename in plan['absentSources']:
        try: missing = absent(path(filename))
        except FileNotFoundError: missing = True
        if not missing: raise Refusal('Previously absent installed source appeared')
    for selected_path, proof in plan['ownershipPaths'].items():
        with directory(path(selected_path)) as fd:
            if {'identity': identity(os.fstat(fd)), 'acl': access_acl(fd)} != proof:
                raise Refusal('Reviewed ownership path changed')
    for selected_path, expected_identity in plan['authorityDirectories'].items():
        with directory(path(selected_path)) as fd:
            if identity(os.fstat(fd)) != expected_identity: raise Refusal('Authority directory identity changed')


def review(root, intent_sha256):
    root = path(root)
    with ownership_session(), locked(root):
        plan = plan_locked(root, intent_sha256)
        return {'plan': plan, 'planSha256': sha(canonical(plan))}


def write_evidence(fd, filename, value):
    out = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        raw = canonical(value)
        while raw:
            written = os.write(out, raw)
            if written <= 0: raise Refusal('Evidence write incomplete')
            raw = raw[written:]
        os.fsync(out)
    finally: os.close(out)
    os.fsync(fd)


def erase(fd, entries):
    if sorted(os.listdir(fd)) != [e['name'] for e in entries]: raise Refusal('App tree CAS changed')
    for entry in entries:
        name = entry['name']
        if snapshot_stat(os.stat(name, dir_fd=fd, follow_symlinks=False)) != entry['stat']:
            raise Refusal('App inode CAS changed')
        if 'children' in entry:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if snapshot_stat(os.fstat(child)) != entry['stat']: raise Refusal('App directory changed on open')
                erase(child, entry['children'])
                if identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(os.fstat(child)):
                    raise Refusal('App directory replaced during deletion')
            finally: os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    os.fsync(fd)
    if os.listdir(fd): raise Refusal('App data repopulated during reset')


def reset(root, intent_sha256, plan_sha256):
    """Exact CAS; no automatic retry, journal retirement or authority bypass.

    Partial failures keep intent/result evidence. A retry needs a NEW review/CAS
    of the remaining tree; no previous installation journal is rewritten.
    """
    if not isinstance(plan_sha256, str) or not SHA.fullmatch(plan_sha256): raise Refusal('Exact plan SHA required')
    root = path(root)
    with ownership_session(), locked(root) as root_fd:
        plan = plan_locked(root, intent_sha256)
        if sha(canonical(plan)) != plan_sha256: raise Refusal('Reviewed reset plan CAS changed')
        try: os.mkdir('.host-reset', mode=0o700, dir_fd=root_fd)
        except FileExistsError: pass
        with directory(root / '.host-reset') as evidence:
            if stat.S_IMODE(os.fstat(evidence).st_mode) != 0o700: raise Refusal('Unsafe evidence directory')
            attempt = plan_sha256 + '-' + uuid.uuid4().hex
            result = {'schemaVersion': 1, 'kind': 'exact-synthetic-app-reset', 'phase': 'intent',
                      'intentSha256': intent_sha256, 'planSha256': plan_sha256,
                      'emptied': [], 'scope': 'selected-synthetic-app-data-only',
                      'resetClass': 'engineering-data-only-not-complete-clean',
                      'completeCleanReset': False}
            write_evidence(evidence, attempt + '-intent.json', dict(result, plan=plan))
            try:
                # No reviewed proof is a persisted claim that can authorize a
                # later reset. Re-read native state and exact selection now.
                verify_binding(root, intent_sha256, plan)
                verify_inactive(plan['managers'])
                verify_unmounted([path(d['path']) for d in plan['directories']])
                for entry in plan['directories']:
                    verify_binding(root, intent_sha256, plan)
                    verify_unmounted([path(entry['path'])])
                    with directory(path(entry['path'])) as fd:
                        if identity(os.fstat(fd)) != entry['identity']: raise Refusal('App root inode CAS changed')
                        current = tree(fd, entry['owners'], os.fstat(fd).st_dev, [0])
                        if current != entry['children']: raise Refusal('App content CAS changed')
                        # Hashing a large app tree is not a lease on inactivity.
                        # Repeat the canonical manager/trigger/process proof at
                        # each destructive root boundary, never revive it.
                        verify_inactive(plan['managers'])
                        erase(fd, current)
                    result['emptied'].append(entry['path'])
                    write_evidence(evidence, attempt + '-progress-' + str(len(result['emptied'])) + '.json', result)
                verify_binding(root, intent_sha256, plan)
                verify_inactive(plan['managers'])
                for entry in plan['directories']:
                    with directory(path(entry['path'])) as fd:
                        if identity(os.fstat(fd)) != entry['identity'] or os.listdir(fd):
                            raise Refusal('Reset directory repopulated or replaced')
                result['phase'] = 'empty-owned-app-data'
            except BaseException:
                result['phase'] = 'failed-partial-no-automatic-retry'
                write_evidence(evidence, attempt + '-result.json', result)
                raise
            write_evidence(evidence, attempt + '-result.json', result)
            return result
