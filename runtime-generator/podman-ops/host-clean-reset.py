#!/usr/bin/env python3
"""Internal complete synthetic clean reset. No CLI, admission flag or daemon.

review(root, expectedIntentSha) -> {plan, planSha256}
issue_stopped_lease(root, expectedIntentSha, expectedPlanSha) -> StoppedLease
review_runtime_custody(root, expectedIntentSha) -> journal-owner runtime fingerprints
execute(root, expectedIntentSha, expectedPlanSha, lease) -> durable report

All entrypoints use the EXISTING .install.lock, borrowing an already locked FD9
when present, otherwise taking a nonblocking flock. The lease is process-local,
short-lived, single-use, and obtainable only by repeating the canonical stopped
proof. It is NOT a JSON permission or a substitute for installer authorization.
The journal owner alone performs the eventual retired-clean transition.

Only the seven fixed lab actors and /mnt/stack/host-stack-lab are supported.
Root metadata must ALREADY be 0700; no chmod/chown/account/ACL repair occurs.
All scope contents except its exact marker are removed, including whole graph
stores and Podman-managed volumes. Exact selected private roots are left ABSENT,
including legacy 2700/ACL leaves; only shared ancestors remain infrastructure.
The default ROOTFUL store permits only unforced removal of exact source-selected
unused bridge networks. Images/build caches there are NOT deletion scope; a
non-cold default store refuses rather than pruning or adopting shared caches.
No container/volume/image/cache deletion, global graph walk/removal, prune,
Docker/package operation, backup, restart, stop or migration is allowed.

External selected runtime trees require root-receipted cleanResetCustody tree
fingerprints; deterministic installed unit/config files require exact source
hashes. Missing custody refuses BEFORE deletion, never reports partial clean as
complete. Custody is metadata written by the existing journal owner after stop,
not an authorization token. No arbitrary path in that metadata is accepted.
Recognized historical helper bytes are stop-only authority, NEVER activation.
Only a genuinely absent historical native-selection.py may use the exact pinned
canonical backend sibling. Its path/inode/ancestry/backend source are rechecked;
no caller, receipt or environment donor path and no present-unknown fallback.
"""
import ast
import base64
import contextlib
import ctypes
import datetime
import errno
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import tomllib
import types
import uuid


class Refusal(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


SCOPE = Path('/mnt/stack/host-stack-lab')
SHARED = Path('/mnt/stack')
MARKER = '.stack-installation.json'
ROOTS = ('stateRoot', 'graphRoot', 'volumeRoot')
IDENTITIES = {name: (780 + index, 'webservices-lab-' + name) for index, name in enumerate(
    ('platform', 'apps', 'homeassistant', 'finance', 'ci-runner', 'workloads', 'test-runners'))}
HEX = re.compile(r'[a-f0-9]{64}')
MAX_NODES = 250000
# Finite exact synthetic-scope inventory capacity. Unrelated interface,
# evidence, catalog and kernel bounds remain unchanged.
MAX_SCOPE_NODES = 2000000
MAX_FILE = 16 * 1024 * 1024
UNDEFINED = 0xffffffff
# Reviewed owning source identities. Do NOT accept arbitrary root-owned Python,
# a receipt-supplied helper pointer, environment override or a mutable old tree.
# Adding historical versions needs source review + exact fixtures, not a flag.
RECOGNIZED = {
    'install-journal.py': {'0e2ac38b64f8b7cea5384e59d23e3c636b3e71b43bd7121c45c07753720844dd',
                           '53bdb4b77f9f4b50644cba92a78602ecc3b27b855f00fe6d2be71d4ac06724be',
                           'ae4694efcb00999d42297cd5f79905925b09e65cf930c5ebddb38bd27f3403e8'},
    'grant-rootless-volume-parent-traverse.py': {'3a6b4e405f8b06d0e641c9f4d527d71b18cf7d7dca45d3d95a65018557f6171d',
                                               '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32'},
    # b550 adds only retired-clean SOURCE/STOP inspection, never restart.
    'native-selection.py': {'ae771fcf2db288b6faa5a53445b38f55059d78a8614e688036254201c2c2d998',
                            'b550ac3c89006af86cb17634e84562da27161b25ee4066eea02b56f06c32d96e'},
    'install-podman-bundle.sh': {'b71e28cfb607b1464d11039deeca192c5bdd92f42b66e4f2d15492c4584706eb',
                                'e9c4ba3878623518900447c8b1259c5287ad22d1c54f8769892f92e4c5d73cc5',
                                '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'},
}
# These old generations actually created the legacy updater/drop-in namespace.
# A NEW installer shipping compatibility Ops artifacts is NOT that ownership.
LEGACY_SOURCE_INSTALLERS = frozenset({
    'b71e28cfb607b1464d11039deeca192c5bdd92f42b66e4f2d15492c4584706eb',
    'e9c4ba3878623518900447c8b1259c5287ad22d1c54f8769892f92e4c5d73cc5',
    '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'})
# Explicit reviewed owner checkpoints only; empty dependencies remain hard
# refusals until Main reviews their final source. Never auto-approve workspace
# code. Render-only alias closure; no Session/load/old executable is evaluated.
RUNTIME_ENV_RENDERER_PINS = {
    'native-runtime-env-units.py': frozenset({'5534fb2b85640d8a18bbccfbf35a7d70c1d565c782723d2d2a7e1c96dae48e39'}),
    'native-install-files.py': frozenset({'69250c79cc1bec438c94efb9b262e8a03d6c32994f7fa12f9b259c8807770617'}),
    'native-runtime-projection-owner.py': frozenset({'61ca500df2b61de8746b75281a5493b7fafdb5e6ac6de3db8ea5852b2b1c634e'}),
    'project-domain-runtime.py': frozenset({'366377c3a75125ee688425d63a1ada2e5587ada1660431981dfee723a695f29a'})}
UPDATER_SOURCES = {
    'webservices-auto-update': 'c70e7b9ce9cf3f1b7beaf925274a389f8732cc57fcb8f2b88ca4237d8a3325d5',
    'webservices-auto-update.service': 'f9b3fe2f89e769a160cbf7319378db5f1670d8be08d98d1de600e00fbcc8992a',
    'webservices-auto-update.timer': 'a600e3066aa543d3643d21b891e592932fee8262b4a7290b91fb61995a7c7171'}
CORE = ('bundle.json', 'stack.ir.json', 'source-provenance.json', 'podman-domains.json', 'site/manifest.json')
OPTIONAL = ('site/agent-vm.json', 'site/agent-vm.provenance.json', 'site/components.lock.json',
            'site/global.settings/registry-image-ids.json', 'site/global.settings/webservices.sops.json',
            'site/global.settings/build-base-image-ids.json')
_LEASE_KEY = object()
_NETWORK_STOP_KEY = object()
_NETWORK_STOP_UNITS = frozenset({'webservices-caddy-network.service', 'webservices-internet-network.service',
                                 'webservices-mailserver-network.service', 'webservices-monitoring-network.service',
                                 'webservices-runtime-env.service'})
_COMPILED = {}  # Only the finite, exact recognized Python hashes; never module state.


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def strict(body):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate authority key')
            result[key] = value
        return result
    def invalid(_):
        raise Refusal('Nonfinite authority value')
    result = json.loads(body, object_pairs_hook=pairs, parse_constant=invalid)
    require(isinstance(result, dict), 'Object authority required')
    return result


def absolute(value):
    require(isinstance(value, (str, Path)), 'Absolute path required')
    text = str(value); result = Path(text)
    require(result.is_absolute() and text == str(result) and text != '/'
            and '..' not in result.parts and not text.startswith('//'), 'Noncanonical authority path')
    return result


def stable(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def fingerprint(info):
    return stable(info) + [info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def acl(fd, default=False):
    try:
        raw = os.getxattr(fd, 'system.posix_acl_' + ('default' if default else 'access'))
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP): return []
        raise
    require(len(raw) >= 4 and (len(raw) - 4) % 8 == 0 and struct.unpack('<I', raw[:4])[0] == 2,
            'Malformed inode ACL')
    rows = [list(struct.unpack('<HHI', raw[pos:pos + 8])) for pos in range(4, len(raw), 8)]
    require(len({(tag, who) for tag, _, who in rows}) == len(rows)
            and all(tag in (1, 2, 4, 8, 16, 32) and 0 <= rights <= 7 for tag, rights, _ in rows),
            'Ambiguous inode ACL')
    return sorted(rows)


def custody(fd):
    return {'identity': stable(os.fstat(fd)), 'acl': acl(fd), 'defaultAcl': acl(fd, True)}


def root_directory(fd, private=False):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
            and (not private or stat.S_IMODE(info.st_mode) == 0o700)
            and not acl(fd) and not acl(fd, True), 'Unsafe sealed metadata directory')


@contextlib.contextmanager
def directory(path, policies=None):
    """NOFOLLOW each component. Exact exceptions, never prefix permissions."""
    path = absolute(path); policies = policies or {}
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pins = []; current = Path('/')
    try:
        root_directory(fd)
        pins.append((current, custody(fd)))
        for component in path.parts[1:]:
            current /= component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            if current in policies:
                require(custody(fd) == policies[current], 'Directory custody CAS changed')
            else:
                root_directory(fd)
            pins.append((current, custody(fd)))
        yield fd
        # Reopen with descriptors, never resolve a renamed/replaced chain.
        check = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(custody(check) == pins[0][1], 'Root custody changed')
            for selected, pin in pins[1:]:
                child = os.open(selected.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=check)
                os.close(check); check = child
                require(custody(check) == pin, 'Ancestor replaced during operation')
        finally:
            os.close(check)
    finally:
        os.close(fd)


def fd_mount_id(fd):
    with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as source: body = source.read(65537)
    rows = [line.split()[1] for line in body.splitlines() if line.startswith('mnt_id:')]
    require(len(body) <= 65536 and len(rows) == 1 and rows[0].isdecimal() and int(rows[0]) > 0, 'File mount identity unavailable')
    return int(rows[0])


def read_at(fd, name, owner=0, gid=None, private=False, limit=MAX_FILE, proof=None, scope_marker=False):
    if scope_marker:
        # Only this exact native scope marker may retain its inherited GID and
        # latent operator ACL. Never grant this profile to journal/source files.
        parent, scope = os.fstat(fd), os.stat(SCOPE, follow_symlinks=False)
        require(name == MARKER and owner == 0 and gid is None and private
                and stat.S_ISDIR(parent.st_mode) and stat.S_ISDIR(scope.st_mode)
                and (parent.st_dev, parent.st_ino) == (scope.st_dev, scope.st_ino),
                'Native marker profile requires exact scope parent/name')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child)
        access = acl(child)
        if scope_marker:
            native_acl = sorted([[1, 6, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED],
                                 [16, 0, UNDEFINED], [32, 0, UNDEFINED]])
            require(before.st_gid in (0, 1000) and access in ([], native_acl)
                    and not acl(child, True), 'Native scope marker mode/ACL differs')
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                and (gid is None or before.st_gid == gid) and not before.st_mode & 0o022
                and (not private or stat.S_IMODE(before.st_mode) == 0o600)
                and before.st_size <= limit and (scope_marker or not access), 'Unsafe sealed authority file')
        if proof is not None:
            require(fingerprint(before) == proof['stat'] and fd_mount_id(child) == proof['mountId']
                    and not acl(child, True), 'Original owning file FD/inode/mount CAS differs')
        output = bytearray()
        while len(output) <= limit:
            block = os.read(child, min(65536, limit + 1 - len(output)))
            if not block: break
            output.extend(block)
        require(len(output) == before.st_size and len(output) <= limit
                and fingerprint(os.fstat(child)) == fingerprint(before)
                and fingerprint(os.stat(name, dir_fd=fd, follow_symlinks=False)) == fingerprint(before),
                'Authority read CAS changed')
        if scope_marker:
            require(acl(child) == access and not acl(child, True), 'Native scope marker ACL read CAS changed')
        return bytes(output), fingerprint(before)
    finally:
        os.close(child)


def read_file(path, **kwargs):
    with directory(path.parent) as fd:
        return read_at(fd, path.name, **kwargs)


def fd9_lock(info):
    """Observe, do not acquire, the inherited open-description flock."""
    with open('/proc/self/fdinfo/9', encoding='ascii') as source:
        body = source.read(65537)
    rows = [row.split() for row in body.splitlines() if row.startswith('lock:')]
    require(len(body) <= 65536 and len(rows) == 1 and len(rows[0]) >= 9
            and rows[0][2:5] == ['FLOCK', 'ADVISORY', 'WRITE'], 'Inherited installer lock is not held')
    inode = rows[0][6].split(':')
    require(len(inode) == 3 and int(inode[0], 16) == os.major(info.st_dev)
            and int(inode[1], 16) == os.minor(info.st_dev) and int(inode[2]) == info.st_ino,
            'Inherited installer flock identity differs')


@contextlib.contextmanager
def locked(root):
    require(os.geteuid() == 0, 'Root installer authority required')
    with directory(root) as parent:
        root_directory(parent, True)
        fd = os.open('.install.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                    and not acl(fd), 'Unsafe existing installer lock')
            try: inherited = os.fstat(9)
            except OSError as error:
                if error.errno != errno.EBADF: raise
                inherited = None
            borrowed = inherited is not None and stable(inherited) == stable(info)
            if borrowed:
                fd9_lock(info)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    require(error.errno in (errno.EACCES, errno.EAGAIN), 'Installer flock observation failed')
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    raise Refusal('Inherited installer flock absent')
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(stable(os.stat('.install.lock', dir_fd=parent, follow_symlinks=False)) == stable(info),
                    'Installer lock replaced')
            yield parent, stable(info)
            if borrowed: fd9_lock(info)
            require(stable(os.stat('.install.lock', dir_fd=parent, follow_symlinks=False)) == stable(info),
                    'Installer lock replaced during operation')
        finally:
            os.close(fd)


def allocation_authority(rows):
    tables = {}; pins = {}
    for filename in ('subuid', 'subgid'):
        body, pin = read_file(Path('/etc') / filename, limit=1024 * 1024)
        pins[filename] = {'sha256': sha(body), 'stat': pin}; entries = []
        for line in body.decode('ascii').splitlines():
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            require(len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit(), 'Malformed allocation table')
            owner, start, count = parts[0], int(parts[1]), int(parts[2])
            require(start > 0 and count > 0 and start + count < 2**32, 'Invalid allocation interval')
            entries.append((owner, start, count))
        tables[filename] = entries
    ids = {p.pw_uid for p in pwd.getpwall()} | {g.gr_gid for g in grp.getgrall()}
    actors = []
    for row in rows:
        account = pwd.getpwnam(row['user']); reverse = pwd.getpwuid(row['uid'])
        group = grp.getgrgid(account.pw_gid)
        require(account.pw_uid == row['uid'] and account.pw_name == reverse.pw_name == row['user']
                and account.pw_dir == '/home/' + row['user'] and account.pw_gid > 0
                and group.gr_name == row['user'] and not group.gr_mem, 'Actor account/group identity drift')
        ranges = []
        for entries in tables.values():
            selected = [entry for entry in entries if entry[0] in (row['user'], str(row['uid']))]
            require(len(selected) == 1 and selected[0][2] == 65536, 'Exact single subordinate allocation required')
            owner, start, count = selected[0]
            require(not any(entry != selected[0] and start < entry[1] + entry[2] and entry[1] < start + count
                            for entry in entries), 'Overlapping allocated identity range')
            require(not any(start <= value < start + count for value in ids), 'Allocation overlaps host UID/GID')
            ranges.append(start)
        require(ranges[0] == ranges[1] and ('subuidStart' not in row or row['subuidStart'] == ranges[0]),
                'Receipted UID/GID allocation differs')
        actors.append({'name': row['name'], 'user': row['user'], 'uid': row['uid'], 'gid': account.pw_gid,
                       'start': ranges[0], 'count': 65536, 'home': account.pw_dir})
    for index, actor in enumerate(actors):
        require(not any(actor['start'] < other['start'] + 65536 and other['start'] < actor['start'] + 65536
                        for other in actors[index + 1:]), 'Cross-domain allocated identity overlap')
    operator = pwd.getpwuid(1000)
    require(operator.pw_uid == operator.pw_gid == 1000, 'Canonical operator UID/GID required')
    return {'files': pins, 'actors': actors, 'operator': {'uid': 1000, 'gid': 1000, 'name': operator.pw_name}}


def expected_acl(public=False, execute=(), operator_rights=7, default=False):
    result = [[1, 7, UNDEFINED], [2, operator_rights, 1000], [4, 7 if operator_rights == 7 else 5, UNDEFINED],
              [8, 7 if operator_rights == 7 else 5, 1000], [16, 7 if operator_rights == 7 else 5, UNDEFINED],
              [32, 5 if public and not default else 0, UNDEFINED]]
    if not default:
        result += [[2, 1, value] for value in sorted(execute)]
    return sorted(result)


def operator_acl(rows):
    # The named operator group is optional/redundant, never an authority to
    # broaden masks or accept another group. Canonical real defaults omit it.
    return [row for row in rows if row != [8, 7, 1000]]


def private_policy(fd, actor):
    info = os.fstat(fd)
    require((info.st_uid, info.st_gid) == (actor['uid'], actor['gid']), 'Private root identity differs')
    access, default = acl(fd), acl(fd, True)
    # Both ordinary private roots and native-engine owner-only SGID roots are
    # already private. Observe/pin them; never chmod/chown/clear inherited ACLs.
    modern = stat.S_IMODE(info.st_mode) in (0o700, 0o2700) and not access and not default
    legacy_access = sorted([[1, 7, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED],
                            [16, 0, UNDEFINED], [32, 0, UNDEFINED]])
    legacy_default = sorted([[1, 7, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED],
                             [16, 7, UNDEFINED], [32, 0, UNDEFINED]])
    require(modern or (stat.S_IMODE(info.st_mode) == 0o2700 and access == legacy_access
                       and default == legacy_default), 'Unknown private root mode/ACL; no repair permitted')
    return custody(fd)


def shared_policy(fd, path, execute):
    info = os.fstat(fd); mode = stat.S_IMODE(info.st_mode)
    access = acl(fd)
    fixed_access = [row for row in access if not (row[0] == 2 and row[2] in execute and row[1] == 1)]
    if path == SHARED:
        require((info.st_uid, info.st_gid, mode) == (1000, 1000, 0o2775)
                and operator_acl(fixed_access) == operator_acl(expected_acl(True))
                and operator_acl(acl(fd, True)) == operator_acl(expected_acl(True, default=True)), 'Shared parent custody/ACL differs')
    elif path == SCOPE:
        require((info.st_uid, info.st_gid, mode) == (1000, 1000, 0o2770)
                and operator_acl(fixed_access) == operator_acl(expected_acl(False))
                and operator_acl(acl(fd, True)) == operator_acl(expected_acl(False, default=True)), 'Exact scope custody/ACL differs')
    elif path == SCOPE / 'volumes':
        # Public certificate traversal is legitimate. The operator's named rwx
        # entry can remain MASKED to r-x; no mask broadening or repair occurs.
        require((info.st_uid, info.st_gid, mode) == (0, 1000, 0o755), 'Volume ancestor custody differs')
        rows = acl(fd)
        require(rows and not acl(fd, True), 'Volume ancestor ACL required')
        for tag, rights, who in rows:
            require((tag == 1 and rights == 7 and who == UNDEFINED)
                    or (tag == 2 and ((who == 1000 and rights in (5, 7)) or (who in execute and rights == 1)))
                    or (tag == 4 and rights == 5 and who == UNDEFINED)
                    or (tag == 8 and who == 1000 and rights in (5, 7))
                    or (tag in (16, 32) and rights == 5 and who == UNDEFINED), 'Foreign volume ancestor ACL')
        require({tag for tag, _, _ in rows} >= {1, 2, 4, 16, 32}
                and any(tag == 2 and who == 1000 for tag, _, who in rows), 'Incomplete volume ancestor ACL')
    else:
        require(info.st_uid in (0, 1000) and info.st_gid in (0, 1000)
                and mode in (0o700, 0o750, 0o2770), 'Foreign scoped ancestor')
        for tag, rights, who in acl(fd):
            require((tag == 2 and ((who == 1000 and rights == 7) or (who in execute and rights == 1)))
                    or (tag in (1, 4, 16) and who == UNDEFINED)
                    or (tag == 8 and who == 1000 and rights == 7)
                    or (tag == 32 and who == UNDEFINED and rights == 0), 'Foreign scoped ancestor ACL')
        require(operator_acl(acl(fd, True)) in ([], operator_acl(expected_acl(False, default=True))),
                'Foreign inherited scope ACL')
    return custody(fd)


def source_ancestry(path):
    """Pin the complete root-sealed source parent chain without resolving links."""
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pins = {}; current = Path('/')
    try:
        root_directory(fd); pins[str(current)] = custody(fd)
        for component in path.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child; current /= component
            root_directory(fd); pins[str(current)] = custody(fd)
        return pins
    finally: os.close(fd)


def helper_file(path):
    path = absolute(path); parents = source_ancestry(path)
    with directory(path.parent) as fd:
        body, pin = read_at(fd, path.name, gid=0)
    require(source_ancestry(path) == parents, 'Helper source ancestry changed')
    return body, {'path': str(path), 'sha256': sha(body), 'stat': pin, 'ancestry': parents}


def helper_bytes(release, name):
    """Selected bytes, or ONLY the closed stop-only missing-selection donor.

    An ENOENT from reading a formerly present inode/parent is NOT absence
    authority. Check the exact selected leaf first; present unknown/unsafe
    sources never select a donor. The canonical donor is a sibling of THIS
    root-sealed backend, not of a receipt pointer or another supplied path.
    """
    selected = release / 'ops' / name; parents = source_ancestry(selected)
    with directory(selected.parent) as fd:
        try: os.stat(selected.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: absent = True
        else: absent = False
        if not absent:
            body, pin = helper_file(selected)
            require(source_ancestry(selected) == parents, 'Selected helper ancestry changed')
            return body, dict(pin, origin='selected-release')
    require(name == 'native-selection.py', 'Missing historical helper has no stop-only donor')
    backend = absolute(__file__); donor = backend.with_name('native-selection.py')
    require(donor != selected, 'Canonical helper donor is the absent selected path')
    _, backend_pin = helper_file(backend)
    body, pin = helper_file(donor)
    require(pin['sha256'] in RECOGNIZED[name], 'Unrecognized canonical stop-only donor source')
    require(source_ancestry(selected) == parents, 'Absent selected helper ancestry changed')
    with directory(selected.parent) as fd:
        try: os.stat(selected.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise Refusal('Selected helper appeared during stop-only donor review')
    return body, dict(pin, origin='canonical-backend-sibling-stop-only', backend=backend_pin,
                      selectedPath=str(selected), selectedAbsent=True, selectedAncestry=parents)


def legacy_offline_actor(release, label):
    """Read-only closure from reviewed0e2ac journal; never execute old ae469."""
    if not label.startswith('rootless-'): return None
    metadata = json.loads((release / 'podman-domains.json').read_text())
    if metadata.get('deploymentMode') != 'standalone': return None
    name = label.removeprefix('rootless-')
    row = next(r for r in metadata['domains'] if r['name'] == name)
    manager = 'user@' + str(row['uid']) + '.service'
    result = subprocess.run(['systemctl', 'show', manager, '-p', 'Id', '-p', 'LoadState',
                             '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'Job'],
                            capture_output=True, text=True, timeout=15)
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if result.returncode or props.get('Id') != manager or props.get('LoadState') != 'loaded':
        raise ValueError('Unknown selected manager state')
    if props.get('ActiveState') == 'active' and props.get('SubState') == 'running': return None
    if (props.get('ActiveState') not in ('inactive', 'failed') or
            props.get('SubState') not in ('dead', 'failed') or props.get('MainPID') != '0' or props.get('Job') != ''):
        raise ValueError('Selected manager has pending activity')
    return row


def legacy_offline_control(command):
    return command[:-2] + ['SYSTEMD_OFFLINE=1', *command[-2:], '--no-reload']


def legacy_namespace_root_id(user, *, files=('/etc/subuid', '/etc/subgid')):
    """Exact read-only namespace closure from reviewed3a6b storage helper."""
    ranges = []
    for filename in files:
        path = Path(filename); info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 1024 * 1024):
            raise ValueError('Unsafe subordinate identity authority')
        matches = []; allocations = []
        for line in path.read_text().splitlines():
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
                raise ValueError('Malformed subordinate identity authority')
            start, count = int(parts[1]), int(parts[2])
            if start <= 0 or count <= 0 or start + count > 2**32 - 1:
                raise ValueError('Invalid subordinate identity interval')
            allocations.append((parts[0], start, count))
            if parts[0] == user: matches.append((start, count))
        if len(matches) != 1 or matches[0][1] != 65536:
            raise ValueError('Exact selected subordinate range required')
        start, count = matches[0]
        if any(owner != user and start < other + size and other < start + count
               for owner, other, size in allocations):
            raise ValueError('Selected subordinate interval overlaps another authority')
        ranges.append(matches[0])
    if ranges[0] != ranges[1]: raise ValueError('Subordinate UID/GID range disagreement')
    start, count = ranges[0]
    if any(start <= account.pw_uid < start + count for account in pwd.getpwall()) or any(
            start <= group.gr_gid < start + count for group in grp.getgrall()):
        raise ValueError('Selected subordinate interval overlaps a host identity')
    return start


def legacy_verify_offline_actor(row, command):
    """Only canonical reads; backend stopped() additionally checks ALL UID/GIDs."""
    linger = Path('/var/lib/systemd/linger') / row['user']
    if linger.exists() or linger.is_symlink(): raise ValueError('Stopped actor still has a linger trigger')
    result = subprocess.run(offline_control(command) + ['is-enabled', 'webservices.target', 'podman.socket'],
                            capture_output=True, text=True, timeout=15)
    states = result.stdout.splitlines()
    if result.returncode not in (0, 1, 4) or len(states) != 2 or any(
            state not in ('disabled', 'masked', 'not-found') for state in states):
        raise ValueError('Stopped actor still has boot/API activation')
    start = offline_subordinate_start(row['user'])
    for proc in Path('/proc').glob('[0-9]*'):
        try: status = (proc / 'status').read_text()
        except (FileNotFoundError, ProcessLookupError): continue
        uid_lines = [line for line in status.splitlines() if line.startswith('Uid:')]
        if len(uid_lines) != 1: raise ValueError('Unknown process identity during stopped proof')
        ids = list(map(int, uid_lines[0].split()[1:]))
        if any(uid == row['uid'] or start <= uid < start + 65536 for uid in ids):
            raise ValueError('Stopped actor still owns a live namespace/process')
    jobs = subprocess.run(['systemctl', 'list-jobs', '--no-legend', '--no-pager'],
                          capture_output=True, text=True, timeout=15)
    manager = 'user@' + str(row['uid']) + '.service'
    if jobs.returncode or any(manager in line.split() for line in jobs.stdout.splitlines()):
        raise ValueError('Stopped actor manager job remains')


def legacy_stop_module(name):
    # Clone ONLY these backend-owned read-only definitions into private globals,
    # so stopped() can inject the separately verified subordinate-ID reader.
    # No historical module top-level code, import loader, CLI or mutation API.
    module = types.ModuleType('_legacy_stop_only')
    module.__dict__.update(Path=Path, json=json, stat=stat, pwd=pwd, grp=grp, subprocess=subprocess)
    functions = ({'offline_actor': legacy_offline_actor, 'offline_control': legacy_offline_control,
                  'verify_offline_actor': legacy_verify_offline_actor} if name == 'install-journal.py'
                 else {'namespace_root_id': legacy_namespace_root_id})
    for key, function in functions.items():
        cloned = types.FunctionType(function.__code__, module.__dict__, key, function.__defaults__)
        cloned.__kwdefaults__ = function.__kwdefaults__
        setattr(module, key, cloned)
    return module


def source_module(release, name):
    body, pin = helper_bytes(release, name)
    digest = sha(body)
    require(digest in RECOGNIZED[name], 'Unrecognized historical helper source; source review required')
    # Actual dev16 helpers predate the offline APIs and contain mutation APIs
    # that reset must NEVER invoke. Only exact reviewed source identities use
    # this backend-owned canonical read-only closure; no old module exec/import.
    if name == 'install-journal.py' and digest == 'ae4694efcb00999d42297cd5f79905925b09e65cf930c5ebddb38bd27f3403e8':
        return legacy_stop_module(name), dict(pin, stopOnlyAdapter='journal0e2ac-offline')
    if name == 'grant-rootless-volume-parent-traverse.py' and digest == '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32':
        return legacy_stop_module(name), dict(pin, stopOnlyAdapter='storage3a6b-namespace')
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
        '_clean_' + name.replace('-', '_').replace('.', '_'), pin['path']))
    # Re-read/re-hash/re-pin on EVERY call, but avoid compiling the same reviewed
    # bytes at each private-root CAS. Fresh globals and the ACTUAL source
    # __file__ every time; journal sibling imports must not point at the donor.
    key = (name, digest)
    if key not in _COMPILED: _COMPILED[key] = compile(body, '<reviewed-clean-reset:' + name + '>', 'exec')
    exec(_COMPILED[key], module.__dict__)
    return module, pin


def prior_completed_reset(root, receipt):
    """Authenticate history only; never reuse its plan, inventory or stopped lease."""
    proof = receipt.get('completeCleanReset')
    flags = ('applicationAcceptance', 'rootfulStoreColdAcceptance', 'automaticRestart', 'dataCompatibilityProven')
    require(receipt.get('phase') == 'retired-clean' and isinstance(proof, dict)
            and set(proof) == {'intentSha256', 'planSha256', 'resultPath', 'resultSha256', *flags}
            and all(proof.get(flag) is False for flag in flags)
            and all(isinstance(proof.get(key), str) and HEX.fullmatch(proof[key])
                    for key in ('intentSha256', 'planSha256', 'resultSha256')),
            'Retired-clean requires exact prior canonical completion evidence')
    result_path = absolute(proof['resultPath'])
    match = re.fullmatch(re.escape(proof['planSha256']) + r'-[a-f0-9]{32}-result\.json', result_path.name)
    require(result_path.parent == root / '.host-clean-reset' and match is not None,
            'Prior completion evidence escaped exact source-owned namespace')
    body, result_pin = read_file(result_path, private=True, gid=0)
    require(sha(body) == proof['resultSha256'], 'Prior completion result hash differs')
    result = strict(body)
    prefix = '.clean-reset-' + result_path.name.removesuffix('-result.json') + '-'
    require(type(result.get('schemaVersion')) is int and result['schemaVersion'] == 1
            and result.get('kind') == 'complete-owned-synthetic-clean-reset'
            and result.get('phase') == 'complete-owned-synthetic-clean'
            and result.get('completeCleanReset') is True
            and result.get('requiredJournalTransition') == 'journal-owner-exact-CAS-retired-clean-no-restart'
            and result.get('intentSha256') == proof['intentSha256']
            and result.get('planSha256') == proof['planSha256'] and result.get('claimPrefix') == prefix,
            'Prior canonical completion result differs')
    intent_path = result_path.with_name(result_path.name.removesuffix('-result.json') + '-intent.json')
    intent_body, intent_pin = read_file(intent_path, private=True, gid=0)
    operation = strict(intent_body); plan = operation.get('plan')
    require(isinstance(plan, dict) and sha(canonical(plan)) == proof['planSha256']
            and operation.get('intentSha256') == proof['intentSha256']
            and operation.get('planSha256') == proof['planSha256'] and operation.get('claimPrefix') == prefix
            and plan.get('kind') == 'complete-owned-synthetic-clean-reset'
            and plan.get('root') == str(root) and plan.get('scope') == str(SCOPE)
            and plan.get('authority', {}).get('release') == receipt.get('release')
            and all(plan.get('authority', {}).get('sourceInputs', {}).get(name, {}).get('sha256') == receipt.get('inputs', {}).get(name)
                    for name in CORE), 'Prior canonical source/scope/intent evidence differs')
    return {'result': {'path': str(result_path), 'sha256': sha(body), 'stat': result_pin},
            'intent': {'path': str(intent_path), 'sha256': sha(intent_body), 'stat': intent_pin}}


def binding(root, expected):
    require(isinstance(expected, str) and HEX.fullmatch(expected), 'Exact intent CAS required')
    raw, journal_pin = read_file(root / '.install-intent.json', private=True, gid=0)
    require(sha(raw) == expected, 'Intent CAS changed')
    receipt = strict(raw); release = absolute(receipt.get('release'))
    require(type(receipt.get('schemaVersion')) is int and receipt['schemaVersion'] == 1
            and receipt.get('phase') in ('failed', 'retired-failed', 'active', 'retired-clean')
            and release.parent == root / 'releases', 'Unrecognized terminal journal authority')
    with directory(release) as fd: root_directory(fd, True)
    receipt_body, receipt_pin = read_file(release / 'installation-receipt.json', private=True, gid=0)
    require(receipt_body == raw, 'Root receipt differs from selected intent')
    with directory(root) as fd:
        pointer = os.stat('current', dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISLNK(pointer.st_mode) and pointer.st_uid == pointer.st_gid == 0 and pointer.st_nlink == 1
                and os.readlink('current', dir_fd=fd) == str(release), 'Current is not the exact receipted release')
        require(fingerprint(pointer) == fingerprint(os.stat('current', dir_fd=fd, follow_symlinks=False)),
                'Current pointer CAS changed')
    inputs = receipt.get('inputs')
    require(isinstance(inputs, dict) and set(CORE) <= set(inputs) <= set(CORE + OPTIONAL), 'Missing canonical source pins')
    documents = {}; source_pins = {}
    # Source documents establish authority. Optional receipted inputs are only
    # hashed as opaque bytes (never interpreted/decrypted); absence is also a
    # pin. No key, token, rendered environment or arbitrary store is discovered.
    for name in CORE:
        require(isinstance(inputs[name], str) and HEX.fullmatch(inputs[name]), 'Invalid source hash')
        body, pin = read_file(release / name)
        require(sha(body) == inputs[name], 'Receipted source hash changed')
        documents[name] = strict(body); source_pins[name] = {'sha256': sha(body), 'stat': pin}
    for name in OPTIONAL:
        if name not in inputs: continue
        path = release / name; digest = inputs[name]
        if digest is None:
            try:
                with directory(path.parent) as fd:
                    try: os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError: pass
                    else: raise Refusal('Receipted absent source appeared')
            except FileNotFoundError: pass
            source_pins[name] = None
        else:
            require(isinstance(digest, str) and HEX.fullmatch(digest), 'Invalid optional source hash')
            body, pin = read_file(path)
            require(sha(body) == digest, 'Receipted optional source hash changed')
            source_pins[name] = {'sha256': digest, 'stat': pin}
    bundle, ir, provenance, metadata, manifest = [documents[name] for name in CORE]
    require(bundle.get('backend') == 'podman' and bundle.get('irSha256') == inputs['stack.ir.json']
            and bundle.get('sourceProvenanceSha256') == inputs['source-provenance.json']
            and provenance.get('manifestSha256') == inputs['site/manifest.json']
            and isinstance(provenance.get('generatorCommit'), str)
            and re.fullmatch(r'[a-f0-9]{40}', provenance['generatorCommit']), 'Source provenance differs')
    scope_config = {'root': str(SCOPE), 'dataClass': 'synthetic'}
    require(manifest.get('deploymentMode') == metadata.get('deploymentMode') == 'standalone'
            and manifest.get('storageScope') == metadata.get('storageScope') == scope_config
            and manifest.get('installerStateRoot') == metadata.get('installerStateRoot') == str(root)
            and 'venue' not in metadata and 'agentVmSpec' not in manifest
            and not root.is_relative_to(SCOPE) and not SCOPE.is_relative_to(root), 'Not the exact host synthetic scope')
    rows = metadata.get('domains')
    require(isinstance(rows, list) and len(rows) == len(IDENTITIES)
            and {row.get('name') for row in rows if isinstance(row, dict)} == set(IDENTITIES), 'Seven exact lab domains required')
    roots = {}; marker_rows = []
    for row in rows:
        require((row.get('uid'), row.get('user')) == IDENTITIES[row['name']]
                and type(row.get('uid')) is int, 'Selected domain account differs')
        marker_row = {key: row[key] for key in ('name', 'user', 'uid')}
        for key in ROOTS:
            path = absolute(row.get(key))
            require(path != SCOPE and path.is_relative_to(SCOPE) and path not in roots, 'Private root escapes or collides')
            roots[path] = row['name']; marker_row[key] = str(path)
        marker_rows.append(marker_row)
    ordered = sorted(roots)
    require(not any(a.is_relative_to(b) or b.is_relative_to(a) for i, a in enumerate(ordered) for b in ordered[i + 1:]),
            'Overlapping private domain roots')
    allocation = allocation_authority(rows)
    execute_ids = {entry[key] for entry in allocation['actors'] for key in ('uid', 'start')}
    policies = {}
    parents = {SHARED, SCOPE}
    for path in roots:
        parents.update(parent for parent in path.parents if parent.is_relative_to(SCOPE))
    # Open the exact known shared ancestors. No policy is inferred from current
    # permissions; each is checked against the closed canonical layout first.
    for selected in sorted(parents, key=lambda path: (len(path.parts), str(path))):
        with directory(selected.parent, policies) as parent:
            fd = os.open(selected.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try: policies[selected] = shared_policy(fd, selected, execute_ids)
            finally: os.close(fd)
    actors = {entry['name']: entry for entry in allocation['actors']}
    absent_roots = []
    for path, name in roots.items():
        with directory(path.parent, policies) as parent:
            try: fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                absent_roots.append(str(path)); continue
            try: policies[path] = private_policy(fd, actors[name])
            finally: os.close(fd)
    marker = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': manifest.get('site'),
              'scope': scope_config, 'domains': sorted(marker_rows, key=lambda row: row['name']),
              'roots': sorted(str(path) for path in roots)}
    with directory(SCOPE, policies) as fd:
        marker_raw, marker_pin = read_at(fd, MARKER, private=True, limit=65536, scope_marker=True)
        require(canonical(strict(marker_raw)) == canonical(marker), 'Exact synthetic scope marker differs')
    helpers = {}; modules = {}
    for name in RECOGNIZED:
        if name.endswith('.py'):
            modules[name], helpers[name] = source_module(release, name)
        else:
            body, pin = read_file(release / 'ops' / name)
            require(sha(body) in RECOGNIZED[name], 'Unrecognized installer generation authority')
            helpers[name] = {'sha256': sha(body), 'stat': pin}
    native = modules['native-selection.py']
    # Previous-only is SOURCE/STOP/REMOVAL authority. No new role verifier or
    # active-transition gate is relaxed to cope with historical data stores.
    selected = native.source_plan(release, previous=True)
    # The donor supplies selection CODE only. Its plan above remains bound to
    # the OLD selected release/receipt/manifest, never the donor's installation.
    # Recheck origin/source/inode/ancestry and selected absence after use; later
    # full bindings repeat this check before lease issuance and any deletion.
    for name, pin in helpers.items():
        if pin.get('origin') == 'canonical-backend-sibling-stop-only':
            _, current = helper_bytes(release, name)
            require(current == pin, 'Canonical stop-only donor CAS changed during use')
    selection = {'root': root, 'release': release, 'receipt': receipt, 'rows': rows, 'roots': roots,
            'actors': actors, 'policies': policies, 'modules': modules, 'ir': ir,
            'pin': {'intentSha256': expected, 'journal': journal_pin, 'receipt': receipt_pin,
                    'release': str(release), 'pointer': fingerprint(pointer), 'marker': marker_pin,
                    'markerSha256': sha(marker_raw), 'sourceInputs': source_pins, 'helpers': helpers,
                    'allocation': allocation, 'selection': selected, 'absentPrivateRoots': sorted(absent_roots),
                    'custody': {str(path): pin for path, pin in sorted(policies.items())}}}
    if receipt['phase'] == 'retired-clean':
        selection['pin']['priorCompletedReset'] = prior_completed_reset(root, receipt)
    selection['pin']['originalFixtureProfiles'] = original_fixture_profiles(selection)
    selection['pin']['emptyRootfulLogNamespaces'] = empty_rootful_log_namespaces(selection)
    return selection


def run_read(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=15,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def actor_command(actor):
    return ['/usr/sbin/runuser', '-u', actor['user'], '--', '/usr/bin/env', '-i', 'HOME=' + actor['home'],
            'XDG_RUNTIME_DIR=/run/user/' + str(actor['uid']),
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(actor['uid']) + '/bus', '/usr/bin/systemctl', '--user']


def process_statuses():
    # Read only process identities. Unreadable namespace/process views refuse.
    for path in sorted(Path('/proc').glob('[0-9]*/status')):
        try: yield path.read_text()
        except (FileNotFoundError, ProcessLookupError): continue


def _stopped_observation(selection, network_stop=None):
    """Shared reads; only a source-bound internal context observes pending networks."""
    if network_stop is not None:
        require(type(network_stop) is _NetworkStopContext, 'Exact network stop context required')
        network_stop.validate(selection)
    controls = {}
    journal = selection['modules']['install-journal.py']
    storage = selection['modules']['grant-rootless-volume-parent-traverse.py']
    # Reuse the verified historical function, but bind its subordinate helper
    # to the already verified bytes; never import a mutable pyc or unknown file.
    journal.offline_subordinate_start = storage.namespace_root_id
    selected = selection['pin']['selection']['scopes']
    for row in selection['rows']:
        actor = selection['actors'][row['name']]; command = actor_command(actor)
        proof = journal.offline_actor(selection['release'], 'rootless-' + row['name'])
        require(proof is not None and all(proof.get(key) == row[key] for key in ('name', 'user', 'uid') + ROOTS),
                'Canonical stopped actor differs or manager remains active')
        journal.verify_offline_actor(proof, command)
        # Canonical gate handles target + API. Include every exact selected
        # target and runtime oneshot; never contact a stopped user manager bus.
        units = selected['rootless-' + row['name']]['targets'] + ['podman.socket']
        result = run_read(journal.offline_control(command) + ['is-enabled', *units])
        states = result.stdout.splitlines()
        require(result.returncode in (0, 1, 4) and len(states) == len(units)
                and all(state in ('disabled', 'masked', 'not-found') for state in states), 'Actor boot/API trigger remains')
    # Include all four UID/GID fields, not just real UID, and both allocated
    # tables. Canonical historical gate alone only checks UIDs.
    for body in process_statuses():
        fields = {}
        for line in body.splitlines():
            if line.startswith(('Uid:', 'Gid:', 'Groups:')):
                key, value = line.split(':', 1)
                require(key not in fields, 'Ambiguous process identity')
                fields[key] = value.split()
        require(set(fields) == {'Uid', 'Gid', 'Groups'}
                and all(len(fields[key]) == 4 for key in ('Uid', 'Gid'))
                and all(all(value.isdecimal() for value in values) for values in fields.values()), 'Incomplete process identity')
        for actor in selection['actors'].values():
            for key, own in (('Uid', actor['uid']), ('Gid', actor['gid'])):
                require(not any(int(value) == own or actor['start'] <= int(value) < actor['start'] + 65536
                                for value in fields[key] + (fields['Groups'] if key == 'Gid' else [])),
                        'Actor or allocated UID/GID process remains')
    units = sorted(set(selected['rootful']['units']) | {
        'webservices-auto-update.timer', 'webservices-auto-update.service', 'webservices-runtime-env.service'})
    for unit in units:
        fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Job', 'UnitFileState',
                  'Triggers', 'TriggeredBy', 'Transient', 'DropInPaths', 'Names', 'FragmentPath', 'SourcePath')
        result = run_read(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                           *[item for field in fields for item in ('-p', field)]])
        props = {}
        for line in result.stdout.splitlines():
            require('=' in line, 'Malformed native unit proof')
            key, value = line.split('=', 1)
            require(key in fields and key not in props, 'Ambiguous native unit proof'); props[key] = value
        # MainPID belongs to the Service D-Bus interface, not Target/Timer/Socket.
        # Preserve honest absence for those exact types, never invent a PID0 or
        # permit incomplete service/other control evidence.
        no_pid_type = unit.endswith(('.target', '.timer', '.socket'))
        expected_fields = set(fields) - ({'MainPID'} if no_pid_type and 'MainPID' not in props else set())
        generated = (props.get('UnitFileState') == 'generated' and unit.endswith('.service')
                     and props.get('LoadState') == 'loaded' and props.get('Names') == unit
                     and props.get('SourcePath') in selection.get('unitAuthorities', {}).get(unit, set())
                     and Path(props.get('SourcePath', '')).parent == Path('/etc/containers/systemd')
                     and props.get('FragmentPath') == '/run/systemd/generator/' + unit)
        original_env = (unit == 'webservices-runtime-env.service' and props.get('LoadState') == 'loaded'
                        and props.get('UnitFileState') == 'static' and props.get('Names') == unit
                        and props.get('SourcePath') == '' and props.get('FragmentPath') == '/etc/systemd/system/' + unit)
        pending_network = (network_stop is not None and (generated or original_env)
                           and network_stop.units.get(unit) == (props.get('SourcePath') or props.get('FragmentPath'))
                           and props.get('ActiveState') == 'active' and props.get('SubState') == 'exited'
                           and props.get('Triggers') == props.get('TriggeredBy') == props.get('DropInPaths') == '')
        require(not result.returncode and set(props) == expected_fields and props['Id'] == unit
                and props['LoadState'] in ('loaded', 'not-found')
                and ((props['ActiveState'] in ('inactive', 'failed') and props['SubState'] in ('dead', 'failed'))
                     or pending_network)
                and (props.get('MainPID') == '0' if 'MainPID' in props else no_pid_type) and props['Job'] in ('', '0')
                and (props['UnitFileState'] in ('', 'disabled', 'masked', 'static', 'not-found') or generated)
                and props['Transient'] == 'no' and props['Names'].split() in ([], [unit])
                and props['DropInPaths'].split() in ([], ['/etc/systemd/system/webservices.target.d/10-runtime-env.conf']
                                                    if unit == 'webservices.target' else [])
                and set(props['Triggers'].split()) <= set(units)
                and set(props['TriggeredBy'].split()) <= set(units), 'Root selected workload not canonically stopped')
        if unit.endswith(('.target', '.timer', '.socket')):
            require(props['UnitFileState'] in ('disabled', 'masked', 'not-found', ''), 'Root selected activation remains')
        authorities = selection.get('unitAuthorities', {})
        allowed = authorities.get(unit, set())
        require((not props['SourcePath'] and not props['FragmentPath']) if props['LoadState'] == 'not-found'
                else (props['SourcePath'] or props['FragmentPath']) in allowed, 'Loaded root source not selected')
        controls[unit] = props
    jobs = run_read(['/usr/bin/systemctl', 'list-jobs', '--no-legend', '--no-pager', '--plain'])
    require(not jobs.returncode and not jobs.stdout.strip(), 'Native jobs remain; no jobs are cancelled')
    return controls


def stopped(selection):
    """Unchanged strict reset gate: EVERY selected workload must be stopped."""
    _stopped_observation(selection)


def _mount_kernel_fs(fd, namespace=False):
    """Actual held kernel descriptors, never ns symlink text or caller JSON."""
    libc = ctypes.CDLL(None, use_errno=True); data = ctypes.create_string_buffer(512)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]; libc.fstatfs.restype = ctypes.c_int
    require(libc.fstatfs(fd, data) == 0
            and ctypes.c_long.from_buffer(data).value == (0x6e736673 if namespace else 0x9fa0),
            'Mount observation is not a held kernel procfs/nsfs object')
    if namespace:
        require(fcntl.ioctl(fd, 0xb703) == 0x00020000, 'Held namespace is not a kernel mount namespace')  # NS_GET_NSTYPE / CLONE_NEWNS


def _mount_proc_read(parent, leaf):
    require(leaf in ('stat', 'mountinfo'), 'Unknown process mount observation')
    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        _mount_kernel_fs(fd)
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'Process mount observation is not regular procfs')
        data = bytearray(); limit = 16 * 1024 * 1024 if leaf == 'mountinfo' else 65536
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        require(len(data) <= limit, 'Process mount observation bound exceeded')
        return bytes(data)
    finally: os.close(fd)


def _mount_proc_start(process, pid):
    data = _mount_proc_read(process, 'stat'); end = data.rfind(b')')
    fields = data[end + 1:].split()
    require(data.startswith(str(pid).encode() + b' (') and end > 0 and len(fields) >= 20
            and fields[19].isdigit(), 'Original process start identity unavailable')
    return int(fields[19])


def _mount_missing_kernel_object_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_descriptor_capacity_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_access_denied_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_invalid_kernel_reference_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_bad_descriptor_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_wrong_kernel_object_type_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_unsupported_kernel_operation_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


def _mount_interrupted_kernel_operation_observation():
    raise Refusal('Original process/kernel namespace/root proof unavailable') from None


@contextlib.contextmanager
def _mount_process(proc, name):
    own = name == 'self'; pid = os.getpid() if own else int(name)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | (0 if own else os.O_NOFOLLOW)
    process = os.open(name, flags, dir_fd=proc)
    namespace = root = None
    try:
        _mount_kernel_fs(process); process_pin = stable(os.fstat(process))
        def start(): return _mount_proc_start(process, pid)
        original_start = start()
        def open_namespace():
            parent = os.open('ns', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=process)
            try:
                _mount_kernel_fs(parent)
                fd = os.open('mnt', os.O_RDONLY | os.O_CLOEXEC, dir_fd=parent)  # intentional kernel magic-link open
                try: _mount_kernel_fs(fd, namespace=True)
                except BaseException: os.close(fd); raise
                return fd
            finally: os.close(parent)
        namespace = open_namespace()
        root = os.open('root', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process)  # kernel root FD, not readlink
        namespace_pin, root_pin = stable(os.fstat(namespace)), stable(os.fstat(root))
        def check():
            require(stable(os.fstat(process)) == process_pin
                    and stable(os.stat(name, dir_fd=proc, follow_symlinks=own)) == process_pin
                    and start() == original_start, 'Original process/PID changed during mount observation')
            current = open_namespace()
            try:
                require(stable(os.fstat(current)) == stable(os.fstat(namespace)) == namespace_pin,
                        'Original kernel mount namespace changed')
            finally: os.close(current)
            current = os.open('root', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=process)
            try:
                require(stable(os.fstat(current)) == stable(os.fstat(root)) == root_pin,
                        'Original process root changed during mount observation')
            finally: os.close(current)
        check()
        yield process, namespace_pin, root_pin, check
        check()
    except OSError as error:
        # Predefined trusted ops frames only; no errno values, process names,
        # paths, exception text or locals become diagnostics. All cases refuse.
        if error.errno in (errno.ENOENT, errno.ESRCH):
            _mount_missing_kernel_object_observation()
        if error.errno in (errno.EMFILE, errno.ENFILE):
            _mount_descriptor_capacity_observation()
        if error.errno in (errno.EACCES, errno.EPERM):
            _mount_access_denied_observation()
        if error.errno in (errno.EIO, errno.EINVAL, errno.ESTALE):
            _mount_invalid_kernel_reference_observation()
        if error.errno == errno.EBADF:
            _mount_bad_descriptor_observation()
        if error.errno in (errno.ENOTDIR, errno.ELOOP, errno.ENOTTY):
            _mount_wrong_kernel_object_type_observation()
        if error.errno in (errno.ENOSYS, errno.EOPNOTSUPP):
            _mount_unsupported_kernel_operation_observation()
        if error.errno in (errno.EINTR, errno.EAGAIN):
            _mount_interrupted_kernel_operation_observation()
        raise Refusal('Original process/kernel namespace/root proof unavailable') from None
    finally:
        if root is not None: os.close(root)
        if namespace is not None: os.close(namespace)
        os.close(process)


def mount_views():
    proc = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _mount_kernel_fs(proc); proc_pin = stable(os.fstat(proc))
        with _mount_process(proc, 'self') as (own, own_ns, own_root, check_self):
            host = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try: require(stable(os.fstat(host)) == own_root, 'Full current process root unavailable')
            finally: os.close(host)
            original = _mount_proc_read(own, 'mountinfo')
            lines = original.decode('utf-8').splitlines()
            roots = [line.split() for line in lines if len(line.split()) >= 5 and line.split()[4] == '/']
            device = str(os.major(own_root[0])) + ':' + str(os.minor(own_root[0]))
            require(lines and len(roots) == 1 and roots[0][2:5] == [device, '/', '/'],
                    'Complete current root mount view unavailable')
            result = [lines]
            names = sorted(name for name in os.listdir(proc) if re.fullmatch(r'[0-9]+', name))
            require(len(names) <= MAX_NODES, 'Process mount observation count exceeded')
            for name in names:
                # Preserve the old ENOENT/ESRCH policy ONLY before observing a
                # mountinfo file (including kernel tasks without such a view).
                # An observed EMPTY file is NEVER skipped. Subsequent change refuses.
                process = None
                try:
                    try:
                        process = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc)
                        _mount_kernel_fs(process); original_process = stable(os.fstat(process))
                        original_start = _mount_proc_start(process, int(name))
                        observed = _mount_proc_read(process, 'mountinfo')
                    except (FileNotFoundError, ProcessLookupError): continue
                    with _mount_process(proc, name) as (fd, namespace, root, check):
                        require(stable(os.fstat(fd)) == original_process and _mount_proc_start(fd, int(name)) == original_start,
                                'Original observed process/PID changed')
                        view = _mount_proc_read(fd, 'mountinfo')
                        require(view == observed, 'Original observed mount view changed')
                        if not view:
                            require(namespace == own_ns and root != own_root,
                                    'Empty foreign/unknown/non-chroot mount view')
                            check_self(); check()
                            require(_mount_proc_read(own, 'mountinfo') == original,
                                    'Original full namespace mount view changed')
                            result.append(list(lines))  # same held kernel namespace: complete self view, NOT skipping a process
                        else: result.append(view.decode('utf-8').splitlines())
                        require(_mount_proc_read(fd, 'mountinfo') == view, 'Process mount view changed during observation')
                    require(stable(os.fstat(process)) == original_process and _mount_proc_start(process, int(name)) == original_start,
                            'Original held process/PID changed')
                finally:
                    if process is not None: os.close(process)
            check_self()
            require(_mount_proc_read(own, 'mountinfo') == original
                    and stable(os.fstat(proc)) == stable(os.stat('/proc', follow_symlinks=False)) == proc_pin,
                    'Original proc/full namespace mount CAS changed')
            require(len(result) >= 2, 'Process mount proof unavailable')
            return result
    finally: os.close(proc)


class _NamespaceMountRoot:
    """Kernel NSFS inode label, deliberately NOT a filesystem Path."""
    __slots__ = ('label', 'inode')
    def __init__(self, label, inode): self.label, self.inode = label, inode


def _mount_nsfs_device():
    # Observe only OUR kernel namespace, never open another user's mountpoint.
    proc = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _mount_kernel_fs(proc); original = stable(os.fstat(proc))
        with _mount_process(proc, 'self') as (_, namespace, _, check):
            check(); device = namespace[0]
        require(stable(os.fstat(proc)) == stable(os.stat('/proc', follow_symlinks=False)) == original,
                'Original namespace device proc proof changed')
        return str(os.major(device)) + ':' + str(os.minor(device))
    finally: os.close(proc)


def unmounted(paths, policies=None):
    views = []; nsfs_device = None
    for lines in mount_views():
        rows = []
        for line in lines:
            fields = line.split()
            require(len(fields) >= 10 and '-' in fields and re.fullmatch(r'\d+:\d+', fields[2]), 'Invalid mount proof')
            def decode(value):
                value = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
                require(value.startswith('/') and '\x00' not in value and '..' not in Path(value).parts, 'Invalid mount path')
                return Path(value)
            mountpoint = decode(fields[4])
            separator = fields.index('-')
            if fields[separator + 1:separator + 2] == ['nsfs']:
                require(fields.count('-') == 1 and separator >= 6 and len(fields) == separator + 4
                        and fields[separator + 2] == 'nsfs', 'Invalid typed NSFS record')
                label = re.fullmatch(r'net:\[([1-9][0-9]{0,19})\]', fields[3])
                require(label is not None and int(label[1]) < 2**64 and mountpoint != Path('/'),
                        'Invalid typed NSFS network namespace root')
                if nsfs_device is None: nsfs_device = _mount_nsfs_device()
                require(fields[2] == nsfs_device, 'NSFS record differs from actual kernel namespace device')
                root = _NamespaceMountRoot(fields[3], int(label[1]))
            else: root = decode(fields[3])  # ordinary/unknown filesystem paths remain strictly absolute
            rows.append((fields[2], root, mountpoint))
        require(rows, 'Empty process mount view'); views.append(rows)
    for path in paths:
        parents = [row for row in views[0] if path.is_relative_to(row[2])]
        require(parents, 'Mount ancestry unavailable')
        base = max(parents, key=lambda row: len(row[2].parts))
        require(isinstance(base[1], Path), 'Selected data cannot reside on a namespace file')
        with directory(path, policies) as fd:
            device = os.fstat(fd).st_dev
            require(base[0] == str(os.major(device)) + ':' + str(os.minor(device)), 'Mount/device proof differs')
            require(nsfs_device is None or base[0] != nsfs_device, 'Selected data cannot use the namespace filesystem')
        require(path != base[2] and not any(row[2].is_relative_to(path) for row in views[0]), 'Scope or child is mounted')
        fs_path = base[1] / path.relative_to(base[2])
        for rows in views:
            for device, fs_root, mountpoint in rows:
                if isinstance(fs_root, _NamespaceMountRoot):
                    require(not (path.is_relative_to(mountpoint) or mountpoint.is_relative_to(path)),
                            'Namespace file mount overlaps selected data in a process view')
                    require(device != base[0], 'Namespace inode cannot be a selected data filesystem alias')
                else:
                    require(not (device == base[0] and (fs_root.is_relative_to(fs_path)
                            or (fs_path.is_relative_to(fs_root) and fs_root != base[1]))), 'Scope has a mount namespace alias')


def owns(value, actor, group=False):
    return value == 0 or (actor is not None and (value == actor['gid' if group else 'uid']
                                                or actor['start'] <= value < actor['start'] + 65536))


def original_fixture_profiles(selection):
    """Closed OLD source contract only; never a current-NSS/group permission.

    binding() has verified original dual receipts, input/provenance hashes,
    marker/allocation and these exact owning helper bytes.  Public installer
    creates IR hostPaths, grants shared strategy access to the ORIGINAL actor;
    original empty named inputs/ancestors are distinct from private data roots.
    No inode, caller JSON flag, regenerated input or audit hash selects a rule.
    """
    pin = selection.get('pin', {}); helpers = pin.get('helpers', {}); receipt = selection.get('receipt', {})
    installer = '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'
    if not (helpers.get('install-podman-bundle.sh', {}).get('sha256') == installer
            and helpers.get('grant-rootless-volume-parent-traverse.py', {}).get('sha256')
                == '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32'
            and receipt.get('phase') == 'retired-failed' and legacy_installer_published(installer, receipt)
            and all(HEX.fullmatch(pin.get('sourceInputs', {}).get(name, {}).get('sha256', ''))
                    and receipt.get('inputs', {}).get(name) == pin['sourceInputs'][name]['sha256']
                    for name in ('stack.ir.json', 'site/manifest.json'))
            and selection.get('actors', {}).get('apps', {}).get('uid') == 781
            and selection['actors']['apps'].get('gid') == 781): return {}
    base = SCOPE / 'fixtures'; media = base / 'media'
    volumes = {'jellyfin_media': {'hostPath': str(media / 'jellyfin-media'), 'rootlessStrategy': 'shared'},
               'qbittorrent_data': {'hostPath': str(media / 'qbittorrent'), 'rootlessStrategy': 'shared'},
               'seafile_files': {'hostPath': str(media / 'seafile-media'), 'rootlessStrategy': 'copy'}}
    ir = selection['ir']
    declared = {name: value for name, value in ir.get('volumes', {}).items()
                if name in volumes or (isinstance(value, dict) and isinstance(value.get('hostPath'), str)
                    and (value['hostPath'] == str(base) or value['hostPath'].startswith(str(base) + '/')))}
    if declared != volumes: return {}
    expected = {name: {'module': name, 'placement': 'rootless', 'rootlessDomain': 'apps', 'mounts': [mount]}
                for name, mount in [('jellyfin', 'jellyfin_media:/media:ro'),
                                    ('qbittorrent', 'qbittorrent_data:/downloads'), ('seafile', 'seafile_files:/shared')]}
    expected['volume-init'] = {'module': 'stack-foundation', 'placement': 'rootful', 'rootlessDomain': None,
                              'mounts': sorted(value['hostPath'] + ':' + value['hostPath'] + ':rw' for value in volumes.values())}
    consumers = {}
    for name, service in ir.get('services', {}).items():
        mounts = []
        for mount in service.get('volumes', []):
            source = mount.split(':', 1)[0] if isinstance(mount, str) else mount.get('source', '')
            if source in volumes or source == str(base) or source.startswith(str(base) + '/'):
                if not isinstance(mount, str): return {}
                mounts.append(mount)
        if mounts: consumers[name] = {'module': service.get('module'), 'placement': service.get('placement', 'rootful'),
                                      'rootlessDomain': service.get('rootlessDomain'), 'mounts': sorted(mounts)}
    if consumers != expected: return {}
    def profile(mode, other=0, mask=5, apps=False, children=()):
        access = [[1, 7, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED], [16, mask, UNDEFINED], [32, other, UNDEFINED]]
        default = [[1, 7, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED], [16, 7, UNDEFINED], [32, 0, UNDEFINED]]
        if apps: access.append([2, 7, 781]); default.append([2, 7, 781])
        return {'uid': 0, 'gid': 1000, 'mode': mode, 'acl': sorted(access), 'defaultAcl': sorted(default), 'children': sorted(children)}
    return {str(base): profile(0o2750, children=['media']),
            str(media): profile(0o2750, children=['jellyfin-media', 'qbittorrent', 'seafile-media']),
            str(media / 'jellyfin-media'): profile(0o775, other=5, mask=7, apps=True),
            str(media / 'qbittorrent'): profile(0o755, other=5, apps=True),
            str(media / 'seafile-media'): profile(0o755, other=5)}


def empty_rootful_log_namespaces(selection):
    """Closed empty Caddy host-parent role, not a fixture or data-adoption rule."""
    if selection.get('receipt', {}).get('phase') != 'retired-clean': return {}
    caddy = selection.get('ir', {}).get('services', {}).get('caddy', {})
    root = SCOPE / 'volumes'; logs = root / '_logs'; leaf = logs / 'caddy'
    if not (caddy.get('module') == 'caddy' and caddy.get('placement', 'rootful') == 'rootful'
            and caddy.get('rootlessDomain') is None
            and caddy.get('volumes', []).count(str(leaf) + ':/var/log/caddy') == 1): return {}
    entries = sorted([[1, 7, UNDEFINED], [2, 7, 1000], [4, 7, UNDEFINED],
                      [16, 7, UNDEFINED], [32, 0, UNDEFINED]])
    def profile(children):
        return {'uid': 0, 'gid': 1000, 'mode': 0o2770, 'acl': entries,
                'defaultAcl': entries, 'children': children}
    return {str(root): profile(['_logs']), str(logs): profile(['caddy']), str(leaf): profile([])}


def original_overlay_graphs(selection):
    helpers = selection.get('pin', {}).get('helpers', {}); receipt = selection.get('receipt', {})
    installer = '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'
    if not (helpers.get('install-podman-bundle.sh', {}).get('sha256') == installer
            and helpers.get('grant-rootless-volume-parent-traverse.py', {}).get('sha256')
                == '0dcf715f2581a783702128d2fc12ff390fe21de45868bc4347dc809d08a74a32'
            and receipt.get('phase') == 'retired-failed' and legacy_installer_published(installer, receipt)): return {}
    result = {}
    for row in selection['rows']:
        actor = selection['actors'][row['name']]; graph = Path(row['graphRoot'])
        control = selection.get('overlayStorageControls', {}).get(row['name'])
        body = ('[storage]\ndriver = "overlay"\ngraphroot = "' + str(graph) + '"\n').encode()
        if (control is not None and control['stat'] is not None and control['source'] == 'recognized-installer:storage.conf'
                and control['path'] == str(Path(actor['home']) / '.config/containers/storage.conf')
                and control['uid'] == actor['uid'] == row['uid'] and actor['gid'] == actor['uid']
                and control['sha256'] == sha(body) and selection['roots'].get(graph) == row['name']
                and graph in selection['policies'] and graph.is_relative_to(SCOPE) and graph != SCOPE):
            result[str(graph)] = {'actor': actor, 'control': control}
    return result


def named_whiteout(parent, name, actor, expected=None):
    """Named metadata ONLY: never open a device, not even with O_PATH."""
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISCHR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0 and info.st_rdev == 0
            and (info.st_uid, info.st_gid) == (actor['uid'], actor['gid'])
            and info.st_nlink == 1 and info.st_size == 0, 'Not an exact original overlay whiteout')
    pin = fingerprint(info)
    if expected is not None: require(pin == expected, 'Original whiteout named inode CAS changed')
    # lgetxattr through a HELD parent; final component is never followed/opened.
    path = '/proc/self/fd/' + str(parent) + '/' + name
    for suffix in ('access', 'default'):
        try: os.getxattr(path, 'system.posix_acl_' + suffix, follow_symlinks=False)
        except OSError as error:
            if error.errno in (errno.ENODATA, errno.ENOTSUP): continue
            raise
        raise Refusal('Unexpected original whiteout ACL; no clearance')
    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(fingerprint(after) == pin and after.st_rdev == 0, 'Whiteout changed during named metadata observation')
    return pin


class OverlayWhiteoutCatalog:
    """Original actor graph FD + private native storage CONTROL, not diff data.

    Pinned c/storage archive_linux.go converts .wh.* to S_IFCHR/dev0 and chowns
    through the extraction map; layers.go registers IDs; overlay.go uses id/diff.
    NO engine, device open, mknod, permission repair or additional-store search.
    """
    def __init__(self, graph_fd, graph, selection, rule):
        self.fds = []; self.graph = graph; self.selection = selection; self.actor = rule['actor']; self.control = rule['control']
        try:
            self.graph_fd = os.dup(graph_fd); self.fds.append(self.graph_fd)
            require(custody(self.graph_fd) == selection['policies'][Path(graph)], 'Original private overlay graph custody differs')
            self.mount = fd_mount_id(self.graph_fd); self.device = os.fstat(self.graph_fd).st_dev
            self.fd = os.open('overlay-layers', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.graph_fd); self.fds.append(self.fd)
            info = os.fstat(self.fd)
            require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
                    == (self.actor['uid'], self.actor['gid'], 0o700, 2) and info.st_dev == self.device
                    and not acl(self.fd) and not acl(self.fd, True) and fd_mount_id(self.fd) == self.mount,
                    'Original overlay layer-control directory differs')
            self.parent = fingerprint(info)
            raw, pin = self.read_control()
            require(pin[0] == self.device, 'Overlay layer control crosses filesystem')
            # Existing object strictness/duplicate/nonfinite checks stay global.
            # This ONE native interface is a closed array, not authority JSON.
            document = strict(b'{"layers":' + raw + b'}')
            require(set(document) == {'layers'} and type(document['layers']) is list
                    and 0 < len(document['layers']) <= MAX_NODES, 'Native overlay layer list refused')
            self.rows = {}
            for row in document['layers']:
                require(type(row) is dict and type(row.get('id')) is str and HEX.fullmatch(row['id'])
                        and row['id'] not in self.rows and type(row.get('parent', '')) is str
                        and (row.get('parent', '') == '' or HEX.fullmatch(row['parent'])), 'Native layer ID/parent/uniqueness refused')
                self.rows[row['id']] = row
            self.proof = {'path': str(Path(graph) / 'overlay-layers/layers.json'), 'stat': pin, 'sha256': sha(raw),
                          'parent': self.parent, 'mountId': self.mount, 'storageControl': self.control}
            self.guard()
        except BaseException:
            self.close(); raise

    def close(self):
        while self.fds: os.close(self.fds.pop())

    def read_control(self):
        # Refuse a named special control inode BEFORE any data-open attempt.
        info = os.stat('layers.json', dir_fd=self.fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_dev == self.device
                and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    == (self.actor['uid'], self.actor['gid'], 0o600), 'Not an exact native regular layer-control file')
        raw, pin = read_at(self.fd, 'layers.json', owner=self.actor['uid'], gid=self.actor['gid'], private=True,
                           proof={'stat': fingerprint(info), 'mountId': self.mount})
        require(pin == fingerprint(info), 'Native layer-control named/open CAS changed')
        return raw, pin

    def guard(self):
        require(custody(self.graph_fd) == self.selection['policies'][Path(self.graph)]
                and fd_mount_id(self.graph_fd) == self.mount and fingerprint(os.fstat(self.fd)) == self.parent
                and fingerprint(os.stat('overlay-layers', dir_fd=self.graph_fd, follow_symlinks=False)) == self.parent
                and fd_mount_id(self.fd) == self.mount, 'Original held/named overlay control namespace changed')
        raw, pin = self.read_control()
        require(pin == self.proof['stat'] and sha(raw) == self.proof['sha256'], 'Original layer registration/control bytes changed')
        path = Path(self.control['path'])
        with directory(path.parent, self.selection['externalPolicies']) as fd:
            config_mount = fd_mount_id(fd)
            named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(named.st_mode) and fingerprint(named) == self.control['stat'], 'Original storage control named inode changed')
            body, pin = read_at(fd, path.name, owner=self.actor['uid'], gid=self.actor['gid'], private=True,
                               proof={'stat': self.control['stat'], 'mountId': config_mount})
        require(pin == self.control['stat'] and sha(body) == self.control['sha256'], 'Original native overlay storage configuration changed')
        if 'storageControlMountId' not in self.proof: self.proof['storageControlMountId'] = config_mount
        require(config_mount == self.proof['storageControlMountId'], 'Original storage control mount namespace changed')

    def source(self, path, directories):
        relative = path.relative_to(self.graph); parts = relative.parts
        require(len(parts) >= 4 and parts[0] == 'overlay' and HEX.fullmatch(parts[1]) and parts[2] == 'diff'
                and parts[1] in self.rows, 'Whiteout is not in an original registered layer diff')
        row = self.rows[parts[1]]
        fields = {'id', 'parent', 'created', 'compressed-diff-digest', 'compressed-size', 'compression', 'diff-digest', 'diff-size', 'uidset', 'gidset'}
        # Go's known Layer fields are omitempty: e.g. uncompressed layers omit
        # compression=0; a root layer omits parent. Do not require one row's
        # accidental field count, or allow flags/maps/unknown profiles instead.
        require({'id', 'created'} <= set(row) <= fields and type(row['created']) is str,
                'Unreviewed native whiteout layer record profile')
        for key in ('compressed-diff-digest', 'diff-digest'):
            require(key not in row or type(row[key]) is str, 'Invalid native layer digest shape')
        for key in ('compressed-size', 'diff-size', 'compression'):
            require(key not in row or (type(row[key]) is int and 0 <= row[key] < 2**63), 'Invalid native layer integer shape')
        require(row.get('compression', 0) <= 4, 'Unknown native layer compression profile')
        for key in ('uidset', 'gidset'):
            require(key not in row or (type(row[key]) is list and len(row[key]) <= MAX_NODES
                    and all(type(value) is int and 0 <= value < 2**32 for value in row[key])), 'Invalid native layer numeric set')
        chain = []; current = parts[1]
        while current:
            require(current in self.rows and current not in chain, 'Unregistered/cyclic original layer parent chain')
            chain.append(current); value = self.rows[current]
            require(type(value.get('flags', {})) is dict and value.get('flags', {}).get('incomplete', False) is False,
                    'Incomplete/unknown layer provenance')
            current = value.get('parent', '')
        ancestors = {}
        original_sgid = stat.S_IMODE(os.fstat(self.graph_fd).st_mode) == 0o2700
        chain_fds = [(Path('.'), None), (Path('overlay'), 0o700), (Path('overlay') / parts[1], 0o700),
                     (Path('overlay') / parts[1] / 'diff', 0o555)]
        chain_fds += [(Path(*parts[:index + 1]), None) for index in range(3, len(parts) - 1)]
        for index, (suffix, mode) in enumerate(chain_fds):
            selected = Path(self.graph) / suffix; fd = directories.get(str(selected))
            require(fd is not None, 'Original overlay ancestry FD unavailable')
            info = os.fstat(fd)
            own = ((info.st_uid, info.st_gid) == (self.actor['uid'], self.actor['gid'])) if index < 4 else (
                owns(info.st_uid, self.actor) and owns(info.st_gid, self.actor))
            modes = {mode}
            # Native overlay create(): private id directory0700, diff default
            # 0555 or inherited/extracted root0755. mkdirAs/MkdirAllAndChownNew
            # preserves kernel-inherited SGID when SafeChown already owns it.
            # ONLY the registered layer below an ORIGINAL private SGID graph;
            # SGID diff additionally needs its held private SGID layer parent.
            if index == 2 and original_sgid: modes.add(0o2700)
            if index == 3:
                modes.add(0o755)
                layer = ancestors[str(Path(self.graph) / 'overlay' / parts[1])]['identity']
                if original_sgid and stat.S_IMODE(layer[4]) == 0o2700: modes.update((0o2555, 0o2755))
            require(info.st_dev == self.device and own
                    and (mode is None or stat.S_IMODE(info.st_mode) in modes) and not acl(fd) and not acl(fd, True)
                    and fd_mount_id(fd) == self.mount, 'Original own overlay diff ancestry/mount differs')
            ancestors[str(selected)] = custody(fd)
        self.guard()
        return {'graph': self.graph, 'layer': parts[1], 'catalog': self.proof, 'layerSha256': sha(canonical(row)),
                'parentChain': chain, 'ancestors': ancestors}


def whiteout_source(path, directories, catalogs, resources, selection):
    rules = original_overlay_graphs(selection)
    graph = next((name for name in rules if path.is_relative_to(name)), None)
    require(graph is not None and graph in directories, 'Special inode lacks ORIGINAL own graph/control authority')
    if graph not in catalogs:
        catalogs[graph] = OverlayWhiteoutCatalog(directories[graph], graph, selection, rules[graph])
        resources.callback(catalogs[graph].close)
    return catalogs[graph].source(path, directories), catalogs[graph]


def scan(fd, selection, base=None, retain=None):
    with contextlib.ExitStack() as resources:
        return _scan(fd, selection, base, retain, resources)


def _scan(fd, selection, base, retain, resources):
    """One FD walk, one hardlink census across ALL roots of each exact domain.

    Symlink targets are never even readlink'ed. Regular-file bytes are hashed,
    not interpreted. Internal layer hardlinks pass iff ALL aliases occur in the
    exact same scoped domain. st_nlink proves that no external alias survives.
    """
    base = SCOPE if base is None else base
    retain = set(retain or ())
    nodes = []; links = {}; initial = fingerprint(os.fstat(fd)); device = initial[0]
    fixtures = original_fixture_profiles(selection) if base == SCOPE else {}
    log_namespaces = empty_rootful_log_namespaces(selection) if base == SCOPE else {}
    require(not set(fixtures) & set(log_namespaces), 'Conflicting source directory roles')
    profiles = dict(fixtures, **log_namespaces)
    directories = {}; catalogs = {}
    def visit(parent, relative):
        for name in sorted(os.listdir(parent)):
            require(name not in ('.', '..') and '/' not in name, 'Invalid scope entry')
            selected = base / relative / name; rel = str(relative / name)
            if base == SCOPE and rel == MARKER: continue
            require(len(nodes) < (MAX_SCOPE_NODES if base == SCOPE else MAX_NODES), 'Scope inventory node bound exceeded')
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(info.st_dev == device, 'Scope crosses a filesystem')
            owner = next((domain for root, domain in selection['roots'].items()
                          if selected == root or selected.is_relative_to(root)), None)
            actor = selection['actors'].get(owner)
            if base != SCOPE:
                actor = selection.get('externalActor'); owner = actor['name'] if actor else None
            shared = selected in retain and selected in selection['policies']
            fixture = profiles.get(str(selected))
            if fixture is not None:
                require(actor is None and not shared and not selected in retain and stat.S_ISDIR(info.st_mode)
                        and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                            == (fixture['uid'], fixture['gid'], fixture['mode']), 'Source-qualified directory identity/profile differs')
            require(shared or fixture is not None or (owns(info.st_uid, actor) and owns(info.st_gid, actor, True)),
                    'Foreign or cross-domain UID/GID in exact scope')
            require(shared or actor is not None or stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o002,
                    'Public-writable temporary artifact outside a private domain')
            node = {'path': rel, 'stat': fingerprint(info), 'domain': owner, 'retain': selected in retain}
            if str(selected) in log_namespaces: node['sourceEmptyRootfulLogNamespace'] = True
            nodes.append(node)
            if stat.S_ISDIR(info.st_mode):
                node['kind'] = 'directory'
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                directories[str(selected)] = child
                try:
                    require(fingerprint(os.fstat(child)) == node['stat'], 'Directory scan open CAS changed')
                    node['acl'] = acl(child); node['defaultAcl'] = acl(child, True)
                    if fixture is not None:
                        require(node['acl'] == fixture['acl'] and node['defaultAcl'] == fixture['defaultAcl']
                                and sorted(os.listdir(child)) == fixture['children']
                                and info.st_nlink == 2 + len(fixture['children']),
                                'Source-qualified empty directory ACL/membership differs; no adoption or repair')
                    elif shared or (selected in selection['roots'] and selected in selection['policies']):
                        require(custody(child) == selection['policies'][selected], 'Sealed scoped directory CAS changed')
                    else:
                        validate_data_acl(node, actor)
                    visit(child, relative / name)
                    require(fingerprint(os.fstat(child)) == node['stat'], 'Directory changed during scan')
                finally:
                    directories.pop(str(selected)); os.close(child)
            elif stat.S_ISREG(info.st_mode):
                node['kind'] = 'file'; child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                try:
                    require(fingerprint(os.fstat(child)) == node['stat'], 'File scan open CAS changed')
                    node['acl'] = acl(child); validate_data_acl(node, actor)
                    # Census ALL aliases before reading ANY file contents. An
                    # external hardlink could alias original/private host data.
                    require(fingerprint(os.fstat(child)) == node['stat'], 'File metadata changed during census')
                finally: os.close(child)
                links.setdefault((info.st_dev, info.st_ino), []).append(node)
            elif stat.S_ISLNK(info.st_mode):
                require(info.st_nlink == 1 and not node['retain'], 'Linked scope symlink or linked retained root')
                node['kind'] = 'inert-symlink'
            elif base == SCOPE and actor is not None and stat.S_ISCHR(info.st_mode) and info.st_rdev == 0:
                named_whiteout(parent, name, actor, node['stat'])
                source, catalog = whiteout_source(selected, directories, catalogs, resources, selection)
                node.update(kind='overlay-whiteout', rdev=0, overlaySource=source)
                named_whiteout(parent, name, actor, node['stat']); catalog.guard()
            else:
                raise Refusal('Special inode in selected scope')
            require(fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) == node['stat'], 'Scope entry changed during scan')
    visit(fd, Path(''))
    for group in links.values():
        require(len(group) == group[0]['stat'][5] and len({node['domain'] for node in group}) == 1
                and all(node['stat'] == group[0]['stat'] for node in group), 'Hardlink alias outside exact scoped domain')
    by_path = {node['path']: node for node in nodes}
    for node in nodes:
        if node['kind'] != 'file': continue
        parent = os.dup(fd); relative = Path('')
        try:
            for part in Path(node['path']).parts[:-1]:
                relative /= part
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent); parent = child
                require(fingerprint(os.fstat(parent)) == by_path[str(relative)]['stat'], 'Hash ancestor CAS changed')
            name = Path(node['path']).name
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                require(fingerprint(os.fstat(child)) == node['stat'] and acl(child) == node['acl'], 'Hash inode CAS changed')
                digest = hashlib.sha256()
                while True:
                    block = os.read(child, 1024 * 1024)
                    if not block: break
                    digest.update(block)
                require(fingerprint(os.fstat(child)) == node['stat']
                        and fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) == node['stat'], 'Hash read CAS changed')
                node['sha256'] = digest.hexdigest()
            finally: os.close(child)
        finally: os.close(parent)
    for catalog in catalogs.values(): catalog.guard()
    require(fingerprint(os.fstat(fd)) == initial, 'Scope root changed during inventory')
    return nodes


def validate_data_acl(node, actor):
    for tag, _, who in node.get('acl', []) + node.get('defaultAcl', []):
        if tag in (2, 8):
            require(owns(who, actor, tag == 8), 'Foreign named data ACL')


def env_unit(state, runtime):
    return ('[Unit]\nDescription=Restore rendered webservices environment files\n\n'
            '[Service]\nType=oneshot\nWorkingDirectory=/\n'
            "ExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 " + runtime + '; for env_file in ' + state +
            '/runtime-env/*.env; do [ -e "$env_file" ] || continue; /usr/bin/install -m 0600 "$env_file" ' +
            runtime + "/; done'\nRemainAfterExit=yes\n").encode()


def current_env_renderer(selection):
    """Frozen CURRENT sibling pure API slice; no module/dependency loaders.

    The four approved source files close render_unit's alias dependency on
    project-domain-runtime. Only pure definitions/literal data are compiled;
    RUNTIME_PROGRAM is embedded as DATA, never executed by this backend.
    """
    backend = absolute(__file__); _, backend_pin = helper_file(backend)
    live = strict(read_file(selection['release'] / 'bundle.json')[0]).get('liveOps')
    require(isinstance(live, dict), 'New runtime-env format lacks CORE-pinned liveOps')
    bodies = {}; pins = {}
    for name, recognized in sorted(RUNTIME_ENV_RENDERER_PINS.items()):
        body, pin = helper_file(backend.with_name(name))
        require(pin['sha256'] in recognized, 'Final canonical runtime-env renderer source hash needs explicit review')
        require(live.get('ops/' + name) == pin['sha256'], 'Old liveOps/canonical runtime-env renderer version differs')
        bodies[name] = body; pins[name] = pin
    tree = ast.parse(bodies['project-domain-runtime.py'])
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('encoded', 'declarations')]
    names = [node for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == 'NAME' for target in node.targets)]
    require(len(functions) == 2 and len(names) == 1 and isinstance(names[0].value, ast.Call), 'Pure encoder/declaration API differs')
    project = {'json': json, 're': re, 'NAME': re.compile(ast.literal_eval(names[0].value.args[0])), 'Refusal': Refusal}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<reviewed-current-env-pure-encoding>', 'exec'), project)
    tree = ast.parse(bodies['native-runtime-env-units.py'])
    program = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'RUNTIME_PROGRAM' for target in node.targets)]
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('render_unit', 'render_dropin')]
    require(len(program) == 1 and isinstance(ast.literal_eval(program[0]), str) and len(functions) == 2, 'Pure renderer API/literal differs')
    namespace = {'base64': base64, 'p': types.SimpleNamespace(encoded=project['encoded']),
                 'require': require, 'RUNTIME_PROGRAM': ast.literal_eval(program[0])}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<reviewed-current-env-pure-render>', 'exec'), namespace)
    for name, expected in pins.items():
        require(helper_file(backend.with_name(name))[1] == expected, 'Canonical renderer source/inode/ancestry CAS changed')
    require(helper_file(backend)[1] == backend_pin, 'Canonical renderer backend source CAS changed')
    return namespace, project['declarations'], {'backend': backend_pin, 'sources': pins}


def native_file_proof(value, uid, gid, digest):
    keys = {'dev', 'ino', 'uid', 'gid', 'mode', 'mountId', 'acl', 'defaultAcl', 'identity', 'sha256'}
    require(isinstance(value, dict) and set(value) == keys and isinstance(value['identity'], list)
            and len(value['identity']) == 9 and all(type(item) is int for item in value['identity']), 'Original adjunct FD proof shape differs')
    ids = value['identity']
    require(all(type(value[key]) is int for key in ('dev', 'ino', 'uid', 'gid', 'mode', 'mountId'))
            and value['uid'] == uid and value['gid'] == gid and value['mode'] == 0o644 and value['sha256'] == digest
            and value['dev'] == ids[0] and value['ino'] == ids[1] and ids[2:6] == [uid, gid, stat.S_IFREG | 0o644, 1]
            and value['acl'] == value['defaultAcl'] == '' and type(value['mountId']) is int and value['mountId'] > 0,
            'Original adjunct owner/mode/inode/hash/ACL differs')
    return {'stat': ids, 'mountId': value['mountId']}


def native_env_specs(selection):
    receipt = selection['receipt']
    if 'nativeRuntimeEnvUnitCustody' not in receipt and 'nativeRuntimeEnvUnits' not in receipt: return None
    custody, proof = receipt.get('nativeRuntimeEnvUnitCustody'), receipt.get('nativeRuntimeEnvUnits')
    require(isinstance(custody, dict) and isinstance(proof, dict), 'Present new runtime-env custody lacks completed proof; no legacy fallback')
    roles = {'rootful'} | {'rootless-' + row['name'] for row in selection['rows']}
    require(type(custody.get('schemaVersion')) is type(proof.get('schemaVersion')) is int
            and custody.get('schemaVersion') == proof.get('schemaVersion') == 1
            and custody.get('kind') == 'native-runtime-env-unit-custody' and proof.get('kind') == 'native-runtime-env-units'
            and proof.get('status') == 'completed' and custody.get('release') == proof.get('release') == str(selection['release'])
            and custody.get('inputs') == proof.get('inputs') == receipt['inputs']
            and custody.get('scopeMarkerSha256') == selection['pin']['markerSha256']
            and isinstance(custody.get('roles'), dict) and set(custody['roles']) == roles
            and proof.get('custodySha256') == sha(canonical(custody)) and proof.get('runtimeDeferred') is True
            and isinstance(proof.get('intentSha256'), str) and HEX.fullmatch(proof['intentSha256'])
            and proof.get('receiptSha256') == proof['intentSha256']
            and all(value.get('activationAuthorized') is False and value.get('readinessAuthorized') is False
                    and value.get('updaterOwned') is False for value in (custody, proof)),
            'New runtime-env custody/role/source proof differs; no legacy fallback')
    renderer, declarations, source_pin = current_env_renderer(selection)
    specs = {}; root_handoff = receipt.get('rootfulEnvironmentStoreHandoff')
    require(isinstance(root_handoff, dict) and isinstance(receipt.get('rootfulEnvCustody'), dict)
            and root_handoff.get('kind') == 'rootful-persistent-environment'
            and root_handoff.get('scopeMarkerSha256') == selection['pin']['markerSha256']
            and receipt['rootfulEnvCustody'].get('kind') == 'rootful-environment-custody'
            and receipt['rootfulEnvCustody'].get('release') == str(selection['release'])
            and receipt['rootfulEnvCustody'].get('inputs') == receipt['inputs']
            and receipt['rootfulEnvCustody'].get('scopeMarkerSha256') == selection['pin']['markerSha256']
            and root_handoff.get('sourceCustodySha256') == sha(canonical(receipt.get('rootfulEnvCustody'))), 'Rootful producer custody differs')
    root_files = root_handoff.get('files'); root_sources = receipt['rootfulEnvCustody'].get('files')
    require(isinstance(root_files, dict) and isinstance(root_sources, dict) and set(root_files) == set(root_sources)
            and all(isinstance(value, dict) and isinstance(root_sources[name], dict)
                    and value.get('sha256') == root_sources[name].get('sha256')
                    for name, value in root_files.items()), 'Rootful producer name/SHA set differs')
    for role in sorted(roles):
        actor = None if role == 'rootful' else selection['actors'][role.removeprefix('rootless-')]
        row = None if actor is None else next(row for row in selection['rows'] if row['name'] == actor['name'])
        uid, gid, user = (0, 0, 'root') if actor is None else (actor['uid'], actor['gid'], actor['user'])
        anchor = selection['root'] if actor is None else Path(row['stateRoot'])
        runtime = '/run/webservices' if actor is None else '/run/user/' + str(uid) + '/webservices'
        folder = Path('/etc/systemd/system') if actor is None else Path(actor['home']) / '.config/systemd/user'
        handoff = root_handoff
        if actor is not None:
            producer = receipt.get('domainRuntimeProjections', {}).get(actor['name'])
            require(isinstance(producer, dict), 'Actor environment producer missing')
            handoff = producer.get('environmentStoreHandoff')
            require(isinstance(handoff, dict) and handoff.get('kind') == 'domain-persistent-environment'
                    and handoff.get('domain') == actor['name'] and handoff.get('uid') == uid and handoff.get('gid') == gid
                    and handoff.get('scopeMarkerSha256') == selection['pin']['markerSha256']
                    and isinstance(producer.get('custodySha256'), str) and HEX.fullmatch(producer['custodySha256'])
                    and handoff.get('custodySha256') == producer.get('custodySha256')
                    and handoff.get('sourceProjectionSha256') == sha(canonical({key: value for key, value in producer.items() if key != 'environmentStoreHandoff'})),
                    'Actor producer namespace/profile/marker/custody differs')
        require(handoff.get('status') == 'completed' and handoff.get('release') == str(selection['release'])
                and handoff.get('inputs') == receipt['inputs'] and handoff.get('stateStore') == str(anchor / 'runtime-env')
                and handoff.get('runtimeStore', runtime) == runtime and handoff.get('runtimeDeferred') is True
                and handoff.get('activationAuthorized') is False and handoff.get('readinessAuthorized') is False,
                'Canonical role environment producer differs')
        manifest = custody['roles'][role]; files = handoff.get('files')
        require(isinstance(files, dict) and isinstance(manifest, dict), 'Role environment manifest/files malformed')
        expected_names = {name + '.env' for name, service in selection['ir']['services'].items()
            if (service.get('placement') == 'rootful' if actor is None else
                service.get('placement') == 'rootless' and service.get('rootlessDomain') == actor['name']) and declarations(service)}
        require(all(isinstance(value, dict) and isinstance(value.get('identity'), list) and len(value['identity']) == 9
                    and isinstance(value.get('sha256'), str) and HEX.fullmatch(value['sha256']) for value in files.values()),
                'Environment producer file seals malformed')
        for value in files.values():
            ids = value['identity']
            require(all(type(item) is int for item in ids) and ids[2:6] == [uid, gid, stat.S_IFREG | 0o600, 1]
                    and value.get('uid') == uid and value.get('gid') == gid and value.get('mode') == 0o600
                    and value.get('dev', ids[0]) == ids[0] and value.get('ino', ids[1]) == ids[1]
                    and value.get('acl') == value.get('defaultAcl') == ''
                    and type(value.get('mountId')) is int and value['mountId'] > 0, 'Environment producer file profile differs')
        normalized = {name: dict(value, dev=value['identity'][0], ino=value['identity'][1]) for name, value in files.items()}
        parent = selection['release'] if actor is None else anchor / 'releases' / selection['release'].name
        require(type(manifest.get('schemaVersion')) is int and type(manifest.get('uid')) is type(manifest.get('gid')) is int
                and set(files) == expected_names and manifest.get('schemaVersion') == 1 and manifest.get('kind') == 'exact-runtime-environment'
                and (manifest.get('role'), manifest.get('uid'), manifest.get('gid'), manifest.get('user')) == (role, uid, gid, user)
                and manifest.get('release') == str(selection['release']) and manifest.get('inputsSha256') == sha(canonical(receipt['inputs']))
                and manifest.get('scopeMarkerSha256') == selection['pin']['markerSha256']
                and manifest.get('sourceCustodySha256') == handoff.get('sourceCustodySha256' if actor is None else 'custodySha256')
                and manifest.get('sourceAnchor') == str(anchor) and manifest.get('stateStore') == str(anchor / 'runtime-env')
                and manifest.get('runtimeStore') == runtime and manifest.get('custodyFile') == str(parent / 'runtime-env-copy-custody.json')
                and manifest.get('files') == normalized and manifest.get('store') == handoff.get('store')
                and isinstance(manifest.get('sourceDirectories'), dict) and isinstance(manifest.get('custodyDirectories'), dict),
                'Runtime-env manifest source/role/current namespace/marker/input set differs')
        for path, body in ((folder / 'webservices-runtime-env.service', renderer['render_unit'](manifest)),
                           (folder / 'webservices.target.d/10-runtime-env.conf', renderer['render_dropin']())):
            digest = sha(body); ownership = native_file_proof(proof.get('files', {}).get(str(path)), uid, gid, digest)
            planned = custody.get('files', {}).get(str(path))
            require(isinstance(planned, dict) and planned.get('sha256') == digest and planned.get('uid') == uid
                    and planned.get('gid') == gid and planned.get('mode') == 0o644, 'Owning adjunct planned body differs')
            specs[str(path)] = {'sha256': digest, 'uid': uid, 'gid': gid, 'ownership': ownership,
                               'source': 'recognized-current:runtime-env-dropin' if path.name == '10-runtime-env.conf'
                                         else 'recognized-current:runtime-env-unit'}
    require(set(proof.get('files', {})) == set(custody.get('files', {})) == set(specs), 'Adjunct owning file namespace differs')
    return {'specs': specs, 'sourcePin': source_pin, 'custodySha256': proof['custodySha256']}


def legacy_installer_published(digest, receipt):
    if digest not in LEGACY_SOURCE_INSTALLERS: return False
    if digest == '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2':
        # This exact installer writes the namespace BEFORE units-selected.
        # Merely shipping its compatibility artifacts, or failing before that
        # original journal frame, cannot confer installed-file ownership.
        steps = receipt.get('steps')
        return isinstance(steps, list) and steps[:2] == ['preparing', 'units-selected']
    return True


def legacy_source_authority(selection):
    pin = selection['pin']['helpers']['install-podman-bundle.sh']
    if legacy_installer_published(pin['sha256'], selection['receipt']):
        return {'release': str(selection['release']), 'installer': pin,
                'intentSha256': selection['pin']['intentSha256']}
    previous = selection['receipt'].get('previousRelease')
    if previous is None: return None
    # Same exact source-only previous receipt/input/provenance closure used for
    # previous networks. Presence of an Ops artifact alone never grants custody.
    source = rootful_network_sources(selection)[previous]['authority']
    receipt_body, _ = read_file(Path(previous) / 'installation-receipt.json', private=True, gid=0)
    require(sha(receipt_body) == source['sha256'], 'Previous legacy ownership receipt CAS changed')
    # A clean retirement consumed that old namespace ownership. Reappearing
    # same-byte updater/drop-in artifacts are not adopted by a new profile.
    if strict(receipt_body).get('phase') == 'retired-clean': return None
    body, previous_pin = read_file(Path(previous) / 'ops/install-podman-bundle.sh', gid=0)
    if not legacy_installer_published(sha(body), strict(receipt_body)): return None
    return {'release': previous, 'installer': {'sha256': sha(body), 'stat': previous_pin}, 'previousSource': source}


def updater_source_pins(selection, legacy):
    release = selection['release'] if legacy is None else Path(legacy['release'])
    result = []
    for name, digest in sorted(UPDATER_SOURCES.items()):
        path = release / 'ops' / name; body, pin = read_file(path, gid=0)
        require(sha(body) == digest, 'Unrecognized historical updater source body')
        result.append({'path': str(path), 'sha256': digest, 'stat': pin})
    return result


def external_plan(selection, *, custody_inventory=False, _network_stop=None):
    """Exact deterministic sources + root receipt sealed runtime-tree hashes.

    No prefix sweep. Foreign installed files refuse and remain unmodified.
    Empty external directories can remain EXCEPT exact old source-created
    webservices.target.d parents, which must close for strict unit publication.
    """
    native = selection['modules']['native-selection.py']; result = []; authorities = {}
    native_owned = native_env_specs(selection)  # present-invalid is NEVER legacy fallback
    legacy = legacy_source_authority(selection)
    updater_sources = updater_source_pins(selection, legacy)
    scopes = selection['pin']['selection']['scopes']; policies = dict(selection['policies'])
    def home_policy(actor, path):
        # Only exact configuration and selected runtime ancestors, never every
        # descendant of a home. Pin modes/ACL without accepting foreign writers.
        with directory(path.parent, policies) as parent:
            try: fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError: return False
            try:
                info = os.fstat(fd)
                require(info.st_uid in (0, actor['uid']) and info.st_gid in (0, actor['gid'])
                        and not info.st_mode & 0o022 and not acl(fd) and not acl(fd, True), 'Foreign selected config ancestry')
                policies[path] = custody(fd)
            finally: os.close(fd)
        return True
    for actor in selection['actors'].values():
        home = Path(actor['home'])
        for suffix in ('', '.config', '.config/containers', '.config/containers/systemd', '.config/systemd',
                       '.config/systemd/user', '.config/systemd/user/webservices.target.d'):
            path = home / suffix
            try: present = home_policy(actor, path)
            except FileNotFoundError: present = False
            if not present: continue
    specs = {}
    for scope, entry in scopes.items():
        for relative, item in entry['files'].items():
            path = native.destination(scope, entry, relative)
            specs[path] = {'sha256': item['sha256'], 'uid': entry['uid'], 'source': relative}
            if scope == 'rootful': authorities.setdefault(item['unit'], set()).add(str(path))
        actor = None if scope == 'rootful' else selection['actors'][scope.removeprefix('rootless-')]
        unit_root = Path('/etc/systemd/system') if actor is None else Path(actor['home']) / '.config/systemd/user'
        state = str(selection['root']) if actor is None else next(row['stateRoot'] for row in selection['rows'] if row['name'] == actor['name'])
        runtime = '/run/webservices' if actor is None else '/run/user/' + str(actor['uid']) + '/webservices'
        unit = unit_root / 'webservices-runtime-env.service'; drop = unit_root / 'webservices.target.d/10-runtime-env.conf'
        if native_owned is None:
            specs[unit] = {'sha256': sha(env_unit(state, runtime)), 'uid': entry['uid'], 'source': 'recognized-installer:runtime-env'}
            specs[drop] = {'sha256': sha(b'[Unit]\nRequires=webservices-runtime-env.service\nAfter=webservices-runtime-env.service\n'),
                           'uid': entry['uid'], 'source': 'recognized-installer:runtime-env-dropin'}
        else:
            specs[unit] = native_owned['specs'][str(unit)]; specs[drop] = native_owned['specs'][str(drop)]
        if actor is None:
            authorities.setdefault('webservices-runtime-env.service', set()).add(str(unit_root / 'webservices-runtime-env.service'))
        else:
            row = next(row for row in selection['rows'] if row['name'] == actor['name'])
            for filename, body in {
                'storage.conf': ('[storage]\ndriver = "overlay"\ngraphroot = "' + row['graphRoot'] + '"\n').encode(),
                'containers.conf': b'[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n',
            }.items():
                specs[Path(actor['home']) / '.config/containers' / filename] = {
                    'sha256': sha(body), 'uid': actor['uid'], 'source': 'recognized-installer:' + filename}
    for filename in ('webservices-auto-update.timer', 'webservices-auto-update.service', 'webservices-auto-update'):
        digest = UPDATER_SOURCES[filename]
        path = (Path('/usr/local/sbin') if filename == 'webservices-auto-update'
                else Path('/etc/systemd/system')) / filename
        specs[path] = {'sha256': digest, 'uid': 0, 'source': 'ops/' + filename, 'legacyAuthority': legacy}
        if filename != 'webservices-auto-update': authorities.setdefault(filename, set()).add(str(path))
    for path, spec in sorted(specs.items()):
        try:
            with directory(path.parent, policies) as fd:
                body, pin = read_at(fd, path.name, owner=spec['uid'], gid=spec.get('gid'), proof=spec.get('ownership'))
                require(not spec['source'].startswith('ops/webservices-auto-update') or legacy is not None,
                        'Installed updater lacks recognized old private-source ownership')
                require(sha(body) == spec['sha256'], 'Installed selected source hash differs')
                result.append(dict(spec, path=str(path), stat=pin))
        except FileNotFoundError:
            result.append(dict(spec, path=str(path), stat=None))
    parents = []
    for item in result:
        if item['source'] not in ('recognized-installer:runtime-env-dropin', 'recognized-current:runtime-env-dropin'): continue
        path = Path(item['path']).parent
        try:
            with directory(path, policies) as fd:
                info = os.fstat(fd)
                require(legacy is not None or native_owned is not None, 'Drop-in parent lacks recognized private-source ownership')
                require(info.st_uid == info.st_gid == item['uid'] and stat.S_IMODE(info.st_mode) == 0o755
                        and info.st_nlink == 2 and not acl(fd) and not acl(fd, True), 'Foreign legacy drop-in parent metadata')
                names = sorted(os.listdir(fd)); pin = fingerprint(info)
                require(names == ([] if item['stat'] is None else ['10-runtime-env.conf'])
                        and fingerprint(os.fstat(fd)) == pin, 'Unknown file in legacy drop-in parent; preserved')
                parents.append({'path': str(path), 'stat': pin, 'custody': custody(fd), 'uid': item['uid'],
                    'source': 'recognized-installer:runtime-env-dropin-parent', 'legacyAuthority': legacy,
                    'templateSha256': item['sha256'], 'childStat': item['stat'], 'childProof': item.get('ownership'),
                    'nativeSource': None if native_owned is None else native_owned['sourcePin']})
        except FileNotFoundError:
            require(item['stat'] is None, 'Legacy drop-in parent disappeared')
            parents.append({'path': str(path), 'stat': None, 'uid': item['uid'],
                            'source': 'recognized-installer:runtime-env-dropin-parent'})
    selection['unitAuthorities'] = authorities
    selection['externalPolicies'] = policies
    selection['overlayStorageControls'] = {name: item for name, actor in selection['actors'].items() for item in result
        if item['path'] == str(Path(actor['home']) / '.config/containers/storage.conf')
        and item['source'] == 'recognized-installer:storage.conf' and item['stat'] is not None}
    if _network_stop is None: stopped(selection)
    else: _stopped_observation(selection, _network_stop)
    # Only these exact runtime locations may be named in receipt custody.
    trees = {selection['root'] / 'runtime-env': None, Path('/run/webservices'): None,
             selection['release'] / 'runtime': None, selection['release'] / 'repos': None}
    for actor in selection['actors'].values():
        runtime = Path('/run/user') / str(actor['uid'])
        try: present = home_policy(actor, runtime)
        except FileNotFoundError: present = False
        for suffix in ('webservices', 'containers', 'podman'):
            trees[runtime / suffix] = actor
    sealed = selection['receipt'].get('cleanResetCustody', {})
    require(isinstance(sealed, dict) and set(sealed) <= {'externalTrees'}, 'Unknown clean-reset custody')
    hashes = sealed.get('externalTrees', {})
    require(isinstance(hashes, dict) and set(hashes) <= {str(path) for path in trees}
            and all(isinstance(digest, str) and HEX.fullmatch(digest) for digest in hashes.values()), 'Unselected external runtime authority')
    tree_plan = []; runtime_hashes = {}
    for path, actor in sorted(trees.items()):
        try:
            if actor is None:
                with directory(path) as fd:
                    root_directory(fd, private=not path.is_relative_to(selection['release']))
                    pin = custody(fd)
                    data = scan(fd, dict(selection, externalActor=None), path)
            else:
                require(home_policy(actor, path), 'Missing runtime directory')
                with directory(path, policies) as fd:
                    require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'Runtime tree must be private')
                    pin = custody(fd); data = scan(fd, dict(selection, externalActor=actor), path)
        except FileNotFoundError:
            tree_plan.append({'path': str(path), 'pin': None, 'nodes': []}); continue
        runtime_hashes[str(path)] = sha(canonical({'pin': pin, 'nodes': data}))
        require(custody_inventory or not data or hashes.get(str(path)) == runtime_hashes[str(path)],
                'Nonempty external runtime lacks exact root-receipted fingerprint')
        tree_plan.append({'path': str(path), 'pin': pin, 'nodes': data})
    unmounted([path for path in trees if any(tree['path'] == str(path) and tree['pin'] is not None for tree in tree_plan)], policies)
    return {'files': result, 'dropinParents': parents, 'nativeRuntimeEnvSources': native_owned, 'legacySourceAuthority': legacy,
            'updaterSourcePins': updater_sources, 'trees': tree_plan, 'runtimeFingerprints': runtime_hashes,
            'custody': {str(path): pin for path, pin in sorted(policies.items())}}


def evidence_generation(root_fd):
    try:
        fd = os.open('.host-clean-reset', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    except FileNotFoundError:
        return sha(canonical(None))
    try:
        root_directory(fd, True)
        names = sorted(os.listdir(fd)); require(len(names) <= MAX_NODES, 'Oversized clean-reset evidence')
        pins = []
        for name in names:
            require(re.fullmatch(r'[a-f0-9-]+-(?:intent|result|progress-[0-9]+)\.json', name), 'Foreign clean-reset evidence')
            body, pin = read_at(fd, name, private=True, gid=0, limit=512 * 1024 * 1024)
            pins.append({'name': name, 'stat': pin, 'sha256': sha(body)})
        return sha(canonical(pins))
    finally: os.close(fd)


# Default ROOTFUL store only. Never inherit remote/storage/auth/config steering,
# select another HOME, or use dedicated/receipt/caller-selected engine configs.
ROOT_GRAPH = '/var/lib/containers/storage'
ROOT_RUN = '/run/containers/storage'
ROOT_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'USER': 'root',
            'LOGNAME': 'root', 'LANG': 'C', 'LC_ALL': 'C', 'XDG_RUNTIME_DIR': ''}


def cold_call(tool, args, mutate=False):
    require(tool in ('podman', 'buildah', 'ip'), 'Unknown rootful cold tool')
    require(not mutate or (tool == 'podman' and len(args) == 3 and args[:2] == ['network', 'rm']
                           and isinstance(args[2], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', args[2])),
            'Only exact unforced selected network removal is a default-store mutator; no cache authority')
    path = '/usr/sbin/ip' if tool == 'ip' else '/usr/bin/' + tool
    # No shell, inherited environment, application output or raw engine errors.
    try:
        result = subprocess.run([path, *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if mutate else subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(ROOT_ENV), timeout=30, text=True)
    except (OSError, subprocess.SubprocessError):
        raise Refusal('Bounded rootful cold command refused') from None
    require(mutate or len(result.stdout) <= 4 * 1024 * 1024, 'Rootful inventory output bound exceeded')
    return result.returncode, '' if mutate else result.stdout


def cold_json(tool, args):
    code, body = cold_call(tool, args)
    require(code == 0, 'Rootful inventory command failed')
    try:
        # Duplicate/nonfinite rejection for arrays as well as objects.
        value = strict('{"value":' + body + '}')['value']
    except (ValueError, TypeError): raise Refusal('Invalid rootful inventory metadata') from None
    return value


def cold_path(path, contents=False):
    """Fixed control files only; retain missing-component ancestry as CAS.

    Never read auth stores or inspect user config bodies. Source/config bytes
    are opaque proof or parsed TOML, never included in operation reports.
    """
    path = absolute(path); pins = {}; fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path('/')
    try:
        root_directory(fd); pins[str(current)] = custody(fd)
        for part in path.parts[1:-1]:
            current /= part
            try: child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError: return None, {'ancestry': pins, 'absent': str(current)}
            os.close(fd); fd = child; root_directory(fd); pins[str(current)] = custody(fd)
        try: info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: return None, {'ancestry': pins, 'absent': str(path)}
        require(contents, 'User engine configuration/override is present')
        body, pin = read_at(fd, path.name, gid=0)
        require(fingerprint(info) == pin, 'Rootful control file CAS changed')
        return body, {'ancestry': pins, 'file': pin, 'sha256': sha(body)}
    finally: os.close(fd)


def default_context():
    pins = {}; configs = {}
    for name in ('storage.conf', 'containers.conf', 'containers.conf.d'):
        _, pins['/root/.config/containers/' + name] = cold_path(Path('/root/.config/containers') / name)
    for filename in ('/usr/share/containers/storage.conf', '/etc/containers/storage.conf',
                     '/usr/share/containers/containers.conf', '/etc/containers/containers.conf'):
        body, pin = cold_path(Path(filename), contents=True); pins[filename] = pin
        if body is None: continue
        try: document = tomllib.loads(body.decode('utf-8'))
        except (ValueError, UnicodeError): raise Refusal('Rootful system config TOML refused') from None
        if filename.endswith('/storage.conf'):
            storage_config = document.get('storage', {})
            require(isinstance(storage_config, dict) and storage_config.get('driver', 'overlay') == 'overlay'
                    and storage_config.get('graphroot', ROOT_GRAPH) == ROOT_GRAPH
                    and storage_config.get('runroot', ROOT_RUN) == ROOT_RUN
                    and storage_config.get('options', {}).get('additionalimagestores', []) == []
                    and not storage_config.get('imagestore')
                    and not storage_config.get('options', {}).get('additionallayerstores')
                    and not storage_config.get('transient_store', False), 'Foreign rootful storage configuration')
            configs[filename] = pin
        else:
            engine, network = document.get('engine', {}), document.get('network', {})
            require(engine.get('static_dir', ROOT_GRAPH + '/libpod') == ROOT_GRAPH + '/libpod'
                    and engine.get('volume_path', ROOT_GRAPH + '/volumes') == ROOT_GRAPH + '/volumes'
                    and engine.get('tmp_dir', '/run/libpod') == '/run/libpod'
                    and not engine.get('remote', False) and not engine.get('active_service')
                    and not engine.get('service_destinations') and not engine.get('env')
                    and network.get('network_config_dir', '/etc/containers/networks') == '/etc/containers/networks',
                    'Foreign rootful engine/network configuration')
    # Drop-ins can override those exact controls. No ignored mutable overrides.
    for base in ('/usr/share/containers/containers.conf.d', '/etc/containers/containers.conf.d'):
        path = Path(base)
        try:
            with directory(path) as fd:
                require(not os.listdir(fd), 'Unreviewed rootful system configuration drop-ins')
                pins[base] = custody(fd)
        except FileNotFoundError:
            _, pins[base] = cold_path(path)
    require(configs, 'No reviewed default rootful storage configuration')
    return {'controls': pins, 'storageConfigs': configs}


def root_runtime_identity():
    namespaces = {}
    for name in ('user', 'net'):
        own = os.readlink('/proc/self/ns/' + name); host = os.readlink('/proc/1/ns/' + name)
        require(own == host, 'Rootful cold caller is outside host namespace')
        namespaces[name] = own
    for proc in sorted(Path('/proc').glob('[0-9]*')):
        try:
            lines = (proc / 'status').read_text().splitlines()
            ids = [line.split()[1:] for line in lines if line.startswith('Uid:')]
            require(len(ids) == 1 and len(ids[0]) == 4 and all(value.isdecimal() for value in ids[0]),
                    'Unknown rootful process identity')
            if '0' not in ids[0]: continue  # UID1001/rootless namespaces remain untouched.
            executable = Path(os.readlink(proc / 'exe')).name
        except (FileNotFoundError, ProcessLookupError): continue
        require(executable not in ('conmon', 'crun', 'runc', 'podman', 'buildah'),
                'Rootful engine/runtime process remains; no stop or kill performed')
    for unit in ('podman.socket', 'podman.service'):
        pid_field = 'ControlPID' if unit.endswith('.socket') else 'MainPID'
        fields = ('Id', 'LoadState', 'ActiveState', 'SubState', pid_field, 'Job', 'UnitFileState')
        response = run_read(['/usr/bin/systemctl', 'show', unit, '--no-pager',
                             *[part for field in fields for part in ('-p', field)]])
        props = {}; lines = response.stdout.splitlines()
        for line in lines:
            require('=' in line, 'Rootful API proof malformed')
            key, value = line.split('=', 1); require(key not in props, 'Rootful API proof ambiguous'); props[key] = value
        absent = props.get('LoadState') == 'not-found'
        require(response.returncode in ((0, 1) if absent else (0,))
                and (set(props) == set(fields) or absent and set(props) == set(fields) - {pid_field})
                and props['Id'] == unit and props['LoadState'] in ('loaded', 'masked', 'not-found')
                and props['ActiveState'] in ('inactive', 'failed') and props['SubState'] in ('dead', 'failed')
                and props.get(pid_field, '0') == '0' and props['Job'] in ('', '0')
                and props['UnitFileState'] in ('disabled', 'disabled-runtime', 'masked', 'masked-runtime', 'static', 'not-found', ''),
                'Rootful API trigger/service not closed; no stop/disable performed')
    return namespaces


def rootful_network_sources(selection):
    native = selection['modules']['native-selection.py']; result = {}; releases = []
    previous = selection['receipt'].get('previousRelease')
    if previous is not None:
        previous = absolute(previous)
        require(previous.parent == selection['root'] / 'releases' and previous != selection['release'], 'Previous rootful source escapes')
        with directory(previous) as fd: root_directory(fd, True)
        body, pin = read_file(previous / 'installation-receipt.json', private=True, gid=0)
        receipt = strict(body); inputs = receipt.get('inputs')
        require(type(receipt.get('schemaVersion')) is int and receipt['schemaVersion'] == 1
                and receipt.get('release') == str(previous) and receipt.get('phase') in ('active', 'failed', 'retired-failed', 'retired-clean')
                and isinstance(inputs, dict) and set(CORE) <= set(inputs) <= set(CORE + OPTIONAL), 'Previous source receipt differs')
        documents = {}; pins = {}
        for name, digest in sorted(inputs.items()):
            if digest is None:
                _, absent = cold_path(previous / name); pins[name] = absent; continue
            require(isinstance(digest, str) and HEX.fullmatch(digest), 'Previous source digest invalid')
            data, file_pin = read_file(previous / name)
            require(sha(data) == digest, 'Previous source input hash changed')
            pins[name] = {'stat': file_pin, 'sha256': digest}
            if name in CORE: documents[name] = strict(data)
        manifest, metadata = documents['site/manifest.json'], documents['podman-domains.json']
        require(manifest.get('storageScope') == metadata.get('storageScope') == {'root': str(SCOPE), 'dataClass': 'synthetic'}
                and manifest.get('installerStateRoot') == metadata.get('installerStateRoot') == str(selection['root'])
                and manifest.get('site') == strict(read_file(selection['release'] / 'site/manifest.json')[0]).get('site')
                and manifest.get('deploymentMode') == metadata.get('deploymentMode') == 'standalone'
                and documents['bundle.json'].get('irSha256') == inputs['stack.ir.json']
                and documents['bundle.json'].get('sourceProvenanceSha256') == inputs['source-provenance.json']
                and documents['source-provenance.json'].get('manifestSha256') == inputs['site/manifest.json'],
                'Previous rootful source provenance/scope differs')
        fields = ('name', 'uid', 'user') + ROOTS
        require(sorted([{key: row[key] for key in fields} for row in metadata.get('domains', [])], key=lambda row: row['name'])
                == sorted([{key: row[key] for key in fields} for row in selection['rows']], key=lambda row: row['name']),
                'Previous source actor/storage scope differs')
        releases.append((previous, native.source_plan(previous, previous=True), {'receipt': pin, 'sha256': sha(body), 'inputs': pins}))
    releases.append((selection['release'], selection['pin']['selection'], {'intentSha256': selection['pin']['intentSha256']}))
    for release, plan, authority in releases:
        sources = []
        for relative, info in sorted(plan['scopes']['rootful']['files'].items()):
            if info['kind'] != 'network': continue
            body, pin = read_file(release / relative)
            require(sha(body) == info['sha256'], 'Selected rootful network source changed')
            config = native.sections(body); name = native.only(config, 'Network', 'NetworkName')
            require(isinstance(name, str) and re.fullmatch(r'webservices_[A-Za-z0-9_.-]{1,128}', name), 'Unclosed rootful network name')
            sources.append({'path': str(release / relative), 'sha256': sha(body), 'stat': pin, 'name': name})
        result[str(release)] = {'authority': authority, 'selection': plan, 'networks': sources}
    return result


def bridge_state(name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name), 'Invalid selected bridge interface')
    try: index = socket.if_nametoindex(name)
    except OSError as error:
        require(error.errno in (errno.ENODEV, errno.ENXIO)
                or error.errno is None and str(error) == 'no interface with this name',
                'Unknown selected bridge existence state')
        return None
    links = cold_json('ip', ['-j', '-d', 'link', 'show', 'dev', name])
    require(isinstance(links, list) and len(links) == 1 and links[0].get('ifname') == name
            and links[0].get('ifindex') == index and links[0].get('linkinfo', {}).get('info_kind') == 'bridge'
            and not links[0].get('master'), 'Selected bridge identity/type differs')
    ports = cold_json('ip', ['-j', 'link', 'show', 'master', name])
    require(ports == [], 'Unknown selected network kernel consumer; no detach performed')
    addresses = cold_json('ip', ['-j', 'address', 'show', 'dev', name])
    routes = cold_json('ip', ['-j', 'route', 'show', 'table', 'all', 'dev', name])
    routes6 = cold_json('ip', ['-j', '-6', 'route', 'show', 'table', 'all', 'dev', name])
    require(isinstance(addresses, list) and len(addresses) == 1 and addresses[0].get('ifindex') == index
            and addresses[0].get('ifname') == name and isinstance(routes, list) and isinstance(routes6, list),
            'Selected kernel network metadata malformed')
    return {'ifindex': index, 'link': links[0], 'addresses': addresses, 'routes': routes, 'routes6': routes6}


def validate_bridge(inspect, kernel):
    if kernel is None: return
    subnets = inspect.get('subnets', [])
    require(isinstance(subnets, list), 'Selected bridge subnet authority missing')
    networks = [ipaddress.ip_network(row['subnet']) for row in subnets]
    gateways = {str(ipaddress.ip_address(row['gateway'])) for row in subnets if row.get('gateway')}
    allowed_routes = set()
    for network in networks:
        allowed_routes.update((str(network), str(network.network_address), str(network.broadcast_address)))
    allowed_routes |= gateways | {'fe80::/64', 'ff00::/8'}
    for row in kernel['addresses'][0].get('addr_info', []):
        value = ipaddress.ip_address(row['local'])
        known_gateway = str(value) in gateways and any(value in net and row.get('prefixlen') == net.prefixlen for net in networks)
        local6 = value.version == 6 and value.is_link_local and row.get('scope') == 'link' and row.get('prefixlen') == 64
        require(known_gateway or local6, 'Selected bridge has an unowned address')
        if local6: allowed_routes.add(str(value))
    for row in kernel['routes'] + kernel['routes6']:
        destination = row.get('dst')
        require(row.get('dev') == inspect['network_interface'] and not row.get('gateway') and destination in allowed_routes,
                'Selected bridge has an unowned route')


def kernel_absence(mapping):
    """Read-only netlink dumps, filtered by PRIOR owning inspect identity.

    Never delete/filter/move any kernel object. A renamed surviving bridge with
    the old ifindex or an old dev-name route is a failed closure, not authority
    for manual cleanup. Unrelated interface/route presence is ignored.
    """
    bridge = mapping['bridge']; old = mapping.get('kernelIdentity', mapping.get('kernel'))
    links = cold_json('ip', ['-j', '-d', 'link', 'show'])
    addresses = cold_json('ip', ['-j', 'address', 'show'])
    routes = cold_json('ip', ['-j', 'route', 'show', 'table', 'all'])
    routes6 = cold_json('ip', ['-j', '-6', 'route', 'show', 'table', 'all'])
    require(all(isinstance(rows, list) and len(rows) <= MAX_NODES for rows in (links, addresses, routes, routes6)),
            'Kernel selected-absence inventory malformed')
    index = old['ifindex'] if old is not None else None
    require(not any(row.get('ifname') == bridge or index is not None and row.get('ifindex') == index for row in links + addresses)
            and not any(row.get('dev') == bridge or row.get('iif') == bridge for row in routes + routes6),
            'Selected kernel interface/address/route remains; no manual kernel cleanup allowed')


def mapped_readonly_layers(selection, rows, image_rows):
    """Retain only indexed immutable image clones for the exact two native prep maps.

    No cache layer is opened, adopted, chowned or removed. This grants neither
    execution authority nor cold-store credit. Unindexed/writable/foreign maps
    retain the original refusal behavior.
    """
    if selection is None: return {}
    name = 'site/global.settings/registry-image-ids.json'
    source = selection['pin']['sourceInputs'].get(name)
    require(isinstance(source, dict), 'Mapped image cache needs receipted registry identities')
    body, pin = read_file(selection['release'] / name)
    require(sha(body) == source['sha256'] and pin == source['stat'], 'Mapped cache registry source CAS changed')
    registry = strict(body)
    require(isinstance(registry, dict), 'Mapped cache registry source malformed')
    selected_ids = set()
    source_plan = selection['pin']['selection']
    if 'scopes' in source_plan:
        # Closed historical helper envelope: retain its bound release/receipt,
        # not an arbitrary caller-supplied scope projection.
        require(set(source_plan) == {'bundle', 'inputs', 'receipt', 'scopes'}
                and source_plan['bundle'] == str(selection['release'])
                and source_plan['receipt'] == {'phase': selection['receipt']['phase'],
                                               'sha256': selection['pin']['intentSha256']}
                and isinstance(source_plan['scopes'], dict), 'Historical selected-source envelope differs')
        source_plan = source_plan['scopes']
    for service_name in ('seafile', 'mariadb', 'valkey'):
        service = selection['ir']['services'].get(service_name)
        require(isinstance(service, dict), 'Complete native prep image source required')
        domain = service.get('rootlessDomain')
        row = next((row for row in selection['rows'] if row['name'] == domain), None)
        require(row is not None and domain in ('apps', 'platform'), 'Native prep image domain differs')
        relative = 'quadlet/rootless-' + domain + '/webservices-' + service_name + '.container'
        selected = source_plan.get('rootless-' + domain, {}).get('files', {}).get(relative)
        require(isinstance(selected, dict), 'Mapped cache image needs exact selected Quadlet source')
        quadlet, _ = read_file(selection['release'] / relative)
        require(sha(quadlet) == selected.get('sha256'), 'Mapped cache selected Quadlet source CAS changed')
        references = [line[6:] for line in quadlet.decode('utf-8').splitlines() if line.startswith('Image=')]
        require(len(references) == 1, 'Mapped cache selected image reference ambiguous')
        image = registry.get(row['user'] + '|' + references[0])
        require(isinstance(image, str) and image.startswith('sha256:') and HEX.fullmatch(image[7:]),
                'Native prep immutable image identity missing')
        selected_ids.add(image[7:])
    indexed = {row['id']: row for row in rows}; result = {}
    for image in image_rows:
        require(isinstance(image, dict), 'Mapped image index malformed')
        mapped = image.get('mapped-layers', [])
        if not mapped: continue
        if image.get('id') not in selected_ids: continue
        require(isinstance(mapped, list) and len(mapped) <= 32 and len(set(mapped)) == len(mapped),
                'Mapped image clone index ambiguous')
        original = indexed.get(image.get('layer'))
        require(isinstance(original, dict) and not original.get('uidmap') and not original.get('gidmap')
                and isinstance(original.get('diff-digest'), str)
                and re.fullmatch(r'sha256:[a-f0-9]{64}', original['diff-digest']), 'Mapped image original layer differs')
        for layer_id in mapped:
            require(isinstance(layer_id, str) and HEX.fullmatch(layer_id) and layer_id in indexed,
                    'Mapped image clone absent from layer index')
            layer = indexed[layer_id]
            require(set(layer) <= {'id', 'parent', 'created', 'compressed-diff-digest', 'compressed-size',
                                  'compression', 'diff-digest', 'diff-size', 'uidmap', 'gidmap', 'uidset', 'gidset'}
                    and all(type(layer.get(key)) is int and layer[key] >= 0 for key in ('diff-size', 'compressed-size')),
                    'Mapped image clone is not reviewed read-only metadata')
            require(layer.get('parent') == original.get('parent')
                    and all(layer.get(key) == original.get(key) for key in
                        ('diff-digest', 'diff-size', 'compressed-diff-digest', 'compressed-size', 'compression')),
                    'Mapped image clone is not the same immutable layer')
            require(all(isinstance(layer.get(key), list) and len(layer[key]) == 2
                        and all(isinstance(entry, dict) and set(entry) == {'container_id', 'host_id', 'size'}
                                and all(type(value) is int and value >= 0 for value in entry.values())
                                for entry in layer[key]) for key in ('uidmap', 'gidmap')),
                    'Mapped image clone namespace shape differs')
            matches = []
            for domain in ('apps', 'platform'):
                actor = selection['actors'][domain]
                uidmap = [dict(container_id=0, host_id=actor['uid'], size=1),
                          dict(container_id=1, host_id=actor['start'], size=65536)]
                gidmap = [dict(container_id=0, host_id=actor['gid'], size=1),
                          dict(container_id=1, host_id=actor['start'], size=65536)]
                if layer.get('uidmap') == uidmap and layer.get('gidmap') == gidmap:
                    matches.append((actor['uid'], actor['gid']))
            require(len(matches) == 1, 'Mapped image clone namespace is foreign or ambiguous')
            record = {'uid': matches[0][0], 'gid': matches[0][1], 'imageId': image['id'],
                      'layerMetadataSha256': sha(canonical(layer)), 'registrySource': source,
                      'retainedReadOnlyCache': True, 'coldStoreAcceptance': False}
            require(layer_id not in result or result[layer_id] == record, 'Mapped image clone has conflicting owners')
            result[layer_id] = record
    return result


def layer_disk_inventory(mapped=None):
    # Two fixed metadata-directory levels only. NEVER descend into a layer,
    # diff, merged, work, writable contents, volume or other engine directory.
    # Empty JSON alone cannot prove that orphaned disk layer/cache data is cold.
    path = Path(ROOT_GRAPH) / 'overlay'
    try:
        with directory(path) as fd:
            before = custody(fd); names = os.listdir(fd)
            require(len(names) <= MAX_NODES, 'Rootful disk layer bound exceeded')
            entries = {}; layers = []; lower = {}
            for name in sorted(names):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                mapped_owner = (mapped or {}).get(name)
                if mapped_owner is None:
                    require(info.st_uid == info.st_gid == 0, 'Foreign rootful disk layer metadata custody')
                else:
                    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                            and (info.st_uid, info.st_gid) == (mapped_owner['uid'], mapped_owner['gid']),
                            'Exact mapped immutable cache directory custody differs')
                entries[name] = fingerprint(info)
                if HEX.fullmatch(name):
                    require(stat.S_ISDIR(info.st_mode), 'Rootful disk layer identity is not a directory')
                    layers.append(name)  # No open/read/scan of this directory.
                elif name == 'l':
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        root_directory(child); pin = custody(child); links = os.listdir(child)
                        require(len(links) <= MAX_NODES, 'Rootful lower-link metadata bound exceeded')
                        for link in sorted(links):
                            value = os.stat(link, dir_fd=child, follow_symlinks=False)
                            require(stat.S_ISLNK(value.st_mode) and value.st_uid == value.st_gid == 0 and value.st_nlink == 1,
                                    'Unknown rootful lower-link metadata; no traversal allowed')
                            lower[link] = fingerprint(value)  # Never readlink/follow.
                        require(custody(child) == pin, 'Rootful lower-link CAS changed')
                    finally: os.close(child)
                else:
                    require(name in ('backingFsBlockDev', '.has-mount-program')
                            and not stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                            'Unknown rootful overlay metadata; owner classification needed')
            require(custody(fd) == before, 'Rootful disk layer enumeration CAS changed')
            observed = {'control': before, 'entries': entries, 'layers': layers, 'lowerLinks': lower}
            if mapped: observed['retainedMappedReadOnlyCache'] = mapped
            return observed
    except FileNotFoundError:
        _, missing = cold_path(path)
        return {'control': missing, 'entries': {}, 'layers': [], 'lowerLinks': {}}


def image_disk_inventory():
    # Fixed image METADATA directory, not an engine graph walk. Orphan image
    # directories are residue even when the engine's image index says zero.
    path = Path(ROOT_GRAPH) / 'overlay-images'
    try:
        with directory(path) as fd:
            before = custody(fd); entries = {}; ids = []; names = os.listdir(fd)
            require(len(names) <= MAX_NODES, 'Rootful image directory bound exceeded')
            for name in sorted(names):
                value = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(value.st_uid == value.st_gid == 0 and not value.st_mode & 0o022,
                        'Foreign rootful image directory custody')
                entries[name] = fingerprint(value)
                if HEX.fullmatch(name):
                    require(stat.S_ISDIR(value.st_mode), 'Rootful image directory identity is not a directory')
                    ids.append(name)  # NEVER open or descend into it.
                else:
                    require(name in ('images.json', 'images.lock') and stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                            'Unknown rootful image metadata; owner classification needed')
            require(custody(fd) == before, 'Rootful image directory CAS changed')
            return {'control': before, 'entries': entries, 'ids': ids}
    except FileNotFoundError:
        _, missing = cold_path(path)
        return {'control': missing, 'entries': {}, 'ids': []}


def layer_inventory(selection=None):
    # Storage METADATA ONLY after containers/volumes/buildah are independently
    # zero. Do not inspect writable layer contents or walk the global graph.
    body, pin = cold_path(Path(ROOT_GRAPH) / 'overlay-layers/layers.json', contents=True)
    images = image_disk_inventory()
    if body is None:
        disk = layer_disk_inventory()
        return {'ids': [], 'control': pin, 'disk': disk, 'imageDirectories': images}
    try: rows = strict('{"value":' + body.decode('utf-8') + '}')['value']
    except (ValueError, UnicodeError): raise Refusal('Rootful layer metadata refused') from None
    require(isinstance(rows, list) and len(rows) <= MAX_NODES, 'Rootful layer inventory bound exceeded')
    ids = [row.get('id') for row in rows if isinstance(row, dict)]
    require(len(ids) == len(rows) and len(set(ids)) == len(ids)
            and all(isinstance(value, str) and HEX.fullmatch(value) for value in ids), 'Rootful layer identity ambiguous')
    mapped = {}
    if any(row.get('uidmap') or row.get('gidmap') for row in rows) and selection is not None:
        image_body, image_pin = cold_path(Path(ROOT_GRAPH) / 'overlay-images/images.json', contents=True)
        require(image_body is not None, 'Mapped layer image index missing')
        image_rows = strict('{"value":' + image_body.decode('utf-8') + '}')['value']
        require(isinstance(image_rows, list) and len(image_rows) <= MAX_NODES, 'Mapped image index bound exceeded')
        mapped = mapped_readonly_layers(selection, rows, image_rows)
        if mapped: mapped = {key: dict(value, imageIndex=image_pin, imageIndexSha256=sha(image_body)) for key, value in mapped.items()}
    disk = layer_disk_inventory(mapped)
    return {'ids': sorted(ids), 'control': pin, 'disk': disk, 'imageDirectories': images}


def root_images_cold(snapshot):
    layers = snapshot['layers']
    return not snapshot['images'] and not snapshot['buildahImages'] and not layers['ids'] \
        and not layers['disk']['layers'] and not layers['disk']['lowerLinks'] and not layers['imageDirectories']['ids']


def image_inventory(tool):
    args = ['images', '--all', '--no-trunc', '--format=json'] if tool == 'podman' else ['images', '--all', '--no-trunc', '--json']
    rows = cold_json(tool, args)
    require(isinstance(rows, list) and len(rows) <= MAX_NODES, 'Rootful image inventory bound exceeded')
    ids = []
    for row in rows:
        require(isinstance(row, dict), 'Rootful image inventory malformed')
        value = row.get('Id', row.get('ID', row.get('id')))
        require(isinstance(value, str) and HEX.fullmatch(value.removeprefix('sha256:')), 'Full rootful image ID required')
        ids.append(value.removeprefix('sha256:'))
    return sorted(set(ids))


def _builtin_default_network(network):
    # Pinned c/common netavark createDefaultNetwork/networkCreate(defaultNet=true):
    # fixed identity, absent name-matching config, Created=time.Now(), no commit.
    fields = {'containers', 'created', 'dns_enabled', 'driver', 'id', 'internal', 'ipam_options',
              'ipv6_enabled', 'name', 'network_interface', 'subnets'}
    if not (type(network) is dict and set(network) == fields and network['name'] == 'podman'
            and network['id'] == '2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9'
            and network['driver'] == 'bridge' and network['network_interface'] == 'podman0'
            and network['containers'] == {} and network['dns_enabled'] is False
            and network['internal'] is False and network['ipv6_enabled'] is False
            and type(network['ipam_options']) is dict and type(network['subnets']) is list
            and network['subnets'] != [] and type(network['created']) is str): return False
    if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})', network['created']): return False
    try: datetime.datetime.fromisoformat(network['created'].replace('Z', '+00:00'))
    except ValueError: return False
    return True


@contextlib.contextmanager
def _default_network_definition():
    """Original held namespace + exact name state, NEVER read network config bodies."""
    path = Path('/etc/containers/networks/podman.json')
    with contextlib.ExitStack() as stack:
        try: parent = stack.enter_context(directory(path.parent))
        except FileNotFoundError:
            yield None; return  # no absence authority for an unobserved parent
        ancestry = source_ancestry(path); parent_pin = custody(parent); mount = fd_mount_id(parent)
        def state():
            try: return fingerprint(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            except FileNotFoundError: return None
        original = state()
        proof = {'path': str(path), 'ancestry': ancestry, 'parent': parent_pin,
                 'parentMountId': mount, 'file': original}
        yield proof
        require(state() == original and custody(parent) == parent_pin and fd_mount_id(parent) == mount
                and source_ancestry(path) == ancestry, 'Original default network definition/absence namespace changed')


def _unselected_network_record(name, network):
    def record(value): return {'sha256': sha(canonical(value)), 'bridge': value.get('network_interface')}
    if name != 'podman' or not _builtin_default_network(network): return record(network)
    with _default_network_definition() as source:
        rows = cold_json('podman', ['network', 'inspect', 'podman'])
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and rows[0].get('name') == name,
                'Original default network observation changed')
        current = rows[0]
        if source is None or source['file'] is not None:
            require(current == network, 'Real/unproven default network definition changed')
            result = record(current)  # includes created, no synthetic interpretation
            if source is not None: result['definitionSource'] = source
            return result
        require(_builtin_default_network(current)
                and {k: v for k, v in current.items() if k != 'created'}
                    == {k: v for k, v in network.items() if k != 'created'},
                'Synthetic default network non-clock metadata changed')
        result = record({k: v for k, v in current.items() if k != 'created'})
        result['definitionSource'] = source
        result['identityKind'] = 'source-absent-netavark-in-memory-default'
        result['volatileFields'] = ['created']  # explicit read-time clock, not a persisted definition field
        return result


def rootful_inventory(selection, sources, mappings=None):
    context = default_context(); namespaces = root_runtime_identity()
    info = cold_json('podman', ['info', '--format=json'])
    require(isinstance(info, dict), 'Rootful engine info malformed')
    store = info.get('store', {}); host = info.get('host', {})
    require(isinstance(store, dict) and isinstance(host, dict), 'Rootful engine context malformed')
    require(store.get('graphRoot') == ROOT_GRAPH and store.get('runRoot') == ROOT_RUN
            and store.get('graphDriverName') == 'overlay' and store.get('volumePath', ROOT_GRAPH + '/volumes') == ROOT_GRAPH + '/volumes'
            and store.get('configFile') in context['storageConfigs'] and host.get('security', {}).get('rootless') is False
            and host.get('networkBackend') == 'netavark', 'Foreign/default rootful engine context differs')
    buildah_info = cold_json('buildah', ['info'])
    require(isinstance(buildah_info, dict) and isinstance(buildah_info.get('store'), dict), 'Buildah default context malformed')
    buildah_store = buildah_info['store']
    require(buildah_store.get('GraphRoot') == ROOT_GRAPH and buildah_store.get('RunRoot') == ROOT_RUN
            and buildah_store.get('GraphDriverName') == 'overlay', 'Foreign Buildah default rootful store')
    require(cold_json('podman', ['ps', '--all', '--no-trunc', '--format=json']) == [], 'Rootful containers remain; no writable-data deletion')
    require(cold_json('podman', ['volume', 'ls', '--format=json']) == [], 'Rootful volumes remain; no volume deletion')
    # This exact successful Buildah command emits JSON null for its nil Go
    # container slice (pinned upstream0a5cebb3/cmd/buildah/containers.go).
    # No filters, error/null coercion or other inventory normalization.
    buildah_containers = cold_json('buildah', ['containers', '--json'])
    require(buildah_containers is None or (type(buildah_containers) is list and buildah_containers == []),
            'Buildah containers remain or inventory shape unknown; no writable-data deletion')
    images = image_inventory('podman'); buildah = image_inventory('buildah')
    require(images == buildah, 'Default Podman/Buildah image stores disagree')
    layers = layer_inventory(selection)
    names = sorted({row['name'] for entry in sources.values() for row in entry['networks']})
    # Read-only definition inventory protects UNSELECTED definitions/bridge
    # aliases; it never derives deletion authority from a prefix or live list.
    listing = cold_json('podman', ['network', 'ls', '--format=json'])
    require(isinstance(listing, list) and len(listing) <= 1024, 'Root network definition inventory bound exceeded')
    unselected = {}
    for row in listing:
        require(isinstance(row, dict), 'Root network definition inventory malformed')
        name = row.get('name', row.get('Name'))
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name), 'Invalid root network inventory name')
        if name in names: continue
        data = cold_json('podman', ['network', 'inspect', name])
        require(isinstance(data, list) and len(data) == 1 and data[0].get('name') == name,
                'Unselected network identity unavailable; no cleanup permission inferred')
        require(name not in unselected, 'Duplicate unselected network definition')
        unselected[name] = _unselected_network_record(name, data[0])
    networks = {}
    for name in names:
        code, _ = cold_call('podman', ['network', 'exists', name])
        require(code in (0, 1), 'Selected network existence query failed')
        if code == 1:
            mapping = (mappings or {}).get(name)
            if mapping is not None and mapping.get('absenceAttested') is not True: mapping = None
            networks[name] = {'inspect': None, 'kernel': None, 'bridge': None if mapping is None else mapping['bridge'],
                              'kernelIdentity': None if mapping is None else mapping.get('kernelIdentity', mapping.get('kernel')),
                              'absenceAttested': mapping is not None}
            if mapping is not None and mapping['bridge'] is not None:
                networks[name]['kernel'] = bridge_state(mapping['bridge'])
                if networks[name]['kernel'] is None: kernel_absence(mapping)
            continue
        rows = cold_json('podman', ['network', 'inspect', name])
        require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), 'Selected network inspection ambiguous')
        net = rows[0]
        require(net.get('name') == name and isinstance(net.get('id'), str) and HEX.fullmatch(net['id'])
                and net.get('driver') == 'bridge' and not net.get('containers')
                and not net.get('Containers'), 'Selected network has unknown identity/driver/consumer')
        bridge = net.get('network_interface'); kernel = bridge_state(bridge); validate_bridge(net, kernel)
        require(not any(other['bridge'] == bridge for other in unselected.values()),
                'Selected bridge aliases an unselected network; no removal performed')
        networks[name] = {'inspect': net, 'kernel': kernel, 'kernelIdentity': kernel, 'bridge': bridge, 'absenceAttested': True}
    present = [row for row in networks.values() if row['inspect'] is not None]
    require(len({row['bridge'] for row in present}) == len(present)
            and len({row['inspect']['id'] for row in present}) == len(present), 'Selected network bridge/ID aliases')
    require(default_context() == context and root_runtime_identity() == namespaces, 'Rootful control/namespace CAS changed')
    return {'schemaVersion': 1, 'context': context, 'namespaces': namespaces,
            'store': {key: store[key] for key in ('graphRoot', 'runRoot', 'graphDriverName', 'configFile')},
            'buildahStore': {key: buildah_store[key] for key in ('GraphRoot', 'RunRoot', 'GraphDriverName')},
            'containers': [], 'volumes': [], 'buildahContainers': buildah_containers, 'images': images, 'buildahImages': buildah,
            'layers': layers, 'networks': networks, 'unselectedNetworks': unselected}


def prior_network_mappings(root_fd, selection, sources):
    """Recover INSPECT provenance only from our durable exact-CAS operation.

    This is not permission to delete a kernel interface. A surviving bridge
    whose definition is gone still fails closure; no iplink/manual cleanup.
    """
    try: fd = os.open('.host-clean-reset', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    except FileNotFoundError: return {}
    result = {}
    historical = None
    try:
        root_directory(fd, True)
        if selection.get('receipt', {}).get('phase') == 'retired-clean':
            authenticated = prior_completed_reset(selection['root'], selection['receipt'])
            require(authenticated == selection['pin'].get('priorCompletedReset'), 'Prior network provenance CAS changed')
            historical = selection['receipt']['completeCleanReset']
        names = os.listdir(fd); require(len(names) <= MAX_NODES, 'Reset evidence bound exceeded')
        for name in sorted(names):
            if not re.fullmatch(r'[a-f0-9]{64}-[a-f0-9]{32}-intent\.json', name): continue
            body, _ = read_at(fd, name, private=True, gid=0, limit=512 * 1024 * 1024)
            document = strict(body); plan = document.get('plan')
            current = document.get('intentSha256') == selection['pin']['intentSha256']
            prior = historical is not None and name == Path(historical['resultPath']).name.removesuffix('-result.json') + '-intent.json'
            if not isinstance(plan, dict) or not (current or prior): continue
            if prior:
                require(document.get('intentSha256') == historical['intentSha256']
                        and document.get('planSha256') == historical['planSha256'], 'Authenticated prior network intent differs')
            require(document.get('planSha256') == name[:64] == sha(canonical(plan)), 'Reset intent plan evidence CAS differs')
            if prior:
                # Journal SHA/receipt phase necessarily changed on retirement.
                # Compare only the exact current release's immutable network
                # definitions; never inherit a prior action inventory or scope.
                key = str(selection['release'])
                before = plan.get('rootfulNetworkSources', {}).get(key, {})
                if set(sources) != {key} or before.get('networks') != sources[key].get('networks'): continue
                allowed = {row['name'] for row in sources[key]['networks']}
            else:
                if plan.get('rootfulNetworkSources') != sources: continue
                allowed = {row['name'] for entry in sources.values() for row in entry.get('networks', [])}
            require(plan.get('root') == str(selection['root']) and plan.get('scope') == str(SCOPE), 'Reset network evidence scope differs')
            observed = list(plan.get('rootfulDefault', {}).get('networks', {}).items())
            observed += list(plan.get('rootfulNetworkInspectionProvenance', {}).items())
            for network, value in observed:
                if network not in allowed or value.get('inspect') is None or not value.get('absenceAttested'): continue
                require(network == value['inspect'].get('name') and value.get('bridge') == value['inspect'].get('network_interface'),
                        'Reset inspect evidence identity differs')
                if network in result:
                    require(result[network]['bridge'] == value['bridge'] and result[network]['inspect']['id'] == value['inspect']['id'],
                            'Conflicting reset network evidence; fresh owning source inventory needed')
                result[network] = value
        return result
    finally: os.close(fd)


def rootful_cleanup(selection, sources, reviewed, verify, checkpoint):
    """Exact unforced network removal only. No default-store image/cache authority."""
    expected = reviewed
    def source_guard():
        verify()
        require(rootful_network_sources(selection) == sources, 'Rootful source network CAS changed')
    def guard():
        source_guard()
        current = rootful_inventory(selection, sources,
            {name: row for name, row in expected['networks'].items() if row['absenceAttested']})
        require(current == expected, 'Rootful store/object/kernel CAS changed')
    guard()
    # Root's default store is not an isolated actor graph or deletion scope.
    # Even matching image config IDs confer no ownership of shared cache bytes.
    after = expected
    # A missing definition without prior owning inspect data does not establish
    # its old kernel bridge's absence. Retain an exact actionable dependency.
    image_cold = root_images_cold(after)
    checkpoint({'rootImageCold': image_cold, 'rootfulAfterImages': after})
    require(image_cold, 'Rootful images/build-cache/layer metadata remains (including orphan image/layer directories); no external prune or data deletion allowed')
    for name in sorted(expected['networks']):
        network = expected['networks'][name]
        if network['inspect'] is None: continue
        guard()
        code, _ = cold_call('podman', ['network', 'rm', name], mutate=True)
        require(code == 0, 'Owning unforced selected network removal failed')
        source_guard()
        after = rootful_inventory(selection, sources, expected['networks'])
        wanted = dict(expected, networks=dict(expected['networks']))
        wanted['networks'][name] = dict(inspect=None, kernel=None, kernelIdentity=network['kernelIdentity'],
                                        bridge=network['bridge'], absenceAttested=True)
        require(after == wanted, 'Selected network/kernel closure failed or unrelated identity changed')
        expected = after
        checkpoint({'selectedNetworkRemoved': name, 'rootfulAfterNetwork': after})
    guard()
    closed = all(row['inspect'] is None and row['kernel'] is None and row['absenceAttested'] for row in expected['networks'].values())
    require(closed, 'Selected network kernel absence lacks owning inspect provenance; source-bound pre-stop inventory needed')
    return {'rootImageCold': True, 'selectedNetworkClosure': True, 'rootfulStoreColdAcceptance': True,
            'rootfulAfter': expected, 'rootfulNetworkScope': sorted(expected['networks'])}


def plan_locked(root, expected, root_fd, lock_pin, data_only=False):
    selection = binding(root, expected)
    require(type(data_only) is bool and (not data_only or selection['receipt']['phase'] == 'retired-clean'),
            'Data-only engineering reset requires authenticated retained clean-current authority')
    external = external_plan(selection)
    stopped(selection)
    network_sources = rootful_network_sources(selection)
    network_mappings = prior_network_mappings(root_fd, selection, network_sources)
    rootful = rootful_inventory(selection, network_sources, network_mappings)
    require(rootful_inventory(selection, network_sources, network_mappings) == rootful, 'Rootful review inventory CAS changed')
    # No default-store image/cache deletion authority exists. Refuse an
    # impossible complete-clean result BEFORE scope scanning, plan publication,
    # lease issuance or any owned-data erasure. Engineering data-only mode is
    # explicitly separate and still provides zero complete/cold/count credit.
    require(data_only or root_images_cold(rootful),
            'Non-cold shared default store cannot qualify complete reset; isolated selected-store engineering required before mutation')
    present_external = [Path(tree['path']) for tree in external['trees'] if tree['pin'] is not None]
    unmounted([SCOPE, *present_external], selection['externalPolicies'])
    retained = set(selection['policies']) - {SHARED, SCOPE} - set(selection['roots'])
    with directory(SCOPE, selection['policies']) as fd:
        data = scan(fd, selection, retain=retained)
    plan = {'schemaVersion': 1, 'kind': ('owned-synthetic-data-only-reset' if data_only else 'complete-owned-synthetic-clean-reset'),
            'dataOnly': data_only, 'root': str(root), 'scope': str(SCOPE),
            'authority': selection['pin'], 'lock': lock_pin, 'nodes': data, 'external': external,
            'rootfulNetworkSources': network_sources, 'rootfulDefault': rootful,
            'rootfulNetworkInspectionProvenance': dict(network_mappings,
                **{name: row for name, row in rootful['networks'].items() if row['inspect'] is not None and row['absenceAttested']}),
            'defaultStoreImageDeletionAuthorized': False,
            'sharedImageCachesPreserved': True,
            'evidenceGeneration': evidence_generation(root_fd),
            'retainedInfrastructure': sorted(str(path) for path in retained | {SCOPE}),
            'privateRootsLeftAbsent': sorted(str(path) for path in selection['roots']),
            'retainedAccountsAndSubids': selection['pin']['allocation'],
            'retainedMetadata': ['root-journal', 'root-receipts', 'immutable-manifests-and-source-inputs', 'operation-evidence'],
            'retainedOutsideScope': ['operator-age-key', 'unrelated-services-assets-data-and-caches'],
            'backupCreated': False, 'automaticRestart': False, 'applicationAcceptance': False}
    return plan, selection


def review(root, expectedIntentSha, data_only=False):
    root = absolute(root)
    with locked(root) as (fd, pin):
        plan, _ = plan_locked(root, expectedIntentSha, fd, pin, data_only)
        return {'plan': plan, 'planSha256': sha(canonical(plan))}


def review_runtime_custody(root, expectedIntentSha):
    """Read-only tooling for the EXISTING journal owner, not deletion admission.

    The owner may exact-CAS seal cleanResetCustody into BOTH root records. That
    changes the intent SHA: perform a NEW review and obtain a NEW typed lease.
    This function writes nothing and cannot seal, retire, authorize or reset.
    """
    root = absolute(root)
    with locked(root):
        selection = binding(root, expectedIntentSha)
        external = external_plan(selection, custody_inventory=True)
        require(binding(root, expectedIntentSha)['pin'] == selection['pin'], 'Custody review source/CAS changed')
        stopped(selection)
        return {'intentSha256': expectedIntentSha,
                'cleanResetCustody': {'externalTrees': external['runtimeFingerprints']},
                'sourceBindingSha256': sha(canonical(selection['pin'])), 'applicationAcceptance': False}


class _NetworkStopContext:
    __slots__ = ('_key', '_binding', '_units', '_digest')
    def __init__(self, key, selection, units):
        require(key is _NETWORK_STOP_KEY and set(units) <= _NETWORK_STOP_UNITS,
                'Only original selected network preparation may observe active networks')
        self._key, self._binding = key, sha(canonical(selection['pin']))
        self._units = dict(units); self._digest = sha(canonical(self._units))
    @property
    def units(self): return dict(self._units)
    def validate(self, selection):
        require(self._key is _NETWORK_STOP_KEY and self._binding == sha(canonical(selection['pin']))
                and self._digest == sha(canonical(self._units)) and set(self._units) <= _NETWORK_STOP_UNITS,
                'Network stop source context changed')


class NetworkStopLease:
    """One-use authority ONLY for four original networks + original publisher env service."""
    __slots__ = ('_key', '_root', '_intent', '_plan', '_digest', '_pid', '_until', '_used')
    def __init__(self, key, root, intent, plan):
        require(key is _NETWORK_STOP_KEY, 'Only canonical network stop preparation issues authority')
        self._key, self._root, self._intent = key, root, intent
        self._plan = strict(canonical(plan)); self._digest = sha(canonical(plan))
        self._pid, self._until, self._used = os.getpid(), time.monotonic() + 600, False
    def validate(self, root, intent, expected):
        require(self._key is _NETWORK_STOP_KEY and not self._used and os.getpid() == self._pid
                and time.monotonic() < self._until and (root, intent, expected) == (self._root, self._intent, self._digest)
                and sha(canonical(self._plan)) == self._digest, 'Network stop lease expired/used/changed/foreign')


def _network_stop_snapshot(root, expected, lock_pin):
    selection = binding(root, expected)
    installer = selection['pin']['helpers']['install-podman-bundle.sh']['sha256']
    require(selection['receipt'].get('phase') == 'retired-failed'
            and installer == '7d7f7b8758ab5320ea8d7614fe5be5493c717ff28e9d0f10a88afdf7078b3bf2'
            and legacy_source_authority(selection) is not None
            and not any(key in selection['receipt'] for key in ('nativeUnitFiles', 'nativeUnitFileCustody')),
            'Stop-only compatibility requires original retired legacy publication, not new installation custody')
    entry = selection['pin']['selection']['scopes']['rootful']; native = selection['modules']['native-selection.py']
    units = {item['unit']: str(native.destination('rootful', entry, relative))
             for relative, item in entry['files'].items()
             if item['kind'] == 'network' and item['unit'] in _NETWORK_STOP_UNITS}
    require(units and all(Path(path).parent == Path('/etc/containers/systemd')
                          and Path(path).suffix == '.network' for path in units.values()), 'No exact original network stop selection')
    units['webservices-runtime-env.service'] = '/etc/systemd/system/webservices-runtime-env.service'
    context = _NetworkStopContext(_NETWORK_STOP_KEY, selection, units)
    external = external_plan(selection, custody_inventory=True, _network_stop=context)
    controls = _stopped_observation(selection, context)
    fragments = {}
    installed = {row['path']: row for row in external['files']}
    for unit, path in units.items():
        require(installed.get(path, {}).get('stat') is not None, 'Original selected network source is not installed')
        props = controls[unit]
        require(props['LoadState'] == 'loaded' and props['Names'] == unit
                and props['Triggers'] == props['TriggeredBy'] == props['DropInPaths'] == '',
                'Original selected stop control differs')
        if unit == 'webservices-runtime-env.service':
            require(props['UnitFileState'] == 'static' and props['SourcePath'] == '' and props['FragmentPath'] == path
                    and installed[path]['source'] == 'recognized-installer:runtime-env'
                    and external['nativeRuntimeEnvSources'] is None, 'Original publisher env service source differs')
        else:
            require(props['UnitFileState'] == 'generated' and props['SourcePath'] == path
                    and props['FragmentPath'] == '/run/systemd/generator/' + unit,
                    'Original selected network generator source differs')
        fragment = Path(props['FragmentPath'])
        _, fragment_source = helper_file(fragment)  # reuse exact sealed source + complete parent-chain proof
        with directory(fragment.parent) as parent:
            child = os.open(fragment.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                require(fingerprint(os.fstat(child)) == fragment_source['stat'] and not acl(child, True)
                        and source_ancestry(fragment) == fragment_source['ancestry'], 'Network fragment inode/ACL/namespace changed')
                fragments[unit] = dict(fragment_source, mountId=fd_mount_id(child))
            finally: os.close(child)
    sources = rootful_network_sources(selection)
    rootful = rootful_inventory(selection, sources)
    require(binding(root, expected)['pin'] == selection['pin'], 'Network stop source/CAS changed during observation')
    require(_stopped_observation(selection, context) == controls, 'Network stop control observation changed')
    return {'schemaVersion': 1, 'kind': 'exact-legacy-selected-network-stop', 'root': str(root), 'lock': lock_pin,
            'authority': selection['pin'], 'units': units, 'controls': controls, 'fragments': fragments,
            'external': external, 'rootfulNetworkSources': sources, 'rootfulDefault': rootful,
            'activationAuthorized': False, 'deletionAuthorized': False, 'resetAuthorized': False}, selection


def prepare_network_stop(root, expectedIntentSha):
    """Read-only exact preparation. JSON/source data alone cannot dispatch a stop."""
    root = absolute(root)
    with locked(root) as (_, lock_pin):
        plan, _ = _network_stop_snapshot(root, expectedIntentSha, lock_pin)
        lease = NetworkStopLease(_NETWORK_STOP_KEY, root, expectedIntentSha, plan)
        return {'plan': strict(canonical(plan)), 'planSha256': lease._digest, 'lease': lease}


def _dispatch_network_stop(unit):
    require(unit in _NETWORK_STOP_UNITS, 'Unknown selected network stop dispatch')
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'stop', '--', unit], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.SubprocessError):
        raise Refusal('Exact network stop incomplete; no force/retry/restart') from None
    require(result.returncode == 0, 'Exact network stop failed; no force/retry/restart')


def _same_network_stop_plan(current, original, stopped_units):
    expected = strict(canonical(original))
    for unit in stopped_units:
        row = current['controls'][unit]
        require((row['ActiveState'], row['SubState']) in (('inactive', 'dead'), ('failed', 'failed')),
                'Dispatched network did not stop')
        expected['controls'][unit]['ActiveState'] = row['ActiveState']
        expected['controls'][unit]['SubState'] = row['SubState']
    require(current == expected, 'Original network stop source/installed/control/default-engine CAS changed')


def execute_network_stop(root, expectedIntentSha, expectedPlanSha, lease):
    """Stop exact original exited networks/publisher ONLY; never delete/reset/repair."""
    root = absolute(root)
    require(type(lease) is NetworkStopLease, 'Actual process-local network stop lease required')
    with locked(root) as (_, lock_pin):
        lease.validate(root, expectedIntentSha, expectedPlanSha); lease._used = True
        original = lease._plan; done = []
        current, selection = _network_stop_snapshot(root, expectedIntentSha, lock_pin)
        _same_network_stop_plan(current, original, done)
        pending = sorted(unit for unit in original['units'] if original['controls'][unit]['ActiveState'] == 'active')
        for unit in pending:
            current, selection = _network_stop_snapshot(root, expectedIntentSha, lock_pin)
            _same_network_stop_plan(current, original, done)
            require(os.getpid() == lease._pid and time.monotonic() < lease._until
                    and sha(canonical(original)) == lease._digest, 'Network stop lease expired/changed before dispatch')
            _dispatch_network_stop(unit); done.append(unit)
            current, selection = _network_stop_snapshot(root, expectedIntentSha, lock_pin)
            _same_network_stop_plan(current, original, done)
        stopped(selection)  # STILL the unchanged strict gate, no active exception.
        return {'kind': 'exact-legacy-selected-network-stop-result', 'stoppedUnits': done,
                'completed': True, 'intentSha256': expectedIntentSha, 'planSha256': expectedPlanSha,
                'activationAuthorized': False, 'deletionAuthorized': False, 'resetAuthorized': False}


class StoppedLease:
    """Opaque process-local proof; never construct from caller JSON/booleans."""
    __slots__ = ('_key', '_root', '_intent', '_plan', '_pid', '_until', '_used')
    def __init__(self, key, root, intent, plan):
        require(key is _LEASE_KEY, 'Only canonical stopped proof may issue a lease')
        self._key, self._root, self._intent, self._plan = key, root, intent, plan
        self._pid, self._until, self._used = os.getpid(), time.monotonic() + 600, False
    def validate(self, root, intent, plan):
        require(self._key is _LEASE_KEY and not self._used and os.getpid() == self._pid
                and time.monotonic() < self._until and (root, intent, plan) == (self._root, self._intent, self._plan),
                'Stopped lease expired, consumed or differs from exact selection')


def issue_stopped_lease(root, expectedIntentSha, expectedPlanSha, data_only=False):
    root = absolute(root)
    require(isinstance(expectedPlanSha, str) and HEX.fullmatch(expectedPlanSha), 'Exact reviewed plan required')
    with locked(root) as (fd, pin):
        plan, _ = plan_locked(root, expectedIntentSha, fd, pin, data_only)
        require(sha(canonical(plan)) == expectedPlanSha, 'Plan CAS changed before stopped lease')
        return StoppedLease(_LEASE_KEY, root, expectedIntentSha, expectedPlanSha)


def write_evidence(fd, name, value):
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        data = canonical(value)
        while data:
            count = os.write(child, data); require(count > 0, 'Incomplete durable intent write'); data = data[count:]
        os.fsync(child)
    finally: os.close(child)
    os.fsync(fd)


def claim(parent, name, destination, expected):
    """Atomic NOREPLACE claim, then inode fingerprint, BEFORE any deletion.

    A substituted inode is retained under the intent's reserved claim prefix on
    failure, never followed/deleted or silently restored over another entry.
    Linux provides no conditional unlink; this extra claim closes the
    check-then-unlink replacement window in the stopped private parent.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    require(rename is not None, 'Atomic no-replace rename unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(name), parent, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, 'Exact no-replace scope claim failed')
    os.fsync(parent)
    after = fingerprint(os.stat(destination, dir_fd=parent, follow_symlinks=False))
    require(after[:-1] == expected[:-1], 'Claimed inode differs from reviewed fingerprint')
    return after


def erase(fd, nodes, expected_names=None, claim_prefix=None, before_root=None, after_root=None, selection=None):
    with contextlib.ExitStack() as resources:
        return _erase(fd, nodes, expected_names, claim_prefix, before_root, after_root, selection, resources)


def _erase(fd, nodes, expected_names, claim_prefix, before_root, after_root, selection, resources):
    """Real FD deletions; never follow links. Internal hardlink CAS is adjusted
    ONLY for our own successful unlink, using a pinned O_PATH inode descriptor.
    """
    by_parent = {}
    for node in nodes: by_parent.setdefault(str(Path(node['path']).parent), []).append(node)
    hardlinks = {}; pinned = {}; serial = [0]; directories = {}; catalogs = {}
    claim_prefix = claim_prefix or uuid.uuid4().hex
    require(re.fullmatch(r'[a-f0-9-]+', claim_prefix), 'Invalid operation claim identity')
    def visit(parent, relative):
        entries = by_parent.get(str(relative), [])
        expected = sorted(Path(node['path']).name for node in entries)
        if relative == Path('.') and expected_names is not None: expected = sorted(expected_names)
        require(sorted(os.listdir(parent)) == expected, 'Deletion directory names CAS changed')
        for node in entries:
            name = Path(node['path']).name; key = tuple(node['stat'][:2])
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            expected_stat = hardlinks.get(key, node['stat'])
            require(fingerprint(current) == expected_stat, 'Deletion inode fingerprint CAS changed')
            whiteout = None
            if node['kind'] == 'overlay-whiteout':
                require(selection is not None and node.get('rdev') == 0, 'Whiteout erasure lacks original source binding')
                source, whiteout = whiteout_source(SCOPE / node['path'], directories, catalogs, resources, selection)
                require(source == node['overlaySource'], 'Original whiteout graph/layer/control/ancestry CAS changed')
                named_whiteout(parent, name, whiteout.actor, expected_stat)
            if before_root is not None:
                before_root(node)
                require(fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected_stat,
                        'Private root changed during fresh stopped proof')
            if not node['retain']:
                serial[0] += 1
                destination = '.clean-reset-' + claim_prefix + '-' + str(serial[0])
                expected_stat = claim(parent, name, destination, expected_stat)
                name = destination
                if node['kind'] == 'file': hardlinks[key] = expected_stat
                if whiteout is not None: named_whiteout(parent, name, whiteout.actor, expected_stat)
            if node['kind'] == 'directory':
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                directories[str(SCOPE / node['path'])] = child
                try:
                    require(fingerprint(os.fstat(child)) == expected_stat
                            and acl(child) == node['acl'] and acl(child, True) == node['defaultAcl'], 'Deletion directory open/ACL changed')
                    visit(child, Path(node['path']))
                    require(stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stable(os.fstat(child)),
                            'Deletion directory replaced')
                finally:
                    directories.pop(str(SCOPE / node['path'])); os.close(child)
                if not node['retain']: os.rmdir(name, dir_fd=parent)
            else:
                if node['kind'] == 'file':
                    if key not in pinned:
                        pinned[key] = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
                    require(fingerprint(os.fstat(pinned[key])) == expected_stat, 'Pinned layer identity changed')
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        require(fingerprint(os.fstat(child)) == expected_stat and acl(child) == node['acl'], 'Deletion file changed')
                        digest = hashlib.sha256()
                        while True:
                            block = os.read(child, 1024 * 1024)
                            if not block: break
                            digest.update(block)
                        require(digest.hexdigest() == node['sha256'] and fingerprint(os.fstat(child)) == expected_stat,
                                'Deletion file hash CAS changed')
                    finally: os.close(child)
                if whiteout is not None:
                    whiteout.guard(); named_whiteout(parent, name, whiteout.actor, expected_stat)
                os.unlink(name, dir_fd=parent)
                if whiteout is not None:
                    # No force/retry or device FD. Prove exact claimed name gone,
                    # original layer/control/config still unchanged after unlink.
                    try: os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError: pass
                    else: raise Refusal('Claimed original whiteout remains/reappeared')
                    whiteout.guard()
                if key in pinned:
                    after = fingerprint(os.fstat(pinned[key]))
                    require(after[:5] == expected_stat[:5] and after[5] == expected_stat[5] - 1
                            and after[6:8] == expected_stat[6:8], 'Layer changed beyond own unlink')
                    if after[5] == 0:
                        os.close(pinned.pop(key))
                    else:
                        hardlinks[key] = after
            os.fsync(parent)
            if after_root is not None: after_root(node)
        retained_names = [Path(node['path']).name for node in entries if node['retain']]
        if relative == Path('.') and expected_names is not None and MARKER in expected_names:
            retained_names.append(MARKER)
        require(sorted(os.listdir(parent)) == sorted(retained_names),
                'Scope repopulated during deletion')
    try: visit(fd, Path('.'))
    finally:
        for child in pinned.values(): os.close(child)


def remove_dropin_parent(item, policies, attempt, verify):
    """Exact legacy template/file + source-created 0755 parent, real held FDs.

    Only webservices.target.d, never *.d, wants/requires/upholds or defaults.
    Keep the same directory FD across child deletion, parent claim and rmdir.
    A substituted/nonempty inode is preserved under the durable claim contract.
    """
    path = Path(item['path'])
    require(path.name == 'webservices.target.d', 'Unselected drop-in parent')
    verify()
    try:
        with directory(path.parent, policies) as parent:
            try: fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                require(item['stat'] is None, 'Legacy drop-in parent disappeared'); return False
            try:
                require(item['stat'] is not None, 'Absent legacy drop-in parent appeared')
                require(fingerprint(os.fstat(fd)) == item['stat'] and custody(fd) == item['custody']
                        and os.fstat(fd).st_nlink == 2, 'Legacy drop-in parent held-FD CAS changed')
                expected = [] if item['childStat'] is None else ['10-runtime-env.conf']
                require(sorted(os.listdir(fd)) == expected, 'Unknown legacy drop-in parent file; preserved')
                if item['childStat'] is not None:
                    body, pin = read_at(fd, '10-runtime-env.conf', owner=item['uid'], gid=item['uid'], proof=item.get('childProof'))
                    require(pin == item['childStat'] and sha(body) == item['templateSha256'], 'Legacy drop-in child source CAS changed')
                    verify()
                    claimed = '.clean-reset-' + attempt + '-dropin-file'
                    current = claim(fd, '10-runtime-env.conf', claimed, pin)
                    require(fingerprint(os.stat(claimed, dir_fd=fd, follow_symlinks=False)) == current, 'Claimed drop-in child changed')
                    os.unlink(claimed, dir_fd=fd); os.fsync(fd)
                verify()
                require(custody(fd) == item['custody'] and os.fstat(fd).st_nlink == 2 and not os.listdir(fd),
                        'Legacy drop-in parent repopulated or changed; preserved')
                pin = fingerprint(os.fstat(fd)); claimed = '.clean-reset-' + attempt + '-dropin-parent'
                current = claim(parent, path.name, claimed, pin)
                require(fingerprint(os.fstat(fd)) == current and custody(fd) == item['custody'] and not os.listdir(fd)
                        and fingerprint(os.stat(claimed, dir_fd=parent, follow_symlinks=False)) == current,
                        'Claimed legacy drop-in parent differs from held FD')
                os.rmdir(claimed, dir_fd=parent); os.fsync(parent)
                require(stable(os.fstat(fd)) == item['custody']['identity'] and os.fstat(fd).st_nlink == 0,
                        'Legacy drop-in parent removal did not close its held inode')
                return True
            finally: os.close(fd)
    except FileNotFoundError:
        require(item['stat'] is None, 'Legacy drop-in ancestry/source disappeared'); return False


def execute(root, expectedIntentSha, expectedPlanSha, lease, data_only=False):
    root = absolute(root)
    require(type(lease) is StoppedLease, 'Typed canonical stopped lease required; no JSON admission')
    lease.validate(root, expectedIntentSha, expectedPlanSha)
    with locked(root) as (root_fd, lock_pin):
        plan, selection = plan_locked(root, expectedIntentSha, root_fd, lock_pin, data_only)
        require(sha(canonical(plan)) == expectedPlanSha, 'Reviewed complete-clean plan CAS changed')
        lease.validate(root, expectedIntentSha, expectedPlanSha)
        lease._used = True
        reserve = os.statvfs(root)
        require(reserve.f_bavail * reserve.f_frsize >= 2 * len(canonical(plan)) + 4 * 1024 * 1024
                and reserve.f_favail >= 16, 'Root operation evidence reserve insufficient')
        try: os.mkdir('.host-clean-reset', 0o700, dir_fd=root_fd)
        except FileExistsError: pass
        os.fsync(root_fd)
        with directory(root / '.host-clean-reset') as evidence:
            root_directory(evidence, True)
            attempt = expectedPlanSha + '-' + uuid.uuid4().hex
            result = {'schemaVersion': 1, 'kind': plan['kind'], 'intentSha256': expectedIntentSha,
                      'planSha256': expectedPlanSha, 'phase': 'intent', 'completeCleanReset': False,
                      'rootImageCold': False, 'selectedNetworkClosure': False, 'rootfulStoreColdAcceptance': False,
                      'deletedExternalFiles': [], 'deletedExternalDirectories': [], 'emptied': [], 'backupCreated': False,
                      'automaticRestart': False, 'applicationAcceptance': False, 'countedAcceptance': '0/2',
                      'retainedInfrastructure': plan['retainedInfrastructure'],
                      'privateRootsLeftAbsent': plan['privateRootsLeftAbsent'],
                      'retainedAccountsAndSubids': plan['retainedAccountsAndSubids'],
                      'retainedMetadata': plan['retainedMetadata'], 'retainedOutsideScope': plan['retainedOutsideScope']}
            result['claimPrefix'] = '.clean-reset-' + attempt + '-'
            write_evidence(evidence, attempt + '-intent.json', dict(result, plan=plan))
            try:
                # A durable, complete operation intent precedes ANY deletion.
                # Do not re-use a previous result as a stopped-state lease.
                removed_roots = set()
                def verify():
                    require(time.monotonic() < lease._until, 'Stopped lease deadline expired during deletion')
                    current = binding(root, expectedIntentSha)
                    expected_pin = dict(plan['authority'],
                        absentPrivateRoots=sorted(set(plan['authority']['absentPrivateRoots']) | removed_roots),
                        custody={path: pin for path, pin in plan['authority']['custody'].items() if path not in removed_roots})
                    require(current['pin'] == expected_pin, 'Root authority CAS changed beyond own private-root removal')
                    require(native_env_specs(selection) == plan['external']['nativeRuntimeEnvSources'], 'Canonical runtime-env source/role/ownership CAS changed')
                    legacy = legacy_source_authority(selection)
                    require(legacy == plan['external']['legacySourceAuthority']
                            and updater_source_pins(selection, legacy) == plan['external']['updaterSourcePins'],
                            'Legacy source generation/updater source CAS changed')
                    current['unitAuthorities'] = selection['unitAuthorities']
                    stopped(current)
                    unmounted([SCOPE, *[Path(tree['path']) for tree in plan['external']['trees'] if tree['pin'] is not None]],
                              selection['externalPolicies'])
                verify()
                root_progress = [1]
                def root_checkpoint(proof):
                    result.update(proof)
                    write_evidence(evidence, attempt + '-progress-' + str(root_progress[0]) + '.json', result)
                    root_progress[0] += 1
                if data_only:
                    verify()
                    require(rootful_inventory(selection, plan['rootfulNetworkSources'], plan['rootfulDefault']['networks'])
                            == plan['rootfulDefault'], 'Read-only default store CAS changed')
                    root_proof = {'rootfulAfter': plan['rootfulDefault'], 'rootfulStoreColdAcceptance': False,
                                  'defaultStorePreserved': True}
                else:
                    root_proof = rootful_cleanup(selection, plan['rootfulNetworkSources'], plan['rootfulDefault'], verify, root_checkpoint)
                result.update(root_proof)
                # Re-scan the WHOLE scope before its first deletion, not just
                # named DB roots. Includes images, layers, cache and Huly volumes.
                with directory(SCOPE, selection['policies']) as fd:
                    require(scan(fd, selection, retain={Path(path) for path in plan['retainedInfrastructure']}) == plan['nodes'],
                            'Whole-scope content CAS changed')
                    verify()
                    erase(fd, plan['nodes'], [MARKER, *[Path(node['path']).name for node in plan['nodes']
                                                        if Path(node['path']).parent == Path('.')]], claim_prefix=attempt,
                          before_root=lambda node: verify() if SCOPE / node['path'] in selection['roots'] else None,
                          after_root=lambda node: removed_roots.add(str(SCOPE / node['path']))
                              if SCOPE / node['path'] in selection['roots'] else None, selection=selection)
                result['emptied'].append(str(SCOPE))
                write_evidence(evidence, attempt + '-progress-' + str(root_progress[0]) + '.json', result)
                policies = {Path(path): pin for path, pin in plan['external']['custody'].items()}
                for tree in plan['external']['trees']:
                    if tree['pin'] is None: continue
                    verify()
                    path = Path(tree['path'])
                    with directory(path, policies) as fd:
                        require(custody(fd) == tree['pin'], 'External runtime root CAS changed')
                        actor = next((actor for actor in selection['actors'].values()
                                      if path.is_relative_to('/run/user/' + str(actor['uid']))), None)
                        require(scan(fd, dict(selection, externalActor=actor), path) == tree['nodes'], 'External runtime content CAS changed')
                        erase(fd, tree['nodes'], claim_prefix=attempt)
                    result['emptied'].append(str(path))
                checked_parents = set()
                for item in plan['external']['files']:
                    if item['source'] in ('recognized-installer:runtime-env-dropin', 'recognized-current:runtime-env-dropin'): continue
                    path = Path(item['path'])
                    if item['stat'] is not None and path.parent not in checked_parents:
                        verify(); checked_parents.add(path.parent)
                    try:
                        with directory(path.parent, policies) as fd:
                            if item['stat'] is None:
                                try: os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                                except FileNotFoundError: continue
                                raise Refusal('Absent selected source appeared')
                            body, pin = read_at(fd, path.name, owner=item['uid'], gid=item.get('gid'), proof=item.get('ownership'))
                            require(pin == item['stat'] and sha(body) == item['sha256'], 'Installed source removal CAS changed')
                            claimed = '.clean-reset-' + attempt + '-installed'
                            claimed_stat = claim(fd, path.name, claimed, pin)
                            require(fingerprint(os.stat(claimed, dir_fd=fd, follow_symlinks=False)) == claimed_stat,
                                    'Installed claimed source changed')
                            os.unlink(claimed, dir_fd=fd); os.fsync(fd)
                    except FileNotFoundError:
                        require(item['stat'] is None, 'Installed selected source disappeared')
                    if item['stat'] is not None: result['deletedExternalFiles'].append(str(path))
                for parent in plan['external']['dropinParents']:
                    if remove_dropin_parent(parent, policies, attempt, verify):
                        result['deletedExternalDirectories'].append(parent['path'])
                        if parent['childStat'] is not None:
                            result['deletedExternalFiles'].append(str(Path(parent['path']) / '10-runtime-env.conf'))
                verify()
                with directory(SCOPE, selection['policies']) as fd:
                    left = scan(fd, selection, retain={Path(path) for path in plan['retainedInfrastructure']})
                    require(all(node['kind'] == 'directory' and node['retain'] for node in left), 'Owned scope cache/state remains')
                for tree in plan['external']['trees']:
                    if tree['pin'] is not None:
                        with directory(Path(tree['path']), policies) as fd:
                            require(custody(fd) == tree['pin'] and not os.listdir(fd), 'External runtime repopulated')
                for item in plan['external']['files']:
                    path = Path(item['path'])
                    try:
                        with directory(path.parent, policies) as fd:
                            try: os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                            except FileNotFoundError: continue
                            raise Refusal('Selected installed source remains/reappeared')
                    except FileNotFoundError: pass
                verify()
                for parent in plan['external']['dropinParents']:
                    path = Path(parent['path'])
                    try:
                        with directory(path.parent, policies) as fd:
                            try: os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                            except FileNotFoundError: continue
                            raise Refusal('Legacy drop-in parent remains/reappeared')
                    except FileNotFoundError: pass
                final_rootful = rootful_inventory(selection, plan['rootfulNetworkSources'], result['rootfulAfter']['networks'])
                result['rootImageCold'] = root_images_cold(final_rootful)
                result['selectedNetworkClosure'] = all(row['inspect'] is None and row['kernel'] is None and row['absenceAttested']
                                                       for row in final_rootful['networks'].values())
                require(rootful_network_sources(selection) == plan['rootfulNetworkSources']
                        and final_rootful == result['rootfulAfter'], 'Final rootful source/store/kernel closure changed')
                if data_only:
                    result.update(phase='complete-owned-synthetic-data-only', completeCleanReset=False,
                        cleanScope='declared-synthetic-actor-data-and-scoped-runtime-only-default-store-preserved',
                        rootfulStoreColdAcceptance=False,
                        requiredJournalTransition='journal-owner-exact-CAS-data-only-no-restart')
                else:
                    result.update(phase='complete-owned-synthetic-clean', completeCleanReset=True,
                                  cleanScope='declared-synthetic-roots-plus-default-rootful-images-and-selected-networks',
                                  requiredJournalTransition='journal-owner-exact-CAS-retired-clean-no-restart')
            except BaseException:
                result['rootfulStoreColdAcceptance'] = False
                result['phase'] = 'failed-partial-fresh-CAS-review-required'
                write_evidence(evidence, attempt + '-result.json', result)
                raise
            write_evidence(evidence, attempt + '-result.json', result)
            return result
