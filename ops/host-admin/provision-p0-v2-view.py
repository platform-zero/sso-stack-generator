#!/usr/bin/python3 -I
"""Protected native view: bounded SOURCE08 bootstrap, never secret authority.

Whole backend/manager/pause acceptance is NOT established by primitive14.
"""
import sys
if __name__ == '__main__' and not sys.flags.isolated:
    sys.stdout.write('{"version":1,"refused":true,"reason":"isolated-python-required"}\n')
    raise SystemExit(2)

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import pwd
import grp
from pathlib import Path
import re
import stat
import selectors
import signal
import socket
import struct
import time

PHYSICAL = Path('/mnt/stack/p0-v2')
BASE = Path('/var/lib/p0-v2-view')
STACK = BASE / 'stack'
ANCHOR = STACK / 'p0-v2'
AUTHORITY = BASE / 'authority'
HANDLE = Path('/run/p0-v2-native-view/namespace')
PREVIOUS = Path('/var/lib/p0-v2-namespace/active.json')
MANAGER = 'user@1004.service'
DROPIN = Path('/etc/systemd/system/user@1004.service.d/50-p0-v2-view.conf')
DROPIN_BYTES = (b'# Closed P0 dedicated runtime protected data view; no activation.\n'
                b'[Service]\nBindPaths=/var/lib/p0-v2-view/stack:/mnt/stack\nPrivateMounts=yes\n')
LIMIT = 262144
HEX = re.compile(r'[a-f0-9]{64}')
OWNER = re.compile(r'[a-f0-9]{32}')
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
STATES = ('claimed', 'anchor-preclaimed', 'anchor-private', 'native-namespace-claimed',
          'native-view-bound', 'manager-pending', 'complete')


class Refused(Exception):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    need(len(raw) <= LIMIT, 'input-limit')
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'duplicate-key')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite-json')))


def seal(record):
    record['integrity'] = sha(encoded({k: v for k, v in record.items() if k != 'integrity'}))
    return record


def checksum(record):
    need(isinstance(record, dict) and record.get('integrity') == sha(encoded(
        {k: v for k, v in record.items() if k != 'integrity'})), 'record-integrity')


def data_identity(value):
    need(isinstance(value, dict) and set(value) == {'device', 'inode', 'filesystemId'}
         and all(type(v) is int and v > 0 for v in value.values()), 'data-identity')
    return value


def node(value, *, uid=0, gid=0, mode=0o711):
    need(isinstance(value, dict) and set(value) == {'device', 'inode', 'filesystemId', 'uid', 'gid', 'mode'}
         and all(type(v) is int and v >= 0 for v in value.values())
         and value['inode'] > 0 and value['filesystemId'] > 0
         and value['uid'] == uid and value['gid'] == gid and value['mode'] == mode, 'view-node-custody')
    return value


def ns_identity(value):
    need(isinstance(value, dict) and set(value) == {'device', 'inode'}
         and all(type(v) is int and v > 0 for v in value.values()), 'namespace-identity')
    return value


def previous_claim(raw, expected_sha, expected_data):
    """Bootstrap prior Root ownership ONLY, never v2 native pathname authority."""
    need(isinstance(expected_sha, str) and HEX.fullmatch(expected_sha) and sha(raw) == expected_sha, 'previous-sha256')
    record = parse(raw)
    checksum(record)
    need(set(record) == {'version', 'state', 'owner', 'evidenceSha256', 'namespace', 'bootId',
                        'mountNamespace', 'mount', 'cloneMountId', 'integrity'}, 'previous-schema')
    need(type(record['version']) is int and record['version'] == 2 and record['state'] == 'pinned'
         and isinstance(record['owner'], str) and OWNER.fullmatch(record['owner'])
         and isinstance(record['evidenceSha256'], str) and HEX.fullmatch(record['evidenceSha256'])
         and isinstance(record['bootId'], str) and UUID.fullmatch(record['bootId'])
         and data_identity(record['namespace']) == data_identity(expected_data), 'previous-binding')
    ns_identity(record['mountNamespace'])
    mount = record['mount']
    need(isinstance(mount, dict) and set(mount) == {'id', 'parent', 'device', 'root', 'target', 'options', 'optional', 'fsType', 'source'}
         and type(record['cloneMountId']) is int and 0 < record['cloneMountId'] < 2**64
         and type(mount['id']) is int and mount['id'] == record['cloneMountId']
         and type(mount['parent']) is int and 0 < mount['parent'] != mount['id']
         and mount['target'] == str(PHYSICAL) and isinstance(mount['options'], list) and 'rw' in mount['options']
         and isinstance(mount['optional'], list) and not any(
             not isinstance(v, str) or v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable'
             for v in mount['optional']), 'previous-not-complete-private')
    # No comparison to a Host mount ID can turn the mutable dentry into custody.
    return record


def private_mount(value, target, device, parent_id=None):
    need(isinstance(value, dict) and set(value) == {'id', 'parent', 'target', 'device', 'optional'}
         and type(value['id']) is int and value['id'] > 0 and type(value['parent']) is int and value['parent'] > 0
         and value['target'] == str(target) and value['device'] == device
         and isinstance(value['optional'], list) and not any(
             not isinstance(v, str) or v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable'
             for v in value['optional']) and (parent_id is None or value['parent'] == parent_id), 'view-mount-geometry')
    return value['id']


def device(value):
    return f"{os.major(value['device'])}:{os.minor(value['device'])}"


def projection(observation, expected_parent, expected_data):
    need(isinstance(observation, dict) and set(observation) == {'parent', 'data', 'mountNamespace', 'parentMount', 'dataMount'}, 'view-observation-schema')
    need(node(observation['parent']) == node(expected_parent)
         and node(observation['data']) == node(expected_data), 'view-identity-changed')
    ns_identity(observation['mountNamespace'])
    parent_id = private_mount(observation['parentMount'], '/mnt/stack', device(expected_parent))
    private_mount(observation['dataMount'], PHYSICAL, device(expected_data), parent_id)
    # Deliberately DO NOT bind mountinfo.root/source pathname of DATA: an old-NS
    # physical rename can change those strings while protected target/inode stay.
    return observation


def mapping(rows, host):
    need(isinstance(rows, list) and 1 <= len(rows) <= 64, 'idmap-schema')
    for row in rows:
        need(isinstance(row, list) and len(row) == 3 and all(type(v) is int and v >= 0 for v in row)
             and row[2] > 0 and row[0] + row[2] <= 2**32 and row[1] + row[2] <= 2**32, 'idmap-schema')
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            need(all(a[k] + a[2] <= b[k] or b[k] + b[2] <= a[k] for k in (0, 1)), 'idmap-overlap')
    need(not any(b == 0 for a, b, size in rows), 'rootless-host-root-mapped')
    need(any(a == 0 and b == host for a, b, size in rows), 'runtime-idmap')
    return rows


def unshare_witness(parent, data, engine, uid_map, gid_map):
    node(parent)
    node(data)
    node(engine, uid=1004, gid=1004, mode=0o700)
    mapping(uid_map, 1004)
    mapping(gid_map, 1004)
    return {'version': 1, 'parent': parent, 'data': data, 'engine': engine, 'uidMap': uid_map, 'gidMap': gid_map}


# Fixed METADATA-ONLY unprivileged program, no secret bytes, store calls or exec.
# It must run inside actual Podman unshare; a client-only check is insufficient.
UNSHARE_PROGRAM = r'''
import json, os, stat, sys

def probe(w):
    def need(ok):
        if not ok:
            raise ValueError('view-guard')
    def read(path):
        with open(path, 'rb') as f:
            raw = f.read(4097)
        need(len(raw) <= 4096)
        return raw.decode('ascii')
    def maps(path):
        rows = [[int(v) for v in line.split()] for line in read(path).splitlines()]
        need(1 <= len(rows) <= 64 and all(len(r) == 3 and all(v >= 0 for v in r) and r[2] > 0 for r in rows))
        return rows
    uidmap, gidmap = maps('/proc/self/uid_map'), maps('/proc/self/gid_map')
    need(type(w['version']) is int and w['version'] == 1 and uidmap == w['uidMap'] and gidmap == w['gidMap'])
    need(os.geteuid() == os.getegid() == 0)
    need(any(a == 0 and b == 1004 for a, b, c in uidmap) and any(a == 0 and b == 1004 for a, b, c in gidmap))
    need(not any(b == 0 for a, b, c in uidmap + gidmap))
    overflowuid = int(read('/proc/sys/kernel/overflowuid').strip())
    overflowgid = int(read('/proc/sys/kernel/overflowgid').strip())
    def translated(host, rows, overflow):
        found = [a + host - b for a, b, count in rows if b <= host < b + count]
        need(len(found) <= 1)
        return found[0] if found else overflow
    for key, path in (('parent', '/mnt/stack'), ('data', '/mnt/stack/p0-v2'),
                      ('engine', '/mnt/stack/p0-v2/rootless/engine')):
        expected = w[key]
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY)
        try:
            s = os.fstat(fd)
            need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == expected['mode'])
            need((s.st_dev, s.st_ino, os.fstatvfs(fd).f_fsid) == (expected['device'], expected['inode'], expected['filesystemId']))
            need(s.st_uid == translated(expected['uid'], uidmap, overflowuid)
                 and s.st_gid == translated(expected['gid'], gidmap, overflowgid))
        finally:
            os.close(fd)
    return {'version': 1, 'scope': 'p0-native-view-probe', 'guarded': True}

if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('limit')
        print(json.dumps(probe(json.loads(raw))))
    except BaseException:
        print('{"version":1,"scope":"p0-native-view-probe","refused":true}')
        raise SystemExit(2)
'''


def manager_stopped(observation):
    need(isinstance(observation, dict) and set(observation) == {'unit', 'uid', 'gid', 'active', 'pid', 'cgroup',
            'job', 'fragment', 'dropins', 'sourceHashes', 'transientKind'}, 'manager-schema')
    need(observation['unit'] == MANAGER and observation['uid'] == observation['gid'] == 1004
         and observation['active'] in ('inactive', 'failed') and type(observation['pid']) is int and observation['pid'] == 0
         and observation['cgroup'] == observation['job'] == '' and observation['dropins'] == []
         and observation['fragment'] == '/usr/lib/systemd/system/user@.service'
         and observation['transientKind'] == 'service' and isinstance(observation['sourceHashes'], dict)
         and set(observation['sourceHashes']) == {'template'} and HEX.fullmatch(observation['sourceHashes']['template']), 'manager-not-closed')
    return observation


def pause_identity(observation, *, executable_profile_qualified=False):
    # No guesses about Podman/catatonit executable or missing PID-file absence.
    need(executable_profile_qualified, 'pause-executable-profile-unqualified')
    need(isinstance(observation, dict) and set(observation) == {'pid', 'startTime', 'uid', 'gid', 'userNamespace',
        'mountNamespace', 'cgroup', 'pidFileIdentity', 'pidfdIdentity', 'executableSha256', 'emptyContainerReceipt',
        'stoppedUnitReceipt', 'bootId'}, 'pause-schema')
    need(type(observation['pid']) is int and observation['pid'] > 1
         and type(observation['startTime']) is int and observation['startTime'] > 0
         and observation['uid'] == observation['gid'] == 1004 and isinstance(observation['cgroup'], str)
         and observation['cgroup'] != '' and observation['cgroup'].startswith('/user.slice/user-1004.slice/')
         and isinstance(observation['bootId'], str) and UUID.fullmatch(observation['bootId'])
         and all(isinstance(observation[k], str) and HEX.fullmatch(observation[k]) for k in (
             'executableSha256', 'emptyContainerReceipt', 'stoppedUnitReceipt')), 'pause-binding')
    ns_identity(observation['userNamespace'])
    ns_identity(observation['mountNamespace'])
    for key in ('pidFileIdentity', 'pidfdIdentity'):
        ns_identity(observation[key])
    return observation


def validate_record(record):
    checksum(record)
    need(set(record) == {'version', 'state', 'owner', 'previousSha256', 'evidenceSha256', 'bootId', 'data',
                        'anchor', 'native', 'manager', 'pause', 'integrity'}, 'v3-schema')
    need(type(record['version']) is int and record['version'] == 3 and record['state'] in STATES
         and isinstance(record['owner'], str) and OWNER.fullmatch(record['owner'])
         and all(isinstance(record[k], str) and HEX.fullmatch(record[k]) for k in ('previousSha256', 'evidenceSha256'))
         and isinstance(record['bootId'], str) and UUID.fullmatch(record['bootId']), 'v3-binding')
    data_identity(record['data'])
    return record


def complete(record, observation):
    validate_record(record)
    need(record['state'] == 'complete', 'v3-incomplete')
    anchor, native, manager, pause = record['anchor'], record['native'], record['manager'], record['pause']
    need(isinstance(anchor, dict) and set(anchor) == {'parent', 'data', 'mountId'}
         and type(anchor['mountId']) is int and anchor['mountId'] > 0, 'anchor-binding')
    node(anchor['parent'])
    node(anchor['data'])
    need({k: anchor['data'][k] for k in record['data']} == record['data'], 'anchor-data-changed')
    need(isinstance(native, dict) and set(native) == {'handle', 'projection'}
         and isinstance(native['handle'], dict) and set(native['handle']) == {'device', 'inode', 'mountId', 'type', 'fsType'}
         and native['handle']['type'] == 'mnt' and native['handle']['fsType'] == 'nsfs' and all(type(native['handle'][k]) is int and native['handle'][k] > 0
             for k in ('device', 'inode', 'mountId')), 'native-handle-binding')
    projection(native['projection'], anchor['parent'], anchor['data'])
    need({k: native['handle'][k] for k in ('device', 'inode')} == native['projection']['mountNamespace'], 'handle-namespace-changed')
    need(isinstance(manager, dict) and set(manager) == {'unit', 'dropinSha256', 'projection'}
         and manager['unit'] == MANAGER and manager['dropinSha256'] == sha(DROPIN_BYTES), 'manager-view-binding')
    projection(manager['projection'], anchor['parent'], anchor['data'])
    need(isinstance(pause, dict) and set(pause) == {'oldPauseClosed', 'actualUnshareWitness', 'actualUnshareResult'}
         and pause['oldPauseClosed'] is True and pause['actualUnshareResult'] == {'version': 1, 'scope': 'p0-native-view-probe', 'guarded': True}, 'pause-view-unproved')
    witness = pause['actualUnshareWitness']
    need(isinstance(witness, dict) and set(witness) == {'version', 'parent', 'data', 'engine', 'uidMap', 'gidMap'}
         and witness == unshare_witness(anchor['parent'], anchor['data'], witness['engine'], witness['uidMap'], witness['gidMap']), 'unshare-witness-changed')
    need(isinstance(observation, dict) and set(observation) == {'bootId', 'anchor', 'native', 'manager', 'pause'}
         and observation['bootId'] == record['bootId'] and all(observation[k] == record[k] for k in ('anchor', 'native', 'manager', 'pause')), 'v3-live-authority-changed')
    return record


def root_prefix(record, observation):
    # No production consumer may turn fixture-shaped observations into authority.
    raise Refused('native-view-consumer-integration-required')


def proposed_root_prefix(record, observation):
    """Pure proposed argv contract, NOT an executable permit/certificate."""
    complete(record, observation)
    # Namespace FD is independently NSFS/type/mount/boot checked by trusted observer.
    # Caller receives no arbitrary Root exec API; only fixed canonical store prefix.
    return ['/usr/bin/nsenter', '--mount=' + str(HANDLE), '--', '/usr/bin/podman',
            '--root', '/mnt/stack/p0-v2/rootful/engine', '--runroot', '/run/p0-v2-rootful/engine',
            '--storage-driver', 'overlay', '--network-config-dir', '/var/lib/p0-v2-rootful/networks']


def bounded(path, limit):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'observation-limit')
    return raw


def root_ancestors(path, *, leaf_mode=None):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'fixed-path')
    for part in (Path('/'), *reversed(path.parents[:-1]), path):
        value = part.lstat()
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == 0
             and not value.st_mode & 0o022, 'protected-ancestor-custody')
    if leaf_mode is not None:
        need(stat.S_IMODE(path.lstat().st_mode) == leaf_mode, 'protected-ancestor-mode')


def fd_node(fd):
    value = os.fstat(fd)
    need(stat.S_ISDIR(value.st_mode), 'view-not-directory')
    return {'device': value.st_dev, 'inode': value.st_ino, 'filesystemId': os.fstatvfs(fd).f_fsid,
            'uid': value.st_uid, 'gid': value.st_gid, 'mode': stat.S_IMODE(value.st_mode)}


def host_anchor_observation(record):
    """Bounded READONLY independent root metadata, never Host native Podman.

    This alone does NOT qualify manager/pause/native-projection observations or
    enable root_prefix. No physical mutable-parent pathname is consulted.
    """
    validate_record(record)
    need(record['state'] in ('anchor-private', 'native-namespace-claimed', 'native-view-bound', 'manager-pending', 'complete'), 'v3-anchor-incomplete')
    need(isinstance(record['native'], dict) and isinstance(record['native'].get('handle'), dict), 'v3-native-incomplete')
    root_ancestors(STACK, leaf_mode=0o711)
    root_ancestors(ANCHOR, leaf_mode=0o711)
    root_ancestors(HANDLE.parent, leaf_mode=0o700)
    own_ns, host_ns = os.stat('/proc/self/ns/mnt'), os.stat('/proc/1/ns/mnt')
    need((own_ns.st_dev, own_ns.st_ino) == (host_ns.st_dev, host_ns.st_ino), 'not-host-mount-namespace')
    need(bounded('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip() == record['bootId'], 'view-boot-changed')
    opened = []
    try:
        for path in (STACK, ANCHOR):
            opened.append(os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY))
        parent, data = fd_node(opened[0]), fd_node(opened[1])
        need(parent == record['anchor']['parent'] and data == record['anchor']['data'], 'protected-anchor-changed')
        raw = bounded('/proc/self/mountinfo', 4 * 1024**2)
        rows = []
        for line in raw.decode('ascii').splitlines():
            left, right = line.split(' - ')
            columns, tail = left.split(), right.split()
            need(len(columns) >= 6 and len(tail) == 3, 'mountinfo-schema')
            if columns[4] in (str(ANCHOR), str(HANDLE)):
                rows.append((int(columns[0]), columns[4], columns[6:], tail[0]))
        anchors = [row for row in rows if row[1] == str(ANCHOR)]
        handles = [row for row in rows if row[1] == str(HANDLE)]
        need(len(anchors) == len(handles) == 1 and anchors[0][0] == record['anchor']['mountId']
             and handles[0][3] == 'nsfs' and handles[0][0] == record['native']['handle']['mountId']
             and all(not any(v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable'
                             for v in row[2]) for row in rows), 'anchor-handle-mount-changed')
        descriptor = os.open(HANDLE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened.append(descriptor)
        value = os.fstat(descriptor)
        need(value.st_uid == value.st_gid == 0 and (value.st_dev, value.st_ino) == (
            record['native']['handle']['device'], record['native']['handle']['inode'])
             and fcntl.ioctl(descriptor, 0xb703) == 0x00020000, 'native-nsfs-handle-changed')
        return {'parent': parent, 'data': data, 'handle': dict(record['native']['handle'])}
    finally:
        for fd in opened:
            os.close(fd)


def data_reserves(data_fd, expected_data, *, available_ram):
    """Physical100GiB uses held DATA FD, never protected parent RootFS."""
    current = fd_node(data_fd)
    need({k: current[k] for k in ('device', 'inode', 'filesystemId')} == data_identity(expected_data), 'reserve-data-changed')
    need(type(available_ram) is int and available_ram >= 16 * 1024**3, 'ram-reserve')
    physical = os.fstatvfs(data_fd)
    need(physical.f_bavail * physical.f_frsize >= 100 * 1024**3, 'physical-stack-reserve')
    for path, floor in (('/', 50), ('/var/lib', 1)):
        value = os.statvfs(path)
        need(value.f_bavail * value.f_frsize >= floor * 1024**3, 'root-staging-reserve')


class MountAttr(ctypes.Structure):
    _fields_ = [('set', ctypes.c_uint64), ('clear', ctypes.c_uint64),
                ('propagation', ctypes.c_uint64), ('userns', ctypes.c_uint64)]


def independent_clone(api, source_fd, target_fd, *, mount_id, claim, before_attach, verify):
    """Exact FD protocol; source and target MUST differ. Source08 backend boundary.

    api is private trusted libc syscall, never a caller command or path. Actual
    source/target custody and operation lock must already be held by backend.
    """
    source, target = os.fstat(source_fd), os.fstat(target_fd)
    need(source_fd != target_fd and (source.st_dev, source.st_ino) != (target.st_dev, target.st_ino)
         and stat.S_ISDIR(source.st_mode) and stat.S_ISDIR(target.st_mode)
         and ctypes.sizeof(ctypes.c_void_p) == 8 and ctypes.sizeof(MountAttr) == 32, 'independent-target-required')
    tree = api(428, ctypes.c_int(source_fd), ctypes.c_char_p(b''), ctypes.c_uint(0x1000 | 1 | os.O_CLOEXEC))
    need(tree >= 0, 'anchor-clone-unavailable')
    try:
        clone = mount_id(tree)
        need(type(clone) is int and 0 < clone < 2**64, 'anchor-clone-id')
        claim(clone)  # MUST fsync private preclaim before any attachment.
        attr = MountAttr(0, 0, 1 << 18, 0)
        need(api(442, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_uint(0x1000), ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'anchor-private-unavailable')
        before_attach()
        need(api(429, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_int(target_fd), ctypes.c_char_p(b''), ctypes.c_uint(0x44)) == 0, 'anchor-attach-unavailable')
        verify(clone, False)
        need(api(442, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_uint(0x1000), ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'anchor-private-unavailable')
        verify(clone, True)
    finally:
        os.close(tree)  # Never unmount/delete on failure.


def recursive_projection(api, parent_fd, target_fd, *, mount_id, claim, before_attach, verify):
    """Fixed protected STACK -> native /mnt/stack recursive FD projection.

    Backend must already be inside its NEW private mount namespace, not Host.
    Record BOTH detached parent and child mount IDs before attachment; source
    Stack parent and child are independently Root-owned, never physical aliases.
    Primitive14 qualified the empty ABI; the Source08 whole backend is unqualified.
    """
    source, target = os.fstat(parent_fd), os.fstat(target_fd)
    need((source.st_dev, source.st_ino) != (target.st_dev, target.st_ino), 'projection-independent-target-required')
    tree = api(428, ctypes.c_int(parent_fd), ctypes.c_char_p(b''), ctypes.c_uint(0x1000 | 0x8000 | 1 | os.O_CLOEXEC))
    need(tree >= 0, 'recursive-clone-unavailable')
    child = None
    try:
        child = os.open('p0-v2', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=tree)
        ids = {'parent': mount_id(tree), 'data': mount_id(child)}
        need(all(type(v) is int and 0 < v < 2**64 for v in ids.values()) and ids['parent'] != ids['data'], 'recursive-clone-ids')
        claim(ids)
        attr = MountAttr(0, 0, 1 << 18, 0)
        flags = ctypes.c_uint(0x1000 | 0x8000)
        need(api(442, ctypes.c_int(tree), ctypes.c_char_p(b''), flags, ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'recursive-private-unavailable')
        before_attach()
        need(api(429, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_int(target_fd), ctypes.c_char_p(b''), ctypes.c_uint(0x44)) == 0, 'recursive-attach-unavailable')
        verify(ids, False)
        need(api(442, ctypes.c_int(tree), ctypes.c_char_p(b''), flags, ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'recursive-private-unavailable')
        verify(ids, True)
    finally:
        if child is not None:
            os.close(child)
        os.close(tree)


def file_snapshot(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def owned_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0
             and stat.S_IMODE(value.st_mode) == 0o400 and value.st_nlink == 1 and value.st_size <= LIMIT, 'private-file-custody')
        raw = os.read(fd, LIMIT + 1)
        need(len(raw) == value.st_size and file_snapshot(os.fstat(fd)) == file_snapshot(value), 'private-file-changed')
        return raw, file_snapshot(value)
    finally:
        os.close(fd)


def read_previous(expected_sha):
    root_ancestors(PREVIOUS.parent, leaf_mode=0o700)
    raw, snapshot = owned_file(PREVIOUS)
    need(isinstance(expected_sha, str) and HEX.fullmatch(expected_sha) and sha(raw) == expected_sha, 'previous-sha256')
    return raw, snapshot


class ViewStore:
    """Private source ledger; Source08 CLI uses a separate fresh bootstrap root.

    Parent must preflight BEFORE private bootstrap; private authority container
    setup is not authority to create/repair an independent mount target.
    """
    def __init__(self, base=AUTHORITY):
        self.base, self.fd, self.previous = Path(base), None, None

    def open(self, *, create=False):
        root_ancestors(self.base.parent)
        if not os.path.lexists(self.base):
            need(create, 'view-record-missing')
            parent_fd = os.open(self.base.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                no_default_acl(parent_fd)
                os.mkdir(self.base.name, mode=0o700, dir_fd=parent_fd)
                fresh = os.open(self.base.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    os.fchmod(fresh, 0o700)  # This operation's fresh control inode only.
                    os.fsync(fresh)
                finally:
                    os.close(fresh)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        root_ancestors(self.base, leaf_mode=0o700)
        self.fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = os.fstat(self.fd)
        self.directory = (value.st_dev, value.st_ino)
        self.check()
        self.previous = self.current()

    def check(self):
        root_ancestors(self.base, leaf_mode=0o700)
        value, held = self.base.lstat(), os.fstat(self.fd)
        need((value.st_dev, value.st_ino) == self.directory == (held.st_dev, held.st_ino), 'view-ledger-directory-changed')
        need(set(os.listdir(self.fd)) <= {'active.json', 'previous-v2.json'}, 'view-ledger-interrupted-publication')

    def current(self):
        self.check()
        try:
            return owned_file(self.base / 'active.json')
        except FileNotFoundError:
            return None

    def load(self):
        if self.previous is None:
            return None
        record = parse(self.previous[0])
        validate_record(record)
        retained = self.base / 'previous-v2.json'
        if record['state'] != 'claimed' or os.path.lexists(retained):
            raw, _ = owned_file(retained)
            need(sha(raw) == record['previousSha256'], 'retained-previous-changed')
        return record

    def save(self, record):
        need(self.current() == self.previous, 'view-ledger-cas')
        validate_record(seal(record))
        raw = encoded(record)
        need(len(raw) <= LIMIT, 'view-ledger-size')
        name = '.publish-active'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o400)  # Fresh O_EXCL private inode only.
            need(os.write(fd, raw) == len(raw), 'view-ledger-short-write')
            os.fsync(fd)
        finally:
            os.close(fd)
        # check() deliberately rejects interrupted .publish on next invocation;
        # during this exact publication compare old active bytes/stat directly.
        root_ancestors(self.base, leaf_mode=0o700)
        current_dir, held_dir = self.base.lstat(), os.fstat(self.fd)
        need((current_dir.st_dev, current_dir.st_ino) == self.directory == (held_dir.st_dev, held_dir.st_ino), 'view-ledger-directory-changed')
        old = None if not os.path.lexists(self.base / 'active.json') else owned_file(self.base / 'active.json')
        need(old == self.previous, 'view-ledger-cas')
        os.replace(name, 'active.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.previous = self.current()

    def retain_previous(self, raw, expected_sha):
        need(self.previous is not None and sha(raw) == expected_sha, 'previous-retention-binding')
        record = self.load()
        need(record['state'] == 'claimed' and record['previousSha256'] == expected_sha, 'previous-retention-claim')
        need(self.current() == self.previous, 'view-ledger-cas')
        fd = os.open('previous-v2.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=self.fd)
        try:
            os.fchmod(fd, 0o400)
            need(os.write(fd, raw) == len(raw), 'previous-retention-short-write')
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        need(owned_file(self.base / 'previous-v2.json')[0] == raw, 'previous-retention-readback')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Transition:
    """Historical07 mechanism model, NOT the Source08 CLI backend.

    Source08 uses Bootstrap; this retained model/ClosedHost keeps old fixture
    ordering coverage, NOT an operational permit or installed proof.
    """
    def __init__(self, store, backend):
        self.store, self.backend = store, backend

    def apply(self, raw, expected_sha, expected_data, mode='transition'):
        previous = previous_claim(raw, expected_sha, expected_data)
        old = self.store.load()
        need(mode in ('transition', 'resume'), 'transition-mode')
        self.backend.preflight(previous)  # Stopped scopes, manager, known pause, reserves; NO Root native store.
        if old is not None:
            validate_record(old)
            need(mode == 'resume' and old['previousSha256'] == expected_sha, 'explicit-transition-resume-required')
            # Partial effects require reviewed reconciliation; never allocate/replay.
            raise Refused('partial-view-transition-review-required')
        need(mode == 'transition', 'view-record-required')
        record = {'version': 3, 'state': 'claimed', 'owner': previous['owner'], 'previousSha256': expected_sha,
                  'evidenceSha256': previous['evidenceSha256'], 'bootId': self.backend.boot(),
                  'data': expected_data, 'anchor': None, 'native': None, 'manager': None, 'pause': None}
        self.store.save(seal(record))
        self.store.retain_previous(raw, expected_sha)  # Exact old bytes; old active.json NEVER written.
        held = self.backend.prepare_independent_target(expected_data)
        need(isinstance(held, dict) and set(held) == {'parent', 'cover', 'data'}, 'held-anchor-schema')
        node(held['parent'])
        node(held['cover'])
        node(held['data'])
        need({k: held['data'][k] for k in expected_data} == expected_data
             and (held['cover']['device'], held['cover']['inode']) != (held['data']['device'], held['data']['inode']), 'held-anchor-data')
        def claim(clone):
            record.update(state='anchor-preclaimed', anchor={'preclaimedId': clone, **held})
            self.store.save(seal(record))
        self.backend.clone_anchor(held, claim)
        need(record['state'] == 'anchor-preclaimed', 'anchor-preclaim-required')
        clone = record['anchor']['preclaimedId']
        observed = self.backend.observe_anchor(held)
        need(observed['mountId'] == clone and observed['parent'] == held['parent']
             and observed['data'] == held['data'], 'anchor-preclaim-changed')
        record.update(state='anchor-private', anchor=observed)
        self.store.save(seal(record))
        need({k: record['anchor']['data'][k] for k in expected_data} == expected_data, 'anchor-data-changed')
        record['state'] = 'native-namespace-claimed'
        self.store.save(seal(record))
        record['native'] = self.backend.create_native_namespace(record)
        projection(record['native']['projection'], record['anchor']['parent'], record['anchor']['data'])
        record['state'] = 'native-view-bound'
        self.store.save(seal(record))
        record['state'] = 'manager-pending'
        self.store.save(seal(record))
        # NO implicit manager activation, old pause kill, or complete publication.
        return {'version': 1, 'scope': 'p0-native-view', 'state': 'manager-pending', 'nativeAuthority': False,
                'installationCertified': False, 'remaining': ['manager-private-view', 'exact-old-pause-closure', 'actual-unshare-guard']}


# SOURCE08: private bootstrap ledger is outside the as-yet-uncreated target tree.
BOOTSTRAP = Path('/var/lib/p0-v2-view-bootstrap')
# Public packaged OS hashes independently observed by Parent15; source profile,
# not caller-supplied approval. PID/cgroup/view observations remain live facts.
QUALIFIED_MANAGER_SOURCES = {
    '/usr/lib/systemd/system/user@.service': '3e64dd11e1f9f5b39e31b689adecebf6f2e79153d271acd4c55172002e468236',
    '/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf': '1c1452839b609b0609cccaba3c648d780372df6f244deb487da6da5ee002a993'}
MANAGER_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID',
    'ControlPID', 'Job', 'ControlGroup', 'FragmentPath', 'DropInPaths', 'User',
    'Group', 'NeedDaemonReload', 'Triggers', 'TriggeredBy')
# Unit-interface keys are common; execution/cgroup keys are NOT universal.
SCOPED_COMMON_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Job',
    'FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'Triggers', 'TriggeredBy')
SCOPED_PROPERTIES = {
    'service': MANAGER_PROPERTIES,
    'socket': SCOPED_COMMON_PROPERTIES + ('ControlPID', 'ControlGroup'),
    'target': SCOPED_COMMON_PROPERTIES,
    'timer': SCOPED_COMMON_PROPERTIES,
    'path': SCOPED_COMMON_PROPERTIES}
SCOPED_UNIT_PATTERN = r'p0-v2-[a-z0-9][a-z0-9-]{0,62}\.(service|socket|timer|path|target)'


def scoped_unit_type(name):
    match = re.fullmatch(SCOPED_UNIT_PATTERN, name)
    need(match is not None, 'scoped-unit-type-not-closed')
    return match.group(1)


def unit_properties(name):
    return MANAGER_PROPERTIES if name == MANAGER else SCOPED_PROPERTIES[scoped_unit_type(name)]


def initial_host_user_namespace():
    for kind in ('uid', 'gid'):
        rows = [line.split() for line in bounded('/proc/self/' + kind + '_map', 4096).splitlines()]
        need(rows == [[b'0', b'0', b'4294967295']], 'host-initial-user-namespace-required')


def same_file(path, expected):
    raw, snapshot = owned_file(path)
    need(snapshot == expected, 'held-source-snapshot-changed')
    return raw


class SelfGuard:
    """Exact private source snapshot, not an executable permit for other code."""
    def __init__(self, digest):
        self.path = Path(__file__).absolute()
        need(self.path.is_relative_to('/var/lib') and HEX.fullmatch(digest or ''), 'private-source-location')
        root_ancestors(self.path.parent, leaf_mode=0o700)
        need(self.path.name == 'provision-p0-v2-view.py', 'private-source-name')
        initial_host_user_namespace()
        self.raw, self.snapshot = owned_file(self.path)
        need(sha(self.raw) == digest, 'helper-sha256')
        need(not os.statvfs(self.path).f_flag & os.ST_NOEXEC, 'source-filesystem-noexec')
        self.digest = digest

    def check(self):
        root_ancestors(self.path.parent, leaf_mode=0o700)
        need(same_file(self.path, self.snapshot) == self.raw, 'helper-source-changed')


def binary_snapshot(path):
    """Read/hash only trusted fixed OS executable/default source, never import."""
    path = Path(path)
    root_ancestors(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 0
             and not value.st_mode & 0o022 and value.st_size <= 64 * 1024**2, 'os-source-custody')
        digest, count = hashlib.sha256(), 0
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            count += len(raw)
            need(count <= 64 * 1024**2, 'os-source-limit')
            digest.update(raw)
        need(count == value.st_size and file_snapshot(value) == file_snapshot(os.fstat(fd)), 'os-source-changed')
        return {'sha256': digest.hexdigest(), 'snapshot': list(file_snapshot(value))}
    finally:
        os.close(fd)


_CHILD_SUPERVISION_READY = False


def check_child_supervision():
    # Single-threaded trusted helper: no asynchronous handler/wait-any reaper.
    # Never repair after fork: an already auto-reaped PID cannot be recovered.
    need(_CHILD_SUPERVISION_READY and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
         and not signal.pthread_sigmask(signal.SIG_BLOCK, set()), 'child-signal-profile-required')


def establish_child_supervision():
    """Own process only; before EVERY fork/Popen, not a Host signal operation.

    CPython/Linux signal.signal installs a fresh sigaction, clearing inherited
    SIG_IGN/SA_NOCLDWAIT. Empty mask is explicit, not inherited launcher state.
    Python's other dispositions (including SIGPIPE) are deliberately unchanged.
    """
    global _CHILD_SUPERVISION_READY
    _CHILD_SUPERVISION_READY = False
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
             and not signal.pthread_sigmask(signal.SIG_BLOCK, set()), 'child-signal-profile-unavailable')
    except (OSError, ValueError):
        raise Refused('child-signal-profile-unavailable') from None
    _CHILD_SUPERVISION_READY = True


def metadata_call(arguments):
    """Only fixed systemctl READ operations; bounded child/pipe, no raw stderr."""
    need(arguments in (['show', MANAGER, '--property=' + ','.join(MANAGER_PROPERTIES)],
                       ['list-units', '--all', '--plain', '--no-legend', 'p0-v2-*'])
         or (len(arguments) == 3 and arguments[0] == 'show'
             and re.fullmatch(SCOPED_UNIT_PATTERN, arguments[1])
             and arguments[2] == '--property=' + ','.join(unit_properties(arguments[1]))), 'metadata-command-not-closed')
    before = binary_snapshot('/usr/bin/systemctl')
    need(before['sha256'] == '848c70d7e2c2f43f4f93287897ac8946e8eda45e7daa5f2975d9728071856b1a',
         'systemctl-os-code-profile-unqualified')
    close_range = metadata_close_range()
    with LocalResources(4) as resources:
        resources.pipe(0, nonblocking=False)
        resources.fds[2] = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        # Child dup2 sources must survive all three stdio replacements, even
        # when our caller initially had stdin/stdout/stderr closed.
        resources.above_stdio(1, 3)
        resources.above_stdio(2, 3)
        reader, writer, null, _ = resources.fds
        os.set_blocking(reader, False)  # Own new read end only; child stdout blocks normally.
        raw, deadline = bytearray(), time.monotonic() + 10
        establish_child_supervision()
        pid = os.fork()
        if pid == 0:
            metadata_exec(arguments, writer, null, close_range)
            os._exit(2)
        resources.child.adopt(pid)
        resources.close_fd(1)
        resources.close_fd(2)
        while True:
            wait_ready(reader, selectors.EVENT_READ, deadline, 'metadata-timeout')
            try:
                chunk = os.read(reader, min(4096, 65537 - len(raw)))
            except (InterruptedError, BlockingIOError):
                continue
            if not chunk:
                break
            raw.extend(chunk)
            need(len(raw) <= 65536, 'metadata-limit')
        resources.child.wait(deadline=deadline)
        need(binary_snapshot('/usr/bin/systemctl') == before, 'metadata-executable-changed')
        return bytes(raw)


def metadata_close_range():
    """Binding only here; fixed child-only FD closure, never a caller syscall API."""
    try:
        close_range = ctypes.CDLL(None, use_errno=True).close_range
        close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
        close_range.restype = ctypes.c_int
        return close_range
    except (AttributeError, OSError):
        raise Refused('metadata-close-range-unavailable') from None


def metadata_exec(arguments, writer, null, close_range):
    # Only metadata_call's child branch calls this. No generic exec interface.
    try:
        need(writer > 2 and null > 2 and writer != null, 'metadata-stdio-source')
        for source, target in ((null, 0), (writer, 1), (null, 2)):
            os.dup2(source, target, inheritable=True)
        for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
            number = getattr(signal, name, None)
            if number is not None:
                signal.signal(number, signal.SIG_DFL)
        need(close_range(3, 0xffffffff, 0) == 0, 'metadata-close-range-unavailable')
        os.execve('/usr/bin/systemctl', ['/usr/bin/systemctl', '--no-pager', *arguments],
                  {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'})
    except BaseException:
        os._exit(2)  # No exec-error channel, stderr/exception or partial success.
    os._exit(2)  # execve must not return.


def properties(raw, unit=MANAGER):
    expected = unit_properties(unit)
    need(len(raw) <= 65536, 'metadata-limit')
    result = {}
    for line in raw.decode('ascii').splitlines():
        key, sep, value = line.partition('=')
        need(sep and key in expected and key not in result and len(value) <= 8192, 'metadata-property')
        result[key] = value
    need(set(result) == set(expected), 'metadata-properties-incomplete')
    return result


def inactive(facts):
    need(facts['LoadState'] == 'loaded' and facts['ActiveState'] in ('inactive', 'failed')
         and facts['MainPID'] == facts['ControlPID'] == '0'
         and facts['Job'] in ('', '0') and facts['ControlGroup'] == ''
         and facts['Triggers'] == facts['TriggeredBy'] == '', 'scoped-unit-not-stopped')


def scoped_inactive(facts, name):
    kind = scoped_unit_type(name)
    need(facts['Id'] == name, 'scoped-unit-identity')
    if kind == 'service':
        inactive(facts)
        return
    need(facts['LoadState'] == 'loaded' and facts['ActiveState'] in ('inactive', 'failed')
         and facts['Job'] in ('', '0') and facts['Triggers'] == facts['TriggeredBy'] == '',
         'scoped-unit-not-stopped')
    if kind == 'socket':
        need(facts['ControlPID'] == '0' and facts['ControlGroup'] == '', 'scoped-unit-not-stopped')
    # No PID/cgroup properties exist on target/timer/path. This is unit metadata,
    # not kernel-task absence or native inventory authority.


class MetadataObserver:
    """Readonly facts; unknown OS defaults are observations, NEVER an approval."""
    def manager(self):
        facts = properties(metadata_call(['show', MANAGER, '--property=' + ','.join(MANAGER_PROPERTIES)]))
        need(facts['Id'] == MANAGER and facts['FragmentPath'] == '/usr/lib/systemd/system/user@.service', 'manager-fragment')
        names = facts['DropInPaths'].split()
        need(len(names) <= 64 and len(set(names)) == len(names), 'manager-dropin-limit')
        sources = {facts['FragmentPath']: binary_snapshot(facts['FragmentPath'])}
        unknown = []
        for name in names:
            path = Path(name)
            # Collect immutable OS defaults without assuming this machine has none.
            # Authored /etc or runtime overrides cannot become a qualified default.
            if (path.parent.parent == Path('/usr/lib/systemd/system') and
                    path.parent.name in ('user@.service.d', 'user-.service.d', 'service.d') and
                    re.fullmatch(r'[A-Za-z0-9_.-]+\.conf', path.name)):
                sources[name] = binary_snapshot(path)
            elif path == DROPIN:
                raw, snapshot = owned_file(path)
                need(raw == DROPIN_BYTES, 'manager-owned-source-bytes')
                sources[name] = {'sha256': sha(raw), 'snapshot': list(snapshot)}
            else:
                unknown.append(name)
        approved = {k: v['sha256'] for k, v in sources.items() if k != str(DROPIN)}
        process = None
        if facts['MainPID'].isdigit() and int(facts['MainPID']) > 1:
            process = ProcessObserver().observe(int(facts['MainPID']), 'manager')
        need(properties(metadata_call(['show', MANAGER, '--property=' + ','.join(MANAGER_PROPERTIES)])) == facts,
             'manager-observation-changed')
        return {'version': 1, 'facts': facts, 'sources': sources, 'process': process,
                'unknownDropins': len(unknown), 'profileQualified': bool(QUALIFIED_MANAGER_SOURCES)
                    and approved == QUALIFIED_MANAGER_SOURCES and not unknown}

    def stopped_scope(self):
        raw = metadata_call(['list-units', '--all', '--plain', '--no-legend', 'p0-v2-*'])
        names = []
        for line in raw.decode('ascii').splitlines():
            fields = line.split()
            need(fields and re.fullmatch(SCOPED_UNIT_PATTERN, fields[0]), 'scoped-unit-inventory')
            names.append(fields[0])
        need(len(names) <= 256 and len(names) == len(set(names)), 'scoped-unit-limit')
        result = {}
        for name in sorted(names):
            facts = properties(metadata_call(['show', name, '--property=' + ','.join(unit_properties(name))]), name)
            scoped_inactive(facts, name)
            result[name] = sha(encoded(facts))
        return result


def runtime_account():
    entry = pwd.getpwnam('p0-runtime')
    group = grp.getgrgid(1004)
    need(entry.pw_uid == entry.pw_gid == 1004 and entry.pw_dir == '/var/lib/p0-runtime'
         and entry.pw_shell == '/usr/sbin/nologin' and group.gr_name == 'p0-runtime' and not group.gr_mem
         and not any('p0-runtime' in item.gr_mem for item in grp.getgrall()), 'dedicated-account-binding')
    return entry


def boot_id():
    value = bounded('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    need(UUID.fullmatch(value), 'boot-id')
    return value


def host_namespace():
    own, host = os.stat('/proc/self/ns/mnt'), os.stat('/proc/1/ns/mnt')
    need((own.st_dev, own.st_ino) == (host.st_dev, host.st_ino), 'not-host-mount-namespace')
    return {'device': own.st_dev, 'inode': own.st_ino}


def available_ram():
    values = [line.split() for line in bounded('/proc/meminfo', 65536).decode('ascii').splitlines()
              if line.startswith('MemAvailable:')]
    need(len(values) == 1 and len(values[0]) == 3 and values[0][2] == 'kB', 'ram-observation')
    return int(values[0][1]) * 1024


def no_default_acl(fd):
    try:
        value = os.getxattr(fd, 'system.posix_acl_default')
    except OSError as error:
        import errno
        need(error.errno in (errno.ENODATA, errno.ENOTSUP), 'default-acl-observation')
    else:
        need(not value, 'inherited-default-acl')


def fd_mount_id(fd):
    values = [line.split(':', 1)[1].strip() for line in
              bounded('/proc/self/fdinfo/' + str(fd), 4096).decode('ascii').splitlines() if line.startswith('mnt_id:')]
    need(len(values) == 1 and values[0].isdigit() and int(values[0]) > 0, 'fd-mount-id')
    return int(values[0])


def mount_row(path, fd=None, fs_type=None):
    found = []
    for line in bounded('/proc/self/mountinfo', 4 * 1024**2).decode('ascii').splitlines():
        left, right = line.split(' - ')
        fields, tail = left.split(), right.split()
        need(len(fields) >= 6 and len(tail) == 3, 'mountinfo-schema')
        if fields[4] == str(path):
            need(fs_type is None or tail[0] == fs_type, 'mount-filesystem-type')
            found.append({'id': int(fields[0]), 'parent': int(fields[1]), 'target': fields[4],
                          'device': fields[2], 'optional': fields[6:]})
    need(len(found) == 1, 'exact-mount-required')
    row = found[0]
    need(not any(v.startswith(('shared:', 'master:', 'propagate_from:')) or v == 'unbindable'
                 for v in row['optional']), 'private-mount-required')
    if fd is not None:
        need(fd_mount_id(fd) == row['id'], 'mount-descriptor-changed')
    return row


def projection_now(expected_parent, expected_data):
    parent, data = fd_node_path('/mnt/stack'), fd_node_path(PHYSICAL)
    ns = os.stat('/proc/self/ns/mnt')
    return projection({'parent': parent, 'data': data,
        'mountNamespace': {'device': ns.st_dev, 'inode': ns.st_ino},
        'parentMount': mount_row('/mnt/stack'), 'dataMount': mount_row(PHYSICAL)}, expected_parent, expected_data)


def wait_ready(fd, event, deadline, reason):
    with selectors.DefaultSelector() as poller:
        poller.register(fd, event)
        while True:
            remaining = deadline - time.monotonic()
            need(remaining > 0, reason)
            try:
                ready = poller.select(min(0.25, remaining))
            except InterruptedError:
                continue
            if ready:
                need(time.monotonic() < deadline, reason)
                return


def send_frame(fd, value):
    deadline = time.monotonic() + 15
    raw = encoded(value) + b'\n'
    need(len(raw) <= 8192, 'worker-frame-limit')
    need(not os.get_blocking(fd), 'worker-nonblocking-required')
    while raw:
        need(time.monotonic() < deadline, 'worker-write-timeout')
        try:
            count = os.write(fd, raw)
        except InterruptedError:
            continue
        except BlockingIOError:
            wait_ready(fd, selectors.EVENT_WRITE, deadline, 'worker-write-timeout')
            continue
        except OSError:
            raise Refused('worker-write-unavailable') from None
        need(count > 0, 'worker-write')
        raw = raw[count:]
    need(time.monotonic() < deadline, 'worker-write-timeout')


def receive_frame(fd):
    raw, deadline = bytearray(), time.monotonic() + 15
    need(not os.get_blocking(fd), 'worker-nonblocking-required')
    while not raw.endswith(b'\n'):
        wait_ready(fd, selectors.EVENT_READ, deadline, 'worker-timeout')
        try:
            chunk = os.read(fd, 8193 - len(raw))
        except (InterruptedError, BlockingIOError):
            continue
        except OSError:
            raise Refused('worker-read-unavailable') from None
        need(chunk, 'worker-closed')
        raw.extend(chunk)
        need(len(raw) <= 8192 and raw.count(b'\n') <= 1, 'worker-frame-limit')
    need(time.monotonic() < deadline, 'worker-timeout')
    return parse(bytes(raw))


class OwnedChild:
    """Preallocated direct-child custody, one status consumer, no PID signals."""
    def __init__(self):
        self.pid = self.fd = self.start = None
        self.reaped = self.closed = self.lost = self.uncertain = False

    def adopt(self, pid):
        need(self.pid is None and not self.closed and type(pid) is int and pid > 1, 'owned-worker-association')
        self.pid = pid  # BEFORE any fallible profile/pidfd/proc observation.
        check_child_supervision()
        self.fd = os.pidfd_open(pid, 0)
        self.start = process_start(bounded('/proc/' + str(pid) + '/stat', 4096))

    def reap(self, deadline):
        while not self.reaped:
            need(not self.lost and time.monotonic() < deadline, 'owned-worker-supervision-uncertain')
            if self.fd is not None:
                wait_ready(self.fd, selectors.EVENT_READ, deadline, 'owned-worker-supervision-uncertain')
            try:
                got, status = os.waitpid(self.pid, os.WNOHANG)
            except InterruptedError:
                continue
            except OSError:
                self.lost = self.uncertain = True  # ECHILD is NOT intended exit.
                raise Refused('owned-worker-supervision-uncertain') from None
            if got == self.pid:
                self.reaped = True  # Before any nonzero-status conversion/refusal.
                return status
            if got != 0:
                self.lost = self.uncertain = True
                raise Refused('owned-worker-supervision-uncertain')
            if self.fd is None:
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def wait(self, *, deadline=None):
        need(self.pid is not None and self.fd is not None and not self.closed and not self.reaped,
             'owned-worker-wait-state')
        deadline = time.monotonic() + 15 if deadline is None else deadline
        wait_ready(self.fd, selectors.EVENT_READ, deadline, 'owned-worker-exit-timeout')
        status = self.reap(deadline)
        need(os.waitstatus_to_exitcode(status) == 0, 'owned-worker-failed')

    def close(self):
        if self.closed:
            return
        self.closed = True  # Never signal/wait/close again, including uncertain failure.
        failure = False
        try:
            if self.pid is not None and not self.reaped:
                deadline = time.monotonic() + 5
                if self.lost:
                    raise Refused('owned-worker-supervision-uncertain')
                if self.fd is not None:
                    try:
                        signal.pidfd_send_signal(self.fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Still need an exact consumed wait status.
                    except OSError:
                        failure = True  # Still attempt bounded status collection.
                self.reap(deadline)
        except BaseException:
            failure = True
        finally:
            fd, self.fd = self.fd, None  # Detach BEFORE possibly uncertain close.
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    failure = True
        if failure:
            self.uncertain = True
            raise Refused('owned-worker-supervision-uncertain') from None
        # No-pidfd timeout may leave a live child after helper exit. Never claim
        # clean stop/absence/managed-after-exit or replay the retained intent.


class LocalResources:
    """Preallocated local FD slots and child; no public Root resource API."""
    def __init__(self, slots):
        self.child = OwnedChild()
        self.fds = [None] * slots

    def __enter__(self):
        return self

    def pipe(self, slot, *, nonblocking=True):
        need(self.fds[slot] is None and self.fds[slot + 1] is None, 'local-fd-slot-owned')
        self.fds[slot], self.fds[slot + 1] = os.pipe2(os.O_CLOEXEC | (os.O_NONBLOCK if nonblocking else 0))

    def close_fd(self, slot):
        fd, self.fds[slot] = self.fds[slot], None
        if fd is not None:
            os.close(fd)

    def above_stdio(self, slot, spare):
        if self.fds[slot] <= 2:
            self.fds[spare] = fcntl.fcntl(self.fds[slot], fcntl.F_DUPFD_CLOEXEC, 3)
            old = self.fds[slot]
            self.fds[slot], self.fds[spare] = self.fds[spare], None
            os.close(old)

    def __exit__(self, *exc):
        failure = None
        for slot in reversed(range(len(self.fds))):
            try:
                self.close_fd(slot)
            except BaseException:
                failure = Refused('local-fd-cleanup-unavailable')
        try:
            self.child.close()  # Even after another FD's close failed.
        except BaseException:
            failure = Refused('owned-worker-supervision-uncertain')
        if failure is not None:
            raise failure from None


class KernelBackend:
    """Source implementation of primitive14, NOT whole-backend qualification.

    Only fixed mount/projection/readonly child operations. No exec, Podman,
    migration, cleanup/unmount, ancestor privatization or caller code API.
    """
    def __init__(self):
        need(os.uname().machine == 'x86_64' and ctypes.sizeof(MountAttr) == 32, 'modern-mount-abi')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.libc.syscall.argtypes = [ctypes.c_long]
        self.libc.unshare.argtypes = [ctypes.c_int]
        self.libc.unshare.restype = ctypes.c_int
        self.libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
        self.libc.setns.restype = ctypes.c_int

    def clone_anchor(self, source_fd, target_fd, *, claim, recheck, verify):
        independent_clone(self.libc.syscall, source_fd, target_fd, mount_id=fd_mount_id,
                          claim=claim, before_attach=recheck, verify=verify)

    def attach(self, source, target, path, claim, recheck, *, nsfs=False):
        # Self-clone is permitted ONLY for this operation's new private holder;
        # all data anchors still require independent_clone's different inode.
        tree = self.libc.syscall(428, ctypes.c_int(source), ctypes.c_char_p(b''), ctypes.c_uint(0x1001 | os.O_CLOEXEC))
        need(tree >= 0, 'modern-clone-unavailable')
        try:
            mid = fd_mount_id(tree)
            claim(mid)
            attr = MountAttr(0, 0, 1 << 18, 0)
            def private():
                need(self.libc.syscall(442, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_uint(0x1000),
                     ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'modern-private-unavailable')
            private()
            recheck()
            need(self.libc.syscall(429, ctypes.c_int(tree), ctypes.c_char_p(b''), ctypes.c_int(target),
                 ctypes.c_char_p(b''), ctypes.c_uint(0x44)) == 0, 'modern-attach-unavailable')
            private()
            reopened = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                a, b = os.fstat(source), os.fstat(reopened)
                need((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and fd_mount_id(reopened) == mid, 'modern-attached-identity')
                mount_row(path, reopened, 'nsfs' if nsfs else None)
            finally:
                os.close(reopened)
            return mid
        finally:
            os.close(tree)

    def persist_namespace(self, parent_fd, record, *, claim, recheck):
        anchor = record['anchor']['result']
        facts = {'phase': 'holder-directory-claimed'}
        need(not os.path.lexists(HANDLE.parent), 'namespace-holder-exists')
        root_ancestors(HANDLE.parent.parent)
        with LocalResources(3) as resources:
            resources.fds[0] = os.open(HANDLE.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            run = resources.fds[0]
            no_default_acl(run)
            claim(dict(facts))  # Before fresh directory; uncertain mkdir never replayed.
            recheck()
            os.mkdir(HANDLE.parent.name, 0o700, dir_fd=run)
            resources.fds[1] = os.open(HANDLE.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run)
            holder = resources.fds[1]
            os.fchmod(holder, 0o700)
            no_default_acl(holder)
            identity = fd_node(holder)
            node(identity, mode=0o700)
            os.fsync(holder); os.fsync(run)
            facts.update(phase='holder-prepared', holder={'identity': identity})
            claim(dict(facts))
            def holder_claim(mid):
                facts.update(phase='holder-mount-preclaimed', holder={'identity': identity, 'mountId': mid})
                claim(dict(facts))
            # A lost detached effect cannot silently retry even before its ID
            # was read. Request claim precedes open_tree; ID precedes attachment.
            facts.update(phase='holder-clone-requested')
            claim(dict(facts))
            # Primitive14 correction: PRIVATE fresh holder mount BEFORE forking.
            self.attach(holder, holder, HANDLE.parent, holder_claim, recheck)
            resources.close_fd(1)
            resources.fds[1] = os.open(HANDLE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            holder = resources.fds[1]
            need(fd_node(holder) == identity and fd_mount_id(holder) == facts['holder']['mountId'], 'holder-mount-changed')
            mount_row(HANDLE.parent, holder)
            facts.update(phase='holder-private')
            claim(dict(facts))
            facts.update(phase='handle-file-claimed')
            claim(dict(facts))
            resources.fds[2] = os.open(HANDLE.name, os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=holder)
            cover = resources.fds[2]
            os.fchmod(cover, 0o400)
            os.fsync(cover); os.fsync(holder)
            facts.update(phase='handle-file-prepared', coverSnapshot=list(file_snapshot(os.fstat(cover))))
            claim(dict(facts))
            recheck()
            result = self.create_projection(parent_fd, cover, record, facts, claim, recheck)
            return result

    def create_projection(self, parent_fd, cover, record, facts, claim, recheck):
        anchor = record['anchor']['result']
        with LocalResources(4) as resources:
            resources.pipe(0)
            resources.pipe(2)
            from_parent, to_child, from_child, to_parent = resources.fds
            creator = resources.child
            facts.update(phase='creator-claimed')
            claim(dict(facts))  # Durable effect claim before fork/unshare.
            establish_child_supervision()
            pid = os.fork()
            if pid == 0:
                try:
                    resources.close_fd(1); resources.close_fd(2)
                    need(self.libc.unshare(0x20000) == 0, 'worker-unshare-unavailable')
                    now = os.stat('/proc/self/ns/mnt')
                    need({'device': now.st_dev, 'inode': now.st_ino} != record['anchor']['bootstrap']['hostNamespace'], 'worker-still-host-namespace')
                    root = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        attr = MountAttr(0, 0, 1 << 18, 0)
                        # Only this NEW child namespace, never Host propagation.
                        need(self.libc.syscall(442, ctypes.c_int(root), ctypes.c_char_p(b''), ctypes.c_uint(0x9000),
                             ctypes.byref(attr), ctypes.c_size_t(32)) == 0, 'worker-private-root-unavailable')
                    finally:
                        os.close(root)
                    # Reopen in the NEW namespace: inherited Host mount FDs
                    # witness identity but are not its local clone source mount.
                    local_parent = os.open(STACK, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                    target = os.open('/mnt/stack', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        need(fd_node(local_parent) == fd_node(parent_fd) == anchor['parent'], 'worker-protected-parent-changed')
                        send_frame(to_parent, {'kind': 'projection-request'})
                        need(receive_frame(from_parent) == {'ack': 'projection-request'}, 'worker-request-ack')
                        def preclaim(ids):
                            send_frame(to_parent, {'kind': 'projection-claim', 'ids': ids})
                            need(receive_frame(from_parent) == {'ack': 'projection-claim'}, 'worker-claim-ack')
                        recursive_projection(self.libc.syscall, local_parent, target, mount_id=fd_mount_id,
                            claim=preclaim, before_attach=lambda: None,
                            verify=lambda ids, private: projection_now(anchor['parent'], anchor['data']) if private else None)
                    finally:
                        os.close(target)
                        os.close(local_parent)
                    send_frame(to_parent, {'kind': 'projection-bound', 'projection': projection_now(anchor['parent'], anchor['data'])})
                    need(receive_frame(from_parent) == {'exit': True}, 'worker-exit-ack')
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            creator.adopt(pid)
            resources.close_fd(0)
            resources.close_fd(3)
            message = receive_frame(from_child)
            need(message == {'kind': 'projection-request'}, 'projection-request-frame')
            facts.update(phase='projection-clone-requested', creator={'pid': pid, 'startTime': creator.start, 'exited': False})
            claim(dict(facts))
            send_frame(to_child, {'ack': 'projection-request'})
            message = receive_frame(from_child)
            need(set(message) == {'kind', 'ids'} and message['kind'] == 'projection-claim'
                 and set(message['ids']) == {'parent', 'data'} and all(type(v) is int and v > 0 for v in message['ids'].values())
                 and message['ids']['parent'] != message['ids']['data'], 'projection-claim-frame')
            recheck()
            facts.update(phase='projection-preclaimed', projectionPreclaim=message['ids'],
                         creator={'pid': pid, 'startTime': creator.start, 'exited': False})
            claim(dict(facts))
            send_frame(to_child, {'ack': 'projection-claim'})
            message = receive_frame(from_child)
            need(set(message) == {'kind', 'projection'} and message['kind'] == 'projection-bound', 'projection-bound-frame')
            observed = projection(message['projection'], anchor['parent'], anchor['data'])
            need(observed['parentMount']['id'] == facts['projectionPreclaim']['parent']
                 and observed['dataMount']['id'] == facts['projectionPreclaim']['data'], 'projection-preclaim-changed')
            nsfd = os.open('/proc/' + str(pid) + '/ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
            try:
                ns = os.fstat(nsfd)
                need(fcntl.ioctl(nsfd, 0xb703) == 0x20000 and {'device': ns.st_dev, 'inode': ns.st_ino} == observed['mountNamespace'], 'creator-namespace-changed')
                def handle_claim(mid):
                    facts.update(phase='handle-mount-preclaimed', handlePreclaim=mid, projection=observed)
                    claim(dict(facts))
                facts.update(phase='handle-clone-requested', projection=observed)
                claim(dict(facts))
                mid = self.attach(nsfd, cover, HANDLE, handle_claim, recheck, nsfs=True)
                facts['handle'] = {'device': ns.st_dev, 'inode': ns.st_ino, 'mountId': mid, 'type': 'mnt', 'fsType': 'nsfs'}
            finally:
                os.close(nsfd)  # Original namespace FD gone BEFORE creator exit.
            send_frame(to_child, {'exit': True})
            creator.wait()
            facts['creator']['exited'] = True
            facts.update(phase='creator-exited')
            claim(dict(facts))
            # Reopen persistent handle and independently setns in readonly child.
            temporary = dict(record, native=facts)
            self.verify_bound(temporary)
            facts.update(phase='bound')
            claim(dict(facts))
            return facts

    def verify_bound(self, record):
        need(record['bootId'] == boot_id(), 'native-view-boot-changed')
        native, anchor = record['native'], record['anchor']['result']
        need(observe_anchor_mount(anchor['mountId'], record['data']) == anchor, 'native-anchor-changed')
        need(native['phase'] in ('creator-exited', 'bound') and native['creator']['exited'] is True, 'native-creator-not-closed')
        root_ancestors(HANDLE.parent, leaf_mode=0o700)
        holder = os.open(HANDLE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        nsfd = None
        try:
            need(fd_node(holder) == native['holder']['identity']
                 and mount_row(HANDLE.parent, holder)['id'] == native['holder']['mountId'], 'native-holder-changed')
            nsfd = os.open(HANDLE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            value = os.fstat(nsfd)
            need(value.st_uid == value.st_gid == 0 and fcntl.ioctl(nsfd, 0xb703) == 0x20000
                 and {'device': value.st_dev, 'inode': value.st_ino} == native['projection']['mountNamespace']
                 and (value.st_dev, value.st_ino) == (native['handle']['device'], native['handle']['inode'])
                 and mount_row(HANDLE, nsfd, 'nsfs')['id'] == native['handle']['mountId'], 'native-handle-changed')
            self.readonly_consumer(nsfd, native['projection'], anchor)
            need(fd_mount_id(nsfd) == native['handle']['mountId'], 'native-held-handle-changed')
        finally:
            os.close(holder)
            if nsfd is not None:
                os.close(nsfd)

    def readonly_consumer(self, nsfd, expected, anchor):
        with LocalResources(2) as resources:
            resources.pipe(0)
            reader, writer = resources.fds
            child = resources.child
            establish_child_supervision()
            pid = os.fork()
            if pid == 0:
                try:
                    resources.close_fd(0)
                    need(self.libc.setns(nsfd, 0x20000) == 0, 'consumer-setns-unavailable')
                    os.chdir('/')
                    observed = projection_now(anchor['parent'], anchor['data'])
                    need(observed == expected, 'consumer-projection-changed')
                    send_frame(writer, {'observed': True})
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            child.adopt(pid)
            resources.close_fd(1)
            need(receive_frame(reader) == {'observed': True}, 'consumer-observation-failed')
            child.wait()


class BootstrapHost:
    """Real readonly bootstrap and fresh-only effects, not native store authority."""
    targets = ((BASE, 0o700), (STACK, 0o711), (ANCHOR, 0o711))

    def __init__(self, guard, previous_sha):
        self.guard, self.previous_sha = guard, previous_sha
        self.raw, self.previous_snapshot = read_previous(previous_sha)
        prior = parse(self.raw)
        self.prior = previous_claim(self.raw, previous_sha, prior.get('namespace'))
        self.boot, self.namespace = boot_id(), host_namespace()
        need(self.prior['bootId'] == self.boot, 'previous-boot-pathless-bootstrap-required')
        self.data_fd = None

    def check(self):
        self.guard.check()
        need(read_previous(self.previous_sha) == (self.raw, self.previous_snapshot), 'previous-snapshot-changed')
        need(boot_id() == self.boot and host_namespace() == self.namespace, 'bootstrap-epoch-changed')

    def hold_data(self, anchored=False):
        path = ANCHOR if anchored else PHYSICAL
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            actual = fd_node(fd)
            node(actual)
            need({k: actual[k] for k in self.prior['namespace']} == self.prior['namespace'], 'bootstrap-data-changed')
            data_reserves(fd, self.prior['namespace'], available_ram=available_ram())
            if self.data_fd is not None:
                need(fd_node(self.data_fd) == actual, 'bootstrap-held-data-changed')
            else:
                self.data_fd, fd = fd, None
            return actual
        finally:
            if fd is not None:
                os.close(fd)

    def preflight(self, *, anchored=False):
        self.check()
        actual = self.hold_data(anchored)
        manager = MetadataObserver().manager()
        facts = manager['facts']
        # Qualification is necessary before publishing manager source or starting
        # it, NOT to collect facts or make a fresh independent protected anchor.
        inactive(facts)
        runtime_account()
        # Empty Group means the verified account's primary GID for this hashed
        # packaged template, not an arbitrary inferred group or caller assertion.
        need(facts['User'] in ('1004', 'p0-runtime') and facts['Group'] in ('', '1004', 'p0-runtime')
             and not manager['unknownDropins'] and str(DROPIN) not in manager['sources'], 'manager-bootstrap-not-stopped')
        scope = MetadataObserver().stopped_scope()
        self.check()
        return {'manager': manager, 'stoppedScope': scope, 'data': actual}

    def plan(self):
        need(not os.path.lexists(BOOTSTRAP), 'existing-bootstrap-explicit-resume-or-boot-review-required')
        facts = self.preflight()
        for path, _ in self.targets:
            need(not os.path.lexists(path), 'bootstrap-target-exists')
            # Existing nearest ancestor is trusted; future parents are fresh.
            parent = path.parent
            while not parent.exists():
                parent = parent.parent
            root_ancestors(parent)
        return {'version': 1, 'scope': 'p0-native-view', 'state': 'planned',
                'nativeAuthority': False, 'installationCertified': False,
                'previousSha256': self.previous_sha, 'bootId': self.boot,
                'targets': [str(p) for p, _ in self.targets],
                'managerProfileQualified': facts['manager']['profileQualified'],
                'next': 'explicit-transition-fresh-targets-then-native12-boundary'}

    def close(self):
        if self.data_fd is not None:
            os.close(self.data_fd)
            self.data_fd = None


class Bootstrap:
    """Bounded real phase backend. Every uncertain effect is retained/refused."""
    def __init__(self, host, store, kernel=None):
        self.host, self.store = host, store
        self.kernel = KernelBackend() if kernel is None else kernel

    def save(self, record):
        self.host.check()
        space = os.fstatvfs(self.store.fd)
        need(space.f_bavail * space.f_frsize >= 1024**3, 'actual-ledger-staging-reserve')
        self.store.save(seal(record))

    def validate_binding(self, record):
        validate_record(record)
        journal = record['anchor']['bootstrap']
        need(record['owner'] == self.host.prior['owner'] and record['previousSha256'] == self.host.previous_sha
             and record['evidenceSha256'] == self.host.prior['evidenceSha256'] and record['bootId'] == self.host.boot
             and record['data'] == self.host.prior['namespace']
             and journal['sourceSha256'] == self.host.guard.digest
             and journal['previousSnapshot'] == list(self.host.previous_snapshot)
             and journal['hostNamespace'] == self.host.namespace
             and journal['ledgerDirectory'] == list(self.store.directory), 'bootstrap-record-binding')
        need(set(journal) == {'sourceSha256', 'previousSnapshot', 'hostNamespace', 'ledgerDirectory', 'effects'}, 'bootstrap-journal-schema')
        effects = journal['effects']
        need(isinstance(effects, list) and len(effects) <= len(self.host.targets), 'bootstrap-effect-limit')
        for effect, (path, mode) in zip(effects, self.host.targets):
            need(set(effect) == {'path', 'mode', 'state', 'identity'} and effect['path'] == str(path)
                 and effect['mode'] == mode and effect['state'] in ('claimed', 'prepared'), 'bootstrap-effect-schema')
            if effect['state'] == 'claimed':
                raise Refused('mkdir-effect-review-required')  # Even absent: no replay.
            root_ancestors(path, leaf_mode=mode)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                expected = effect['identity']
                if path == ANCHOR and record['state'] in ('anchor-private', 'native-namespace-claimed', 'native-view-bound'):
                    expected = record['anchor']['result']['data']
                    observe_anchor_mount(record['anchor']['preclaimedId'], record['data'])
                need(fd_node(fd) == expected, 'bootstrap-created-inode-changed')
                no_default_acl(fd)
            finally:
                os.close(fd)
        return journal

    def stable_objects(self, record):
        self.host.check()
        self.validate_binding(record)

    def mkdir(self, record, path, mode):
        journal = record['anchor']['bootstrap']
        need(not os.path.lexists(path), 'bootstrap-target-exists')
        root_ancestors(path.parent)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            held = fd_node(parent)
            no_default_acl(parent)
            effect = {'path': str(path), 'mode': mode, 'state': 'claimed', 'identity': None}
            journal['effects'].append(effect)
            self.save(record)  # Durable intent BEFORE mkdir, never adopt existing.
            need(fd_node(parent) == held and fd_node_path(path.parent) == held, 'bootstrap-parent-changed')
            self.host.check()
            os.mkdir(path.name, mode=mode, dir_fd=parent)
            child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(child, mode)  # This operation's new inode ONLY; umask independent.
                no_default_acl(child)
                value = fd_node(child)
                node(value, mode=mode)
                need(fd_node_path(path) == value and fd_node_path(path.parent) == held, 'bootstrap-created-inode-changed')
                os.fsync(child)
                os.fsync(parent)
                effect.update(state='prepared', identity=value)
                self.save(record)
            finally:
                os.close(child)
        finally:
            os.close(parent)

    def run(self, mode):
        need(mode in ('transition', 'resume'), 'bootstrap-mode')
        record = self.store.load()
        if record is not None:
            # Neither mutable PHYSICAL nor an unmounted old covering stub is a
            # reboot locator. Refuse BEFORE any data-path preflight/lookup.
            need(record['bootId'] == self.host.boot, 'bootstrap-old-boot-pathless-recovery-required')
            retained, _ = owned_file(self.store.base / 'previous-v2.json')
            need(retained == self.host.raw, 'bootstrap-retention-incomplete')
        anchored = record is not None and record['state'] in ('anchor-private', 'native-namespace-claimed', 'native-view-bound')
        self.host.preflight(anchored=anchored)
        if record is None:
            need(mode == 'transition', 'view-record-required')
            # Validate all absences before claiming ANY target effect.
            for path, _ in self.host.targets:
                need(not os.path.lexists(path), 'bootstrap-target-exists')
            record = {'version': 3, 'state': 'claimed', 'owner': self.host.prior['owner'],
                'previousSha256': self.host.previous_sha, 'evidenceSha256': self.host.prior['evidenceSha256'],
                'bootId': self.host.boot, 'data': self.host.prior['namespace'],
                'anchor': {'bootstrap': {'sourceSha256': self.host.guard.digest,
                    'previousSnapshot': list(self.host.previous_snapshot), 'hostNamespace': self.host.namespace,
                    'ledgerDirectory': list(self.store.directory), 'effects': []}},
                'native': None, 'manager': None, 'pause': None}
            self.save(record)
            self.store.retain_previous(self.host.raw, self.host.previous_sha)
        else:
            need(mode == 'resume', 'explicit-transition-resume-required')
            self.validate_binding(record)
            need(record['state'] in ('claimed', 'anchor-private', 'native-view-bound'), 'detached-or-namespace-effect-review-required')
        journal = self.validate_binding(record)
        if record['state'] == 'claimed':
            for path, mode_bits in self.host.targets[len(journal['effects']):]:
                self.mkdir(record, path, mode_bits)
            target = os.open(ANCHOR, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                record['state'] = 'anchor-preclaimed'
                record['anchor'].update(cloneRequested=True, preclaimedId=None)
                self.save(record)  # Before open_tree, not just before move_mount.
                def claim(mid):
                    need(type(mid) is int and mid > 0, 'anchor-clone-id')
                    record['state'] = 'anchor-preclaimed'
                    record['anchor']['preclaimedId'] = mid
                    self.save(record)
                def verify(mid, private):
                    observed = observe_anchor_mount(mid, self.host.prior['namespace'])
                    if private:
                        record['anchor']['result'] = observed
                self.kernel.clone_anchor(self.host.data_fd, target, claim=claim,
                    recheck=lambda: (self.host.preflight(), self.stable_objects(record)), verify=verify)
            finally:
                os.close(target)
            need(record['state'] == 'anchor-preclaimed' and 'result' in record['anchor'], 'anchor-observation-required')
            record['state'] = 'anchor-private'
            self.save(record)
        if record['state'] == 'anchor-private':
            observe_anchor_mount(record['anchor']['preclaimedId'], self.host.prior['namespace'])
            parent = os.open(STACK, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                def claim_namespace(facts):
                    record['state'] = 'native-namespace-claimed'
                    record['native'] = facts
                    self.save(record)
                native = self.kernel.persist_namespace(parent, record, claim=claim_namespace,
                                                       recheck=lambda: self.stable_objects(record))
            finally:
                os.close(parent)
            need(record['state'] == 'native-namespace-claimed', 'namespace-preclaim-required')
            projection(native['projection'], record['anchor']['result']['parent'], record['anchor']['result']['data'])
            record.update(state='native-view-bound', native=native)
            self.save(record)
        need(record['state'] == 'native-view-bound', 'bootstrap-phase-incomplete')
        return {'version': 1, 'state': record['state'], 'nativeAuthority': False, 'installationCertified': False,
                'next': ['readonly-manager-pause-metadata', 'explicit-fresh-manager-publication', 'qualified-manager-transition']}


def fd_node_path(path):
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        return fd_node(fd)
    finally:
        os.close(fd)


def observe_anchor_mount(expected_id, expected_data):
    root_ancestors(STACK, leaf_mode=0o711)
    root_ancestors(ANCHOR, leaf_mode=0o711)
    parent, data = fd_node_path(STACK), fd_node_path(ANCHOR)
    node(parent)
    node(data)
    need({k: data[k] for k in expected_data} == expected_data, 'anchor-data-changed')
    rows = []
    for line in bounded('/proc/self/mountinfo', 4 * 1024**2).decode('ascii').splitlines():
        left, right = line.split(' - ')
        fields = left.split()
        if fields[4] == str(ANCHOR):
            rows.append({'id': int(fields[0]), 'parent': int(fields[1]), 'device': fields[2],
                         'target': fields[4], 'optional': fields[6:]})
    need(len(rows) == 1 and private_mount(rows[0], ANCHOR, device(data)) == expected_id, 'anchor-mount-changed')
    return {'parent': parent, 'data': data, 'mountId': expected_id}


# Parent15 metadata fixes the current old-pause candidate, never a release permit.
# A changed incarnation/cgroup requires review, not broad prefix signaling.
PAUSE_PROFILE = {
    'pidfile': '/run/user/1004/libpod/tmp/pause.pid', 'executable': '/usr/bin/catatonit',
    'sha256': '84e9bde9a352e11949c9a09abe64b81e83d5dc345a9d99c62eefdfdfc359bb96',
    'cgroup': '/user.slice/user-1004.slice/user@1004.service/user.slice/podman-pause-bd390fb9.scope'}


def process_start(raw):
    # comm may contain spaces and parentheses; fields after final ')' start at3.
    text = raw.decode('ascii')
    end = text.rfind(')')
    need(end > 1 and text[end + 1:end + 2] == ' ', 'process-stat-schema')
    fields = text[end + 2:].split()
    need(len(fields) >= 20 and fields[19].isdigit(), 'process-stat-schema')
    return int(fields[19])


class PauseObserver:
    """Direct bounded proc metadata with retained pidfd. NO signals/absence proof.

    The PIDfile location/executable profile is deliberately not guessed. A failed
    or missing read never returns oldPauseClosed. CLI can report exact missing
    decisions until Parent gathers the actual dedicated-runtime OS contract.
    """
    def collect(self):
        if PAUSE_PROFILE is None:
            return {'version': 1, 'available': False, 'reason': 'pause-os-profile-required',
                    'required': ['exact-pidfile', 'immutable-executable-sha256', 'owned-cgroup-profile'],
                    'oldPauseClosed': False, 'signalAuthority': False}
        return self.observe(PAUSE_PROFILE)

    def observe(self, profile):
        need(isinstance(profile, dict) and set(profile) == {'pidfile', 'executable', 'sha256', 'cgroup'}, 'pause-profile-schema')
        path = Path(profile['pidfile'])
        need(path.is_absolute() and '..' not in path.parts and path.is_relative_to('/run/user/1004')
             and isinstance(profile['sha256'], str) and HEX.fullmatch(profile['sha256'])
             and isinstance(profile['cgroup'], str) and profile['cgroup'].startswith('/user.slice/user-1004.slice/')
             and '..' not in Path(profile['cgroup']).parts, 'pause-profile-binding')
        # Mutable actor-owned PIDfile is merely a candidate, never signal authority.
        descriptors = []
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            descriptors.append(fd)
            value = os.fstat(fd)
            need(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 1004
                 and value.st_nlink == 1 and value.st_size <= 32 and not value.st_mode & 0o022, 'pause-pidfile-custody')
            raw = os.read(fd, 33)
            need(re.fullmatch(rb'[1-9][0-9]{0,9}\n?', raw) and len(raw) == value.st_size, 'pause-pidfile-schema')
            pid = int(raw)
            need(1 < pid < 2**31, 'pause-pid-range')
            process = Path('/proc') / str(pid)
            start = process_start(bounded(process / 'stat', 4096))
            pidfd = os.pidfd_open(pid, 0)
            descriptors.append(pidfd)
            procfd = os.open(process, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(procfd)
            status = {}
            for line in bounded(process / 'status', 16384).decode('ascii').splitlines():
                key, _, val = line.partition(':')
                if key in ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'NoNewPrivs'):
                    need(key not in status, 'pause-status-schema')
                    status[key] = val.split()
            need(status.get('Uid') == status.get('Gid') == ['1004'] * 4
                 and status.get('Groups') == ['1004'], 'pause-process-identity')
            # Parent15 pause is root inside its userNS: CapPrm/Eff are NOT zero.
            # Observe capabilities; do not mistake userNS privileges for Host0,
            # or turn either observation into permission to signal/release.
            need(all(status.get(k) and len(status[k]) == 1 and re.fullmatch(r'[0-9a-f]{16}', status[k][0])
                     for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd')), 'pause-status-capabilities')
            exe = os.readlink(process / 'exe')
            need(exe == profile['executable'] and Path(exe).is_absolute()
                 and Path(exe).is_relative_to('/usr') and '..' not in Path(exe).parts, 'pause-executable-profile')
            expected = binary_snapshot(exe)
            need(expected['sha256'] == profile['sha256'], 'pause-executable-sha256')
            # Open the actual running executable, not only its pathname target.
            actual_exe = os.open(process / 'exe', os.O_RDONLY)
            descriptors.append(actual_exe)
            need(list(file_snapshot(os.fstat(actual_exe))) == expected['snapshot'], 'pause-running-executable-changed')
            cgroup = bounded(process / 'cgroup', 4096).decode('ascii')
            need(cgroup == '0::' + profile['cgroup'] + '\n', 'pause-cgroup-changed')
            maps = {}
            for kind in ('uid', 'gid'):
                rows = [[int(v) for v in line.split()] for line in bounded(process / (kind + '_map'), 8192).decode('ascii').splitlines()]
                maps[kind] = mapping(rows, 1004)
            views = {}
            for key, relative in (('parent', 'mnt/stack'), ('data', 'mnt/stack/p0-v2')):
                viewfd = os.open(process / 'root' / relative, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                descriptors.append(viewfd)
                views[key] = fd_node(viewfd)
            namespaces = {}
            for kind in ('user', 'mnt'):
                ns = os.open(process / 'ns' / kind, os.O_RDONLY | os.O_CLOEXEC)
                descriptors.append(ns)
                ns_stat = os.fstat(ns)
                need(fcntl.ioctl(ns, 0xb703) == {'user': 0x10000000, 'mnt': 0x20000}[kind], 'pause-namespace-type')
                namespaces[kind] = {'device': ns_stat.st_dev, 'inode': ns_stat.st_ino}
            info = bounded('/proc/self/fdinfo/' + str(pidfd), 4096).decode('ascii').splitlines()
            need([v.split(':', 1)[1].strip() for v in info if v.startswith('Pid:')] == [str(pid)], 'pause-pidfd-changed')
            with selectors.DefaultSelector() as poller:
                poller.register(pidfd, selectors.EVENT_READ)
                need(not poller.select(0), 'pause-process-exited')
            for kind, key in (('user', 'user'), ('mnt', 'mnt')):
                current = os.stat(process / 'ns' / kind)
                need({'device': current.st_dev, 'inode': current.st_ino} == namespaces[key], 'pause-namespace-changed')
            after_status = {}
            for line in bounded(process / 'status', 16384).decode('ascii').splitlines():
                key, _, val = line.partition(':')
                if key in status:
                    need(key not in after_status, 'pause-status-schema')
                    after_status[key] = val.split()
            need(after_status == status and bounded(process / 'cgroup', 4096).decode('ascii') == cgroup
                 and binary_snapshot(exe) == expected, 'pause-observation-changed')
            need(process_start(bounded(process / 'stat', 4096)) == start
                 and file_snapshot(os.fstat(fd)) == file_snapshot(value)
                 and file_snapshot(os.stat(path, follow_symlinks=False)) == file_snapshot(value)
                 and os.readlink(process / 'exe') == exe, 'pause-observation-changed')
            return {'version': 1, 'available': True, 'pid': pid, 'startTime': start,
                    'uid': 1004, 'gid': 1004, 'pidfileSnapshot': list(file_snapshot(value)),
                    'executableSha256': expected['sha256'], 'namespaces': namespaces, 'maps': maps, 'view': views,
                    'cgroup': profile['cgroup'], 'bootId': boot_id(), 'oldPauseClosed': False,
                    'capabilities': {k: status[k][0] for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd')},
                    'signalAuthority': False, 'emptyContainerReceipt': None}
        except (OSError, ValueError):
            raise Refused('pause-metadata-unavailable') from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)


class ProcessObserver:
    """Fixed manager metadata only; PID from actual exact unit, no command API."""
    def observe(self, pid, role):
        need(role == 'manager' and type(pid) is int and pid > 1, 'process-observer-scope')
        expected_hash = '799fd89964a716fb5f26c4506047190b6e842ac2745b473bd45351c4d8cbd929'
        base = Path('/proc') / str(pid)
        descriptors = []
        try:
            pidfd = os.pidfd_open(pid, 0)
            descriptors.append(pidfd)
            before = process_start(bounded(base / 'stat', 8192))
            status = {}
            for line in bounded(base / 'status', 65536).decode('ascii').splitlines():
                key, _, val = line.partition(':')
                if key in ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs'):
                    need(key not in status, 'manager-process-status')
                    status[key] = val.split()
            need(status.get('Uid') == status.get('Gid') == ['1004'] * 4
                 and status.get('Groups') == ['1004'], 'manager-process-principal')
            exe = os.readlink(base / 'exe')
            need(exe == '/usr/lib/systemd/systemd', 'manager-process-executable')
            code = binary_snapshot(exe)
            need(code['sha256'] == expected_hash, 'manager-process-code-profile')
            actual = os.open(base / 'exe', os.O_RDONLY)
            descriptors.append(actual)
            need(list(file_snapshot(os.fstat(actual))) == code['snapshot'], 'manager-running-code-changed')
            cgroup = bounded(base / 'cgroup', 4096).decode('ascii')
            need(cgroup == '0::/user.slice/user-1004.slice/user@1004.service/init.scope\n', 'manager-process-cgroup')
            namespaces = {}
            for kind, flag in (('user', 0x10000000), ('mnt', 0x20000)):
                nsfd = os.open(base / 'ns' / kind, os.O_RDONLY | os.O_CLOEXEC)
                descriptors.append(nsfd)
                value = os.fstat(nsfd)
                need(fcntl.ioctl(nsfd, 0xb703) == flag, 'manager-process-namespace')
                namespaces[kind] = {'device': value.st_dev, 'inode': value.st_ino}
            views = {}
            for name, relative in (('parent', 'mnt/stack'), ('data', 'mnt/stack/p0-v2')):
                # Metadata only via exact process root; no env/cmdline/log/data read.
                fd = os.open(base / 'root' / relative, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
                descriptors.append(fd)
                views[name] = fd_node(fd)
            with selectors.DefaultSelector() as poller:
                poller.register(pidfd, selectors.EVENT_READ)
                need(not poller.select(0), 'manager-process-exited')
            for kind, expected in namespaces.items():
                value = os.stat(base / 'ns' / kind)
                need({'device': value.st_dev, 'inode': value.st_ino} == expected, 'manager-namespace-changed')
            after_status = {}
            for line in bounded(base / 'status', 65536).decode('ascii').splitlines():
                key, _, val = line.partition(':')
                if key in status:
                    need(key not in after_status, 'manager-process-status')
                    after_status[key] = val.split()
            need(after_status == status and binary_snapshot(exe) == code, 'manager-process-observation-changed')
            need(before == process_start(bounded(base / 'stat', 8192)) and os.readlink(base / 'exe') == exe
                 and bounded(base / 'cgroup', 4096).decode('ascii') == cgroup, 'manager-process-changed')
            return {'pid': pid, 'startTime': before, 'namespaces': namespaces, 'view': views,
                    'code': code, 'status': status, 'cgroup': cgroup.strip()[3:],
                    'signalAuthority': False, 'viewAuthority': False}
        except (OSError, ValueError):
            raise Refused('manager-process-metadata-unavailable') from None
        finally:
            for fd in reversed(descriptors):
                os.close(fd)


def phase_operations(record):
    """Closed operation vocabulary, not an authorization certificate."""
    validate_record(record)
    return {'claimed': ('prepare-fresh-targets',), 'anchor-preclaimed': (),
            'anchor-private': ('create-private-native-namespace',), 'native-namespace-claimed': (),
            'native-view-bound': ('observe-manager', 'observe-pause', 'publish-manager-source'),
            'manager-pending': ('observe-manager', 'observe-pause', 'explicit-manager-transition'),
            'complete': ()}[record['state']]


def rename_fresh(parent, source, destination):
    # Fixed same-held-directory publication only. No overwrite/legacy fallback.
    need(source == '.p0-view-manager-publish' and destination == DROPIN.name, 'manager-publication-name')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    need(rename(parent, source.encode(), parent, destination.encode(), 1) == 0, 'manager-source-publication-unavailable')
    os.fsync(parent)


class ManagerPublication:
    """Only one literal drop-in; live bounded namespace authority is mandatory.

    New directory/source are claimed before effects. Interruptions never adopt
    matching data. Explicit publication recovery accepts a recorded inode at
    exactly its stage OR final name, not a content-only equivalence.
    """
    def __init__(self, bootstrap):
        self.bootstrap = bootstrap

    def gate(self, record):
        need('publish-manager-source' in phase_operations(record), 'manager-publication-phase')
        self.bootstrap.host.check()
        self.bootstrap.validate_binding(record)
        # Exact concrete Native12 reopen/live projection verifier, not a caller
        # boolean, historic result or default-store Podman observation.
        self.bootstrap.kernel.verify_bound(record)
        observed = MetadataObserver().manager()
        inactive(observed['facts'])
        need(observed['profileQualified'] and not observed['unknownDropins'], 'manager-os-profile-unqualified')
        MetadataObserver().stopped_scope()
        self.bootstrap.stable_objects(record)
        self.bootstrap.kernel.verify_bound(record)
        return observed

    def run(self):
        b = self.bootstrap
        record = b.store.load()
        need(record is not None, 'view-record-required')
        self.gate(record)
        claim = record['manager']
        root_ancestors(DROPIN.parent.parent)
        if claim is None:
            need(not os.path.lexists(DROPIN.parent), 'manager-directory-exists')
            record['manager'] = {'state': 'directory-claimed', 'directory': None, 'source': None}
            b.save(record)
            os.mkdir(DROPIN.parent, mode=0o700)
            fd = os.open(DROPIN.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, 0o700)
                no_default_acl(fd)
                directory = fd_node(fd)
                node(directory, mode=0o700)
                os.fsync(fd)
                parent = os.open(DROPIN.parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
                record['manager'].update(state='directory-prepared', directory=directory)
                b.save(record)
            finally:
                os.close(fd)
            claim = record['manager']
        need(isinstance(claim, dict) and set(claim) == {'state', 'directory', 'source'}, 'manager-publication-claim')
        need(claim['state'] not in ('directory-claimed', 'source-claimed'), 'manager-publication-effect-review-required')
        root_ancestors(DROPIN.parent, leaf_mode=0o700)
        parent = os.open(DROPIN.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            need(fd_node(parent) == claim['directory'] == fd_node_path(DROPIN.parent), 'manager-directory-changed')
            no_default_acl(parent)
            allowed = {'.p0-view-manager-publish', DROPIN.name}
            need(set(os.listdir(parent)) <= allowed, 'manager-directory-unknown-source')
            stage = DROPIN.parent / '.p0-view-manager-publish'
            if claim['state'] == 'directory-prepared':
                need(not os.path.lexists(stage) and not os.path.lexists(DROPIN), 'manager-source-exists')
                claim['state'] = 'source-claimed'
                b.save(record)
                fd = os.open(stage.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
                try:
                    os.fchmod(fd, 0o400)
                    need(os.write(fd, DROPIN_BYTES) == len(DROPIN_BYTES), 'manager-source-short-write')
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
                raw, snapshot = owned_file(stage)
                need(raw == DROPIN_BYTES, 'manager-source-bytes')
                claim.update(state='source-prepared', source=list(snapshot))
                b.save(record)
            if claim['state'] in ('source-prepared', 'publish-claimed'):
                names = [p for p in (stage, DROPIN) if os.path.lexists(p)]
                need(len(names) == 1, 'manager-publication-position')
                raw, snapshot = owned_file(names[0])
                need(raw == DROPIN_BYTES and (list(snapshot) == claim['source'] if names[0] == stage
                     else list(snapshot)[:8] == claim['source'][:8]), 'manager-source-inode-changed')
                if names[0] == stage:
                    self.gate(record)
                    claim['state'] = 'publish-claimed'
                    b.save(record)
                    need(fd_node_path(DROPIN.parent) == claim['directory'], 'manager-directory-changed')
                    rename_fresh(parent, stage.name, DROPIN.name)
                else:
                    need(claim['state'] == 'publish-claimed', 'manager-source-not-owned')
                raw, snapshot = owned_file(DROPIN)
                # rename changes ctime; bind dev/inode/mode/owner/link/size/mtime.
                need(raw == DROPIN_BYTES and list(snapshot)[:8] == claim['source'][:8], 'manager-published-inode-changed')
                claim.update(state='published', source=list(snapshot))
                b.save(record)
            need(claim['state'] == 'published' and owned_file(DROPIN) == (DROPIN_BYTES, tuple(claim['source'])), 'manager-publication-incomplete')
            return {'version': 1, 'state': 'native-view-bound', 'managerSource': 'published',
                    'daemonReloadRequired': True, 'nativeAuthority': False, 'installationCertified': False,
                    'next': 'explicit-manager-transition-after-owned-offline-app-trigger-inventory'}
        finally:
            os.close(parent)


BOOT_TARGET = Path('/etc/systemd/user/p0-v2-native.target')
BOOT_TARGET_BYTES = (b'# P0 dedicated native-view bootstrap; no app activation.\n'
                     b'[Unit]\nDescription=P0 native bootstrap only\nDefaultDependencies=no\n')
PROPOSED_MANAGER_BYTES = (DROPIN_BYTES + b'ExecStart=\n'
    b'ExecStart=/usr/lib/systemd/systemd --user --unit=p0-v2-native.target\n')


def manager_boot_proposal():
    """Pure versioned literal/hash contract, NOT publication or start authority.

    Current ManagerPublication still publishes ONLY DROPIN_BYTES/BindPaths.
    Search/generator/private-control qualification must precede adopting this.
    """
    return {'version': 1, 'scope': 'p0-v2-manager-bootstrap-target-v1',
        'target': str(BOOT_TARGET), 'targetMode': 0o444, 'targetSha256': sha(BOOT_TARGET_BYTES),
        'dropinSha256': sha(PROPOSED_MANAGER_BYTES), 'currentBindOnlySha256': sha(DROPIN_BYTES),
        'managerExecutableSha256': '799fd89964a716fb5f26c4506047190b6e842ac2745b473bd45351c4d8cbd929',
        'podmanPublicCodeSha256': '6e4993e061eb88205003892252e2e13bbf49c12a6f67f519881b9b3c94e980e6',
        'quadletPublicCodeSha256': '5e605b8d917c954e353538858dab6baf77f90ac326e2216b7a261d49551600f2',
        'qualified': False, 'publicationImplemented': False, 'transitionImplemented': False,
        'nativeAuthority': False, 'installationCertified': False,
        'required': ['closed-user-searchpath-and-overrides', 'unqualified-search-roots-and-aliases',
                     'generator-and-environment-source-output-profile',
                     'private-control-socket-and-service-transport', 'stopped-owned-app-trigger-scope',
                     'exact-old-pause-and-protected-native-inventory']}


RUNTIME_HOME = Path('/var/lib/p0-runtime')
STORAGE_BYTES = (b'[storage]\ndriver = "overlay"\nrunroot = "/run/user/1004/containers"\n'
                 b'graphroot = "/mnt/stack/p0-v2/rootless/engine"\n')


def actor_directory(path):
    """Held nofollow walk of fixed actor metadata roots; never imports content."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'actor-source-path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            value = os.fstat(fd)
            need(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, 1004)
                 and value.st_gid in (0, 1004) and not value.st_mode & 0o022, 'actor-source-directory-custody')
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def install_replay(raw):
    """Conservative source observation only; no enablement/absence certificate."""
    section = ''
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'Install':
            key, sep, value = line.partition('=')
            if sep and key.strip() in ('WantedBy', 'RequiredBy', 'Also', 'Alias') and value.strip():
                return True
    return False


class ActorSourceObserver:
    """Fixed dedicated-account source/config metadata, NEVER native inventory.

    No Podman/unshare/ps/info invocation and no engine/data content read. File
    comparisons do not prove running-task absence, stopped DB-object absence or
    safety of cached pause reexec. Mutable Quadlet content observation is CLOSED;
    future immutable public-source custody requires separate Parent review.
    """
    def storage(self):
        runtime_account()
        directory = RUNTIME_HOME / '.config/containers'
        parent = actor_directory(directory)
        fd = None
        try:
            identity = fd_node(parent)
            fd = os.open('storage.conf', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            value = os.fstat(fd)
            need(stat.S_ISREG(value.st_mode) and value.st_uid == value.st_gid == 1004 and value.st_nlink == 1
                 and stat.S_IMODE(value.st_mode) == 0o600 and value.st_size == len(STORAGE_BYTES), 'actor-storage-source-custody')
            raw = os.read(fd, 4097)
            need(raw == STORAGE_BYTES and file_snapshot(os.fstat(fd)) == file_snapshot(value), 'actor-storage-source-changed')
            current = actor_directory(directory)
            try:
                need(fd_node(current) == identity, 'actor-source-parent-changed')
                need(file_snapshot(os.stat('storage.conf', dir_fd=current, follow_symlinks=False)) == file_snapshot(value),
                     'actor-storage-source-changed')
            finally:
                os.close(current)
            return {'version': 1, 'sha256': sha(raw), 'snapshot': list(file_snapshot(value)),
                    'nativeAuthority': False}
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def quadlets(self):
        runtime_account()
        # A familiar filename/UID/expected literal cannot prove mutable CONTENT
        # public BEFORE reading it. No actor entry (even selected PG) is opened,
        # compared, read, hashed, parsed or followed. Future immutable public
        # source custody needs separate review; this is temporary denial, not cut.
        return {'version': 1, 'available': False, 'reason': 'actor-quadlet-content-unqualified',
                'files': [], 'nativeAuthority': False, 'frozenSupplyCompared': False,
                'bootGraphCertified': False, 'absenceCertified': False}

    def collect(self):
        return {'version': 1, 'storage': self.storage(), 'quadlets': self.quadlets(),
                'runningKernelTasksCertifiedAbsent': False, 'stoppedDatabaseObjectsCertifiedAbsent': False,
                'approvedProtectedViewUnshareProbe': False, 'oldPauseReleaseAuthorized': False}


class PrivateControlObserver:
    """Kernel peer metadata ONLY, no D-Bus handshake/methods or reusable FD.

    Observes the existing exact dedicated manager. It does not prove new-target
    startup/transport works or that no bus/socket/default unit was activated.
    """
    def collect(self):
        runtime_account()
        manager = MetadataObserver().manager()
        facts = manager['facts']
        need(facts['ActiveState'] == 'active' and facts['MainPID'].isdigit()
             and int(facts['MainPID']) > 1 and manager['process'] is not None
             and manager['process']['pid'] == int(facts['MainPID']), 'control-manager-not-active')
        path = Path('/run/user/1004/systemd/private')
        parent = actor_directory(path.parent)
        peer = None
        try:
            directory = fd_node(parent)
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISSOCK(before.st_mode) and before.st_uid == before.st_gid == 1004
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1, 'control-socket-custody')
            epoch = boot_id()
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            peer.settimeout(2)
            peer.connect(str(path))
            raw = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            need(len(raw) == struct.calcsize('3i'), 'control-peer-schema')
            pid, uid, gid = struct.unpack('3i', raw)
            need((pid, uid, gid) == (int(facts['MainPID']), 1004, 1004), 'control-peer-identity')
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            current = actor_directory(path.parent)
            try:
                need(fd_node(current) == directory and file_snapshot(before) == file_snapshot(after), 'control-path-changed')
            finally:
                os.close(current)
            need(boot_id() == epoch and MetadataObserver().manager() == manager, 'control-manager-changed')
            return {'version': 1, 'bootId': epoch, 'socketSnapshot': list(file_snapshot(before)),
                    'peerPid': pid, 'peerUid': uid, 'peerGid': gid,
                    'process': manager['process'], 'noMethodsSent': True,
                    'transportQualified': False, 'activationCertifiedAbsent': False,
                    'nativeAuthority': False, 'oldPauseReleaseAuthorized': False}
        except OSError:
            raise Refused('control-metadata-unavailable') from None
        finally:
            if peer is not None:
                peer.close()
            os.close(parent)


class ClosedHost:
    def preflight(self, previous):
        raise Refused('native-manager-pause-gates-unqualified')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('cli-arguments')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'transition', 'resume', 'observe-manager', 'observe-pause', 'observe-actor-sources', 'observe-control-peer', 'publish-manager'))
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--expected-previous-sha256', required=True)
    args = parser.parse_args(argv)
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'root-required')
    establish_child_supervision()
    guard = SelfGuard(args.helper_sha256)
    if args.mode in ('observe-manager', 'observe-pause', 'observe-actor-sources', 'observe-control-peer'):
        result = {'observe-manager': lambda: MetadataObserver().manager(),
                  'observe-pause': lambda: PauseObserver().collect(),
                  'observe-actor-sources': lambda: ActorSourceObserver().collect(),
                  'observe-control-peer': lambda: PrivateControlObserver().collect()}[args.mode]()
        guard.check()
        print(json.dumps({'version': 1, 'scope': 'p0-native-view-metadata', 'observation': result,
                          'nativeAuthority': False, 'installationCertified': False}, sort_keys=True))
        return
    host, store = BootstrapHost(guard, args.expected_previous_sha256), None
    try:
        if args.mode == 'plan':
            result = host.plan()
        else:
            host.check()
            if os.path.lexists(BOOTSTRAP):
                # Never adopt an empty/unknown private directory or crash window.
                need(os.path.lexists(BOOTSTRAP / 'active.json'), 'bootstrap-ledger-setup-review-required')
            else:
                need(args.mode == 'transition', 'bootstrap-ledger-required')
                host.preflight()  # Stopped/resource gates BEFORE private setup.
            store = ViewStore(BOOTSTRAP)
            store.open(create=args.mode == 'transition')
            if args.mode == 'publish-manager':
                result = ManagerPublication(Bootstrap(host, store)).run()
            else:
                result = Bootstrap(host, store).run(args.mode)
        guard.check()
        print(json.dumps(result, sort_keys=True))
    finally:
        host.close()
        if store is not None:
            store.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'version': 1, 'scope': 'p0-native-view', 'refused': True,
                          'reason': str(error) if isinstance(error, Refused) else 'operation-unavailable',
                          'installationCertified': False}))
        raise SystemExit(2)
