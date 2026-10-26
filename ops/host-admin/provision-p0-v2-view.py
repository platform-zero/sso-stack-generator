#!/usr/bin/python3 -I
"""Critical07 protected-view transition protocol; unqualified Host effects REFUSE."""
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
from pathlib import Path
import re
import stat

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
    """Exact FD protocol; source and target MUST differ. Pure fake ABI tests only.

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
    Exact ABI is unqualified; production ClosedHost cannot reach this primitive.
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
    """Private source ledger only. Production CLI cannot yet reach this store.

    Parent must preflight BEFORE private bootstrap; private authority container
    setup is not authority to create/repair an independent mount target.
    """
    def __init__(self, base=AUTHORITY):
        self.base, self.fd, self.previous = Path(base), None, None

    def open(self, *, create=False):
        root_ancestors(self.base.parent)
        if not os.path.lexists(self.base):
            need(create, 'view-record-missing')
            self.base.mkdir(mode=0o700)  # Fresh private inode only, no normalization.
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
    """Source state machine. Backend observes facts, not intent-supplied permits.

    Production backend is deliberately closed until exact native/manager/pause
    qualification. Fake adapters exercise ordering/CAS, NOT installed proof.
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


class ClosedHost:
    def preflight(self, previous):
        raise Refused('native-manager-pause-gates-unqualified')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('cli-arguments')


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'transition', 'resume'))
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--expected-previous-sha256', required=True)
    args = parser.parse_args(argv)
    need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, 'root-required')
    # No Host mutation path is exposed while stopped/manager/pause ABI is unqualified.
    # Deliberately refuse BEFORE source/old-record access or target/private mkdir.
    raise Refused('native-manager-pause-gates-unqualified')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'version': 1, 'scope': 'p0-native-view', 'refused': True,
                          'reason': str(error) if isinstance(error, Refused) else 'operation-unavailable',
                          'installationCertified': False}))
        raise SystemExit(2)
