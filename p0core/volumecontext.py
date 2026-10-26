"""Actual unprivileged Host context witness; never a privileged pin installer."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
import re
import stat

from .volumes import GRAPHROOT, VolumeError, need, open_directory, parse

HOME = Path('/var/lib/p0-runtime')
NAMESPACE = Path('/mnt/stack/p0-v2')


def _read(path, limit):
    with open(path, 'rb') as source:
        raw = source.read(limit + 1)
    need(len(raw) <= limit, 'volume-context-bound')
    return raw


def _directory(path, uid, gid, mode):
    fd = open_directory(path)
    try:
        s = os.fstat(fd)
        need(s.st_uid == uid and s.st_gid == gid and stat.S_IMODE(s.st_mode) == mode,
             'volume-context-directory')
        return {'device': s.st_dev, 'inode': s.st_ino, 'uid': uid, 'gid': gid, 'mode': f'{mode:04o}'}
    finally:
        os.close(fd)


def _mount_identity(raw, mount_id):
    need(isinstance(raw, bytes) and len(raw) <= 4 * 1024**2, 'volume-context-mount-bound')
    result = []
    for line in raw.splitlines():
        fields = line.split()
        need(len(fields) >= 10 and b'-' in fields, 'volume-context-mountinfo')
        separator = fields.index(b'-')
        need(separator >= 6 and len(fields) >= separator + 4, 'volume-context-mountinfo')
        if fields[0] != str(mount_id).encode('ascii'):
            continue
        try:
            fields = [field.decode('ascii') for field in fields]
        except UnicodeError:
            raise VolumeError('volume-context-mountinfo') from None
        decode = lambda value: re.sub(r'\\(040|011|012|134)', lambda match: chr(int(match[1], 8)), value)
        need(decode(fields[4]) == str(NAMESPACE) and separator == 6,
             'volume-context-private-pin')
        need(re.fullmatch(r'\d+:\d+', fields[2]) is not None, 'volume-context-mountinfo')
        result.append({'id': mount_id, 'device': fields[2], 'root': decode(fields[3]),
                       'target': str(NAMESPACE), 'filesystem': fields[separator + 1]})
    need(len(result) == 1, 'volume-context-private-pin')
    return result[0]


def observe(runner):
    """No Root-private record read; trust actual Host Root-owned private kernel pin.

    Initial Host UID maps prevent a rootless nested namespace from faking raw
    Host Root directory custody. Only Root can establish this protected mount;
    the unprivileged component receives no authority to create/repair it.
    """
    from .lifecycle import verify_reserves
    verify_reserves()
    uid, gid = os.getuid(), os.getgid()
    entry = pwd.getpwuid(uid)
    need(uid >= 1000 and os.geteuid() == uid and os.getegid() == gid
         and entry.pw_name == 'p0-runtime' and entry.pw_gid == gid and entry.pw_dir == str(HOME)
         and Path.home() == HOME and all(group == gid for group in os.getgroups()),
         'volume-context-host-actor')
    for kind in ('uid', 'gid'):
        rows = [line.split() for line in _read('/proc/self/' + kind + '_map', 4096).splitlines()]
        need(rows == [[b'0', b'0', b'4294967295']], 'volume-context-initial-host-namespace')
    need(Path.cwd() in (Path('/'), HOME), 'volume-context-parent-cwd')
    directories = {}
    for path, owner, group, mode in ((NAMESPACE, 0, 0, 0o711),
            (HOME, uid, gid, 0o700), (HOME / '.config', uid, gid, 0o700),
            (HOME / '.config/containers', uid, gid, 0o700),
            (GRAPHROOT.parent, uid, gid, 0o700), (GRAPHROOT, uid, gid, 0o700),
            (Path(f'/run/user/{uid}'), uid, gid, 0o700),
            (Path(f'/run/user/{uid}/containers'), uid, gid, 0o700)):
        directories[str(path)] = _directory(path, owner, group, mode)
    fd = open_directory(NAMESPACE)
    try:
        metadata = _read(f'/proc/self/fdinfo/{fd}', 4096).decode('ascii')
        ids = re.findall(r'^mnt_id:\s*(\d+)\s*$', metadata, re.M)
        need(len(ids) == 1, 'volume-context-mount-id')
        mount = _mount_identity(_read('/proc/self/mountinfo', 4 * 1024**2), int(ids[0]))
        s = os.fstat(fd)
        need(directories[str(NAMESPACE)]['device'] == s.st_dev
             and directories[str(NAMESPACE)]['inode'] == s.st_ino
             and mount['device'] == f'{os.major(s.st_dev)}:{os.minor(s.st_dev)}',
             'volume-context-namespace-changed')
        filesystem_id = os.fstatvfs(fd).f_fsid
    finally:
        os.close(fd)
    config = HOME / '.config/containers/storage.conf'
    fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        expected = ('[storage]\ndriver = "overlay"\n' + f'runroot = "/run/user/{uid}/containers"\n'
                    + f'graphroot = "{GRAPHROOT}"\n').encode()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_gid == gid and s.st_nlink == 1
             and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == len(expected), 'volume-context-config')
        need(os.read(fd, 4097) == expected, 'volume-context-config')
        after = os.fstat(fd)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode,
                                  item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        need(signature(s) == signature(after), 'volume-context-config-changed')
        configuration = {'identity': list(signature(s)), 'sha256': hashlib.sha256(expected).hexdigest()}
    finally:
        os.close(fd)
    prefix = ['/usr/bin/podman', '--root', str(GRAPHROOT), '--runroot',
              f'/run/user/{uid}/containers', '--storage-driver', 'overlay']
    info = parse(runner(prefix + ['info', '--format', 'json'], timeout=30))
    need(isinstance(info, dict) and isinstance(info.get('store'), dict)
         and isinstance(info.get('host'), dict) and isinstance(info['host'].get('security'), dict),
         'volume-context-native-info')
    need(info['store'].get('graphRoot') == str(GRAPHROOT)
         and info['store'].get('runRoot') == f'/run/user/{uid}/containers'
         and info['store'].get('graphDriverName') == 'overlay'
         and info['store'].get('configFile') == str(config)
         and info['host']['security'].get('rootless') is True, 'volume-context-native-info')
    # Reopen all directory identities after native info; no mutable mtimes bound.
    for path, previous in directories.items():
        need(_directory(Path(path), previous['uid'], previous['gid'], int(previous['mode'], 8)) == previous,
             'volume-context-directory-changed')
    need(_mount_identity(_read('/proc/self/mountinfo', 4 * 1024**2), mount['id']) == mount,
         'volume-context-pin-changed')
    need(signature(config.lstat()) == signature(s), 'volume-context-config-changed')
    mount_ns = os.stat('/proc/self/ns/mnt')
    boot = _read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    need(re.fullmatch('[a-f0-9-]{36}', boot) is not None, 'volume-context-boot')
    verify_reserves()
    return {'version': 1, 'uid': uid, 'gid': gid, 'graphRoot': str(GRAPHROOT),
            'runRoot': f'/run/user/{uid}/containers', 'driver': 'overlay',
            'home': str(HOME), 'commandCwd': str(HOME), 'boot': boot,
            'mountNamespace': [mount_ns.st_dev, mount_ns.st_ino], 'mount': mount,
            'filesystemId': filesystem_id, 'directories': directories, 'configuration': configuration}
