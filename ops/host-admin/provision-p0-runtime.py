#!/usr/bin/python3 -I
"""Source-owned bootstrap for the sole P0 v2 rootless account.

Run a hash-verified, Root-owned private copy with /usr/bin/python3 -I.
No service source imports, engine pruning, policy changes, or old actor mutation.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess

ACCOUNT = 'p0-runtime'
HOME = Path('/var/lib/p0-runtime')
STACK = Path('/mnt/stack/p0-v2')
STORAGE = STACK / 'rootless'


class Refused(RuntimeError):
    pass


def command(arguments):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=45, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise Refused('account operation failed; inspect exact owned state before retry')


def reserves():
    available = None
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            available = int(line.split()[1]) * 1024
    if available is None or available < 16 * 1024 ** 3:
        raise Refused('available RAM below reserve')
    for path, floor in ((Path('/'), 50), (Path('/mnt/stack'), 100)):
        data = os.statvfs(path)
        if data.f_bavail * data.f_frsize < floor * 1024 ** 3:
            raise Refused('free storage below reserve')


def account():
    try:
        entry = pwd.getpwnam(ACCOUNT)
    except KeyError:
        return None
    if entry.pw_uid < 1000 or entry.pw_dir != str(HOME) or entry.pw_shell != '/usr/sbin/nologin':
        raise Refused('existing account identity mismatch')
    group = grp.getgrgid(entry.pw_gid)
    if group.gr_name != ACCOUNT or group.gr_mem:
        raise Refused('runtime primary group identity mismatch')
    for group in grp.getgrall():
        if ACCOUNT in group.gr_mem:
            raise Refused('runtime account has supplementary group privileges')
    return entry


def private_directory(path, uid, gid, *, create, mode=0o700):
    if not path.exists() and not path.is_symlink():
        if not create:
            return False
        path.mkdir(mode=mode)
        # Parent default ACL/setgid and process umask may change a fresh inode.
        # Normalize only the inode just created, through a no-follow descriptor.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    observed = path.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != uid
            or observed.st_gid != gid or stat.S_IMODE(observed.st_mode) != mode):
        raise Refused('runtime directory identity or mode mismatch')
    if path.resolve(strict=True) != path:
        raise Refused('runtime directory has symlink ancestor')
    return True


def subordinate_ranges(entry):
    for path in (Path('/etc/subuid'), Path('/etc/subgid')):
        ranges = []
        own = []
        for line in path.read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            owner, start, count = line.split(':')
            start, count = int(start), int(count)
            if start < 1 or count < 1:
                raise Refused('invalid subordinate range registry')
            ranges.append((start, start + count, owner))
            if owner in (ACCOUNT, str(entry.pw_uid)):
                own.append((start, start + count))
        if not own or sum(end - start for start, end in own) < 65536:
            raise Refused('runtime account lacks sufficient subordinate IDs')
        for start, end in own:
            for other_start, other_end, owner in ranges:
                if owner not in (ACCOUNT, str(entry.pw_uid)) and start < other_end and other_start < end:
                    raise Refused('runtime subordinate IDs overlap another allocation')


def finish_created_namespace(identity):
    """Explicit recovery of this bootstrap's empty namespace, never shared paths."""
    try:
        device, inode = map(int, identity.split(':'))
    except (ValueError, AttributeError) as error:
        raise Refused('invalid created namespace identity') from error
    fd = os.open(STACK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(fd)
        if ((observed.st_dev, observed.st_ino) != (device, inode)
                or observed.st_uid != 0 or observed.st_gid != 0
                or stat.S_IMODE(observed.st_mode) != 0o2710
                or STACK.resolve(strict=True) != STACK or os.listdir(fd)):
            raise Refused('created namespace recovery identity mismatch')
        os.fchmod(fd, 0o711)
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--finish-created-namespace', metavar='DEVICE:INODE')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise Refused('Root required for account inventory/provisioning')
    reserves()
    entry = account()
    if args.finish_created_namespace:
        if not args.apply or entry is None:
            raise Refused('namespace recovery requires matching runtime account and apply')
        finish_created_namespace(args.finish_created_namespace)
    created = False
    if entry is None and args.apply:
        if HOME.exists() or HOME.is_symlink() or STORAGE.exists() or STORAGE.is_symlink():
            raise Refused('unowned pre-existing runtime paths')
        command(['/usr/sbin/useradd', '--no-create-home', '--user-group', '--home-dir', str(HOME),
                 '--shell', '/usr/sbin/nologin', '--no-log-init', ACCOUNT])
        entry = account()
        created = True
    if entry:
        subordinate_ranges(entry)
        private_directory(HOME, entry.pw_uid, entry.pw_gid, create=args.apply)
        # A new Root-owned namespace allows traversal, not listing or writing.
        private_directory(STACK, 0, 0, create=args.apply, mode=0o711)
        if args.apply:
            private_directory(STORAGE, entry.pw_uid, entry.pw_gid, create=True)
            for directory in (HOME / '.config', HOME / '.config/containers'):
                private_directory(directory, entry.pw_uid, entry.pw_gid, create=True)
            configuration = ('[storage]\ndriver = "overlay"\n'
                             f'runroot = "/run/user/{entry.pw_uid}/containers"\n'
                             f'graphroot = "{STORAGE}/storage"\n').encode()
            destination = HOME / '.config/containers/storage.conf'
            if destination.exists() or destination.is_symlink():
                observed = destination.lstat()
                if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != entry.pw_uid
                        or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) != 0o600
                        or destination.read_bytes() != configuration):
                    raise Refused('runtime storage configuration identity mismatch')
            else:
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    os.fchown(fd, entry.pw_uid, entry.pw_gid)
                    os.fchmod(fd, 0o600)
                    os.write(fd, configuration)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            command(['/usr/bin/loginctl', 'enable-linger', ACCOUNT])
    print(json.dumps({'schemaVersion': 1, 'scope': 'runtime-account-only',
                      'account': ACCOUNT, 'exists': entry is not None, 'created': created,
                      'uid': entry.pw_uid if entry else None,
                      'storageHandoffRequired': False,
                      'installationCertified': False}))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, Refused) else 'owned account operation unavailable'
        print(json.dumps({'schemaVersion': 1, 'refused': True, 'reason': reason,
                          'scope': 'runtime-account-only', 'installationCertified': False}))
        raise SystemExit(2)
