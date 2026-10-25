#!/usr/bin/python3 -I
"""Stage reviewed core/bundle bytes for p0-runtime; never import/execute them as Root."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import stat

ROOT = Path('/var/lib/p0-v2-supply')
LIMIT = 8 * 1024 * 1024


class Refused(RuntimeError):
    pass


def read_regular(path, checksum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > LIMIT or observed.st_nlink != 1:
            raise Refused('unsupported source object')
        content = b''
        while len(content) <= LIMIT:
            part = os.read(fd, min(65536, LIMIT + 1 - len(content)))
            if not part:
                break
            content += part
        if len(content) > LIMIT or hashlib.sha256(content).hexdigest() != checksum:
            raise Refused('source byte identity mismatch')
        return content
    finally:
        os.close(fd)


def directory(path, gid):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o750)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, 0o750)
        finally:
            os.close(fd)
    observed = path.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode) != 0o750 or path.resolve() != path):
        raise Refused('supply directory custody mismatch')


def publish(path, content, gid):
    if path.exists() or path.is_symlink():
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != gid
                or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) != 0o440
                or path.read_bytes() != content):
            raise Refused('existing supply bytes or custody mismatch')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o440)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Refused('duplicate lock field')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--core-sha256', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--bundle-sha256', required=True)
    args = parser.parse_args()
    import re
    if os.geteuid() != 0:
        raise Refused('Root required for immutable supply staging')
    if any(not re.fullmatch('[a-f0-9]{64}', value) for value in (args.core_sha256, args.bundle_sha256)):
        raise Refused('invalid expected byte identity')
    entry = pwd.getpwnam('p0-runtime')
    if entry.pw_uid < 1000 or entry.pw_dir != '/var/lib/p0-runtime' or entry.pw_shell != '/usr/sbin/nologin':
        raise Refused('runtime account identity mismatch')
    core = read_regular(args.core, args.core_sha256)
    encoded = read_regular(args.bundle / 'bundle.json', args.bundle_sha256)
    lock = json.loads(encoded, object_pairs_hook=pairs)
    if (lock.get('schemaVersion') != 1 or lock.get('kind') != 'p0-quadlet-bundle'
            or lock.get('installationCertified') is not False or not isinstance(lock.get('files'), dict)):
        raise Refused('unsupported bundle contract')
    payload = {'bundle.json': encoded}
    for name, checksum in lock['files'].items():
        path = PurePosixPath(name)
        if (not isinstance(checksum, str) or not re.fullmatch('[a-f0-9]{64}', checksum)
                or path.is_absolute() or '..' in path.parts or str(path) != name
                or name == 'bundle.json' or len(path.parts) > 4
                or not name.startswith(('quadlet/rootless/', 'readiness/'))):
            raise Refused('unsupported rootless bundle member')
        # Walk each ancestor without following symlinks before any Root read.
        for parent in list(path.parents)[:-1]:
            candidate = args.bundle / parent
            if candidate.is_symlink() or not candidate.is_dir():
                raise Refused('source bundle directory mismatch')
        payload[name] = read_regular(args.bundle / name, checksum)
    if sum(map(len, payload.values())) > LIMIT:
        raise Refused('rootless bundle exceeds staging size limit')
    directory(ROOT, entry.pw_gid)
    core_root = ROOT / args.core_sha256
    directory(core_root, entry.pw_gid)
    publish(core_root / 'core.pyz', core, entry.pw_gid)
    bundle_root = ROOT / args.bundle_sha256
    directory(bundle_root, entry.pw_gid)
    for name, content in sorted(payload.items()):
        path = bundle_root / name
        for parent in reversed(path.relative_to(bundle_root).parents):
            directory(bundle_root / parent, entry.pw_gid)
        publish(path, content, entry.pw_gid)
    print(json.dumps({'schemaVersion': 1, 'scope': 'immutable-rootless-supply-only',
                      'core': str(core_root / 'core.pyz'), 'bundle': str(bundle_root),
                      'installationCertified': False}))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError):
        print(json.dumps({'schemaVersion': 1, 'refused': True,
                          'scope': 'immutable-rootless-supply-only', 'installationCertified': False}))
        raise SystemExit(2)
