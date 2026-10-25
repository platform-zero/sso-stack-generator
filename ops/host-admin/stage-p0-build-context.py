#!/usr/bin/python3 -I
"""Copy exact reviewed nonsecret source context; never execute/import service code as Root."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat

ROOT = Path('/var/lib/p0-v2-build-inputs')
SOURCE = Path('/home/gerald/p0_work_cleaned/private/rewrite/build-contexts')
LIMIT = 8 * 1024 * 1024
TOTAL = 64 * 1024 * 1024


class Refused(RuntimeError):
    pass


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Refused('duplicate context field')
        result[key] = value
    return result


def read_file(path, expected, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_uid != uid or observed.st_nlink != 1 or observed.st_size > LIMIT:
            raise Refused('unsupported source custody')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            content = stream.read(LIMIT + 1)
        if len(content) > LIMIT or hashlib.sha256(content).hexdigest() != expected:
            raise Refused('source byte identity mismatch')
        return content
    finally:
        os.close(fd)


def directory(path, gid, mode):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            if 'system.posix_acl_default' in os.listxattr(fd):
                os.removexattr(fd, 'system.posix_acl_default')
        finally:
            os.close(fd)
    observed = path.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode) != mode or path.resolve() != path):
        raise Refused('build supply directory mismatch')


def publish(path, content, gid, executable):
    mode = 0o555 if executable else 0o444
    if path.exists() or path.is_symlink():
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != gid
                or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) != mode or path.read_bytes() != content):
            raise Refused('existing build supply mismatch')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch('[a-f0-9]{64}', args.expected_sha256):
        raise Refused('Root and exact context identity required')
    uid = int(os.environ.get('SUDO_UID', '-1'))
    account = pwd.getpwnam('p0-runtime')
    if uid < 1000 or account.pw_uid < 1000 or account.pw_dir != '/var/lib/p0-runtime':
        raise Refused('operator/runtime identity mismatch')
    if args.context.resolve() != args.context or args.context.parent != SOURCE:
        raise Refused('unsupported explicit build context location')
    encoded = read_file(args.context / 'context.json', args.expected_sha256, uid)
    lock = json.loads(encoded, object_pairs_hook=pairs)
    if (set(lock) != {'schemaVersion', 'kind', 'id', 'recipe', 'baseImages', 'files'}
            or type(lock['schemaVersion']) is not int or lock['schemaVersion'] != 1
            or lock['kind'] != 'p0-build-context' or lock['recipe'] != 'Containerfile'
            or not isinstance(lock['files'], dict) or not 1 <= len(lock['files']) <= 1000):
        raise Refused('unsupported build context contract')
    payload = {'context.json': (encoded, False)}
    for name, identity in lock['files'].items():
        path = PurePosixPath(name)
        if (not isinstance(identity, dict) or set(identity) != {'sha256', 'executable'}
                or type(identity['executable']) is not bool or not re.fullmatch('[a-f0-9]{64}', identity['sha256'])
                or path.is_absolute() or str(path) != name or len(path.parts) > 12
                or any(part.startswith('.') or part in ('private', 'historical', 'secrets') for part in path.parts)
                or not re.fullmatch('[a-zA-Z0-9_/-][a-zA-Z0-9_./-]*', name) or name == 'context.json'):
            raise Refused('unsafe build context member')
        for parent in path.parents:
            candidate = args.context / parent
            if candidate.is_symlink() or not candidate.is_dir():
                raise Refused('source ancestor mismatch')
        payload[name] = (read_file(args.context / path, identity['sha256'], uid), identity['executable'])
    if sum(len(content) for content, _ in payload.values()) > TOTAL:
        raise Refused('build context too large')
    directory(ROOT, account.pw_gid, 0o750)
    destination = ROOT / args.expected_sha256
    directory(destination, account.pw_gid, 0o550)
    for name, (content, executable) in sorted(payload.items()):
        target = destination / name
        for parent in reversed(target.relative_to(destination).parents):
            directory(destination / parent, account.pw_gid, 0o550)
        publish(target, content, account.pw_gid, executable)
    print(json.dumps({'schemaVersion': 1, 'scope': 'immutable-build-context-only',
                      'context': str(destination), 'sha256': args.expected_sha256, 'installationCertified': False}))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({'schemaVersion': 1, 'refused': True, 'scope': 'immutable-build-context-only'}))
        raise SystemExit(2)
