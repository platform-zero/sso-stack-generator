#!/usr/bin/env python3
"""Private metadata journal for the existing, serialized Podman installer.

No service, volume, account, credential or source mutation/replay. A pending
attempt requires exact journal CAS plus an unchanged input fingerprint.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

PHASES = ('preparing', 'units-selected', 'building', 'starting', 'active', 'failed')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe installation journal directory')


def read(path):
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ValueError('Unsafe installation journal')
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or value.get('schemaVersion') != 1 or value.get('phase') not in PHASES:
        raise ValueError('Unknown installation journal')
    return value


def write(path, value):
    directory(path.parent)
    read(path)
    fd, name = tempfile.mkstemp(prefix='.install-journal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True); output.write('\n')
            output.flush(); os.fsync(output.fileno())
        os.chmod(name, 0o600); os.replace(name, path)
        fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def fingerprint(bundle):
    return {name: digest(bundle / name) for name in ('bundle.json', 'stack.ir.json', 'source-provenance.json')}


def update(root, bundle, release, phase, expected=''):
    directory(root)
    if not root.is_absolute() or release.parent != root / 'releases':
        raise ValueError('Installation receipt escaped selected release root')
    release.parent.mkdir(mode=0o755, exist_ok=True)
    directory(release.parent)
    path = root / '.install-intent.json'
    old = read(path)
    inputs = fingerprint(bundle)
    if phase == 'preparing':
        if old and old['phase'] != 'active':
            if expected != digest(path) or old.get('inputs') != inputs:
                raise ValueError('Pending installation needs exact CAS and unchanged inputs')
        elif expected:
            raise ValueError('Stale installation recovery CAS')
        value = {'schemaVersion': 1, 'release': str(release), 'inputs': inputs, 'phase': phase,
                 'steps': [phase], 'resumedFrom': old.get('release') if old and old['phase'] != 'active' else None}
    else:
        if not old or old.get('release') != str(release) or old.get('inputs') != inputs:
            raise ValueError('Installation journal binding mismatch')
        if old['phase'] in ('active', 'failed'):
            raise ValueError('Terminal installation journal cannot advance')
        if phase != 'failed' and PHASES.index(phase) != PHASES.index(old['phase']) + 1:
            raise ValueError('Installation phase ordering mismatch')
        value = dict(old, phase=phase, steps=old['steps'] + [phase])
    release.mkdir(mode=0o755, parents=True, exist_ok=True)
    directory(release)
    # Preserve each immutable release's own compact receipt, not an experiment backup.
    write(release / 'installation-receipt.json', value)
    write(path, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inspect', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--expected', default='')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Root-owned installation journal required')
    try:
        if args.inspect:
            directory(args.root)
            path = args.root / '.install-intent.json'
            value = read(path)
            print(json.dumps({'journal': value, 'sha256': digest(path) if value else None}, sort_keys=True))
        else:
            if args.bundle is None or args.release is None or args.phase is None:
                raise ValueError('Journal inputs required')
            update(args.root, args.bundle, args.release, args.phase, args.expected)
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('Installation journal refused; inspect before retry') from None

if __name__ == '__main__': main()
