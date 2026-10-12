#!/usr/bin/env python3
"""Private metadata journal for the existing, serialized Podman installer.

No service, volume, account, credential or source mutation/replay. A pending
attempt requires exact journal CAS plus an unchanged input fingerprint.
"""
import argparse
import hashlib
import fcntl
import pwd
import subprocess
import json
import os
from pathlib import Path
import stat
import tempfile

PHASES = ('preparing', 'units-selected', 'building', 'starting', 'active', 'failed', 'retired-failed')


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
        if old and old['phase'] not in ('active', 'retired-failed'):
            if expected != digest(path) or old.get('inputs') != inputs:
                raise ValueError('Pending installation needs exact CAS and unchanged inputs')
        elif expected:
            raise ValueError('Stale installation recovery CAS')
        value = {'schemaVersion': 1, 'release': str(release), 'inputs': inputs, 'phase': phase,
                 'steps': [phase], 'resumedFrom': old.get('release') if old and old['phase'] not in ('active', 'retired-failed') else None}
    else:
        if not old or old.get('release') != str(release) or old.get('inputs') != inputs:
            raise ValueError('Installation journal binding mismatch')
        if old['phase'] in ('active', 'failed', 'retired-failed'):
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


def verify_quarantined(release):
    """Read actual selected managers; no service/volume mutation or trigger replay."""
    domains = json.loads((release / 'podman-domains.json').read_text())['domains']
    plans = [('rootful', ['systemctl'])]
    for domain in domains:
        account = pwd.getpwnam(domain['user'])
        if account.pw_uid != domain['uid']:
            raise ValueError('Failed release authority identity drift')
        plans.append(('rootless-' + domain['name'], ['runuser', '-u', domain['user'], '--', 'env',
                      'HOME=' + account.pw_dir, 'XDG_RUNTIME_DIR=/run/user/' + str(account.pw_uid),
                      'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(account.pw_uid) + '/bus', 'systemctl', '--user']))
    os.chdir('/')
    for label, command in plans:
        units = ['webservices.target']
        for path in (release / 'quadlet' / label).iterdir():
            if path.suffix == '.container': units.append(path.stem + '.service')
            elif path.suffix == '.build': units.append(path.stem + '-build.service')
        result = subprocess.run(command + ['show', *units, '-p', 'ActiveState', '--value'],
                                capture_output=True, text=True, timeout=30)
        states = [s for s in result.stdout.splitlines() if s]
        if result.returncode or len(states) != len(units) or any(s not in ('inactive', 'failed') for s in states):
            raise ValueError('Failed selection not stopped; retirement refused')
        result = subprocess.run(command + ['is-enabled', 'webservices.target'],
                                capture_output=True, text=True, timeout=10)
        if result.stdout.strip() not in ('disabled', 'masked'):
            raise ValueError('Failed selection boot trigger not quarantined')
        result = subprocess.run(command + ['list-jobs', '--no-legend', '--no-pager'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or any('webservices' in line for line in result.stdout.splitlines()):
            raise ValueError('Failed selection jobs remain; retirement refused')
    timer = subprocess.run(['systemctl', 'is-enabled', 'webservices-auto-update.timer'],
                           capture_output=True, text=True, timeout=10)
    if timer.stdout.strip() not in ('disabled', 'masked'):
        raise ValueError('Failed selection timer not quarantined')


def retire_failed(root, expected, reviewed, verifier=verify_quarantined):
    directory(root)
    if not reviewed:
        raise ValueError('Explicit data/recovery review required; no automatic compatibility claim')
    path = root / '.install-intent.json'
    value = read(path)
    if not value or value['phase'] != 'failed' or expected != digest(path):
        raise ValueError('Only exact-CAS terminal failure may be retired')
    release = Path(value['release'])
    if release.parent != root / 'releases': raise ValueError('Failed receipt escaped release root')
    directory(release)
    if fingerprint(release) != value['inputs']: raise ValueError('Failed release input binding changed')
    verifier(release)
    retired = dict(value, phase='retired-failed', steps=value['steps'] + ['retired-failed'],
                   dataPreserved=True, dataCompatibilityProved=False, retiredIntentSha256=expected)
    write(release / 'installation-receipt.json', retired)
    write(path, retired)
    return retired


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inspect', action='store_true')
    parser.add_argument('--retire-failed', default='')
    parser.add_argument('--reviewed-data-state', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--expected', default='')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Root-owned installation journal required')
    try:
        if args.retire_failed:
            directory(args.root)
            lock = args.root / '.install.lock'
            fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise ValueError('Unsafe installation lock')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                print(json.dumps(retire_failed(args.root, args.retire_failed, args.reviewed_data_state), sort_keys=True))
            finally: os.close(fd)
        elif args.inspect:
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
