#!/usr/bin/env python3
"""Private metadata journal for the existing, serialized Podman installer.

No service, volume, account, credential or source mutation/replay. A pending
attempt requires exact journal CAS plus an unchanged input fingerprint.
"""
import argparse
import hashlib
import importlib.util
import fcntl
import pwd
import subprocess
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import re

PHASES = ('preparing', 'units-selected', 'building', 'starting', 'active', 'failed', 'retired-failed')
CORE_INPUTS = ('bundle.json', 'stack.ir.json', 'source-provenance.json')
PINNED_INPUTS = ('podman-domains.json', 'site/agent-vm.json',
                 'site/agent-vm.provenance.json', 'site/manifest.json',
                 'site/components.lock.json', 'site/global.settings/registry-image-ids.json',
                 'site/global.settings/webservices.sops.json',
                 'site/global.settings/build-base-image-ids.json')


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


def fingerprint(bundle, names=None):
    # Missing optional site inputs are pinned as absent, not silently skipped.
    # Historical three-key receipts remain verifiable for narrowly guarded
    # retirement; only NEW installations may record the expanded pin set.
    names = tuple(names) if names is not None else CORE_INPUTS + PINNED_INPUTS
    if (len(set(names)) != len(names) or not set(CORE_INPUTS).issubset(names)
            or not set(names).issubset(CORE_INPUTS + PINNED_INPUTS)):
        raise ValueError('Unknown installation pin authority')
    result = {}
    for name in names:
        path = bundle / name
        if name in CORE_INPUTS or path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Installation pin must be a regular file')
            result[name] = digest(path)
        else:
            result[name] = None
    return result


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
        previous = None
        if old and old['phase'] not in ('active', 'retired-failed'):
            if expected != digest(path) or old.get('inputs') != inputs:
                raise ValueError('Pending installation needs exact CAS and unchanged inputs')
            # Retain only a previous-release claim made at the original,
            # active-to-preparing transition; do not infer it from a failure.
            previous = old.get('previousRelease')
            if previous is not None and (not isinstance(previous, str)
                    or Path(previous).parent != root / 'releases'):
                raise ValueError('Untrusted previous native release claim')
        elif expected:
            raise ValueError('Stale installation recovery CAS')
        elif old and old['phase'] == 'active':
            old_release = Path(old['release'])
            if (old_release.parent != root / 'releases' or not old_release.is_dir()
                    or (root / 'current').resolve() != old_release):
                raise ValueError('Current active release does not match prior journal')
            directory(old_release)
            prior_receipt = read(old_release / 'installation-receipt.json')
            if (not prior_receipt or prior_receipt['phase'] != 'active'
                    or prior_receipt['release'] != str(old_release)
                    or prior_receipt['inputs'] != old['inputs']
                    or fingerprint(old_release, old['inputs'].keys()) != old['inputs']):
                raise ValueError('Prior selected release input pins changed')
            previous = str(old_release)
        value = {'schemaVersion': 1, 'release': str(release), 'inputs': inputs, 'phase': phase,
                 'previousRelease': previous,'steps': [phase],
                 'resumedFrom': old.get('release') if old and old['phase'] not in ('active', 'retired-failed') else None}
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


def standalone_binding(release):
    source = Path(__file__).with_name('grant-rootless-volume-parent-traverse.py')
    spec = importlib.util.spec_from_file_location('journal_storage_binding', source)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    scope, operator, expected = module.authority(release)
    module.marker(scope, expected)
    module.safe_parent(scope, operator)
    return expected


def selected_quarantine_plans(release):
    """Bind stop/read plans to root-owned files in only the failed release."""
    directory(release)
    manifest = release / 'podman-domains.json'
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unmanaged failed release domain authority')
    metadata = json.loads(manifest.read_text())
    standalone = metadata.get('deploymentMode') == 'standalone'
    if standalone: standalone_binding(release)  # No relaxed free-form user authority.
    domains = metadata['domains']
    if not isinstance(domains, list) or not domains:
        raise ValueError('Missing failed release domains')
    commands = [('rootful', ['systemctl'])]
    seen = set()
    for domain in domains:
        name, user, uid = domain['name'], domain['user'], domain['uid']
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name)
                or (not standalone and user != 'webservices-' + name)
                or not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                or type(uid) is not int or name in seen):
            raise ValueError('Invalid failed release domain authority')
        seen.add(name)
        account = pwd.getpwnam(user)
        if account.pw_uid != uid:
            raise ValueError('Failed release authority identity drift')
        commands.append(('rootless-' + name, ['runuser', '-u', user, '--', 'env',
                         'HOME=' + account.pw_dir, 'XDG_RUNTIME_DIR=/run/user/' + str(uid),
                         'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(uid) + '/bus', 'systemctl', '--user']))
    plans = []
    for label, command in commands:
        quadlet = release / 'quadlet' / label
        directory(quadlet)
        units = ['webservices.target']
        for path in quadlet.iterdir():
            if path.suffix not in ('.container', '.build'):
                continue
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or not re.fullmatch(r'webservices-[a-zA-Z0-9_.@-]+', path.stem)):
                raise ValueError('Unmanaged failed release service authority')
            units.append(path.stem + ('-build.service' if path.suffix == '.build' else '.service'))
        plans.append((label, command, sorted(set(units))))
    return plans


def unconfigured_unit(command, unit):
    result = subprocess.run(command + ['show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                            '-p', 'FragmentPath', '-p', 'UnitFileState'],
                            capture_output=True, text=True, timeout=30)
    props = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    return (result.returncode == 0 and props.get('LoadState') == 'not-found'
            and props.get('ActiveState') == 'inactive' and props.get('FragmentPath') == ''
            and props.get('UnitFileState') in ('', 'not-found'))


def offline_actor(release, label):
    """Never revive a stopped standalone manager merely to inspect its units."""
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
    if (result.returncode or props.get('Id') != manager or props.get('LoadState') != 'loaded'):
        raise ValueError('Unknown selected manager state')
    if props.get('ActiveState') == 'active' and props.get('SubState') == 'running': return None
    if (props.get('ActiveState') not in ('inactive', 'failed') or
            props.get('SubState') not in ('dead', 'failed') or props.get('MainPID') != '0' or props.get('Job') != ''):
        raise ValueError('Selected manager has pending activity')
    return row


def offline_control(command):
    # Unit-file operations only: never start a manager, socket or application.
    return command[:-2] + ['SYSTEMD_OFFLINE=1', *command[-2:], '--no-reload']


def offline_subordinate_start(user):
    spec = importlib.util.spec_from_file_location('stack_offline_subids',
             Path(__file__).with_name('grant-rootless-volume-parent-traverse.py'))
    storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
    return storage.namespace_root_id(user)


def verify_offline_actor(row, command):
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
        try:
            status = (proc / 'status').read_text()
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


def verify_quarantined(release):
    """Read actual selected managers; no service/volume mutation or trigger replay."""
    plans = selected_quarantine_plans(release)
    os.chdir('/')
    for label, command, units in plans:
        actor = offline_actor(release, label)
        if actor is not None:
            verify_offline_actor(actor, command)
            continue
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
    if (timer.stdout.strip() not in ('disabled', 'masked')
            and not unconfigured_unit(['systemctl'], 'webservices-auto-update.timer')):
        raise ValueError('Failed selection timer not quarantined')


def unselected_configuration_roots(domains):
    roots = [Path('/etc/containers/systemd'), Path('/etc/systemd/system')]
    for row in domains:
        home = Path(pwd.getpwnam(row['user']).pw_dir)
        roots.extend((home / '.config/containers/systemd', home / '.config/systemd/user'))
    return roots


def unselected_preparation_binding(root, release):
    """No selected pointers or installed configuration; never adopt a live stage."""
    binding = standalone_binding(release)
    if binding['scope']['dataClass'] != 'synthetic':
        raise ValueError('Unselected retirement requires an explicitly synthetic scope')
    pointers = [root / 'current', root / 'previous']
    config_roots = unselected_configuration_roots(binding['domains'])
    for row in binding['domains']:
        pointers.extend(Path(row['stateRoot']) / name for name in ('current', 'previous'))
    if any(p.exists() or p.is_symlink() for p in pointers):
        raise ValueError('A selected/current or previous release exists')
    for base in config_roots:
        for parent in (*reversed(base.parents), base):
            if parent.is_symlink(): raise ValueError('Linked unit configuration authority')
        if base.exists() and any(base.rglob('webservices*')):
            raise ValueError('Installed stack unit configuration exists')
    return binding


def verify_unselected_preparation(root, release, value):
    """Never-selected synthetic preparation only; read-only native evidence."""
    unselected_preparation_binding(root, release)
    os.chdir('/')
    for label, command, units in selected_quarantine_plans(release):
        result = subprocess.run(command + ['show', *units, '-p', 'ActiveState', '--value'],
                                capture_output=True, text=True, timeout=30)
        states = [s for s in result.stdout.splitlines() if s]
        if result.returncode or len(states) != len(units) or any(s != 'inactive' for s in states):
            raise ValueError('Never-selected service absence not proved')
        for unit in (['webservices.target', 'webservices-auto-update.timer'] if label == 'rootful' else ['webservices.target']):
            result = subprocess.run(command + ['is-enabled', unit], capture_output=True, text=True, timeout=10)
            if result.stdout.strip() not in ('not-found', 'disabled', 'masked'):
                raise ValueError('Unexpected boot trigger in unselected preparation')
        result = subprocess.run(command + ['list-jobs', '--no-legend', '--no-pager'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or any('webservices' in line for line in result.stdout.splitlines()):
            raise ValueError('Stack jobs remain in unselected preparation')


def seal_unselected(root, expected, reviewed):
    """Repair cp -a's owner reset on an exact never-selected synthetic stage."""
    directory(root)
    path = root / '.install-intent.json'; value = read(path)
    if (not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected) or not value
            or digest(path) != expected or value['phase'] not in ('preparing', 'failed')
            or value.get('steps') not in (['preparing'], ['preparing', 'failed'])
            or value.get('previousRelease') is not None):
        raise ValueError('Exact reviewed initial preparation required for staging seal')
    release = Path(value['release'])
    if release.parent != root / 'releases' or release.is_symlink():
        raise ValueError('Unselected stage escaped metadata root')
    if (read(release / 'installation-receipt.json') != value
            or fingerprint(release, value['inputs'].keys()) != value['inputs']):
        raise ValueError('Unselected staging input/receipt binding changed')
    binding = unselected_preparation_binding(root, release)
    operator = Path(binding['scope']['root']).stat().st_uid
    paths = [release]
    for base, dirs, files in os.walk(release, followlinks=False):
        paths.extend(Path(base) / name for name in dirs + files)
        if len(paths) > 100000: raise ValueError('Oversized staging tree')
    # Validate the entire derived artifact before changing ANY owner. No links,
    # devices, foreign owners, application store or original-cache adoption.
    for item in paths:
        info = item.lstat()
        if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or info.st_uid not in (0, operator)
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise ValueError('Unrecognized staging ownership or linked/special artifact')
    if digest(path) != expected: raise ValueError('Staging seal CAS changed')
    for item in paths:
        info = item.lstat(); os.chown(item, 0, 0, follow_symlinks=False)
        os.chmod(item, stat.S_IMODE(info.st_mode) & ~0o022)
    release.chmod(0o700)
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Staging bytes changed while sealing')
    return {'sealed': True, 'entries': len(paths), 'intentSha256': expected,
            'dataPreserved': True, 'applicationAcceptance': False}


def retire_unselected(root, expected, reviewed, verifier=verify_unselected_preparation):
    """Exact-CAS terminal disposition; no stop/restart/data/account mutation."""
    directory(root)
    path = root / '.install-intent.json'
    value = read(path)
    if (not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected) or not value
            or digest(path) != expected or value['phase'] not in ('preparing', 'failed')
            or value.get('steps') not in (['preparing'], ['preparing', 'failed'])
            or value.get('previousRelease') is not None):
        raise ValueError('Only exact reviewed initial preparation can be retired as unselected')
    release = Path(value['release'])
    if release.parent != root / 'releases': raise ValueError('Unselected release escaped receipt root')
    directory(release)
    if read(release / 'installation-receipt.json') != value:
        raise ValueError('Unselected release receipt binding changed')
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Unselected release input binding changed')
    verifier(root, release, value)
    if digest(path) != expected: raise ValueError('Unselected preparation CAS changed during review')
    retired = dict(value, phase='retired-failed', steps=['preparing', 'failed', 'retired-failed'],
                   retiredIntentSha256=expected, neverSelectedProved=True, dataPreserved=True,
                   dataCompatibilityProved=False)
    write(release / 'installation-receipt.json', retired); write(path, retired)
    return retired


def quarantine_failed(root, expected, reviewed, verifier=verify_quarantined, wait_seconds=120):
    """Exact-CAS, selected-unit-only graceful stop after an interrupted failure.

    This does not retire an intent, touch data, restart a previous release, or
    force-kill a unit. A failed check leaves the intent failed for root review.
    """
    directory(root)
    if not reviewed or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Explicit exact failed-intent/data review required')
    path = root / '.install-intent.json'
    value = read(path)
    if not value or value['phase'] != 'failed' or expected != digest(path):
        raise ValueError('Only exact-CAS terminal failure may be quarantined')
    release = Path(value['release'])
    if release.parent != root / 'releases' or (root / 'current').resolve() != release:
        raise ValueError('Failed selection is not the current immutable release')
    directory(release)
    if fingerprint(release, value['inputs'].keys()) != value['inputs']:
        raise ValueError('Failed release input binding changed')
    plans = selected_quarantine_plans(release)
    os.chdir('/')
    # Disable boot/upgrade triggers before stopping. Never touch a unit that is
    # not named by this root-owned selected release (or its own target/timer).
    failures = []
    if not unconfigured_unit(['systemctl'], 'webservices-auto-update.timer'):
        timer = subprocess.run(['systemctl', 'disable', '--now', 'webservices-auto-update.timer'],
                               capture_output=True, text=True, timeout=30)
        if timer.returncode: failures.append('timer')
    for label, command, units in plans:
        actor = offline_actor(release, label)
        if actor is not None:
            linger = subprocess.run(['loginctl', 'disable-linger', actor['user']], capture_output=True, text=True, timeout=15)
            disabled = subprocess.run(offline_control(command) + ['disable', 'webservices.target', 'podman.socket'],
                                     capture_output=True, text=True, timeout=30)
            if linger.returncode or disabled.returncode: failures.append(label)
            continue
        disabled = subprocess.run(command + ['disable', 'webservices.target'],
                                  capture_output=True, text=True, timeout=30)
        loaded = [unit for unit in units if not unconfigured_unit(command, unit)]
        stopped = (subprocess.run(command + ['--no-block', 'stop', *loaded],
                                  capture_output=True, text=True, timeout=60) if loaded else None)
        if disabled.returncode or (stopped is not None and stopped.returncode):
            failures.append(label)
    if failures:
        raise ValueError('Failed selected-unit quarantine incomplete; no automatic restart')
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            verifier(release)
            break
        except ValueError:
            if time.monotonic() >= deadline:
                raise ValueError('Selected release has running units/jobs or boot triggers') from None
            time.sleep(2)
    if digest(path) != expected or (root / 'current').resolve() != release:
        raise ValueError('Failed selection changed during quarantine')
    return {'release': release.name, 'quarantined': True, 'dataPreserved': True,
            'intentRetired': False, 'forceUsed': False}


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
    if fingerprint(release, value['inputs'].keys()) != value['inputs']: raise ValueError('Failed release input binding changed')
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
    parser.add_argument('--retire-unselected', default='')
    parser.add_argument('--seal-unselected', default='')
    parser.add_argument('--quarantine-failed', default='')
    parser.add_argument('--reviewed-data-state', action='store_true')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--phase', choices=PHASES)
    parser.add_argument('--expected', default='')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Root-owned installation journal required')
    try:
        if args.retire_failed or args.quarantine_failed or args.retire_unselected or args.seal_unselected:
            if sum(bool(v) for v in (args.retire_failed, args.quarantine_failed, args.retire_unselected, args.seal_unselected)) != 1:
                raise ValueError('One exact recovery operation at a time')
            directory(args.root)
            lock = args.root / '.install.lock'
            fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    raise ValueError('Unsafe installation lock')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.seal_unselected:
                    result = seal_unselected(args.root, args.seal_unselected, args.reviewed_data_state)
                elif args.retire_unselected:
                    result = retire_unselected(args.root, args.retire_unselected, args.reviewed_data_state)
                elif args.quarantine_failed:
                    result = quarantine_failed(args.root, args.quarantine_failed, args.reviewed_data_state)
                else:
                    result = retire_failed(args.root, args.retire_failed, args.reviewed_data_state)
                print(json.dumps(result, sort_keys=True))
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
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Installation journal refused; inspect before retry') from None

if __name__ == '__main__': main()
