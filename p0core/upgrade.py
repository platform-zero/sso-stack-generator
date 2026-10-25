"""Explicit stopped, data-preserving rootless selection extension.

No image/schema migration, resource removal, rollback, provisioning replay or
implicit start. Interrupted file publication rolls forward only exact recorded
inodes. Original indeterminate operations and intent history remain evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from .bundle import verify
from .journal import Journal, operation_lock
from .lifecycle import STORE_ROOT, atomic_json, private_directory, verify_reserves
from .model import Catalog, ContractError, _pairs


def read_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(fd)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                or observed.st_gid != os.getgid() or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o600 or observed.st_size > 8 * 1024**2):
            raise ContractError('unsafe upgrade intent custody')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            encoded = stream.read(8 * 1024**2 + 1)
        result = json.loads(encoded, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ContractError('nonfinite upgrade record')))
        if not isinstance(result, dict) or type(result.get('schemaVersion')) is not int or result['schemaVersion'] != 1:
            raise ContractError('unsupported upgrade record')
        return result
    finally:
        os.close(fd)


def identity(path, checksum, *, links=(1,)):
    observed = path.lstat()
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
            or observed.st_gid != os.getgid() or observed.st_nlink not in links
            or stat.S_IMODE(observed.st_mode) != 0o600
            or hashlib.sha256(path.read_bytes()).hexdigest() != checksum):
        raise ContractError('upgrade file custody or bytes differ')
    return [observed.st_dev, observed.st_ino]


def stopped(runtime, registry):
    names = set(registry['services'])
    for filename in registry['units']:
        suffix = '-network' if filename.endswith('.network') else '-volume' if filename.endswith('.volume') else None
        if suffix:
            names.add(filename.rsplit('.', 1)[0].removeprefix('p0-') + suffix)
    if any(not runtime.stopped(name, runtime.observe(name)) for name in sorted(names)):
        raise ContractError('upgrade requires every owned service/resource stopped')


def compatible(previous, desired):
    if not set(previous) <= set(desired):
        raise ContractError('upgrade cannot remove owned services or data')
    for name, old in previous.items():
        new = desired[name]
        # Existing executable/image/environment/storage/network authority cannot
        # be changed without the separately implemented compatibility protocol.
        stable = lambda spec: {key: value for key, value in spec.items() if key not in ('mounts', 'probes', 'requires')}
        if stable(old) != stable(new):
            raise ContractError('existing executable change needs compatibility qualification')
        def mounts(spec):
            result = []
            for mount in spec.get('mounts', []):
                item = dict(mount)
                if item['kind'] == 'secret':
                    item.setdefault('uid', 0)
                    item.setdefault('gid', 0)
                if item['kind'] == 'config':
                    item.pop('sha256', None)  # Explicit newly bound noncredential input.
                result.append(item)
            return sorted(result, key=lambda item: item['target'])
        if mounts(old) != mounts(new):
            raise ContractError('existing data or credential binding change needs migration protocol')


def upgrade(runtime, bundle, expected, predecessor, *, resume=False, pull=False):
    bundle = Path(bundle)
    if hashlib.sha256((bundle / 'bundle.json').read_bytes()).hexdigest() != expected:
        raise ContractError('upgrade release identity mismatch')
    lock = verify(bundle)
    specs = lock['serviceSpecs']
    if any(spec.get('runtime') != 'rootless' for spec in specs.values()):
        raise ContractError('rootless upgrade cannot publish other runtime classes')
    Catalog([{'schemaVersion': 1, 'id': 'selected', 'services': list(specs.values())}])
    from .inputs import ensure_materialized, verify_installed
    verify_installed(specs.values())
    private_directory(runtime.state)
    private_directory(runtime.quadlet)
    publications = {}
    for name, checksum in lock['files'].items():
        if name.startswith('quadlet/rootless/'):
            basename = Path(name).name
            if name != 'quadlet/rootless/' + basename or not basename.startswith('p0-'):
                raise ContractError('unsafe upgrade publication path')
            publications[basename] = checksum
    pointer = runtime.state / 'upgrade-current.json'
    with operation_lock(runtime.state):
        intent = None
        if pointer.exists() or pointer.is_symlink():
            private_directory(runtime.state)
            info = read_record(pointer)
            directory = info.get('directory', '')
            try:
                if directory != 'upgrade-' + str(uuid.UUID(directory.removeprefix('upgrade-'))):
                    raise ValueError()
            except (ValueError, AttributeError):
                raise ContractError('invalid upgrade intent reference') from None
            stage = runtime.state / directory
            private_directory(stage)
            intent = read_record(stage / 'intent.json')
        if resume:
            if not intent:
                raise ContractError('resume needs an exact recorded upgrade intent')
            if intent.get('releaseSha256') != expected or intent.get('predecessorSha256') != predecessor:
                raise ContractError('resume cannot change upgrade inputs')
            previous = intent['previous']
            if runtime._registry()['releaseSha256'] not in (predecessor, expected):
                raise ContractError('installed release diverged from upgrade intent')
        else:
            if intent and intent.get('state') != 'complete':
                raise ContractError('unfinished upgrade requires explicit resume')
            previous = runtime._registry()
            runtime.verify_owned(previous)
            if previous['releaseSha256'] != predecessor:
                raise ContractError('stale predecessor release identity')
        compatible(previous['services'], specs)
        if not set(previous['units']) <= set(publications):
            raise ContractError('upgrade cannot remove owned resource definitions')
        stopped(runtime, previous)
        if resume:
            stopped(runtime, runtime._registry())
        verify_reserves()
        if runtime.run(['/usr/bin/podman', 'info', '--format', '{{.Store.GraphRoot}}']).decode().strip() != STORE_ROOT:
            raise ContractError('unexpected upgrade engine')
        journal = Journal(runtime.state / 'operations.sqlite3')
        operation = journal.create('upgrade', lock['plan']['inputSha256'])
        journal.transition(operation, 0, 'running')
        effects = False
        try:
            if not resume:
                stage = runtime.state / ('upgrade-' + operation)
                stage.mkdir(mode=0o700)
                private_directory(stage)
                if stage.stat().st_dev != runtime.quadlet.stat().st_dev:
                    raise ContractError('atomic publication needs one filesystem')
                records = {}
                for name, checksum in sorted(publications.items()):
                    destination = runtime.quadlet / name
                    old = previous['units'].get(name)
                    old_identity = identity(destination, old) if old else None
                    if not old and (destination.exists() or destination.is_symlink()):
                        raise ContractError('refusing unowned Quadlet collision')
                    if old == checksum:
                        records[name] = {'oldSha256': old, 'oldIdentity': old_identity, 'sha256': checksum,
                                         'newIdentity': old_identity, 'changed': False}
                        continue
                    content = (bundle / 'quadlet/rootless' / name).read_bytes()
                    if hashlib.sha256(content).hexdigest() != checksum:
                        raise ContractError('upgrade source changed during preparation')
                    fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    records[name] = {'oldSha256': old, 'oldIdentity': old_identity, 'sha256': checksum,
                                     'newIdentity': identity(stage / name, checksum), 'changed': True}
                intent = {'schemaVersion': 1, 'state': 'prepared', 'releaseSha256': expected,
                          'predecessorSha256': predecessor, 'previous': previous, 'records': records,
                          'operation': operation}
                atomic_json(stage / 'intent.json', intent)
                atomic_json(pointer, {'schemaVersion': 1, 'directory': stage.name})
            elif intent['records'].keys() != publications.keys() or any(
                    record['sha256'] != publications[name] for name, record in intent['records'].items()):
                raise ContractError('upgrade intent differs from release publications')
            # Durable exact-inode claims exist before any publication/native effect.
            effects = True
            ensure_materialized(runtime, specs.values())
            for image in sorted(set(lock['images'].values())):
                runtime.run(['/usr/bin/podman'] + (['pull', '--quiet', image] if pull else ['image', 'exists', image]), timeout=300)
            for name, record in sorted(intent['records'].items()):
                destination, prepared = runtime.quadlet / name, stage / name
                if destination.exists() or destination.is_symlink():
                    try:
                        found = identity(destination, record['sha256'], links=(1, 2) if record['changed'] else (1,))
                    except ContractError:
                        found = None
                    if found == record['newIdentity']:
                        continue
                    if not record['oldSha256'] or identity(destination, record['oldSha256']) != record['oldIdentity']:
                        raise ContractError('foreign or edited upgrade destination')
                    if identity(prepared, record['sha256']) != record['newIdentity']:
                        raise ContractError('upgrade staged inode changed')
                    os.replace(prepared, destination)
                else:
                    if record['oldSha256'] or identity(prepared, record['sha256']) != record['newIdentity']:
                        raise ContractError('owned predecessor disappeared')
                    os.link(prepared, destination, follow_symlinks=False)  # Exclusive, never replaces a collision.
            for name, record in intent['records'].items():
                destination, prepared = runtime.quadlet / name, stage / name
                if identity(destination, record['sha256'], links=(1, 2)) != record['newIdentity']:
                    raise ContractError('published upgrade inode changed')
                if record['changed'] and prepared.exists():
                    if identity(prepared, record['sha256'], links=(1, 2)) != record['newIdentity']:
                        raise ContractError('staged cleanup identity changed')
                    prepared.unlink()  # Only this operation's exact prepared link, not app data.
            for directory in (stage, runtime.quadlet):
                fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            registry = {'schemaVersion': 1, 'runtime': 'rootless', 'operation': operation,
                        'inputSha256': lock['plan']['inputSha256'], 'releaseSha256': expected,
                        'services': specs, 'plan': lock['plan'], 'units': publications,
                        'predecessorSha256': predecessor, 'installationCertified': False}
            runtime.verify_owned(registry)
            stopped(runtime, previous)
            atomic_json(runtime.state / 'selection.json', registry)
            runtime.run(['/usr/bin/systemctl', '--user', 'daemon-reload'])
            intent['state'] = 'complete'
            intent['completedOperation'] = operation
            atomic_json(stage / 'intent.json', intent)
            journal.transition(operation, 1, 'succeeded')
            return {'schemaVersion': 1, 'operation': operation, 'state': 'upgraded-not-started',
                    'requiresExplicitStart': True, 'dataDeleted': False, 'installationCertified': False}
        except BaseException:
            journal.transition(operation, 1, 'indeterminate' if effects else 'failed')
            raise
        finally:
            journal.close()
