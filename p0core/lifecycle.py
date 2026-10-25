"""Owned rootless Quadlet lifecycle; systemd remains the runtime executor.

This module runs as the dedicated runtime user, never as Host Root. Rootful
publication requires its separate trusted installation boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time

from .bundle import verify
from .journal import Journal, operation_lock
from .model import Catalog, ContractError, canonical, identifier, load_json
from .readiness import wait


STORE_ROOT = '/mnt/stack/p0-v2/rootless/engine'


class OperationError(RuntimeError):
    pass


def verify_reserves(extra_bytes=0):
    available = next((int(line.split()[1]) * 1024 for line in
                      Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:')), 0)
    if available < 16 * 1024 ** 3:
        raise ContractError('available RAM below reserve')
    for path, floor in (('/', 50), ('/mnt/stack', 100)):
        observed = os.statvfs(path)
        if observed.f_bavail * observed.f_frsize < floor * 1024 ** 3 + extra_bytes:
            raise ContractError('free storage below reserve')


class Runner:
    def __call__(self, arguments, timeout=30, input_bytes=None):
        if input_bytes is not None and len(input_bytes) > 4096:
            raise OperationError('owned control input exceeds bound')
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                   cwd=Path.home(), env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()),
                                        'XDG_RUNTIME_DIR': f'/run/user/{os.getuid()}', 'LC_ALL': 'C'})
        selector = selectors.DefaultSelector()
        content, diagnostics = bytearray(), bytearray()
        try:
            if input_bytes is not None:
                process.stdin.write(input_bytes)
                process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                for key, _ in selector.select(min(remaining, 1)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fd)
                        continue
                    if len(content) + len(diagnostics) + len(chunk) > 1024 * 1024:
                        raise OperationError('owned control response exceeds bound')
                    (content if key.data == 'stdout' else diagnostics).extend(chunk)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if process.returncode != 0:
                patterns = {b'go.mod requires go >=': 'go-toolchain-too-old',
                            b'GOTOOLCHAIN=local': 'toolchain-auto-download-disabled',
                            b'permission denied': 'permission-denied', b'no such file': 'missing-file',
                            b'no space left': 'storage-full', b'TLS handshake timeout': 'network-tls-timeout',
                            b'i/o timeout': 'network-timeout', b'network is unreachable': 'network-unreachable',
                            b'checksum mismatch': 'checksum-mismatch', b'undefined:': 'compiler-undefined-symbol',
                            b'not found': 'missing-reference', b'connection refused': 'connection-refused'}
                observed = bytes(content) + bytes(diagnostics)
                classes = sorted({label for text, label in patterns.items() if text in observed})
                raise OperationError('owned control command failed (status ' + str(process.returncode)
                                     + '; classes ' + ','.join(classes) + '); no raw output disclosed')
            return bytes(content)
        except BaseException as error:
            # The unreaped direct child's PID cannot be recycled here. Kill
            # only its fresh process group, never a manager, container, user or
            # a cgroup inferred from an empty path. External effects remain
            # indeterminate and are reconciled by the operation journal.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise OperationError('owned client did not settle; effects require reconciliation') from None
            if isinstance(error, subprocess.TimeoutExpired):
                raise OperationError('owned control command timed out; effects require reconciliation') from None
            raise
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()


def atomic_json(path: Path, value):
    fd, temporary = tempfile.mkstemp(prefix='.p0-state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def private_directory(path):
    observed = path.lstat()
    if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) & 0o077 or path.resolve() != path):
        raise ContractError('private runtime directory identity mismatch')


class Lifecycle:
    def __init__(self, state: Path, quadlet: Path, *, runner=None, enforce_identity=True):
        if enforce_identity:
            if os.geteuid() == 0 or pwd.getpwuid(os.getuid()).pw_name != 'p0-runtime':
                raise ContractError('rootless lifecycle requires the p0-runtime account')
        self.state = state.absolute()
        self.quadlet = quadlet.absolute()
        self.run = runner or Runner()

    def generate_service_secret(self, name):
        # This creates a NEW ordinary service credential, never reads an existing
        # credential or a Keykeeper-protected secret. Podman refuses duplicates.
        import secrets
        identifier(name)
        verify_reserves()
        store = self.run(['/usr/bin/podman', 'info', '--format', '{{.Store.GraphRoot}}'], timeout=30)
        if store.decode().strip() != STORE_ROOT:
            raise ContractError('unexpected rootless image store; refusing secret mutation')
        value = secrets.token_urlsafe(48).encode()
        self.run(['/usr/bin/podman', 'secret', 'create', 'p0-' + name, '-'],
                 timeout=30, input_bytes=value)
        return {'schemaVersion': 1, 'created': 'p0-' + name,
                'scope': 'ordinary-service-credential', 'installationCertified': False}

    def _registry(self):
        path = self.state / 'selection.json'
        if not path.exists():
            raise ContractError('no owned installed selection')
        if path.is_symlink():
            raise ContractError('selection must not be a symlink')
        registry = load_json(path)
        if registry.get('schemaVersion') != 1 or registry.get('runtime') != 'rootless':
            raise ContractError('unsupported runtime selection')
        return registry

    def install(self, bundle: Path, expected_sha256: str, *, pull=False, resume_stopped=False):
        # Expected digest comes from independently reviewed release input, not
        # from blindly trusting the lock inside the same bundle.
        if hashlib.sha256((bundle / 'bundle.json').read_bytes()).hexdigest() != expected_sha256:
            raise ContractError('release lock identity mismatch')
        lock = verify(bundle)
        specs = lock['serviceSpecs']
        if any(spec.get('runtime') != 'rootless' for spec in specs.values()):
            raise ContractError('rootless publication cannot install rootful/test units')
        Catalog([{'schemaVersion': 1, 'id': 'selected', 'services': list(specs.values())}])
        from .inputs import verify_installed
        verify_installed(specs.values())
        self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        private_directory(self.state)
        self.quadlet.mkdir(parents=True, mode=0o700, exist_ok=True)
        private_directory(self.quadlet)
        with operation_lock(self.state):
            journal = Journal(self.state / 'operations.sqlite3')
            operation = journal.create('install', lock['plan']['inputSha256'])
            journal.transition(operation, 0, 'running')
            try:
                # Do not replace an existing selection in the initial-install
                # path. Upgrade must prove stopped/input/recovery conditions.
                previous = None
                if (self.state / 'selection.json').exists():
                    if not resume_stopped:
                        raise ContractError('existing selection requires explicit upgrade')
                    previous = self._registry()
                    self.verify_owned(previous)
                    if previous['releaseSha256'] != expected_sha256:
                        raise ContractError('stopped resume cannot change release inputs')
                    if any(not self.stopped(name, self.observe(name)) for name in previous['services']):
                        raise ContractError('stopped resume requires all owned services stopped')
                elif resume_stopped:
                    raise ContractError('stopped resume requires an owned prior selection')
                publications = {}
                for name, checksum in lock['files'].items():
                    if name.startswith('quadlet/rootless/'):
                        basename = Path(name).name
                        if Path(name).as_posix() != 'quadlet/rootless/' + basename:
                            raise ContractError('unexpected nested unit path')
                        destination = self.quadlet / basename
                        if destination.exists() or destination.is_symlink():
                            if previous is None or previous['units'].get(basename) != checksum:
                                raise ContractError('refusing unowned matching Quadlet name')
                        publications[basename] = checksum
                if previous is not None and publications != previous['units']:
                    raise ContractError('stopped resume cannot change unit selection')
                verify_reserves()
                store = self.run(['/usr/bin/podman', 'info', '--format', '{{.Store.GraphRoot}}'], timeout=30)
                if store.decode().strip() != STORE_ROOT:
                    raise ContractError('unexpected rootless image store; refusing engine mutation')
                for image in sorted(set(lock['images'].values())):
                    command = ['/usr/bin/podman', 'pull', '--quiet', image] if pull else ['/usr/bin/podman', 'image', 'exists', image]
                    self.run(command, timeout=300)
                # Publish selected units exclusively. A failed publication is
                # retained as a failed operation, not silently overwritten/retried.
                for basename, checksum in publications.items():
                    if previous is not None:
                        continue  # Exact owned bytes already verified; never overwrite.
                    content = (bundle / 'quadlet/rootless' / basename).read_bytes()
                    if hashlib.sha256(content).hexdigest() != checksum:
                        raise ContractError('unit changed during publication')
                    fd = os.open(self.quadlet / basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                registry = {'schemaVersion': 1, 'runtime': 'rootless', 'operation': operation,
                            'inputSha256': lock['plan']['inputSha256'], 'releaseSha256': expected_sha256,
                            'services': specs, 'plan': lock['plan'], 'units': publications,
                            'installationCertified': False}
                atomic_json(self.state / 'selection.json', registry)
                self.run(['/usr/bin/systemctl', '--user', 'daemon-reload'])
                journal.transition(operation, 1, 'succeeded')
                return {'schemaVersion': 1, 'operation': operation, 'state': 'published-not-started',
                        'units': sorted(publications), 'installationCertified': False}
            except BaseException:
                journal.transition(operation, 1, 'failed')
                raise
            finally:
                journal.close()

    def verify_owned(self, registry):
        private_directory(self.state)
        private_directory(self.quadlet)
        for name, checksum in registry['units'].items():
            if name != Path(name).name or not name.startswith('p0-'):
                raise ContractError('invalid owned unit identity')
            path = self.quadlet / name
            observed = path.lstat()
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                    or observed.st_nlink != 1 or stat.S_IMODE(observed.st_mode) & 0o077
                    or hashlib.sha256(path.read_bytes()).hexdigest() != checksum):
                raise ContractError('owned unit changed; reconcile rather than execute')

    def observe(self, name):
        identifier(name)
        raw = self.run(['/usr/bin/systemctl', '--user', 'show', 'p0-' + name + '.service',
                        '--property=LoadState,ActiveState,SubState,Result', '--no-pager'], timeout=5)
        allowed = {'LoadState', 'ActiveState', 'SubState', 'Result'}
        result = {}
        for line in raw.decode('utf-8').splitlines():
            key, separator, value = line.partition('=')
            if separator and key in allowed and len(value) < 100 and value.replace('-', '').isalnum():
                result[key] = value
        if not allowed <= result.keys():
            raise OperationError('unit observation incomplete')
        return result

    def status(self):
        # No mkdir, database creation, reload, start, repair or engine query.
        registry = self._registry()
        self.verify_owned(registry)
        return {'schemaVersion': 1, 'inputSha256': registry['inputSha256'],
                'services': {name: self.observe(name) for name in sorted(registry['services'])},
                'installationCertified': False}

    def stopped(self, name, state):
        if state['ActiveState'] not in ('inactive', 'failed'):
            return False
        raw = self.run(['/usr/bin/systemctl', '--user', 'show', 'p0-' + name + '.service',
                        '--property=MainPID,ControlGroup,Job', '--no-pager'], timeout=5)
        values = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
        if values.get('MainPID') != '0' or values.get('Job') != '':
            return False
        group = values.get('ControlGroup')
        if group == '':
            return True  # No empty-cgroup lookup or global process fallback.
        if not group or not group.startswith('/') or not group.endswith('/p0-' + name + '.service'):
            raise OperationError('unexpected owned cgroup identity')
        path = Path('/sys/fs/cgroup') / group.lstrip('/')
        if '..' in path.parts or not path.resolve().is_relative_to('/sys/fs/cgroup'):
            raise OperationError('owned cgroup escaped hierarchy')
        if not path.exists():
            return True
        events = dict(line.split() for line in (path / 'cgroup.events').read_text().splitlines())
        return events.get('populated') == '0'

    def _wait_unit(self, name, *, started, lifecycle, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.observe(name)
            if state['LoadState'] != 'loaded':
                raise OperationError('owned unit is not loaded')
            if state['ActiveState'] == 'failed' and started:
                raise OperationError('owned unit failed')
            if started:
                if state['ActiveState'] == 'active' and (lifecycle != 'oneshot' or state['SubState'] == 'exited'):
                    return state
            elif self.stopped(name, state):
                return state
            time.sleep(0.1)
        raise OperationError('unit transition deadline exceeded; reconcile current effects')

    def recover_empty_engine(self):
        registry = self._registry()
        self.verify_owned(registry)
        if any(spec.get('lifecycle', 'daemon') != 'daemon' for spec in registry['services'].values()):
            raise ContractError('empty-engine recovery cannot reconcile provisioning/external operations')
        with operation_lock(self.state):
            for name in registry['services']:
                if not self.stopped(name, self.observe(name)):
                    raise ContractError('recovery requires stopped owned services')
            store = self.run(['/usr/bin/podman', 'info', '--format', '{{.Store.GraphRoot}}'])
            if store.decode().strip() != STORE_ROOT:
                raise ContractError('unexpected recovery engine')
            for arguments in (['container', 'ls', '--all', '--quiet'], ['volume', 'ls', '--quiet']):
                if self.run(['/usr/bin/podman'] + arguments).strip():
                    raise ContractError('empty-engine recovery requires no containers or data volumes')
            journal = Journal(self.state / 'operations.sqlite3')
            try:
                operation = journal.create('recover', registry['inputSha256'])
                journal.transition(operation, 0, 'running')
                journal.transition(operation, 1, 'succeeded')
                return {'schemaVersion': 1, 'operation': operation, 'state': 'empty-daemon-engine-reconciled',
                        'externalEffectsCertified': False, 'requiresExplicitStart': True,
                        'installationCertified': False}
            finally:
                journal.close()

    def change(self, action, targets, *, resources=False):
        if action not in ('start', 'stop'):
            raise ContractError('unsupported lifecycle action')
        registry = self._registry()
        self.verify_owned(registry)
        if action == 'start':
            from .inputs import verify_installed
            verify_installed(registry['services'].values())
        if resources and (action != 'stop' or set(targets) != set(registry['services'])):
            raise ContractError('resource stop requires explicit complete owned service selection')
        catalog = Catalog([{'schemaVersion': 1, 'id': 'selected', 'services': list(registry['services'].values())}])
        plan = catalog.plan(targets)
        if action == 'stop':
            # A selected dependency may not be stopped beneath a retained
            # dependent. Caller must include the dependent explicitly.
            selected = set(targets)
            for name, spec in registry['services'].items():
                if name not in selected and any(edge.get('kind') != 'integration' and edge.get('service') in selected
                                                for edge in spec.get('requires', [])):
                    raise ContractError('stop would strand a retained dependent')
        with operation_lock(self.state):
            journal = Journal(self.state / 'operations.sqlite3')
            if action == 'start' and journal.connection.execute(
                    "SELECT 1 FROM operations bad WHERE bad.state IN ('prepared','running','indeterminate') AND bad.kind!='build' "
                    "AND NOT (bad.kind='stop' AND EXISTS (SELECT 1 FROM operations done WHERE done.kind='stop' "
                    "AND done.state='succeeded' AND done.input_sha256=bad.input_sha256 AND done.created>bad.updated)) "
                    "AND NOT (bad.kind IN ('start','stop') AND EXISTS (SELECT 1 FROM operations done WHERE done.kind='recover' "
                    "AND done.state='succeeded' AND done.input_sha256=bad.input_sha256 AND done.created>bad.updated)) LIMIT 1").fetchone():
                journal.close()
                raise ContractError('unreconciled effects prevent another start')
            operation = journal.create(action, registry['inputSha256'])
            journal.transition(operation, 0, 'running')
            effects = False
            try:
                if action == 'start':
                    verify_reserves()
                ordered = (plan['services'] if action == 'start' else
                           [name for name in reversed(plan['services']) if name in set(targets)])
                for name in ordered:
                    effects = True
                    if action == 'start':
                        current = self.observe(name)
                        if current['ActiveState'] == 'failed':
                            if not self.stopped(name, current):
                                raise OperationError('failed unit still owns active effects')
                            # Original failure stays in journal/native evidence.
                            # Clear only this stopped unit's retry latch after an
                            # explicit new start request, never on status/attach.
                            self.run(['/usr/bin/systemctl', '--user', 'reset-failed', 'p0-' + name + '.service'])
                    self.run(['/usr/bin/systemctl', '--user', action, '--no-block', 'p0-' + name + '.service'])
                    spec = registry['services'][name]
                    self._wait_unit(name, started=action == 'start', lifecycle=spec.get('lifecycle', 'daemon'))
                    if action == 'start' and spec.get('probes'):
                        wait(spec['probes'], budget=300)
                if resources:
                    for filename in sorted(registry['units']):
                        suffix = '-network' if filename.endswith('.network') else '-volume' if filename.endswith('.volume') else None
                        if suffix:
                            name = filename.rsplit('.', 1)[0] + suffix
                            self.run(['/usr/bin/systemctl', '--user', 'stop', '--no-block', name + '.service'])
                            self._wait_unit(name.removeprefix('p0-'), started=False, lifecycle='oneshot')
                journal.transition(operation, 1, 'succeeded')
                return {'schemaVersion': 1, 'operation': operation, 'state': action + '-observed',
                        'services': ordered, 'installationCertified': False}
            except BaseException:
                journal.transition(operation, 1, 'indeterminate' if effects else 'failed')
                raise
            finally:
                journal.close()
