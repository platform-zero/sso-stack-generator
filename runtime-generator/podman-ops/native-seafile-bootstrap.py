#!/usr/bin/env python3
"""Canonical journal-owned fresh Seafile native preparation; no standalone CLI.

Temporary native Podman containers use the exact eventual actor UID maps and a
networkless shared namespace, never actor managers or host listeners. No data is
removed on failure. This is not application acceptance or a recovery backend.
"""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import threading

PROC = Path('/proc')
CGROUP = Path('/sys/fs/cgroup')


def load_protocol():
    spec = importlib.util.spec_from_file_location('journal_seafile_protocol',
            Path(__file__).with_name('native-seafile-ownership.py'))
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DatabaseConsoleObservations:
    """Drain a private live pipe; retain ONLY predefined observations, never logs."""
    PATTERNS = (
        (b'Initializing database files', 'database-files-initializing'),
        (b'Database files initialized', 'database-files-initialized'),
        (b'Starting temporary server', 'temporary-server-starting'),
        (b'Temporary server started', 'temporary-server-started'),
        (b'01-init-wrapper.sh', 'module-initializer-observed'),
        (b'MariaDB Initialization Starting', 'module-initializer-starting'),
        (b'MariaDB Initialization Complete!', 'module-initializer-completed'),
        (b'MariaDB service initialization refused', 'module-initializer-sql-refused'),
        (b'ready for connections', 'server-ready-message-observed'),
        (b'Permission denied', 'filesystem-permission-refused'),
        (b'Operation not permitted', 'operation-not-permitted'),
        (b'Resource temporarily unavailable', 'resource-temporarily-unavailable'),
        (b'No space left', 'filesystem-capacity-refused'),
        (b'io_uring_queue_init() failed', 'io-uring-unavailable'),
        (b'falling back to libaio', 'native-aio-fallback-observed'),
        (b'Initializing buffer pool', 'innodb-buffer-initializing'),
        (b'Completed initialization of buffer pool', 'innodb-buffer-initialized'),
        (b'Setting file', 'innodb-file-allocation-observed'),
        (b'128 rollback segments', 'innodb-rollback-initialized'),
        (b'Failed to initialize', 'server-initialization-refused'),
        (b'Aborting', 'server-aborting'),
    )

    def __init__(self):
        self.codes = set(); self.lock = threading.Lock()

    def add(self, code):
        with self.lock:
            self.codes.add(code)

    def snapshot(self):
        with self.lock:
            return sorted(self.codes)

    def consume(self, stream):
        tail = b''; total = 0
        try:
            while True:
                chunk = stream.read1(4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > 8 * 1024 * 1024:
                    self.add('database-console-output-bound-exceeded')
                    tail = b''
                    continue  # Drain without retaining or classifying further bytes.
                body = tail + chunk
                for token, code in self.PATTERNS:
                    if token in body:
                        self.add(code)
                tail = body[-1024:]
        except BaseException:
            self.add('database-console-observation-unavailable')


class Fresh:
    def __init__(self, root, release, intent):
        self.p = load_protocol(); self.require = self.p.require
        self.binding = self.p.PreparingBinding(root, release, intent)
        try:
            self.initialize(root, release, intent)
        finally:
            self.binding.close()

    def initialize(self, root, release, intent):
        self.o = self.binding.o
        self.root, self.release, self.old = Path(root), Path(release), intent
        self.cids, self.cidfiles, self.relay, self.capsule = [], {}, None, None
        self.rows = {s.domain: s.row for s in self.binding.sessions}
        self.accounts = {s.domain: s.actor for s in self.binding.sessions}
        self.source = self.binding.source
        self.require(intent.get('previousRelease') is None,
                     'Existing Seafile requires its previous canonical ownership lifecycle')
        # Service payload is interpreted ONLY inside the bounded mapped-UID
        # native qualifier. Host Root uses its own operations schema checker.
        self.contract = self.p
        self.password = secrets.token_urlsafe(48).encode()
        self.require(all(self.password != str(value).encode() for value in self.binding.values.values()))
        self.environments = {name: self.environment(name, '0' * 64) for name in self.source}
        self.fresh_raw, self.marker = self.p.fresh_material(self.contract,
            self.binding.receipt_sha, self.binding.marker_sha, self.binding.data_class,
            self.binding.identity, self.binding.email,
            self.p.database_scope(self.environments['seafile']), self.binding.files,
            self.password, secrets.token_hex(32))
        self.images = {}
        for name, service in self.source.items():
            domain = 'apps' if name == 'seafile' else 'platform'
            with self.o.p.directory(self.release) as fd:
                body, _ = self.o.p.read_at(fd, 'quadlet/rootless-' + domain + '/webservices-' + name + '.container')
            images = [line[6:] for line in body.decode().splitlines() if line.startswith('Image=')]
            self.require(len(images) == 1 and images[0].split('@')[-1] == service['image'].split('@')[-1],
                         'Native support image source differs')
            self.images[name] = images[0]
        self.plan = dict(schemaVersion=1, status='preparing', module='seafile',
                         preparationReceiptSha256=self.binding.receipt_sha,
                         scopeMarkerSha256=self.binding.marker_sha,
                         implementationSha256=self.p.implementation_sha(self.binding.files),
                         freshAuthorizationSha256=self.p.sha(self.fresh_raw),
                         sourceEnvironmentSha256=self.p.sha(self.binding.aggregate),
                         images=self.images)
        self.binding.verify()

    def environment(self, name, authorization_sha):
        values = dict(self.binding.values, SEAFILE_ADMIN_AUTHORIZATION_SHA256=authorization_sha)
        used, result = set(), {}
        forbidden = lambda key: self.o.p.root_only(key, ())
        for key, declaration in self.o.p.declarations(self.source[name]).items():
            self.require(not forbidden(key), 'Root-only service environment declaration refused')
            result[key] = self.o.p.expand(declaration, values, forbidden, used)
        raw = self.env_bytes(result)
        denied = [form for key, value in values.items() if forbidden(key) and value
                  for form in self.o.p.secret_forms(value)]
        _, passwords = self.o.p.owner_import_material(self.release)
        self.require(not any(form in raw for form in [*denied, *passwords]),
                     'Root/owner secret in temporary service environment')
        return result

    @staticmethod
    def env_bytes(values):
        return ('\n'.join(key + '=' + value for key, value in sorted(values.items())) + '\n').encode()

    def reserve(self):
        memory = [int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemAvailable:')]
        self.require(len(memory) == 1 and memory[0] >= 16 * 1024**3, 'Native preparation memory reserve refused')
        for path, gib in ((Path('/'), 50), (self.binding.sessions[-1].scope, 100)):
            space = os.statvfs(path)
            self.require(space.f_bavail * space.f_frsize >= gib * 1024**3 and space.f_favail >= 32,
                         'Native preparation physical disk reserve refused')

    def check(self, expected):
        self.o.lock_held(self.root)
        self.require(expected == dict(self.old, nativeSeafilePreparation=self.plan),
                     'Canonical Seafile preparation changed beyond its exact plan')
        sessions = []
        try:
            for domain in ('platform', 'apps'):
                session = self.o.Session(self.root, self.release, expected, domain)
                sessions.append(session)
                self.require(session.custody == self.binding.pins[domain], 'Seafile source/custody changed')
            with self.o.p.subtree(self.release, 'runtime') as fd:
                body, pin = self.o.p.read_at(fd, 'stack.env', private=True)
            self.require((body, pin) == (self.binding.aggregate, self.binding.aggregate_pin),
                         'Seafile source environment changed')
            with self.o.p.subtree(self.release, 'runtime/configs') as fd:
                selected = self.o.p.config_mounts(self.source); selected.remove(self.p.AUTH_SOURCE)
                files, directories, pins = self.o.p.read_tree(fd, selected)
                realm, realm_pin = self.o.p.read_at(fd, self.o.p.IDP_REALM)
                try:
                    self.o.p.read_at(fd, self.p.AUTH_SOURCE, private=True)
                except FileNotFoundError:
                    pass
                else:
                    raise self.p.Refused('Seafile ownership input already exists')
            self.require((files, directories, pins) == (self.binding.files, self.binding.directories, self.binding.config_pins)
                         and (realm, realm_pin) == (self.binding.realm, self.binding.realm_pin),
                         'Seafile selected source changed')
            for session in sessions:
                session.verify()
            self.reserve()
        finally:
            for session in reversed(sessions):
                session.close()

    def command(self, arguments, timeout=120, environment=None, allow_failure=False, cleanup=False, diagnostic_stderr=False):
        self.require(type(diagnostic_stderr) is bool and (not diagnostic_stderr or
                     (len(arguments) >= 4 and arguments[0] == 'exec' and arguments[2] in self.cids
                      and arguments[3] == 'mariadb')), 'Foreign diagnostic execution refused')
        if cleanup:
            self.require(arguments[0] in ('inspect', 'stop', 'rm')
                         and arguments[-1] in self.cids, 'Foreign cleanup command refused')
        else:
            self.reserve()
        clean = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', REGISTRY_AUTH_FILE=str(self.capsule / 'empty-auth.json'))
        if environment:
            clean.update(environment)
        # Private native output stays in memory; never echo child text/argv.
        result = subprocess.run(['/usr/bin/podman', *arguments], env=clean,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE if diagnostic_stderr else subprocess.DEVNULL,
                    timeout=timeout, close_fds=True, umask=0o077)
        self.require(len(result.stdout) + len(result.stderr or b'') <= 8 * 1024 * 1024,
                     'Native preparation output bound refused')
        self.require(allow_failure or result.returncode == 0, 'Native preparation command refused')
        return result

    def file(self, path, body, uid=0, gid=0, mode=0o600):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchown(fd, uid, gid)
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(fd)

    def temporary_evidence(self, status):
        # Root-private forensic evidence only, NEVER an admission permit/receipt.
        directory = self.release / 'native-seafile'
        info = directory.lstat()
        self.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
                     'Native temporary evidence directory differs')
        self.require(len(self.cids) <= 8, 'Native temporary observation count refused')
        observations = []
        for cid in self.cids:
            try:
                state = self.state(cid, cleanup=True)
                running, exit_code, oom = state.get('Running'), state.get('ExitCode'), state.get('OOMKilled')
                self.require(type(running) is bool and type(exit_code) is int and 0 <= exit_code <= 255
                             and type(oom) is bool, 'Native temporary observation shape refused')
                observations.append(dict(cid=cid, running=running, exitCode=exit_code, oomKilled=oom))
            except BaseException:
                observations.append(dict(cid=cid, observationUnavailable=True))
        body = self.p.encoded(dict(schemaVersion=1, module='seafile', status=status,
            preparationReceiptSha256=self.binding.receipt_sha, cids=list(self.cids),
            plannedNames=list(self.cidfiles.values()), observedStates=observations,
            databaseProbe=getattr(self, 'database_observation', 'not-observed'),
            databaseInitializationProbe=getattr(self, 'database_initialization_observation', 'not-observed'),
            databaseConsole=(self.database_console.snapshot() if hasattr(self, 'database_console') else []),
            databaseProcesses=getattr(self, 'database_process_observation', {'status': 'not-observed'}),
            applicationAcceptance=False))
        temporary = directory / ('.temporary-' + secrets.token_hex(16))
        self.file(temporary, body)
        destination = 'failure-observations.json' if status == 'preparation-failed' else 'temporary.json'
        os.replace(temporary, directory / destination)

    def uidmaps(self, domain):
        account = self.accounts[domain]
        sub = self.o.storage.namespace_root_id(account.pw_name)
        return ['--uidmap', '0:' + str(account.pw_uid) + ':1', '--uidmap', '1:' + str(sub) + ':65536',
                '--gidmap', '0:' + str(account.pw_gid) + ':1', '--gidmap', '1:' + str(sub) + ':65536']

    def data_paths(self):
        return {'mariadb_data': Path(self.rows['platform']['volumeRoot']) / 'mariadb_data',
                'redis_data': Path(self.rows['platform']['volumeRoot']) / 'redis_data',
                'valkey_acl': Path(self.rows['platform']['volumeRoot']) / 'valkey_acl',
                'seafile_files': Path(self.rows['apps']['volumeRoot']) / 'seafile_files'}

    def prepare_data(self):
        paths = self.data_paths()
        # Full absence preflight before any data inode; never adopt even empty data.
        for path in paths.values():
            self.require(not path.exists() and not path.is_symlink(), 'Fresh native data requires owning reset')
        for name, path in paths.items():
            account = self.accounts['apps' if name == 'seafile_files' else 'platform']
            path.mkdir(mode=0o700); os.chown(path, account.pw_uid, account.pw_gid)
        shared = paths['seafile_files'] / 'seafile'
        shared.mkdir(mode=0o700)
        account = self.accounts['apps']; os.chown(shared, account.pw_uid, account.pw_gid)
        self.file(shared / '.webservices-init-complete', self.marker, account.pw_uid, account.pw_gid)

    def create(self, name, authorization_sha=None, action=None, network=None):
        domain = 'apps' if name == 'seafile' else 'platform'
        account = self.accounts[domain]
        native_name = 'stack-seafile-prep-' + self.p.sha(self.fresh_raw)[:16] + '-' + name
        if action == '--verify-owned-admin':
            native_name += '-readback'
        self.require(self.command(['container', 'exists', native_name], allow_failure=True).returncode == 1,
                     'Native preparation name collision')
        env = self.environment(name, authorization_sha or '0' * 64)
        env_path = self.capsule / (native_name + '.env')
        self.file(env_path, self.env_bytes(env))
        cidfile = self.capsule / (native_name + '.cid')
        self.cidfiles[cidfile] = native_name
        arguments = ['create', '--name=' + native_name, '--cidfile=' + str(cidfile), '--timeout=900', '--pull=never', '--image-volume=ignore',
                     '--health-cmd=none', '--log-driver=none', '--security-opt=no-new-privileges',
                     '--memory=2G', '--cpus=1.5', '--pids-limit=256',
                     '--network=' + ('container:' + network if network else 'none'),
                     '--env-file=' + str(env_path), *self.uidmaps(domain)]
        user = self.source[name].get('user')
        if user is not None:
            self.require(isinstance(user, str) and re.fullmatch(r'(0|[1-9][0-9]{0,4}):(0|[1-9][0-9]{0,4})', user)
                         and all(int(value) <= 65536 for value in user.split(':')),
                         'Native container user must fit exact declared numeric UID/GID maps')
            arguments.append('--user=' + user)
        # The isolated database must resolve its OWN deterministic hostname
        # locally, never through external DNS from network=none. Container-net
        # peers reject --hostname/--add-host and do not inherit the hosts file.
        own_hostname = ' ' + native_name if network is None else ''
        if network is None:
            arguments.append('--hostname=' + native_name)
        hosts = self.release / 'native-seafile/config-inputs/hosts' / name
        host_bytes = ('127.0.0.1 localhost host.containers.internal' + own_hostname + '\n::1 localhost\n').encode()
        if not hosts.exists():
            self.file(hosts, host_bytes, mode=0o444)
        self.require(not hosts.is_symlink() and hosts.read_bytes() == host_bytes,
                     'Native private hosts source differs')
        arguments += ['--no-hosts', '--volume=' + str(hosts) + ':/etc/hosts:ro']
        for declaration in self.source[name].get('volumes', []):
            self.require(isinstance(declaration, str), 'Finite native preparation volume form required')
            fields = declaration.split(':'); self.require(len(fields) in (2, 3))
            source, target = fields[:2]
            self.require(target.startswith('/') and '..' not in Path(target).parts)
            if source == './configs/' + self.p.AUTH_SOURCE:
                continue # Exact owning directory includes password ONLY during fresh action.
            if source.startswith('./configs/'):
                rel = source[len('./configs/'):]
                self.require(rel in self.binding.files, 'Native config source absent')
                # /run is noexec; executable/public config staging belongs
                # only in the new Root-private /var/lib release worktree.
                source_path = self.release / 'native-seafile/config-inputs' / domain / rel
                if not source_path.exists():
                    self.file(source_path, self.binding.files[rel], account.pw_uid, account.pw_gid,
                              0o555 if rel.endswith('.sh') else 0o444)
                arguments += ['--volume=' + str(source_path) + ':' + target + ':ro']
            else:
                paths = self.data_paths(); self.require(source in paths, 'Undeclared native preparation data volume')
                self.require(('apps' if source == 'seafile_files' else 'platform') == domain,
                             'Native preparation cross-actor volume refused')
                arguments += ['--volume=' + str(paths[source]) + ':' + target + ':U']
        if name == 'seafile':
            arguments += ['--volume=' + str(self.capsule / 'seafile-admin') + ':/run/seafile-admin:ro']
        entrypoint = self.source[name].get('entrypoint') or []
        self.require(isinstance(entrypoint, list) and all(isinstance(arg, str) for arg in entrypoint))
        # Match the canonical Quadlet systemdQuote's ONE Compose-dollar
        # unescape, without systemd's subsequent dollar/percent encoding.
        # Do not expand variables as Host Root: the child shell owns them.
        entrypoint = [arg.replace('$$', '$') for arg in entrypoint]
        if entrypoint:
            arguments += ['--entrypoint=' + entrypoint[0]]
        command = self.source[name].get('command') or []
        if isinstance(command, str):
            import shlex
            command = shlex.split(command)
        self.require(isinstance(command, list) and all(isinstance(arg, str) for arg in command))
        command = [arg.replace('$$', '$') for arg in command]
        arguments += [self.images[name], *entrypoint[1:], *command]
        if action:
            arguments.append(action)
        cid = self.command(arguments).stdout.strip().decode()
        self.require(self.p.HEX.fullmatch(cid), 'Native preparation CID absent')
        self.cids.append(cid)
        self.temporary_evidence('temporary-created')
        return cid

    def state(self, cid, cleanup=False):
        self.require(cid in self.cids, 'Foreign native preparation CID')
        return self.p.strict(self.command(['inspect', '--format={{json .State}}', cid], cleanup=cleanup).stdout)

    def relay_namespace(self, database_cid):
        state = self.state(database_cid)
        self.require(state.get('Running') is True and type(state.get('Pid')) is int and state['Pid'] > 1)
        pid = state['Pid']; process = os.pidfd_open(pid); namespace = None
        try:
            namespace = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY | os.O_CLOEXEC)
            info = os.fstat(namespace); host = os.stat('/proc/self/ns/net')
            self.require((info.st_dev, info.st_ino) != (host.st_dev, host.st_ino),
                         'Host network namespace refused')
            groups = Path('/proc/' + str(pid) + '/cgroup').read_bytes()
            self.require(len(groups) <= 65536 and any(
                'libpod-' + database_cid + '.scope' in line.decode().split('/') for line in groups.splitlines()),
                'Native relay process cgroup differs')
            after = self.state(database_cid)
            self.require(after.get('Running') is True and after.get('Pid') == pid
                         and not select.select([process], [], [], 0)[0],
                         'Native relay process identity changed')
            result, namespace = namespace, None
            return result
        finally:
            os.close(process)
            if namespace is not None: os.close(namespace)

    def start_relay(self, database_cid):
        env = self.environments['seafile']
        pairs = [[int(env['SEAFILE_MYSQL_DB_PORT']), 3306], [int(env['REDIS_PORT']), 6379]]
        pairs = [pair for pair in pairs if pair[0] != pair[1]]
        if not pairs:
            return
        source = Path(__file__).with_name('native-seafile-loopback.py').read_bytes()
        # Public source only on argv; no Root input/credential/FD9 crosses exec.
        account = self.accounts['platform']
        namespace = self.relay_namespace(database_cid)
        try:
            self.relay = subprocess.Popen(['/usr/bin/nsenter', '--net=/proc/self/fd/' + str(namespace), '--',
                '/usr/bin/setpriv', '--reuid=' + str(account.pw_uid), '--regid=' + str(account.pw_gid),
                '--clear-groups', '--inh-caps=-all', '--bounding-set=-all', '--no-new-privs', '--',
                '/usr/bin/python3', '-B', '-c', source.decode(), json.dumps(pairs)],
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/'}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(namespace,))
        finally:
            os.close(namespace)
        ready, _, _ = select.select([self.relay.stdout], [], [], 10)
        self.require(ready and self.relay.stdout.readline() == b'SEAFILE_PRIVATE_LOOPBACK_READY\n',
                     'Native private loopback unavailable')

    def start_database(self, cid):
        self.require(cid in self.cids, 'Foreign database start observation refused')
        self.reserve()
        self.database_cid = cid
        self.database_console = DatabaseConsoleObservations()
        clean = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root',
                     REGISTRY_AUTH_FILE=str(self.capsule / 'empty-auth.json'))
        # No log driver, raw file or inherited console. The drain retains only
        # fixed codes; --sig-proxy=false isolates helper cleanup from the service.
        self.database_start = subprocess.Popen(['/usr/bin/podman', 'start', '--attach', '--sig-proxy=false', cid],
            env=clean, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, umask=0o077)
        self.database_reader = threading.Thread(target=self.database_console.consume,
            args=(self.database_start.stdout,), daemon=True, name='native-database-observations')
        self.database_reader.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.state(cid).get('Running') is True:
                return
            self.require(self.database_start.poll() is None, 'Native database attached start refused')
            time.sleep(0.05)
        raise self.p.Refused('Native database attached start deadline exceeded')

    def observe_database_processes(self):
        """Only an exact nonempty own CID cgroup; never enumerate/fall back globally."""
        opened = []
        def directory(path):
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened.append(fd)
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                opened.append(child); fd = child
            return fd
        def read(fd, name, limit=8192):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                body = os.read(child, limit + 1)
                self.require(len(body) <= limit, 'Own cgroup observation bound refused')
                return body
            finally:
                os.close(child)
        try:
            cid = getattr(self, 'database_cid', None)
            self.require(cid in self.cids, 'Own database cgroup CID absent')
            state = self.state(cid, cleanup=True); pid = state.get('Pid')
            self.require(state.get('Running') is True and type(pid) is int and pid > 1,
                         'Own database cgroup process absent')
            original = directory(PROC / str(pid))
            process = os.pidfd_open(pid); opened.append(process)
            membership = read(original, 'cgroup').decode('ascii')
            lines = membership.splitlines()
            self.require(len(lines) == 1 and lines[0].startswith('0::/machine.slice/'),
                         'Exact own database cgroup hierarchy absent')
            relative = Path(lines[0][3:])
            self.require(relative.parts == ('/', 'machine.slice', 'libpod-' + cid + '.scope'),
                         'Exact own database cgroup identity absent')
            group = directory(CGROUP / relative.relative_to('/'))
            pids = sorted({int(value) for value in read(group, 'cgroup.procs').split()})
            self.require(pid in pids and 0 < len(pids) <= 256 and all(value > 1 for value in pids),
                         'Nonempty own database cgroup membership absent')
            roles = {b'mariadbd': 'database-server', b'bash': 'shell', b'sh': 'shell',
                     b'cat': 'pipe-reader', b'sleep': 'sleeper', b'chown': 'ownership-worker', b'find': 'file-walker'}
            states = {b'D': 'disk-wait', b'R': 'running', b'S': 'sleeping', b'Z': 'zombie', b'T': 'stopped'}
            waits = {b'io_schedule': 'io-wait', b'futex_wait_queue': 'futex-wait', b'do_wait': 'child-wait',
                     b'pipe_read': 'pipe-read', b'hrtimer_nanosleep': 'timer-wait', b'ep_poll': 'event-wait'}
            rows = []
            for selected in pids[:16]:
                fd = directory(PROC / str(selected))
                self.require(read(fd, 'cgroup').decode('ascii') == membership, 'Own database process moved cgroup')
                raw = read(fd, 'stat'); first, _, rest = raw.rpartition(b')')
                name = first.partition(b'(')[2]; fields = rest.split()
                self.require(len(fields) >= 20, 'Own database process stat absent')
                role = 'database-initializer' if name.startswith(b'mariadb-install') else roles.get(name, 'other')
                rows.append(dict(role=role, state=states.get(fields[0], 'other'),
                                 wait=waits.get(read(fd, 'wchan').strip(), 'other')))
                after = read(fd, 'stat').rpartition(b')')[2].split()
                self.require(len(after) >= 20 and after[19] == fields[19]
                             and read(fd, 'cgroup').decode('ascii') == membership,
                             'Own database process identity changed')
            self.require(read(original, 'cgroup').decode('ascii') == membership
                         and self.state(cid, cleanup=True).get('Pid') == pid
                         and not select.select([process], [], [], 0)[0], 'Own database cgroup anchor changed')
            return dict(status='exact-own-cgroup-observed', processCount=len(pids), bounded=len(pids) > 16, processes=rows)
        except BaseException:
            return {'status': 'own-cgroup-observation-unavailable'}
        finally:
            for fd in reversed(opened):
                os.close(fd)

    def finish_database_observer(self):
        process = getattr(self, 'database_start', None)
        if process is None:
            return True
        clean = True
        try:
            clean = process.wait(timeout=10) == 0
        except BaseException:
            clean = False
            self.database_console.add('database-observer-helper-not-clean')
            try:
                process.terminate(); process.wait(timeout=5)
            except BaseException:
                try:
                    process.kill(); process.wait(timeout=5)
                except BaseException:
                    pass
        try:
            self.database_reader.join(timeout=5)
            clean = clean and not self.database_reader.is_alive()
            process.stdout.close()
        except BaseException:
            clean = False
        return clean

    @staticmethod
    def database_probe_observation(result):
        if result.returncode == 0 and result.stdout.strip() == b'1':
            return 'service-database-ready'
        if result.returncode in (125, 126, 127):
            return {125: 'native-exec-engine-refused', 126: 'native-exec-permission-refused',
                    127: 'native-exec-command-unavailable'}[result.returncode]
        # Only fixed SQL client error classes; never emit child text/usernames,
        # database names, exceptions, SQL, credentials or arbitrary error codes.
        diagnostic = getattr(result, 'stderr', None)
        body = (diagnostic if isinstance(diagnostic, bytes) else result.stdout)[:4096]
        match = re.search(rb'(?m)^ERROR (1045|1049|2002|2003)\b', body)
        if match:
            return {'1045': 'authentication-refused', '1049': 'service-database-absent',
                    '2002': 'database-connectivity-unavailable', '2003': 'database-connectivity-unavailable'}[match[1].decode()]
        return 'other-database-probe-refusal'

    def wait_database(self, cid):
        env = self.environments['seafile']
        deadline = time.monotonic() + 180
        for attempt in range(180):
            if time.monotonic() >= deadline:
                break
            result = self.command(['exec', '--env=MYSQL_PWD', cid, 'mariadb',
                '--protocol=tcp', '--host=127.0.0.1', '--port=3306',
                '--user=' + env['SEAFILE_MYSQL_DB_USER'],
                '--database=' + env['SEAFILE_MYSQL_DB_SEAHUB_DB_NAME'], '--batch', '--skip-column-names',
                '--execute=SELECT 1'], timeout=10, environment={'MYSQL_PWD': env['SEAFILE_MYSQL_DB_PASSWORD']},
                allow_failure=True, diagnostic_stderr=True)
            self.database_observation = self.database_probe_observation(result)
            if self.database_observation == 'service-database-ready':
                return
            self.require(self.state(cid).get('Running') is True, 'Native database stopped before readiness')
            time.sleep(1)
        # A single private, exact-own-CID socket observation distinguishes a
        # temporary initialization server from the required TCP service account.
        # This is diagnostic only and never substitutes for service readiness.
        try:
            root_password = self.environments['mariadb']['MYSQL_ROOT_PASSWORD']
            result = self.command(['exec', '--env=MYSQL_PWD', cid, 'mariadb',
                '--protocol=socket', '--user=root', '--batch', '--skip-column-names',
                '--execute=SELECT 1'], timeout=10, environment={'MYSQL_PWD': root_password},
                allow_failure=True, diagnostic_stderr=True)
            observation = self.database_probe_observation(result)
            self.database_initialization_observation = ('initialization-socket-ready'
                if observation == 'service-database-ready' else observation)
        except BaseException:
            self.database_initialization_observation = 'initialization-observation-unavailable'
        raise self.p.Refused('Native database initialization deadline exceeded')

    def wait_cache(self, cid):
        password = self.environments['seafile']['REDIS_PASSWORD']
        for attempt in range(30):
            result = self.command(['exec', '--env=REDISCLI_AUTH', cid, 'valkey-cli',
                '--raw', '--no-auth-warning', '--host=127.0.0.1', '--port=6379', 'PING'],
                timeout=10, environment={'REDISCLI_AUTH': password}, allow_failure=True)
            if result.returncode == 0 and result.stdout.strip() == b'PONG':
                return
            self.require(self.state(cid).get('Running') is True, 'Native cache stopped before readiness')
            time.sleep(1)
        raise self.p.Refused('Native cache initialization deadline exceeded')

    def stop_all(self):
        passed = True
        # Native cidfiles survive a timed-out client without guessing/reaping names.
        for path in self.cidfiles:
            try:
                info = path.lstat()
                self.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                             and not info.st_mode & 0o022 and info.st_size <= 65,
                             'Native temporary CID evidence differs')
                cid = path.read_text().strip()
                self.require(self.p.HEX.fullmatch(cid), 'Native temporary CID malformed')
                if cid not in self.cids:
                    self.cids.append(cid)
            except FileNotFoundError:
                pass
            except BaseException:
                passed = False
        if self.relay is not None:
            self.relay.terminate()
            try:
                self.relay.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.relay.kill(); self.relay.wait(); passed = False
            self.relay.stdout.close(); self.relay = None
        for cid in reversed(self.cids):
            try:
                if self.state(cid, cleanup=True).get('Running'):
                    self.command(['stop', '--time=30', cid], timeout=40, cleanup=True)
                state = self.state(cid, cleanup=True)
                self.require(state.get('Running') is False and state.get('ExitCode') == 0,
                             'Native preparation did not stop cleanly')
                self.command(['rm', cid], cleanup=True)
            except BaseException:
                passed = False
                # Cleanup is exact CID only; forced cleanup can NEVER be success proof.
                try:
                    self.command(['rm', '--force', cid], allow_failure=True, cleanup=True)
                except BaseException:
                    pass
        self.temporary_evidence('temporary-clean-stop' if passed else 'temporary-stop-failed')
        self.cids.clear()
        return passed

    def run(self, expected):
        self.check(expected)
        self.capsule = Path(tempfile.mkdtemp(prefix='stack-seafile-prep-', dir='/run'))
        proof = normal_raw = readback = None
        stopped = False
        def interrupted(signum, frame):
            raise self.p.Refused('Native Seafile preparation interrupted')
        prior_signal = signal.signal(signal.SIGTERM, interrupted)
        try:
            self.file(self.capsule / 'empty-auth.json', b'{"auths":{}}\n')
            for name in ('mariadb', 'valkey', 'seafile'):
                self.command(['pull', '--quiet', self.images[name]], timeout=900)
            # Exact selected public upstream bytes qualify BEFORE any data init.
            account = self.accounts['apps']
            verifier = self.release / 'native-seafile/config-inputs/reviewed-admin.py'
            self.file(verifier, self.binding.files['seafile/admin_ownership.py'], account.pw_uid, account.pw_gid, 0o444)
            code = 'import runpy;m=runpy.run_path("/reviewed-admin.py");m["verify_upstream_contract"]()'
            qualifier_name = 'stack-seafile-source-' + self.p.sha(self.fresh_raw)[:16]
            self.require(self.command(['container', 'exists', qualifier_name], allow_failure=True).returncode == 1,
                         'Native source qualifier name collision')
            qualifier_cidfile = self.capsule / (qualifier_name + '.cid')
            self.cidfiles[qualifier_cidfile] = qualifier_name
            qualifier = self.command(['create', '--name=' + qualifier_name, '--cidfile=' + str(qualifier_cidfile),
                '--timeout=120', '--pull=never', '--network=none', '--read-only',
                '--cap-drop=all', '--security-opt=no-new-privileges', '--image-volume=ignore',
                '--health-cmd=none', '--log-driver=none', '--memory=512M', '--pids-limit=64', *self.uidmaps('apps'),
                '--volume=' + str(verifier) + ':/reviewed-admin.py:ro', '--entrypoint=/usr/bin/python3',
                self.images['seafile'], '-B', '-c', code], timeout=120).stdout.strip().decode()
            self.require(self.p.HEX.fullmatch(qualifier), 'Native source qualifier CID absent')
            self.cids.append(qualifier)
            self.temporary_evidence('source-qualifier-created')
            self.command(['start', '--attach', qualifier], timeout=120)
            self.require(self.state(qualifier).get('Running') is False
                         and self.state(qualifier).get('ExitCode') == 0, 'Native source qualifier refused')
            self.command(['rm', qualifier]); self.cids.remove(qualifier)
            # Podman rm may already remove its own --cidfile. Native CID
            # removal succeeded above; this private name is optional cleanup.
            qualifier_cidfile.unlink(missing_ok=True); del self.cidfiles[qualifier_cidfile]
            self.check(expected)
            self.prepare_data()
            auth_dir = self.capsule / 'seafile-admin'; auth_dir.mkdir(mode=0o700)
            os.chown(auth_dir, account.pw_uid, account.pw_gid)
            self.file(auth_dir / 'authorization.json', self.fresh_raw, account.pw_uid, account.pw_gid)
            self.file(auth_dir / 'password', self.password, account.pw_uid, account.pw_gid)
            db = self.create('mariadb'); self.start_database(db); self.wait_database(db)
            cache = self.create('valkey', network=db); self.command(['start', cache]); self.wait_cache(cache)
            self.start_relay(db)
            fresh = self.create('seafile', self.p.sha(self.fresh_raw), '--bootstrap-owned-admin', network=db)
            output = self.command(['start', '--attach', fresh], timeout=600).stdout
            state = self.state(fresh)
            self.require(state.get('Running') is False and state.get('ExitCode') == 0,
                         'Native Seafile fresh action exit refused')
            proof = self.p.native_proof(output, self.p.strict(self.fresh_raw))
            normal_raw = self.p.existing_material(self.contract, self.fresh_raw, self.marker, self.binding.files, proof)
            (auth_dir / 'password').unlink(); self.password = b''
            (auth_dir / 'authorization.json').unlink()
            self.file(auth_dir / 'authorization.json', normal_raw, account.pw_uid, account.pw_gid)
            verifier_cid = self.create('seafile', self.p.sha(normal_raw), '--verify-owned-admin', network=db)
            output = self.command(['start', '--attach', verifier_cid], timeout=120).stdout
            state = self.state(verifier_cid)
            self.require(state.get('Running') is False and state.get('ExitCode') == 0,
                         'Native Seafile readback exit refused')
            readback = self.p.native_proof(output, self.p.strict(normal_raw))
        except BaseException as error:
            try:
                self.database_process_observation = self.observe_database_processes()
                self.temporary_evidence('preparation-failed')
            except BaseException:
                pass  # Diagnostics never replace the original guarded failure.
            raise self.p.Refused('Canonical native Seafile preparation failed').with_traceback(error.__traceback__) from None
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            stopped = self.stop_all()
            observer_clean = self.finish_database_observer()
            stopped = stopped and observer_clean
            self.password = b''
            # Only this fresh Root-private credential capsule, never persistent data.
            try:
                shutil.rmtree(self.capsule)
            finally:
                signal.signal(signal.SIGTERM, prior_signal)
        self.require(stopped, 'Native Seafile temporary stop proof refused')
        self.check(expected)
        return dict(authorization=normal_raw, proof=proof, readback=readback,
                    status='completed', nativeTemporaryStop=True)

    def publish(self, expected, result):
        self.require(result.get('status') == 'completed' and result.get('nativeTemporaryStop') is True)
        self.check(expected)
        raw = result['authorization']; auth = self.p.strict(raw)
        self.p.native_proof(self.p.PROOF_PREFIX + self.p.encoded(result['readback']), auth)
        path = self.release / 'runtime/configs/seafile-admin'
        self.require(not path.exists() and not path.is_symlink(), 'Derived Seafile input directory already exists')
        path.mkdir(mode=0o700)
        self.file(path / 'authorization.json', raw)
        aggregate = self.binding.aggregate
        lines = aggregate.decode().splitlines()
        key = 'SEAFILE_ADMIN_AUTHORIZATION_SHA256'
        body = ('\n'.join(line for line in lines if not line.startswith(key + '=')) + '\n'
                + key + '=' + self.p.sha(raw) + '\n').encode()
        with self.o.p.subtree(self.release, 'runtime') as fd:
            old, pin = self.o.p.read_at(fd, 'stack.env', private=True)
            self.require((old, pin) == (aggregate, self.binding.aggregate_pin), 'Derived environment CAS changed')
            name = '.seafile-env-' + secrets.token_hex(16)
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(os.dup(out), 'wb') as stream:
                    stream.write(body); stream.flush(); os.fsync(stream.fileno())
                os.rename(name, 'stack.env', src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
            finally:
                os.close(out)
        return dict(schemaVersion=1, module='seafile', status='completed',
                    preparationReceiptSha256=self.binding.receipt_sha,
                    scopeMarkerSha256=self.binding.marker_sha, images=self.images,
                    implementationSha256=auth['implementation_sha256'],
                    authorizationSha256=self.p.sha(raw), sourceEnvironmentSha256=self.p.sha(aggregate),
                    derivedEnvironmentSha256=self.p.sha(body), freshProof=result['proof'],
                    existingReadback=result['readback'], nativeTemporaryStop=True)
