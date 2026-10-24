#!/usr/bin/env python3
"""Canonical STOPPED same-source recovery owner; no standalone admission CLI.

capture(root, expected_intent_sha256, operation, operations) -> process-local lease.
The journal owner publishes lease.custody in BOTH current Root records, then
lease.bind_published(new_intent). execute(lease) consumes exactly one operation.
Never starts a manager, restores Run, adopts caller JSON, or rewrites source.
"""
import contextlib
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
import time
from types import ModuleType


def load(filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location('_native_recovery_' + filename.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


h = load('host-recovery.py')
_KEY = object()
TTL = 120
OPERATIONS_SHA256 = '782c592ca80da578d96c206a9fae098e94a674d7f8a8f93e5650eefa4fd43012'
GIB = 1024 ** 3


def require(ok, message):
    if not ok: raise ValueError(message)


def normalize(operation):
    require(isinstance(operation, dict), 'Typed recovery operation required')
    kind = operation.get('kind')
    fields = ({'kind', 'archive', 'recipient'} if kind == 'backup' else
              {'kind', 'recoveryJournalSha256'} if kind == 'recover-originals' else
              {'kind', 'archive', 'archiveSha256', 'identityFile'})
    require(kind in ('backup', 'restore', 'recover-originals') and set(operation) == fields, 'Exact backup/restore/recover fields required')
    result = dict(operation)
    for key in ('archive', 'identityFile'):
        if key in result: result[key] = str(h.absolute(result[key]))
    if kind == 'backup':
        require(isinstance(result['recipient'], str) and re.fullmatch('age1[023456789acdefghjklmnpqrstuvwxyz]{58}', result['recipient']), 'One explicit age recipient required')
    else:
        field = 'recoveryJournalSha256' if kind == 'recover-originals' else 'archiveSha256'
        require(isinstance(result[field], str) and re.fullmatch('[a-f0-9]{64}', result[field]), 'Exact archive/recovery journal SHA required')
    return result


def reserve(paths, needed=0):
    # Same physical reserve policy as public host doctor; no cleanup or pruning.
    for path, minimum in paths:
        space = os.statvfs(path)
        require(space.f_bavail * space.f_frsize >= minimum + needed and space.f_favail >= 32,
                'Recovery physical disk/inode reserve insufficient: ' + str(path))
    available = [line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')]
    require(len(available) == 1 and int(available[0]) * 1024 >= 16 * GIB, 'Recovery physical memory reserve below16GiB')


def process_views():
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            text = (proc / 'status').read_text()
            ids = {}
            for label in ('Uid', 'Gid'):
                rows = [line.split()[1:] for line in text.splitlines() if line.startswith(label + ':')]
                require(len(rows) == 1 and len(rows[0]) == 4, 'Unknown recovery process credentials')
                ids[label] = list(map(int, rows[0]))
            files = []
            for info in (proc / 'fdinfo').iterdir():
                try:
                    flags = [line.split()[1] for line in info.read_text().splitlines() if line.startswith('flags:')]
                    require(len(flags) == 1, 'Unknown process FD access mode')
                    if int(flags[0], 8) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                        files.append(os.readlink(proc / 'fd' / info.name))
                except (FileNotFoundError, ProcessLookupError): continue
            maps = (proc / 'maps').read_text().splitlines()
            for line in maps:
                fields = line.split(maxsplit=5)
                require(len(fields) in (5, 6) and re.fullmatch('[r-][w-][x-][ps]', fields[1]), 'Unknown process mapping evidence')
                if len(fields) == 6 and 'w' in fields[1] and fields[1].endswith('s'):
                    files.append(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[5]))
            yield ids, files
        except (FileNotFoundError, ProcessLookupError): continue


def no_writers(actors, paths, lock_path=None):
    own_uids = {a['uid'] for a in actors}; own_gids = {a['gid'] for a in actors}
    def selected(value):
        if not value.startswith('/'): return False
        value = Path(value.removesuffix(' (deleted)'))
        if value == lock_path: return False  # FD9's separately authenticated lock, never payload.
        return any(value == root or value.is_relative_to(root) for root in paths)
    for ids, files in process_views():
        require(not any(value in own_uids or any(a['start'] <= value < a['start'] + a['count'] for a in actors)
                        for value in ids['Uid']), 'Selected own/mapped UID process remains')
        require(not any(value in own_gids or any(a['start'] <= value < a['start'] + a['count'] for a in actors)
                        for value in ids['Gid']), 'Selected own/mapped GID process remains')
        require(not any(selected(value) for value in files), 'Selected writable FD/shared mapping remains (including this process)')


def directory_paths(scope, release, rows, roots):
    paths = {scope, release}
    def below(node):
        while node != scope:
            require(node.is_relative_to(scope), 'Recovery directory escapes canonical scope')
            paths.add(node); node = node.parent
    for row in rows:
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'): below(Path(row[key]))
        below(Path(row['stateRoot']) / 'releases' / release.name)
        paths.add(h.HOME_ROOT / row['user'])
    for root in roots:
        if root != release / 'runtime': below(root.parent)
    return paths


def config_source_rows(path, rows, plans, intent, release, domain):
    """Prove exact .config namespace against source-derived installed file seals."""
    expected = {}
    for plan in plans:
        if plan['role'] != 'rootless-' + domain: continue
        for unit in plan['units'].values():
            source = Path(unit['sourcePath'])
            if source.is_relative_to(path): expected[str(source.relative_to(path))] = unit['sha256']
        for source, digest in plan['configuration'].items():
            expected[str(Path(source).relative_to(path))] = digest
    for source, pin in intent['nativeRuntimeEnvUnits']['files'].items():
        if Path(source).is_relative_to(path): expected[str(Path(source).relative_to(path))] = pin['sha256']
    if rows is None:
        directories = {'.', 'containers', 'containers/systemd', 'systemd', 'systemd/user'}
        for name in expected:
            parent = Path(name).parent
            while str(parent) != '.': directories.add(str(parent)); parent = parent.parent
        return set(expected) | directories
    actual = {}
    directories = {'.'}
    for row in rows:
        suffix = row['name'].split('/', 2)[2] if row['name'].count('/') >= 2 else '.'
        if row['kind'] == 'file': actual[suffix] = row['sha256']
        else: directories.add(suffix)
    required = {'.', 'containers', 'containers/systemd', 'systemd', 'systemd/user'}
    for name in expected:
        parent = Path(name).parent
        while str(parent) != '.': required.add(str(parent)); parent = parent.parent
    require(actual == expected and directories == required, 'Unclaimed/missing actor .config content; no auth-store adoption')


def marker_source(scope, binding, gid):
    parent = h.nofollow_fd(scope); fd = None
    try:
        fd = h.open_at(parent, h.storage.MARKER); before = os.fstat(fd)
        require(before.st_gid in (0, gid) and before.st_size <= 65536
                and h.mount_id(fd) == h.mount_id(parent), 'Private marker group/mount/size differs')
        acl = h.private_marker_acl(fd)
        body = os.pread(fd, 65537, 0)
        require(h.strict(body) == binding and len(body) == before.st_size
                and h.stable(os.fstat(fd)) == h.stable(before), 'Held private marker source CAS differs')
        named = h.open_at(parent, h.storage.MARKER)
        try:
            require(h.stable(os.fstat(named)) == h.stable(before)
                    and h.private_marker_acl(named) == acl and h.mount_id(named) == h.mount_id(fd),
                    'Named private marker replaced/ACL changed')
        finally: os.close(named)
        return dict(identity=list(h.stable(before)), mountId=h.mount_id(fd), acl=acl, sha256=h.sha(body))
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def configuration_files(plans):
    """Exact static account configs: original leaf inode/mount/bytes, not live SHA adoption."""
    result = {}
    for plan in plans:
        for path, expected in plan['configuration'].items():
            node = Path(path); parent = h.nofollow_fd(node.parent); fd = None
            try:
                fd = h.open_at(parent, node.name)
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == plan['uid']
                        and before.st_gid == pwd.getpwuid(plan['uid']).pw_gid
                        and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= 65536
                        and not os.listxattr(fd) and h.mount_id(fd) == h.mount_id(parent), 'Static account configuration custody differs')
                body = os.pread(fd, 65537, 0)
                named = os.stat(node.name, dir_fd=parent, follow_symlinks=False)
                require(len(body) == before.st_size and h.sha(body) == expected
                        and h.stable(before) == h.stable(os.fstat(fd)) == h.stable(named), 'Static account configuration source/race differs')
                result[path] = dict(identity=list(h.stable(before)), mountId=h.mount_id(fd), sha256=expected)
            finally:
                if fd is not None: os.close(fd)
                os.close(parent)
    return result


class StoppedRecoveryLease:
    def __init__(self, key, root, expected, operation, operations):
        require(key is _KEY and type(operations) is ModuleType, 'Canonical in-process recovery issuer required')
        self.root, self.expected, self.operation, self.ops = h.absolute(root), expected, normalize(operation), operations
        self.operation_sha = h.sha(h.canonical(self.operation))
        self.until = time.monotonic() + TTL; self.used = False; self.backend = None; self.closed = False
        self.published = False; self.approved = False
        self.ops_sha = h.sha(operations.body(Path(operations.__file__)))
        require(self.ops_sha == OPERATIONS_SHA256
                and getattr(operations, '_recovery_compiled_source_sha256', None) == OPERATIONS_SHA256,
                'Exact reviewed/compiled native public Ops source required; no live self-approval')
        self.boot = operations.boot_identity()
        self.release, self.intent, self.proof, self.plans, observed = operations.snapshot(self.root, operations.journal_module())
        require(self.intent.get('phase') == 'active' and self.intent.get('steps') == list(h.journal.PHASES[:5])
                and self.proof['intentSha256'] == expected,
                'Recovery requires exact active source receipt, stopped independently')
        self.api = operations.runtime_api(self.release)
        self.api.o.lock_held(self.root)
        self.source = self.api.verify_prepared_units(self.root, self.release, self.intent)
        self.rootful = self.api.load('_native_recovery_rootful_source', 'native-rootful-env-owner.py')
        self.rootful_source = self.rootful.verify_environment(self.root, self.release, self.intent)
        self._stopped(self.plans, observed)
        self.binding = operations.journal_module().standalone_binding(self.release)
        self.rows = operations.load(self.release / 'podman-domains.json')['domains']
        self.scope = Path(self.binding['scope']['root'])
        require(self.binding['scope']['dataClass'] == 'synthetic', 'Production recovery not admitted by this cold synthetic contract')
        self.identity_sha = None
        self.recovery_operation_id = None
        if self.operation['kind'] == 'recover-originals':
            pending_path = self.root / '.host-recovery/intent.json'
            raw = h.read_file(pending_path, private=True, limit=h.MAX_JOURNAL)
            require(h.sha(raw) == self.operation['recoveryJournalSha256'], 'Pending recovery journal CAS differs')
            pending = h.strict(raw)
            require(pending.get('phase') in ('staging', 'staging-failed', 'prepared', 'swapping')
                    and pending.get('request', {}).get('kind') == 'restore', 'Exact interrupted native restore required')
            self.recovery_operation_id = pending['request'].get('operationId')
            require(isinstance(self.recovery_operation_id, str) and re.fullmatch('[a-f0-9]{32}', self.recovery_operation_id), 'Original recovery operation identity required')
        for field in ('archive', 'identityFile'):
            if field not in self.operation: continue
            path = Path(self.operation[field]); h.controlled(path.parent, private=True)
            require(not path.is_relative_to(self.scope) and not path.is_relative_to(self.root), 'Recovery archive/key must be external')
        if self.operation['kind'] == 'restore':
            require(Path(self.operation['identityFile']).parent != Path(self.operation['archive']).parent,
                    'Recovery key must be separately retained')
            self.identity_sha = h.file_sha(Path(self.operation['identityFile']))
        self.roots, self.classification = h.selected_roots(self.release, self.scope, self.binding,
            allow_missing=self.operation['kind'] == 'recover-originals', classified=True)
        self.actors = []
        for row in self.rows:
            account = pwd.getpwnam(row['user']); group = grp.getgrgid(account.pw_gid)
            require(set(group.gr_mem) <= {account.pw_name} and all(a.pw_name == account.pw_name for a in pwd.getpwall() if a.pw_gid == account.pw_gid), 'Foreign actor group writer')
            self.actors.append(dict(name=row['name'], user=row['user'], uid=row['uid'], gid=account.pw_gid,
                                    start=self.api.o.storage.namespace_root_id(row['user']), count=65536))
        self.allocations = self._allocations()
        operator = pwd.getpwuid(1000)
        scope_fd = h.nofollow_fd(self.scope)
        try: scope_gid = os.fstat(scope_fd).st_gid
        finally: os.close(scope_fd)
        group = grp.getgrgid(scope_gid)
        require(set(group.gr_mem) <= {operator.pw_name} and all(a.pw_name == operator.pw_name for a in pwd.getpwall() if a.pw_gid == scope_gid), 'Foreign scope-group writer')
        self.marker_source = marker_source(self.scope, self.binding, scope_gid)
        self.group_pins = self.writer_groups(scope_gid)
        self.configuration_files = configuration_files(self.plans)
        self.finance_reference = self.observe_finance()
        finance_root = Path('/var/lib/webservices-native-finance') if self.finance_reference is not None else None
        finance_entries = None
        configs = []; namespaces = {}
        if finance_root is not None:
            rows = h.tree_entries(finance_root, 'root', [0, 0], self.finance_reference_owners(),
                                  {'root', 'root/input.json'})
            finance_entries = h.sha(h.canonical(h.content_rows(rows)))
            namespaces[str(finance_root)] = ['.', 'input.json']
        for row in self.rows:
            home_config = h.HOME_ROOT / row['user'] / '.config'
            runtime = Path(row['stateRoot']) / 'releases' / self.release.name / 'runtime'
            for path in (home_config, runtime):
                names = None
                if path == home_config:
                    names = config_source_rows(path, None, self.plans, self.intent, self.release, row['name'])
                else:
                    projection = self.intent['domainRuntimeProjections'][row['name']]
                    names = {'.', 'projection.json'} | {name or '.' for name in projection['directories']} | set(projection['files'])
                namespaces[str(path)] = sorted(names)
                allowed = None if names is None else {'reference/0' if name == '.' else 'reference/0/' + name for name in names}
                entries = h.tree_entries(path, 'reference/0', [0, 0], expected_names=allowed)
                if path == home_config: config_source_rows(path, entries, self.plans, self.intent, self.release, row['name'])
                # Real verifier already checked exact actor runtime seals.
                configs.append(dict(domain=row['name'], path=str(path), entriesSha256=h.sha(h.canonical(h.content_rows(entries)))))
        self.paths = directory_paths(self.scope, self.release, self.rows, self.roots)
        if finance_root is not None:
            parent = finance_root
            while parent != Path('/'):
                self.paths.add(parent); parent = parent.parent
        self.directories = {}
        for path in sorted(self.paths):
            fd = h.nofollow_fd(path)
            try: self.directories[str(path)] = h.custody_record(fd)
            finally: os.close(fd)
        self.custody = dict(schemaVersion=1, operatorUid=1000, operatorGid=scope_gid, allocationSha256=self.allocations,
                            actors=self.actors, directories=self.directories, configurationRoots=configs,
                            native=dict(schemaVersion=1, kind='native-stopped-source-recovery',
                                selectionSourceSha256=self.source['selectionSourceSha256'],
                                publicOperationsSha256=self.ops_sha, classification=self.classification,
                                rootfulSourceBindingSha256=self.rootful_source['bindingSha256'],
                                writerGroups=self.group_pins, configurationNamespaces=namespaces,
                                configurationSourceFiles=self.configuration_files,
                                stoppedManagers=self.manager_sources, rootApi=self.root_api,
                                privateMarkerSource=self.marker_source,
                                financeReference=self.finance_reference, financeEntriesSha256=finance_entries,
                                immutableReferencesOnly=True))
        self.writer_paths = self.roots + [Path(c['path']) for c in configs] + [self.root]
        if finance_root is not None: self.writer_paths.append(finance_root)
        self.guard()

    def writer_groups(self, scope_gid):
        result = {}
        for gid in {scope_gid} | {a['gid'] for a in self.actors}:
            result[str(gid)] = dict(members=sorted(grp.getgrgid(gid).gr_mem),
                primary=sorted(a.pw_name for a in pwd.getpwall() if a.pw_gid == gid))
        return result

    def finance_reference_owners(self):
        # This is the completed ACTUAL Root observer result, not a source/site
        # permission flag. Preserve UID0 and exactly its physically pinned GID
        # for archive-only reference custody; never restore/adopt/rekey it.
        reference = self.finance_reference['reference']
        directory, leaf = reference['directory']['identity'], reference['input']['identity']
        require(len(directory) == len(leaf) == 9 and directory[2] == leaf[2] == 0
                and type(directory[3]) is int and directory[3] == leaf[3], 'Original finance reference owner differs')
        return dict(uids=[0], gids=[directory[3]], ranges=[])

    def observe_finance(self):
        selected = [row for row in self.classification if row['kind'] == 'root-control-reference']
        if not selected: return None
        require(len(selected) == 1 and selected[0]['path'] == '/var/lib/webservices-native-finance',
                'Exact selected Root finance reference required')
        observer = self.api.o.journal.readiness_owner()
        value = observer.verify_native_finance_reference(self.root, self.release, self.intent)
        require(isinstance(value, dict) and value.get('kind') == 'root-native-finance-reference-observation'
                and value.get('status') == 'completed' and value.get('root') == str(self.root)
                and value.get('release') == str(self.release) and value.get('intentSha256') == self.expected
                and isinstance(value.get('bindingSha256'), str) and re.fullmatch('[a-f0-9]{64}', value['bindingSha256'])
                and all(value.get(flag) is False for flag in ('activationAuthorized', 'readinessAuthorized', 'journalWritten')),
                'Completed ACTUAL Root finance reference observation required; deferred/JSON is not authority')
        return {key: item for key, item in value.items() if key != 'intentSha256'}

    def _allocations(self):
        return {name: h.sha(self.ops.body(Path('/etc') / name)) for name in ('subuid', 'subgid')}

    def _stopped(self, plans, observed):
        require(self.ops.stopped(plans, observed), 'All selected units/triggers must be stopped/closed')
        managers = {}
        for plan in plans:
            if not plan['uid']: continue
            require(plan['offlineManagerStopped'], 'No selected user manager may remain running')
            manager = self.ops.manager_state(plan['uid'])
            self.ops.offline_manager(manager)
            managers[str(plan['uid'])] = manager
            self.ops.no_actor_logins(plan['uid'])
            self.ops.offline_boot_units(plan, self.ops.journal_module())
        if not hasattr(self, 'manager_sources'): self.manager_sources = managers
        require(managers == self.manager_sources, 'Stopped manager package/source/boot state changed')
        # Root API is not selected ownership; observe/refuse, NEVER stop/adopt.
        api = {}
        properties = ('Id', 'LoadState', 'ActiveState', 'MainPID', 'Job', 'UnitFileState',
                      'FragmentPath', 'SourcePath', 'DropInPaths', 'Names')
        for unit in ('podman.socket', 'podman.service'):
            text = self.ops.run(['/usr/bin/systemctl', 'show', unit, *sum((['-p', name] for name in properties), [])])
            pairs = [line.split('=', 1) for line in text.splitlines()]
            require(len(pairs) == len(properties) and all(len(row) == 2 for row in pairs)
                    and {row[0] for row in pairs} == set(properties), 'Incomplete root API observation')
            props = dict(pairs)
            states = ('disabled', 'masked', 'not-found', '') + (() if unit.endswith('.socket') else ('static',))
            require(props['Id'] == unit and props['LoadState'] in ('loaded', 'not-found')
                    and props['ActiveState'] == 'inactive' and props['MainPID'] in ('', '0')
                    and props['Job'] in ('', '0') and props['UnitFileState'] in states
                    and not props['SourcePath'] and not props['DropInPaths']
                    and set(props['Names'].split()) <= {unit}, 'Root API not closed/canonical')
            if props['LoadState'] == 'loaded':
                require(props['FragmentPath'] == '/usr/lib/systemd/system/' + unit
                        and props['Names'] == unit, 'Root API package source/alias differs')
                props['sourceSha256'] = h.sha(self.ops.body(Path(props['FragmentPath'])))
            else: require(not props['FragmentPath'], 'Unconfigured root API has foreign fragment')
            api[unit] = props
        if not hasattr(self, 'root_api'): self.root_api = api
        require(api == self.root_api, 'Root API source/state changed during recovery')
        require(not Path('/run/podman/podman.sock').exists() and not Path('/run/podman/podman.sock').is_symlink(), 'Root API transport still exists')

    def guard(self):
        require(not self.closed and time.monotonic() < self.until and os.geteuid() == 0, 'Recovery lease expired/closed/non-root')
        require(h.sha(h.canonical(self.operation)) == self.operation_sha, 'Recovery operation changed after issuance')
        if self.identity_sha is not None:
            require(h.file_sha(Path(self.operation['identityFile'])) == self.identity_sha, 'Recovery identity changed after capture')
        if self.operation['kind'] == 'recover-originals' and not self.approved:
            require(h.file_sha(self.root / '.host-recovery/intent.json') == self.operation['recoveryJournalSha256'], 'Pending recovery CAS changed before consumption')
        self.api.o.lock_held(self.root)
        require(self.ops.boot_identity() == self.boot and h.sha(self.ops.body(Path(self.ops.__file__))) == self.ops_sha, 'Recovery boot/public source changed')
        fresh = self.ops.snapshot(self.root, self.ops.journal_module())
        require(fresh[0] == self.release and fresh[1] == self.intent and fresh[2] == self.proof, 'Recovery current source/records/plan CAS changed')
        self._stopped(fresh[3], fresh[4])
        observed = self.api.verify_prepared_units(self.root, self.release, self.intent)
        require(observed['selectionSourceSha256'] == self.source['selectionSourceSha256']
                and observed['copyCustodySha256'] == self.source['copyCustodySha256'], 'Recovery original source/unit custody changed')
        require(self.rootful.verify_environment(self.root, self.release, self.intent) == self.rootful_source,
                'Recovery original rootful source/store custody changed')
        require(self._allocations() == self.allocations, 'Recovery subordinate tables changed')
        require(self.writer_groups(self.custody['operatorGid']) == self.group_pins, 'Recovery group writer membership changed')
        require(configuration_files(fresh[3]) == self.configuration_files, 'Recovery original account-config source inode changed')
        require(marker_source(self.scope, self.binding, self.custody['operatorGid']) == self.marker_source,
                'Recovery original private marker/ACL source changed')
        require(self.observe_finance() == self.finance_reference, 'Recovery original Root finance reference changed')
        no_writers(self.actors, self.writer_paths, self.root / '.install.lock')
        external = Path(self.operation['archive']).parent if 'archive' in self.operation else self.root / '.host-recovery'
        reserve([(Path('/'), 50 * GIB), (self.scope, 100 * GIB), (external, GIB)],
                needed=h.MAX_AUTHENTICATED_BYTES + 4 * 1024 ** 2)

    def bind_published(self, value):
        require(not self.published and value == dict(self.intent, recoveryCustody=self.custody), 'Exact recoveryCustody dual publication required')
        previous = self.source['selectionSourceSha256']; self.intent = value
        fresh = self.ops.snapshot(self.root, self.ops.journal_module())
        require(fresh[0] == self.release and fresh[1] == value and fresh[2]['planSha256'] == self.proof['planSha256'], 'Recovery publication changed source plan')
        self.proof = fresh[2]; self.expected = fresh[2]['intentSha256']; self.published = True
        require(self.api.verify_prepared_units(self.root, self.release, value)['selectionSourceSha256'] == previous, 'Recovery publication rebased source')
        self.guard()

    @contextlib.contextmanager
    def native_lock(self, backend):
        require(type(self) is StoppedRecoveryLease and self.used and self.published and self.backend is backend, 'Exact one-operation backend/lease required')
        self.guard()
        yield
        self.guard()

    def directory_custody(self, node, record, actor, containing):
        ids = {a[k] for a in self.actors for k in ('uid', 'start')}
        if node == self.release:
            require((record['uid'], record['gid'], record['mode']) == (0, 0, 0o700)
                    and not record['acl'] and not record['defaultAcl'], 'Recovery selected release custody differs')
        elif actor or containing:
            selected = actor or containing
            owner = 0 if not actor and record['uid'] == 0 else selected['uid']
            gid = record['gid'] if owner == 0 else selected['gid']
            require(gid in (0, selected['gid']), 'Foreign sealed actor ancestor group')
            self.api.p.custody_permissions(record, owner, gid, set())
        elif record['uid'] == 0 and node != self.scope:
            require(record['gid'] in (0, self.custody['operatorGid']), 'Foreign root ancestry writer group')
            self.api.p.custody_permissions(record, 0, record['gid'], ids, root_ancestor=True, operator_uid=1000)
        else:
            self.api.p.custody_permissions(record, 1000, self.custody['operatorGid'], ids, operator=True)

    def verify_recovery(self, request):
        require(self.used and self.published and self.backend is not None, 'Recovery consumer has no consumed native operation')
        require(request['nativeIntentSha256'] == request['receiptSha256'] == self.expected
                and request['release'] == str(self.release) and request['inputs'] == self.intent['inputs']
                and request['scope'] == str(self.scope) and request['scopeMarkerSha256'] == self.proof['markerSha256']
                and request['roots'] == [str(path) for path in self.roots[1:]]
                and request['referenceRoots'] == ([str(self.release / 'runtime')] + [c['path'] for c in self.custody['configurationRoots']]
                    + (['/var/lib/webservices-native-finance'] if self.finance_reference is not None else []))
                and request['custodySha256'] == h.sha(h.canonical(self.custody))
                and request['allocationSha256'] == self.allocations and request['actors'] == self.actors
                and request['quiesced'] is True and request['exclusiveWriters'] is True and request['restart'] is False,
                'Recovery backend request differs from Root source/lease')
        self.guard()

    def authorize(self, request):
        require(self.used and not self.approved and request.get('kind') == self.operation['kind'], 'Native recovery operation already consumed or wrong kind')
        require(type(request.get('schemaVersion')) is int and request['schemaVersion'] == 1
                and request.get('operationId') == self.operation_id and request.get('restart') is False,
                'Native operation ID/schema/restart binding differs')
        if self.operation['kind'] != 'recover-originals':
            require(request.get('quiesced') is True and request.get('ageBinarySha256') == self.backend.age_expected,
                    'Native crypto/quiescence binding differs')
        selection = request.get('selection')
        require(isinstance(selection, dict), 'Native selection object required')
        self.verify_recovery(dict(selection, allocationSha256=self.allocations, actors=self.actors,
                                  quiesced=True, exclusiveWriters=True, restart=False))
        for key, value in self.operation.items(): require(request.get(key) == value, 'Native recovery destination/key/recipient/hash changed')
        if self.identity_sha is not None: require(request.get('identitySha256') == self.identity_sha, 'Native identity capture CAS changed')
        self.guard(); self.approved = True
        return request

    def close(self): self.closed = True


def capture(root, expected_intent_sha256, operation, operations):
    return StoppedRecoveryLease(_KEY, root, expected_intent_sha256, operation, operations)


def execute(lease):
    require(type(lease) is StoppedRecoveryLease and lease.published and not lease.used, 'Only exact newly issued native lease may execute once')
    lease.guard(); lease.used = True
    backend = h.Backend(lease.root, lease.expected, Path('/usr/bin/age'), lease)
    lease.backend = backend
    operation = lease.operation; identifier = lease.recovery_operation_id or secrets.token_hex(16); lease.operation_id = identifier
    try:
        if operation['kind'] == 'backup':
            result = backend.backup(Path(operation['archive']), operation['recipient'], identifier, lease.authorize)
        elif operation['kind'] == 'restore':
            result = backend.restore(Path(operation['archive']), operation['archiveSha256'], Path(operation['identityFile']), identifier, lease.authorize)
        else:
            result = backend.recover(operation['recoveryJournalSha256'], lease.authorize)
        return dict(result, nativeStoppedRecovery=True, applicationAcceptance='unproven', installedAcceptance=False)
    finally: lease.close()
