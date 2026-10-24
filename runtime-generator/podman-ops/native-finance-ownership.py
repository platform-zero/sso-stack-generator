#!/usr/bin/env python3
"""Root original-native finance relationship collector; canonical J callback only.

No CLI, arbitrary JSON admission, credential output, service-account-user GET,
service start/replay, source/ENV edits or daemon. Arm before the original target
transaction. Capture immediately after launch: observe the ORIGINAL live CID,
conmon/kernel cgroup and source-bound InvocationID, then await that SAME oneshot's
success and export only the native Keycloak database relationship. If the original
container was missed, REFUSE; app stdout/event/logger strings cannot backfill it.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time


def load(filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location('_finance_' + filename.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


n = load('native-readiness-owner.py')
r = n.r
require = r.require
_KEY = object()
SLOT = Path('/var/lib/webservices-native-finance')
MOUNT = '/var/lib/webservices-native-finance:/run/p0-finance:ro'
INPUT = '/run/p0-finance/input.json'
FINANCE_SOURCE_SHA256 = '7da28ce6db648d46b08c2fb9f8926915ea97a22842e6bc83c2b1b9ce32d2a049'
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}')
ORIGIN_KIND = 'original-live-systemd-cid-keycloak-native-link'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return r.frozen(value).encode()


def edge(value):
    require(type(value) is dict and set(value) == {'clientId', 'clientUuid', 'serviceAccountSubject'}
            and value['clientId'] == 'firefly-identity-reader'
            and all(type(value[k]) is str and UUID.fullmatch(value[k]) for k in ('clientUuid', 'serviceAccountSubject'))
            and value['clientUuid'] != value['serviceAccountSubject'], 'Exact native finance edge required')
    return dict(value)


def original_receipt(value, source, issuer):
    require(type(value) is dict and set(value) == {'schemaVersion', 'kind', 'status', 'release', 'inputs',
            'intentSha256', 'custodySha256', 'issuer', 'source', 'original', 'nativeFinanceOwnership',
            'activationAuthorized', 'readinessAuthorized', 'journalWritten'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and value['kind'] == 'root-native-finance-ownership'
            and value['status'] == 'completed' and value['issuer'] == issuer
            and value['source'] == source and value['activationAuthorized'] is False
            and value['readinessAuthorized'] is False and value['journalWritten'] is False,
            'Unknown original Root finance receipt; no adoption')
    origin = value['original']
    require(type(origin) is dict and set(origin) == {'kind', 'bootId', 'invocationId', 'startMonotonicUSec',
            'exitMonotonicUSec', 'container', 'database'} and origin['kind'] == ORIGIN_KIND
            and UUID.fullmatch(origin['bootId']) and r.INVOCATION.fullmatch(origin['invocationId'])
            and type(origin['startMonotonicUSec']) is int and type(origin['exitMonotonicUSec']) is int
            and 0 < origin['startMonotonicUSec'] < origin['exitMonotonicUSec'], 'Unknown native original origin')
    container = origin['container']; database = origin['database']
    fields = {'id', 'image', 'source', 'conmon'} | ({'execution'} if 'authority' in source else set())
    require(type(container) is dict and set(container) == fields
            and r.HEX.fullmatch(container['id']) and re.fullmatch(r'sha256:[a-f0-9]{64}', container['image'])
            and container['source'] == source['configure'] and type(container['conmon']) is dict,
            'Unknown original native container origin')
    if 'authority' in source:
        actor = source['authority']
        rootless_execution(container['execution'], actor, container['id'], container['conmon']['cgroup'])
        require(container['conmon'].get('uid') == actor['uid'] and source.get('imageUser') in ('1000', '1000:0'),
                'Original canonical actor/image namespace origin differs')
    require(type(database) is dict and set(database) == {'kind', 'containerId', 'image', 'source', 'querySha256', 'rowSha256'}
            and database['kind'] == 'keycloak-postgres-native-service-account-link'
            and r.HEX.fullmatch(database['containerId']) and re.fullmatch(r'sha256:[a-f0-9]{64}', database['image'])
            and database['source'] == source['postgres'] and database['querySha256'] == sha(SQL.encode())
            and database['rowSha256'] == sha(encoded(edge(value['nativeFinanceOwnership']))),
            'Unknown original native database export origin')
    for field in ('intentSha256', 'custodySha256'):
        require(type(value[field]) is str and r.HEX.fullmatch(value[field]), 'Invalid original Root CAS')
    return edge(value['nativeFinanceOwnership'])


# Read-only transaction. Native FK, NOT service-account username or custom marker.
# No credentials/passwords/users/realm export are returned by this projection.
SQL = """BEGIN READ ONLY;
SELECT COALESCE(json_agg(json_build_object('clientId',c.client_id,'clientUuid',c.id,'serviceAccountSubject',u.id)), '[]'::json)
FROM client c JOIN realm r ON r.id=c.realm_id JOIN user_entity u ON u.service_account_client_link=c.id AND u.realm_id=r.id
WHERE r.name='webservices' AND c.client_id='firefly-identity-reader';
COMMIT;"""
SQL_SCRIPT = 'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d keycloak -c "$1"'


def rootless_execution(value, actor, cid, conmon_cgroup):
    """Pure validation of an ORIGINAL Root-observed namespace frame, not an ID input."""
    require(type(actor) is dict and set(actor) == {'uid', 'gid', 'user', 'home', 'subuidStart', 'overflowUid'}
            and actor['uid'] == 780 and actor['user'] == 'webservices-lab-platform'
            and actor['home'] == '/home/' + actor['user'] and type(actor['gid']) is int and actor['gid'] > 0
            and type(actor['subuidStart']) is int and actor['subuidStart'] > 0,
            'Unknown original canonical platform authority')
    require(type(value) is dict and set(value) == {'pid', 'process', 'uidMap', 'gidMap', 'user', 'userns', 'mount'}
            and type(value['pid']) is int and value['pid'] > 0 and value['user'] == '1000:0'
            and value['userns'] in ('', 'private')
            and value['uidMap'] == [[0, actor['uid'], 1], [1, actor['subuidStart'], 65536]]
            and value['gidMap'] == [[0, actor['gid'], 1], [1, actor['subuidStart'], 65536]]
            and value['mount'] == dict(source=str(SLOT), target='/run/p0-finance', rw=False, type='bind'),
            'Original rootless configure USER/namespace/readonly mount differs')
    process = value['process']; manager = '/user.slice/user-780.slice/user@780.service/'
    require(type(process) is dict and set(process) == {'uid', 'gid', 'cgroup', 'startTicks'}
            and process['uid'] == actor['subuidStart'] + 999 and process['gid'] == actor['gid']
            and type(process['startTicks']) is int and process['startTicks'] > 0
            and conmon_cgroup.startswith(manager)
            and conmon_cgroup.split('/').count('webservices-keycloak-configure.service') == 1,
            'Original namespace process/account differs')
    group = process['cgroup']
    selected_scope = manager + 'user.slice/libpod-' + cid + '.scope'
    require(group == conmon_cgroup or group.startswith(conmon_cgroup + '/')
            or group == selected_scope or group.startswith(selected_scope + '/'), 'Foreign rootless process cgroup')
    return value


def finance_proc(pid, name):
    require(type(pid) is int and pid > 0 and name in ('uid_map', 'gid_map', 'status'), 'Invalid finance process scalar')
    fd = os.open('/proc/' + str(pid) + '/' + name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        body = os.read(fd, 65537)
        require(len(body) <= 65536, 'Oversized finance namespace scalar')
        return body.decode('ascii')
    finally: os.close(fd)


EXECUTION_FORMAT = ('{"id":{{json .Id}},"pid":{{json .State.Pid}},"user":{{json .Config.User}},'
    '"userns":{{json .HostConfig.UsernsMode}},"mounts":['
    '{{range .Mounts}}{{if eq .Destination "/run/p0-finance"}}'
    '{"source":{{json .Source}},"target":{{json .Destination}},"rw":{{json .RW}},"type":{{json .Type}}}'
    '{{end}}{{end}}]}')


class Native:
    """Only this source-bound canonical backend can mint RootFinanceResult."""
    def __init__(self, root, release, old):
        require(os.geteuid() == 0, 'Root collector required')
        self.root, self.release, self.old = Path(root), Path(release), old
        self.selection = n.Selection(self.root, self.release, old, 'starting')
        self.selection.deadline = time.monotonic() + 1800  # bounded original transaction, no retry
        self.binding = self.selection.snapshot(); self.selection.installed_sources()
        self.commands = self.selection.commands()
        profile = n.load('_finance_exact_reference_profile', 'verify-agent-vm-bundle.py')
        self.descriptor = profile.native_finance_reference(self.selection.ir, self.selection.domains)
        require(self.descriptor is not None, 'Exact selected finance reference descriptor required')
        self.actor = n.finance_actor(self.descriptor)
        scope = 'rootless-platform' if self.actor is not None else 'rootful'
        self.units = {}
        for name, role in (('keycloak-configure', 'oneshot'), ('postgres', 'daemon'), ('keycloak', 'daemon')):
            rows = [u for u in self.selection.plan if u.container == name]
            require(len(rows) == 1 and rows[0].scope == scope and rows[0].role == role,
                    'Exact selected native finance authorities required')
            self.units[name] = rows[0]
        service = self.selection.ir['services']['keycloak-configure']
        require(MOUNT in service.get('volumes', [])
                and service.get('environment', {}).get('FIREFLY_NATIVE_OWNERSHIP_FILE') == INPUT,
                'Source-sealed readonly Root metadata transport required')
        metadata = r.strict(n.read_file(self.release / 'bundle.json'))
        publisher_sha = sha(n.read_file(self.release / 'ops/native-finance-ownership.py'))
        require(metadata.get('liveOps', {}).get('ops/native-finance-ownership.py') == publisher_sha,
                'Exact source-pinned Root finance publisher required')
        self.publisher = dict(path='ops/native-finance-ownership.py', sha256=publisher_sha, origin='root-native-finance-ownership')
        self.source = {}
        for name in self.units:
            u = self.units[name]; props = self.props(name)
            identity = self.selection.source_identity(u, props['SourcePath'], props['FragmentPath'])
            require(identity == old['readiness']['loadedInputs'][u.scope][u.name], 'Loaded original source differs')
            image = old['readiness']['images'][u.scope][u.name]['configId']
            self.source['configure' if name == 'keycloak-configure' else name] = dict(identity, image=image)
        if self.actor is not None:
            unit = self.units['keycloak-configure']
            raw_user = self.selection.run([*self.commands[unit.scope][1], 'image', 'inspect', '--format',
                    '{{json .Config.User}}', '--', self.source['configure']['image']], timeout=self.selection.left()).stdout
            image_user = r.strict(raw_user)
            require(image_user in ('1000', '1000:0'), 'Pinned native configure image USER differs')
            self.source['authority'] = self.actor
            self.source['imageUser'] = image_user
        script = n.read_file(self.release / 'runtime/configs/keycloak/configure-finance.sh')
        require(sha(script) == FINANCE_SOURCE_SHA256, 'Exact reviewed finance producer/consumer source required')
        runtime = n.read_file(self.release / 'runtime/configs/keycloak/configure-runtime.sh')
        self.source['financeScriptSha256'] = sha(script)
        self.source['runtimeScriptSha256'] = sha(runtime)
        env = service.get('environment', {})
        domain = env.get('DOMAIN')
        # DOMAIN can be a sealed ENV reference. Resolve ONLY from Root persistent
        # original environment, whose actual custody is verified by Selection.
        if domain == '${DOMAIN}':
            if self.actor is None:
                raw = n.read_file(self.root / 'runtime-env/keycloak-configure.env', private=True)
            else:
                row = next(row for row in self.selection.domains['domains'] if row['name'] == 'platform')
                path = r.canonical(row['stateRoot']) / 'runtime-env/keycloak-configure.env'
                account = self.selection.account('rootless-platform')
                raw = n.read_file(path, owner=self.actor['uid'], private=True,
                                  directories=self.selection.actor_custody(account, path))
                handoff = old['domainRuntimeProjections']['platform']['environmentStoreHandoff']
                require(handoff.get('kind') == 'domain-persistent-environment' and handoff.get('domain') == 'platform'
                        and handoff.get('uid') == self.actor['uid'] and handoff.get('gid') == self.actor['gid']
                        and handoff.get('stateStore') == str(path.parent)
                        and handoff['files']['keycloak-configure.env']['sha256'] == sha(raw),
                        'Original platform persistent environment source differs')
            rows = [line[7:] for line in raw.decode().splitlines() if line.startswith('DOMAIN=')]
            require(len(rows) == 1, 'One original selected domain required'); domain = rows[0]
        require(type(domain) is str and re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*', domain)
                and env.get('KEYCLOAK_REALM') == 'webservices', 'Selected issuer/realm differs')
        self.issuer = 'https://keycloak.' + domain + '/realms/webservices'
        self.cas = self.binding['intentSha256']; self.boot = n.boot_id()

    def props(self, name):
        u = self.units[name]
        result = self.selection.run([*self.commands[u.scope][0], 'show', '--all', '--no-pager',
                  '--property=' + ','.join(r.PROPERTIES), '--', u.name], timeout=self.selection.left())
        rows = r.parse_show(result.stdout)
        require(set(rows) == {u.name}, 'Exact native unit query required')
        props = rows[u.name]
        require(props['LoadState'] == 'loaded' and props['DropInPaths'] == ''
                and props['ConditionResult'] == 'yes' and props['AssertResult'] == 'yes'
                and (props['Type'] == 'oneshot' if u.role == 'oneshot' else props['Type'] in ('notify', 'simple', 'exec')),
                'Original finance native execution overridden, skipped or unloaded')
        return props

    def recheck(self):
        require(self.selection.snapshot() == self.binding and self.selection.commands() == self.commands
                and n.boot_id() == self.boot and n.finance_actor(self.descriptor) == self.actor,
                'Finance source/store/account/Root CAS changed')
        self.selection.installed_sources()

    def live(self, name, props):
        u = self.units[name]
        raw = self.selection.run([*self.commands[u.scope][1], 'container', 'inspect', '--format',
                                  r.CONTAINER_FORMAT, '--', u.container], timeout=self.selection.left()).stdout
        lines = raw.splitlines(); require(len(lines) == 1, 'One original native container required')
        value = r.strict(lines[0])
        require(type(value) is dict and set(value) == r.CONTAINER_FIELDS and value['name'] == u.container
                and value['running'] is True and value['dead'] is False and value['restarting'] is False
                and value['status'] == 'running' and value['unit'] == u.name and r.HEX.fullmatch(value['id'])
                and n.normalize_image(value['image']) == self.source['configure' if name == 'keycloak-configure' else name]['image'],
                'Original running container/image differs')
        if u.role == 'daemon': self.selection.runtime_matches(u, props, value)
        account = self.selection.account(u.scope)
        uid = account.pw_uid if account else 0
        runtime = Path('/run/user') / str(uid) if account else Path('/run')
        cid_path = runtime / (u.name.removesuffix('.service') + '.cid')
        custody = self.selection.actor_custody(account, cid_path) if account else {}
        cid = n.read_file(cid_path, owner=uid, directories=custody, limit=128)
        require(cid.decode().strip() == value['id'], 'Original native CID differs')
        conmon = n.process_fields(value['conmonPid'], uid)
        require(props['ControlGroup'].endswith('/' + u.name)
                and (conmon['cgroup'] == props['ControlGroup'] or conmon['cgroup'].startswith(props['ControlGroup'] + '/')),
                'Original conmon is outside selected systemd invocation')
        require(n.process_fields(value['conmonPid'], uid) == conmon
                and n.read_file(cid_path, owner=uid, directories=custody, limit=128) == cid, 'Original conmon/CID changed')
        source = self.selection.source_identity(u, props['SourcePath'], props['FragmentPath'])
        source = dict(source, image=n.normalize_image(value['image']))
        require(source == self.source['configure' if name == 'keycloak-configure' else name], 'Original source changed')
        frame = dict(id=value['id'], image=n.normalize_image(value['image']), source=source, conmon=conmon)
        if name == 'keycloak-configure' and self.actor is not None:
            require(type(value['restartCount']) is int and value['restartCount'] == 0
                    and type(value['pid']) is int and value['pid'] > 0
                    and type(value['startedAt']) is str and bool(value['startedAt']), 'Original configure was restarted or has no native PID')
            frame['execution'] = self.execution(value['id'], props)
            require(frame['execution']['pid'] == value['pid'], 'Original native PID changed between projections')
        return frame

    def execution(self, cid, props):
        unit = self.units['keycloak-configure']
        def inspect():
            value = r.strict(self.selection.run([*self.commands[unit.scope][1], 'container', 'inspect', '--format',
                    EXECUTION_FORMAT, '--', cid], timeout=self.selection.left()).stdout)
            require(type(value) is dict and set(value) == {'id', 'pid', 'user', 'userns', 'mounts'}
                    and value['id'] == cid and type(value['mounts']) is list and len(value['mounts']) == 1,
                    'Exact original namespace container required')
            return value
        before = inspect(); pid = before['pid']
        process = n.process_fields(pid, self.actor['subuidStart'] + 999)
        status = finance_proc(pid, 'status')
        gids = [line.split()[1:] for line in status.splitlines() if line.startswith('Gid:')]
        require(gids == [[str(self.actor['gid'])] * 4], 'Original configure process group differs')
        def mapping(name):
            rows = [line.split() for line in finance_proc(pid, name).splitlines()]
            require(rows and all(len(row) == 3 and all(part.isdigit() for part in row) for row in rows),
                    'Unknown original namespace map')
            return [[int(part) for part in row] for row in rows]
        uid_map, gid_map = mapping('uid_map'), mapping('gid_map')
        frame = dict(pid=pid, process=dict(process, gid=self.actor['gid']), uidMap=uid_map, gidMap=gid_map,
                     user=before['user'], userns=before['userns'], mount=before['mounts'][0])
        rootless_execution(frame, self.actor, cid, props['ControlGroup'])
        require(inspect() == before and n.process_fields(pid, self.actor['subuidStart'] + 999) == process
                and mapping('uid_map') == uid_map and mapping('gid_map') == gid_map
                and finance_proc(pid, 'status') == status, 'Original namespace process changed')
        return frame

    def observe_original(self, custody):
        require(custody['bootId'] == self.boot, 'Original boot changed')
        while True:
            self.selection.left(); props = self.props('keycloak-configure')
            invocation = props['InvocationID']; start = r.natural(props['ExecMainStartTimestampMonotonic'])
            if invocation != custody['previousInvocationId'] and r.INVOCATION.fullmatch(invocation) and start >= custody['startMonotonicUSec']:
                break
            require(props['ActiveState'] != 'failed', 'Original configure failed before collection')
            time.sleep(.1)
        # A completed/removed invocation cannot be reconstructed from logs.
        require(props['ActiveState'] == 'activating' and props['SubState'] == 'start',
                'Original live configure CID missed; no logger/event backfill')
        original = self.live('keycloak-configure', props)
        while True:
            time.sleep(.1); now = self.props('keycloak-configure')
            require(now['InvocationID'] == invocation and r.natural(now['ExecMainStartTimestampMonotonic']) == start
                    and now['NRestarts'] == '0', 'Original invocation replayed/replaced')
            if now['ActiveState'] == 'activating':
                require(self.live('keycloak-configure', now) == original, 'Original container changed'); continue
            exit_us = r.natural(now['ExecMainExitTimestampMonotonic'])
            require(now['ActiveState'] == 'active' and now['SubState'] == 'exited' and now['Result'] == 'success'
                    and now['ExecMainCode'] == '1' and now['ExecMainStatus'] == '0'
                    and start < exit_us <= int(time.monotonic() * 1_000_000), 'Original configure did not succeed')
            break
        return dict(kind=ORIGIN_KIND, bootId=self.boot, invocationId=invocation,
                    startMonotonicUSec=start, exitMonotonicUSec=exit_us, container=original)

    def export_edge(self):
        # Bind BOTH the actual database container and actual selected Keycloak
        # daemon before/after native read-only projection. Never default engine.
        props = {name: self.props(name) for name in ('postgres', 'keycloak')}
        live = {name: self.live(name, props[name]) for name in props}
        for name in props:
            require(props[name]['ActiveState'] == 'active' and props[name]['Result'] == 'success', 'Native origin daemon unavailable')
        text = self.selection.run([*self.commands[self.units['postgres'].scope][1], 'exec', '--', live['postgres']['id'],
                   '/bin/sh', '-eu', '-c', SQL_SCRIPT, 'p0-native-finance', SQL], timeout=self.selection.left()).stdout
        rows = r.strict(text)
        require(type(rows) is list and len(rows) == 1, 'Unique original native Keycloak service-account link required')
        result = edge(rows[0])
        for name in props:
            require(self.props(name) == props[name] and self.live(name, props[name]) == live[name], 'Native export origin changed')
        return result, dict(kind='keycloak-postgres-native-service-account-link', containerId=live['postgres']['id'],
                            image=live['postgres']['image'], source=self.source['postgres'], querySha256=sha(SQL.encode()),
                            rowSha256=sha(encoded(result)))


def slot_directory(descriptor=None):
    # New dynamic namespace, never a repair of an existing foreign namespace.
    profile = n.finance_file_profile(descriptor)
    selected = n.load('_finance_slot_selection', 'native-selection.py')
    fd, pins = selected.walk_directory(SLOT.parent)
    try:
        created = False
        try:
            os.mkdir(SLOT.name, 0o700, dir_fd=fd); created = True
        except FileExistsError: pass
        child = os.open(SLOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            # Set permissions ONLY on this call's newly created namespace,
            # independent of Root's private umask. Never repair an existing one.
            if created:
                os.fchown(child, 0, profile['gid']); os.fchmod(child, profile['directoryMode']); os.fsync(child); os.fsync(fd)
            info = os.fstat(child)
            require(info.st_uid == 0 and info.st_gid == profile['gid']
                    and stat.S_IMODE(info.st_mode) == profile['directoryMode']
                    and not os.listxattr(child), 'Foreign dynamic Root finance directory')
            selected.unchanged(pins)
            require(n.identity(os.stat(SLOT.name, dir_fd=fd, follow_symlinks=False)) == n.identity(info),
                    'Dynamic finance directory replaced')
            return child
        except BaseException:
            os.close(child); raise
    finally: os.close(fd)


def publish_input(value, descriptor=None):
    profile = n.finance_file_profile(descriptor)
    fd = slot_directory(descriptor); temp = None
    try:
        names = set(os.listdir(fd))
        require(names <= {'input.json'}, 'Unclaimed dynamic finance metadata')
        if 'input.json' in names:
            previous = r.strict(n.read_file(SLOT / 'input.json'))
            require(previous.get('kind') == 'root-native-finance-input' and previous.get('root') == value['root'],
                    'Foreign/cross-root finance input; no adoption')
        temp = '.input-' + os.urandom(16).hex()
        leaf = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            body = encoded(value) + b'\n'; require(os.write(leaf, body) == len(body), 'Short dynamic input publication')
            os.fchown(leaf, 0, profile['gid']); os.fchmod(leaf, profile['fileMode']); os.fsync(leaf)
        finally: os.close(leaf)
        os.rename(temp, 'input.json', src_dir_fd=fd, dst_dir_fd=fd); temp = None; os.fsync(fd)
        require(n.identity(SLOT.lstat()) == n.identity(os.fstat(fd)) and set(os.listdir(fd)) == {'input.json'}
                and n.read_file(SLOT / 'input.json') == body, 'Dynamic finance publication replaced/raced')
    finally:
        if temp is not None: os.unlink(temp, dir_fd=fd)
        os.close(fd)


class RootFinanceReference:
    """Process-local original physical ownership cue for J and exact cold reset."""
    def __init__(self, key, backend, value):
        require(key is _KEY and type(backend) is Native, 'Canonical Root finance reference issuer required')
        self.backend = backend; self.value = encoded(value)
        physical = n.finance_reference_files(backend.descriptor)
        self.record = dict(schemaVersion=1, kind='root-native-finance-reference', status='completed',
                           root=str(backend.root), release=str(backend.release), inputs=value['inputs'],
                           intentSha256=sha(n.read_file(backend.root / '.install-intent.json', private=True)),
                           descriptor=backend.descriptor, publisher=backend.publisher, **physical)
        self.sealed = encoded(self.record)

    def recheck(self, value):
        require(encoded(value) == self.value and encoded(self.record) == self.sealed,
                'Finance reference typed result changed')
        n.lock_held(self.backend.root)
        raw = n.read_file(self.backend.root / '.install-intent.json', private=True)
        require(r.strict(raw) == value and sha(raw) == self.record['intentSha256']
                and n.read_file(self.backend.release / 'installation-receipt.json', private=True) == raw
                and n.finance_reference_files(self.backend.descriptor) == {k:self.record[k] for k in ('directory','input')},
                'Finance reference physical/current Root dual CAS changed')


class RootFinanceResult:
    def __init__(self, key, backend, action, record):
        require(key is _KEY and type(backend) is Native, 'Canonical process-local Root finance issuer required')
        self.backend, self.action = backend, action
        self.field = 'financeOwnershipCustody' if action == 'arm' else 'nativeFinanceOwnershipReceipt'
        self.record = r.strict(encoded(record)); self.sealed = encoded(record); self.closed = False; self.used = False

    def recheck(self):
        require(not self.closed and not self.used and encoded(self.record) == self.sealed, 'Consumed/changed finance result')
        self.backend.recheck()

    def publish(self, value):
        require(not self.closed and not self.used and value == dict(self.backend.old, **{self.field: self.record})
                and encoded(self.record) == self.sealed, 'Exact canonical finance dual-record publication required')
        root, release = self.backend.root, self.backend.release
        n.lock_held(root)
        raw = n.read_file(root / '.install-intent.json', private=True)
        require(r.strict(raw) == value and n.read_file(release / 'installation-receipt.json', private=True) == raw,
                'Finance publication dual CAS differs')
        self.backend.selection.prior = r.strict(encoded(value)); self.backend.selection.cas = sha(raw)
        current = self.backend.selection.snapshot()
        require({k: v for k, v in current.items() if k != 'intentSha256'} ==
                {k: v for k, v in self.backend.binding.items() if k != 'intentSha256'},
                'Finance source binding changed at publication')
        self.backend.selection.installed_sources()
        self.used = True
        prior = self.backend.old.get('nativeFinanceOwnershipReceipt') if self.action == 'arm' else self.record
        native = original_receipt(prior, self.backend.source, self.backend.issuer) if prior is not None else None
        # Capture has awaited original completion. Publish the admitted edge now
        # so ordinary retained stop/start (without replaying the installer) reads
        # it on its NEXT invocation. Only a file INSIDE the dynamic RO directory
        # is replaced; no sealed ENV/config/unit/reference inode is modified.
        content = dict(schemaVersion=1, kind='root-native-finance-input', root=str(root), release=str(release),
                       intentSha256=sha(raw), sourceSha256=FINANCE_SOURCE_SHA256, issuer=self.backend.issuer,
                       status='retained' if native is not None else 'fresh', nativeFinanceOwnership=native)
        transport = n.finance_transport(self.backend.descriptor)
        if transport is not None:
            content['transport'] = transport
            previous = self.backend.old.get('nativeFinanceReference')
            if previous is None:
                require(not (SLOT / 'input.json').exists(), 'Unclaimed rootless finance input; no adoption')
            else:
                require(n.finance_reference_files(self.backend.descriptor) ==
                        {key: previous[key] for key in ('directory', 'input')}, 'Original finance reference changed before publication')
        publish_input(content, self.backend.descriptor)
        require(n.read_file(root / '.install-intent.json', private=True) == raw
                and n.read_file(release / 'installation-receipt.json', private=True) == raw, 'Finance CAS changed during publication')
        reference = RootFinanceReference(_KEY, self.backend, value)
        reference.recheck(value)
        return reference

    def close(self):
        self.closed = True


def transact(root, release, old, action):
    require(action in ('arm', 'capture') and type(old) is dict and old.get('phase') == 'starting',
            'Only original starting arm/capture allowed')
    backend = Native(root, release, old)
    if action == 'arm':
        require('financeOwnershipCustody' not in old, 'Original finance collector already armed; no replay')
        prior = old.get('nativeFinanceOwnershipReceipt')
        if prior is not None: original_receipt(prior, backend.source, backend.issuer)
        props = backend.props('keycloak-configure')
        require(props['ActiveState'] in ('inactive', 'active') and props['SubState'] in ('dead', 'exited')
                and props['Job'] in ('', '0'), 'Original configure already running/queued')
        record = dict(schemaVersion=1, kind='root-finance-arm', status='armed', release=str(release), inputs=old['inputs'],
                      intentSha256=backend.cas, bootId=backend.boot, startMonotonicUSec=int(time.monotonic() * 1_000_000),
                      startRealtimeNSec=time.time_ns(), source=backend.source, previousInvocationId=props['InvocationID'],
                      priorReceiptSha256=sha(encoded(prior)) if prior is not None else None)
    else:
        custody = old.get('financeOwnershipCustody')
        require(type(custody) is dict and set(custody) == {'schemaVersion', 'kind', 'status', 'release', 'inputs',
                'intentSha256', 'bootId', 'startMonotonicUSec', 'startRealtimeNSec', 'source', 'previousInvocationId',
                'priorReceiptSha256'} and type(custody['schemaVersion']) is int and custody['schemaVersion'] == 1 and custody['kind'] == 'root-finance-arm'
                and custody['status'] == 'armed' and custody['release'] == str(release) and custody['inputs'] == old['inputs']
                and custody['source'] == backend.source, 'Exact Root original arm required')
        prior = old.get('nativeFinanceOwnershipReceipt')
        require(custody['priorReceiptSha256'] == (sha(encoded(prior)) if prior is not None else None), 'Original receipt changed')
        origin = backend.observe_original(custody)
        native, database = backend.export_edge()
        if prior is not None:
            require(native == original_receipt(prior, backend.source, backend.issuer), 'Original native relationship revoked/replaced')
            origin = prior['original']
        else: origin['database'] = database
        record = dict(schemaVersion=1, kind='root-native-finance-ownership', status='completed', release=str(release),
                      inputs=old['inputs'], intentSha256=backend.cas, custodySha256=sha(encoded(custody)),
                      issuer=backend.issuer, source=backend.source, original=origin, nativeFinanceOwnership=native,
                      activationAuthorized=False, readinessAuthorized=False, journalWritten=False)
        original_receipt(record, backend.source, backend.issuer)
    backend.recheck()
    return RootFinanceResult(_KEY, backend, action, record)
