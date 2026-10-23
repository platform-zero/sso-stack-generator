#!/usr/bin/env python3
"""Exact native runtime readiness, NOT application acceptance or admission.

Integration API: derive_plan(ir, domains, rendered) -> tuple[Unit, ...], then
verify_graph(plan, query_units=..., query_containers=..., recheck=...,
             source_matches=..., runtime_matches=..., attempt_start_us=..., ...). recheck MUST validate the existing
journal lock/CAS/current/receipt/marker and sealed rendered inputs; its immutable
JSON-compatible result is compared before every sample and after the final one.
No operation here starts, retries, resets, cancels, or commits anything.

JournalSelection is an optional fail-closed adapter to the existing journal. It
requires the journal owner to seal receipt.readiness = {bootId,
startMonotonicUSec, renderedInputs}. renderedInputs is the exact relative-path
SHA256 map for ALL quadlet files, including explicit empty-domain targets. Old
receipts without that authority are deliberately NOT sufficient. Callers holding
the canonical installer lock can instead supply an equivalent recheck callback.

The CLI validates an offline observation stream only; it never calls a host API.
Use the Python API with the existing lifecycle owner's selected runtime query
adapter for installed proof. An offline CLI pass is synthetic proof only.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time


class Refused(ValueError):
    """Safe metadata-only failure; never include raw command output."""


def require(ok, message):
    if not ok:
        raise Refused(message)


def strict(body):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite JSON')))


def sha(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    require(isinstance(value, (str, Path)), 'invalid absolute path')
    value = str(value)
    path = Path(value)
    require(path.is_absolute() and value == str(path) and '..' not in path.parts
            and not value.startswith('//'), 'noncanonical absolute path')
    return path


def relative(value):
    require(isinstance(value, str) and value and value == str(Path(value))
            and not Path(value).is_absolute() and '..' not in Path(value).parts,
            'noncanonical relative path')
    return value


def read_owned(path, *, owner=0, private=False, limit=8 * 1024 * 1024):
    """Descriptor-anchored, no links, bounded regular read; no chmod/adoption.

    Every ancestor must be root-owned and non-writable by group/other. Tests
    mock this reader rather than relaxing production ownership for temp roots.
    """
    path = canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe authority ancestor')
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(child)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                    and not info.st_mode & 0o022 and info.st_size <= limit
                    and (not private or stat.S_IMODE(info.st_mode) == 0o600),
                    'unsafe authority file')
            blocks = []; remaining = limit + 1
            while remaining:
                block = os.read(child, min(remaining, 65536))
                if not block: break
                blocks.append(block); remaining -= len(block)
            body = b''.join(blocks); after = os.fstat(child)
            require(len(body) == info.st_size and len(body) <= limit and
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    'authority changed during read')
            return body
        finally:
            os.close(child)
    finally:
        os.close(fd)


NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}')
HEX = re.compile(r'[a-f0-9]{64}')
INVOCATION = re.compile(r'[a-f0-9]{32}')


@dataclass(frozen=True)
class Unit:
    scope: str
    name: str
    role: str
    container: str
    health: bool
    source: str
    source_sha256: str
    image: str


def sections(body):
    """Read only identity/selection directives; never emit commands or envs."""
    require(isinstance(body, bytes) and len(body) <= 8 * 1024 * 1024, 'invalid rendered input')
    result = {}; section = None
    for line in body.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')): continue
        require(not line.endswith('\\'), 'continued rendered directive is unsupported')
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]; continue
        require(section and '=' in line, 'malformed rendered inventory')
        key, value = line.split('=', 1)
        result.setdefault((section, key), []).append(value)
    return result


def only(config, section, key, default=None):
    values = config.get((section, key), [])
    require(len(values) <= 1, 'duplicate identity directive')
    return values[0] if values else default


def derive_plan(ir, domains, rendered):
    """IR + exact sealed rendered inventory, never live target enumeration.

    rendered includes every quadlet/* file, keyed by bundle-relative path.
    Empty domains require all four targets with exactly empty subgroup Wants.
    On-demand containers and .build producers are hashed, but never expected up.
    """
    require(isinstance(ir, dict) and isinstance(domains, dict)
            and type(ir.get('schemaVersion')) is int and ir['schemaVersion'] == 1
            and type(domains.get('schemaVersion')) is int and domains['schemaVersion'] == 1,
            'unsupported selected inventory')
    require(domains.get('deploymentMode') == 'standalone' and 'venue' not in domains,
            'only standalone native authority is supported')
    services = ir.get('services'); rows = domains.get('domains')
    require(isinstance(services, dict) and services and isinstance(rows, list), 'empty selected inventory')
    scopes = {'rootful': None}; names = set(); users = set(); uids = set()
    for row in rows:
        name, user, uid = row.get('name'), row.get('user'), row.get('uid')
        require(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name)
                and isinstance(user, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                and type(uid) is int and uid > 0 and name not in names
                and user not in users and uid not in uids, 'invalid selected account identity')
        names.add(name); users.add(user); uids.add(uid)
        scopes['rootless-' + name] = row
    expected = {}; units = []; required_paths = set()
    for name, service in services.items():
        require(isinstance(name, str) and NAME.fullmatch(name) and isinstance(service, dict),
                'invalid selected service')
        role = service.get('lifecycle'); placement = service.get('placement')
        require(role in ('daemon', 'oneshot', 'on-demand') and placement in ('rootful', 'rootless'),
                'unknown selected role or placement')
        scope = 'rootful' if placement == 'rootful' else 'rootless-' + str(service.get('rootlessDomain'))
        require(scope in scopes, 'unknown selected manager')
        target = service.get('target', 'apps')
        require(target in ('core', 'apps', 'observability'), 'unknown selected target')
        unit = 'webservices-' + name + '.service'
        if role != 'on-demand': expected.setdefault((scope, target), set()).add(unit)
        managed = role != 'on-demand' or service.get('quadletManaged') is True or 'build' in service
        if not managed: continue
        path = 'quadlet/' + scope + '/webservices-' + name + '.container'
        required_paths.add(path)
        require(path in rendered, 'missing selected container inventory')
        config = sections(rendered[path])
        require(only(config, 'Container', 'ContainerName') == name, 'container identity differs from IR')
        wanted = only(config, 'Install', 'WantedBy')
        require(wanted == (None if role == 'on-demand' else 'webservices-' + target + '.target'),
                'selected container target differs from IR')
        image = only(config, 'Container', 'Image')
        require(isinstance(image, str) and image and not any(c.isspace() for c in image),
                'missing selected image identity')
        if 'build' in service and 'frozenBuildImage' not in service:
            expected_image = 'webservices-' + name + '.build'
        else:
            expected_image = service.get('image')
            require(isinstance(expected_image, str) and expected_image, 'missing IR image identity')
            if re.fullmatch(r'sha256:[a-f0-9]{64}', expected_image):
                require(service.get('updatePolicy', 'pinned') == 'pinned', 'mutable local image authority')
            elif '/' not in expected_image:
                expected_image = 'docker.io/library/' + expected_image
            elif not any(c in expected_image.split('/', 1)[0] for c in '.:') and expected_image.split('/', 1)[0] != 'localhost':
                expected_image = 'docker.io/' + expected_image
        require(image == expected_image, 'rendered image identity differs from IR')
        health = service.get('health') or {}
        require(isinstance(health, dict) and type(health.get('disable', False)) is bool, 'invalid health authority')
        test = health.get('test')
        if health and not health.get('disable', False):
            require(isinstance(test, list) and test and all(isinstance(t, str) for t in test)
                    and (test == ['NONE'] or (len(test) >= 2 and test[0] in ('CMD', 'CMD-SHELL'))),
                    'invalid selected health command')
        has_health = bool(test) and not health.get('disable', False) and test != ['NONE']
        require(bool(only(config, 'Container', 'HealthCmd')) == has_health, 'rendered health differs from IR')
        if role == 'oneshot':
            require(only(config, 'Service', 'Type') == 'oneshot'
                    and only(config, 'Service', 'RemainAfterExit') == 'yes'
                    and only(config, 'Service', 'Restart') == 'no', 'invalid required oneshot rendering')
        if 'build' in service:
            build = 'quadlet/' + scope + '/webservices-' + name + '.build'
            required_paths.add(build)
            require(build in rendered and ('Build', 'ImageTag') in sections(rendered[build]),
                    'missing selected build producer')
        if role != 'on-demand':
            units.append(Unit(scope, unit, role, name, has_health, path, sha(rendered[path]), image))
    for scope, row in scopes.items():
        for target in ('core', 'apps', 'observability', None):
            base = 'webservices' + ('-' + target if target else '') + '.target'
            path = 'quadlet/' + scope + '/' + base
            required_paths.add(path)
            require(path in rendered, 'missing explicit selected target inventory')
            config = sections(rendered[path]); values = config.get(('Unit', 'Wants'), [])
            wants = [value for line in values for value in line.split()]
            desired = expected.get((scope, target), set()) if target else {
                'webservices-core.target', 'webservices-apps.target', 'webservices-observability.target'}
            require(len(wants) == len(set(wants)) and set(wants) == desired,
                    'rendered target selection differs from IR')
        if row is not None:
            declared = row.get('services'); persistent = row.get('persistentServices')
            selected = {n for n, s in services.items() if s.get('placement') == 'rootless'
                        and s.get('rootlessDomain') == row['name']}
            daemons = {n for n in selected if services[n]['lifecycle'] == 'daemon'}
            require(isinstance(declared, list) and len(declared) == len(set(declared))
                    and set(declared) == selected and isinstance(persistent, list)
                    and len(persistent) == len(set(persistent)) and set(persistent) == daemons,
                    'domain inventory differs from IR')
    for path, body in rendered.items():
        relative(path); parts = Path(path).parts
        require(len(parts) == 3 and parts[0] == 'quadlet' and parts[1] in scopes,
                'rendered input escapes selected managers')
        if path not in required_paths:
            # Network producers are not expected running services. Reject any
            # extra service/build/target: do not silently enlarge selection.
            require(path.endswith('.network') and NAME.fullmatch(Path(path).stem)
                    and ('Network', 'NetworkName') in sections(body), 'unselected rendered workload')
    require(units, 'empty required running graph')
    return tuple(sorted(units, key=lambda u: (u.scope, u.name)))


PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Type', 'Result', 'Job',
              'InvocationID', 'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic',
              'ActiveEnterTimestampMonotonic', 'NRestarts', 'ExecMainCode', 'ExecMainStatus',
              'ConditionResult', 'AssertResult', 'MainPID', 'SourcePath', 'FragmentPath',
              'DropInPaths', 'ControlGroup')


def parse_show(text):
    """Parse systemctl show --property=... UNIT...; missing/duplicate rows fail."""
    require(isinstance(text, str) and len(text) <= 4 * 1024 * 1024, 'invalid unit response')
    result = {}; row = {}
    def finish():
        if row:
            require(set(row) == set(PROPERTIES) and row['Id'] not in result, 'incomplete or duplicate unit response')
            result[row['Id']] = dict(row); row.clear()
    for line in text.splitlines():
        if not line:
            finish(); continue
        require('=' in line, 'invalid unit property response')
        key, value = line.split('=', 1)
        require(key in PROPERTIES and key not in row, 'unexpected or duplicate unit property')
        row[key] = value
    finish()
    return result


def natural(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9]+', value), 'invalid numeric runtime property')
    return int(value)


def unit_identity(unit, props, attempt_start_us, observed_us, source_matches):
    require(set(props) == set(PROPERTIES) and props['Id'] == unit.name, 'unit identity mismatch')
    require(props['LoadState'] == 'loaded' and props['Result'] == 'success'
            and props['Job'] in ('', '0') and props['ConditionResult'] == 'yes'
            and props['AssertResult'] == 'yes' and props['DropInPaths'] == '',
            'unit unloaded, failed, queued, skipped or overridden')
    invocation = props['InvocationID']
    require(INVOCATION.fullmatch(invocation) and int(invocation, 16) != 0, 'missing invocation identity')
    start = natural(props['ExecMainStartTimestampMonotonic'])
    exit_time = natural(props['ExecMainExitTimestampMonotonic'])
    active_enter = natural(props['ActiveEnterTimestampMonotonic'])
    restarts = natural(props['NRestarts']); pid = natural(props['MainPID'])
    require(0 < start <= observed_us and start <= active_enter <= observed_us
            and exit_time <= observed_us and props['ExecMainStatus'] == '0',
            'unit has no successful execution or has impossible timestamps')
    require(source_matches(unit, props['SourcePath'], props['FragmentPath']) is True,
            'unit source ownership/hash mismatch')
    if unit.role == 'oneshot':
        require(props['Type'] == 'oneshot' and props['ActiveState'] == 'active'
                and props['SubState'] == 'exited' and props['ExecMainCode'] == '1'
                and start >= attempt_start_us and exit_time >= start and active_enter >= start
                and pid == 0 and restarts == 0, 'required oneshot not successfully invoked this attempt')
    else:
        require(props['Type'] in ('notify', 'simple', 'exec') and props['ActiveState'] == 'active'
                and props['SubState'] == 'running' and pid > 0 and exit_time == 0
                and props['ExecMainCode'] == '0' and props['ControlGroup'].startswith('/'),
                'daemon not cleanly running')
    return (invocation, start, exit_time, active_enter, restarts, pid,
            props['SourcePath'], props['FragmentPath'])


# The lifecycle-owned adapter must use Podman inspect --format with ONLY these
# fields, exact names/IDs and its already-validated rootful/rootless store.
# Never return full inspect JSON (contains envs, commands and health logs).
CONTAINER_FIELDS = {'name', 'id', 'unit', 'running', 'restarting', 'dead', 'status',
                    'healthConfigured', 'health', 'restartCount', 'startedAt', 'pid', 'conmonPid', 'image'}


def container_identity(unit, value):
    require(isinstance(value, dict) and set(value) == CONTAINER_FIELDS, 'incomplete container observation')
    require(value['name'] == unit.container and value['unit'] == unit.name
            and isinstance(value['id'], str) and HEX.fullmatch(value['id']), 'container identity mismatch')
    require(value['running'] is True and value['restarting'] is False and value['dead'] is False
            and value['status'] == 'running' and type(value['restartCount']) is int
            and value['restartCount'] >= 0 and type(value['pid']) is int and value['pid'] > 0
            and type(value['conmonPid']) is int and value['conmonPid'] > 0
            and isinstance(value['image'], str) and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', value['image'])
            and isinstance(value['startedAt'], str) and bool(value['startedAt']), 'container not cleanly running')
    require(type(value['healthConfigured']) is bool and value['healthConfigured'] == unit.health,
            'container health configuration differs from selection')
    require(value['health'] == ('healthy' if unit.health else ''), 'container health not proven')
    return (value['id'], value['restartCount'], value['startedAt'], value['pid'], value['conmonPid'],
            value['image'], value['health'])


# A projection, not full inspect: no environment, probe command/log, key or app body.
CONTAINER_FORMAT = ('{"name":{{json .Name}},"id":{{json .Id}},'
    '"unit":{{json (index .Config.Labels "PODMAN_SYSTEMD_UNIT")}},'
    '"running":{{.State.Running}},"restarting":{{.State.Restarting}},'
    '"dead":{{.State.Dead}},"status":{{json .State.Status}},'
    '"healthConfigured":{{if .Config.Healthcheck}}{{if .Config.Healthcheck.Test}}'
    '{{if ne (index .Config.Healthcheck.Test 0) "NONE"}}true{{else}}false{{end}}'
    '{{else}}false{{end}}{{else}}false{{end}},'
    '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}},'
    '"restartCount":{{.RestartCount}},"startedAt":{{json .State.StartedAt}},'
    '"pid":{{.State.Pid}},"conmonPid":{{.State.ConmonPid}},"image":{{json .Image}}}')


class SelectedQueries:
    """Bounded read-only queries through the journal owner's exact command plan.

    commands[scope] = (systemctl_argv_prefix, podman_argv_prefix), already bound
    by the owner to the selected UID/home/bus/storage roots/config. There is NO
    default rootful store, environment discovery, runuser guess or live inventory
    fallback. runner(argv, timeout=seconds) must capture stdout/stderr (never log
    them), enforce a timeout and return {returncode, stdout} as attributes.
    """
    def __init__(self, plan, commands, runner):
        self.plan = tuple(plan); self.runner = runner
        require(set(commands) == {u.scope for u in plan}, 'exact selected query authorities required')
        self.commands = {}
        for scope, prefixes in commands.items():
            require(isinstance(prefixes, (list, tuple)) and len(prefixes) == 2,
                    'invalid selected manager/store pair')
            systemctl, podman = prefixes
            require(isinstance(systemctl, (list, tuple)) and systemctl
                    and isinstance(podman, (list, tuple)) and podman
                    and all(isinstance(v, str) and v and '\x00' not in v for v in (*systemctl, *podman)),
                    'invalid selected query command authority')
            self.commands[scope] = (tuple(systemctl), tuple(podman))

    def run(self, args, remaining):
        require(type(remaining) in (int, float) and math.isfinite(remaining) and remaining > 0,
                'query deadline exhausted')
        try:
            result = self.runner(args, timeout=min(remaining, 20))
        except Exception:
            raise Refused('bounded selected runtime query failed') from None
        require(result.returncode == 0 and isinstance(result.stdout, str)
                and len(result.stdout) <= 4 * 1024 * 1024, 'selected runtime query incomplete')
        return result.stdout

    def units(self, scope, names, remaining):
        expected = {u.name for u in self.plan if u.scope == scope}
        require(scope in self.commands and len(names) == len(set(names)) and set(names) == expected,
                'unit query exceeds exact selection')
        return parse_show(self.run([*self.commands[scope][0], 'show', '--all', '--no-pager',
                                    '--property=' + ','.join(PROPERTIES), '--', *names], remaining))

    def containers(self, scope, names, remaining):
        expected = {u.container for u in self.plan if u.scope == scope and u.role == 'daemon'}
        require(scope in self.commands and expected and len(names) == len(set(names)) and set(names) == expected,
                'container query exceeds exact selection')
        text = self.run([*self.commands[scope][1], 'container', 'inspect', '--format',
                         CONTAINER_FORMAT, '--', *names], remaining)
        result = {}
        for line in text.splitlines():
            value = strict(line)
            require(isinstance(value, dict) and set(value) == CONTAINER_FIELDS
                    and value['name'] in expected and value['name'] not in result,
                    'invalid selected container projection')
            result[value['name']] = value
        require(set(result) == expected, 'selected container projection incomplete')
        return result


def frozen(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def verify_graph(plan, *, query_units, query_containers, recheck, source_matches, runtime_matches,
                 attempt_start_us, stable_seconds=10, timeout_seconds=120,
                 poll_seconds=1, clock=time.monotonic, sleep=time.sleep):
    """Bounded whole-graph sampling. No transient failure resets into success.

    query_units(scope, exact_names, remaining_seconds) -> {name: properties}
    query_containers(scope, exact_names, remaining_seconds) -> {name: safe_fields}
    Each sample uses forward and reverse whole-graph sweeps with identical
    identities. This is bounded polling, not an atomic host-wide snapshot: no
    claim is made about events invisible between observations. Trigger fencing
    and the final serialized admission remain the journal owner's obligation.
    Each callback MUST enforce that deadline on its subprocess. source_matches
    validates exact selected installed SourcePath/FragmentPath and source hash,
    without trusting manager output as authority. runtime_matches(unit, props,
    container) MUST bind the exact native CID receipt/conmon cgroup and selected
    pinned image ID through the lifecycle owner's runtime/store authority (a
    matching container name/label alone is not ownership). recheck is called immediately
    before and after every COMPLETE sample, including the final sample. This is
    readiness only: the lock-holding journal owner must recheck and commit active
    without releasing serialization. No persisted proof can authorize admission.
    """
    require(plan and len({(u.scope, u.name) for u in plan}) == len(plan), 'empty or duplicate readiness plan')
    require(type(attempt_start_us) is int and attempt_start_us > 0, 'attempt monotonic start required')
    for value in (stable_seconds, timeout_seconds, poll_seconds):
        require(type(value) in (int, float) and math.isfinite(value) and value > 0, 'invalid readiness bounds')
    require(stable_seconds < timeout_seconds and timeout_seconds <= 120 and poll_seconds <= stable_seconds,
            'readiness bounds exceed contract')
    started = clock(); deadline = started + timeout_seconds
    require(attempt_start_us <= int(started * 1_000_000), 'future attempt start')
    binding = frozen(recheck()); baseline = None; stable_start = None; samples = 0
    scopes = sorted({u.scope for u in plan})
    def remaining():
        left = deadline - clock()
        require(left > 0, 'whole graph readiness deadline exceeded')
        return left
    def observe(ordered_scopes):
        observation = []
        for scope in ordered_scopes:
            selected = [u for u in plan if u.scope == scope]
            names = tuple(u.name for u in selected)
            rows = query_units(scope, names, remaining())
            remaining()
            require(isinstance(rows, dict) and set(rows) == set(names), 'missing or extra selected unit query result')
            for unit in selected:
                observation.append(('unit', scope, unit.name, unit_identity(
                    unit, rows[unit.name], attempt_start_us, int(clock() * 1_000_000), source_matches)))
            daemons = [u for u in selected if u.role == 'daemon']
            if daemons:
                names = tuple(u.container for u in daemons)
                containers = query_containers(scope, names, remaining())
                remaining()
                require(isinstance(containers, dict) and set(containers) == set(names), 'missing or extra selected container query result')
                for unit in daemons:
                    container = containers[unit.container]
                    identity = container_identity(unit, container)
                    require(runtime_matches(unit, rows[unit.name], container) is True,
                            'container native owner or selected image mismatch')
                    observation.append(('container', scope, unit.container, identity))
        return sorted(observation)
    while True:
        remaining(); require(frozen(recheck()) == binding, 'selection authority changed')
        sample_start = clock()
        observation = observe(scopes)
        # Close in reverse manager order: earlier scopes may have failed while
        # a later manager/store was observed. Never admit on a one-way sweep.
        require(observe(reversed(scopes)) == observation, 'selected graph changed within observation')
        require(frozen(recheck()) == binding, 'selection authority changed during observation')
        now = clock(); remaining(); samples += 1
        if baseline is None:
            baseline = observation; stable_start = now
        else:
            require(observation == baseline, 'selected graph identity/restart/health changed')
        if samples >= 2 and sample_start - stable_start >= stable_seconds:
            require(frozen(recheck()) == binding, 'selection authority changed before return')
            remaining()
            return {'schemaVersion': 1, 'kind': 'native-runtime-readiness',
                    'applicationAcceptance': False, 'samples': samples,
                    'units': len(plan), 'stableSeconds': sample_start - stable_start,
                    'attemptStartMonotonicUSec': attempt_start_us,
                    'bindingSha256': sha(binding.encode()),
                    'planSha256': sha(frozen([vars(u) for u in plan]).encode())}
        sleep(min(poll_seconds, remaining()))


class JournalSelection:
    """Read-only bridge; journal/storage authority stays with the current owner.

    journal: existing install-journal module (never call its mutation methods).
    storage_binding(release): existing hardened journal/storage owner callback,
    validates scope/marker/accounts and returns immutable public identity pins,
    including scope (absolute string) and markerSha256. This adapter independently
    reads/hashes the root-owned marker too; it never creates/seals a data scope.
    pointer_matches(root, release): existing hardened current-pointer validator;
    only that native metadata pointer may be a symlink. All payload reads deny
    links. assert_locked(): verifies the CALLER holds the canonical installer lock.
    inventory_paths(release): owner's descriptor-safe exact quadlet file list.
    No plugin discovery, additional lock, daemon, or alternate root authority.
    """
    def __init__(self, root, expected_cas, *, journal, storage_binding, pointer_matches,
                 assert_locked, inventory_paths, boot_id, reader=read_owned):
        self.root = canonical(root); self.expected = expected_cas
        require(isinstance(expected_cas, str) and HEX.fullmatch(expected_cas), 'exact journal CAS required')
        self.journal = journal; self.storage_binding = storage_binding
        self.pointer_matches = pointer_matches; self.assert_locked = assert_locked
        self.inventory_paths = inventory_paths; self.boot_id = boot_id; self.reader = reader
        self.plan = None; self.attempt_start_us = None

    def snapshot(self):
        require(self.assert_locked() is True, 'canonical installer lock required')
        raw = self.reader(self.root / '.install-intent.json', private=True)
        require(sha(raw) == self.expected, 'native intent CAS changed')
        value = strict(raw)
        require(isinstance(value, dict) and type(value.get('schemaVersion')) is int
                and value['schemaVersion'] == 1 and value.get('phase') == 'starting',
                'native intent is not starting')
        release = canonical(value.get('release'))
        require(release.parent == self.root / 'releases', 'release escapes native root')
        require(self.pointer_matches(self.root, release) is True, 'selected current pointer changed')
        receipt = self.reader(release / 'installation-receipt.json', private=True)
        require(receipt == raw, 'native receipt/intent mismatch')
        inputs = value.get('inputs')
        require(isinstance(inputs, dict) and set(inputs) == set(self.journal.CORE_INPUTS + self.journal.PINNED_INPUTS),
                'expanded native input pins required')
        input_bodies = {}
        for name, digest in inputs.items():
            relative(name)
            try: body = self.reader(release / name)
            except FileNotFoundError:
                require(digest is None, 'missing canonical input'); continue
            require(isinstance(digest, str) and HEX.fullmatch(digest) and sha(body) == digest,
                    'canonical input hash changed')
            input_bodies[name] = body
        proof = value.get('readiness')
        require(isinstance(proof, dict) and set(proof) == {'bootId', 'startMonotonicUSec', 'renderedInputs'},
                'journal-sealed readiness inputs required')
        require(proof['bootId'] == self.boot_id() and isinstance(proof['bootId'], str) and proof['bootId'],
                'readiness attempt belongs to another boot')
        require(type(proof['startMonotonicUSec']) is int and proof['startMonotonicUSec'] > 0,
                'journal-sealed attempt start required')
        rendered_pins = proof['renderedInputs']
        require(isinstance(rendered_pins, dict) and rendered_pins, 'empty sealed rendered inventory')
        paths = self.inventory_paths(release)
        require(isinstance(paths, (list, tuple)) and len(paths) == len(set(paths))
                and set(paths) == set(rendered_pins), 'exact rendered inventory changed')
        rendered = {}
        for name, digest in rendered_pins.items():
            relative(name)
            require(len(Path(name).parts) == 3 and Path(name).parts[0] == 'quadlet'
                    and isinstance(digest, str) and HEX.fullmatch(digest), 'invalid rendered pin')
            body = self.reader(release / name)
            require(sha(body) == digest, 'sealed rendered unit hash changed')
            rendered[name] = body
        require(set(self.journal.CORE_INPUTS).issubset(input_bodies)
                and {'podman-domains.json', 'site/manifest.json'}.issubset(input_bodies),
                'required selected authority is absent')
        metadata = strict(input_bodies['podman-domains.json'])
        manifest = strict(input_bodies['site/manifest.json'])
        require(manifest.get('deploymentMode') == 'standalone' and
                canonical(manifest.get('installerStateRoot', '/var/lib/webservices')) == self.root and
                metadata.get('installerStateRoot') == str(self.root), 'native root authority differs from site')
        scope_config = manifest.get('storageScope')
        require(isinstance(scope_config, dict) and set(scope_config) == {'root', 'dataClass'}
                and scope_config['dataClass'] in ('synthetic', 'production')
                and metadata.get('storageScope') == scope_config, 'missing pinned storage scope')
        scope = canonical(scope_config['root'])
        require(scope != Path('/') and not scope.is_relative_to(self.root)
                and not self.root.is_relative_to(scope), 'native metadata/storage overlap')
        storage = self.storage_binding(release)
        require(isinstance(storage, dict) and storage.get('scope') == str(scope)
                and isinstance(storage.get('markerSha256'), str) and HEX.fullmatch(storage['markerSha256']),
                'missing selected storage/marker authority')
        marker_path = scope / '.stack-installation.json'
        require(sha(self.reader(marker_path, private=True)) == storage['markerSha256'],
                'selected storage marker hash changed')
        plan = derive_plan(strict(input_bodies['stack.ir.json']), metadata, rendered)
        if self.plan is not None: require(self.plan == plan, 'selected readiness plan changed')
        self.plan = plan; self.attempt_start_us = proof['startMonotonicUSec']
        # Check CAS again after all potentially expensive inventory work.
        require(sha(self.reader(self.root / '.install-intent.json', private=True)) == self.expected
                and sha(self.reader(release / 'installation-receipt.json', private=True)) == sha(receipt)
                and sha(self.reader(marker_path, private=True)) == storage['markerSha256']
                and self.pointer_matches(self.root, release) is True, 'native authority changed during read')
        return {'intentSha256': self.expected, 'receiptSha256': sha(receipt),
                'release': str(release), 'storage': storage, 'readiness': proof}


def main():
    parser = argparse.ArgumentParser(description='Offline native readiness fixture validation; NOT installed/app acceptance')
    parser.add_argument('--offline-fixture', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.offline_fixture.stat().st_size <= 8 * 1024 * 1024, 'oversized fixture')
        fixture = strict(args.offline_fixture.read_bytes())
        rendered = {name: text.encode() for name, text in fixture['rendered'].items()}
        plan = derive_plan(fixture['ir'], fixture['domains'], rendered)
        ticks = [float(fixture['attemptStartMonotonicUSec']) / 1_000_000 + 10]
        index = [0]
        def sleep(seconds): ticks[0] += seconds; index[0] += 1
        def sample():
            require(index[0] < len(fixture['samples']), 'offline evidence exhausted')
            return fixture['samples'][index[0]]
        result = verify_graph(plan, query_units=lambda s, n, t: sample()['units'][s],
                              query_containers=lambda s, n, t: sample()['containers'][s],
                              recheck=lambda: sample()['binding'],
                              source_matches=lambda u, s, f: s == u.source and f == u.name,
                              runtime_matches=lambda u, p, c: c['conmonPid'] == int(p['MainPID'])
                              and c['image'] == u.image,
                              attempt_start_us=fixture['attemptStartMonotonicUSec'],
                              stable_seconds=fixture.get('stableSeconds', 2),
                              clock=lambda: ticks[0], sleep=sleep)
        result['proofClass'] = 'synthetic-offline-only'
        print(json.dumps(result, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, AttributeError):
        parser.exit(1, 'native readiness refused (offline evidence; no admission)\n')


if __name__ == '__main__':
    main()
