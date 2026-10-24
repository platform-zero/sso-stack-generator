#!/usr/bin/env python3
"""Read-only exact native source selection; NOT admission or lifecycle authority.

inventory(bundle) returns scopes -> {uid,user,files,units,services,daemons,
oneshots,builds,networks,targets,persistent}. files keys are bundle-relative;
values contain sha256, kind (container/build/network/target), unit.
persistent means daemon + required oneshot,
NOT the historical domain persistentServices field (daemon-only).
selection(bundle, previous=None) unions exact IDs but keeps each release's file
hashes separately in sources. previous is an EXPLICIT caller-selected release,
never inferred from current, the environment, directory names or unit prefixes.
validate_installed(bundle, previous=None) checks only that exact union's install
destinations. It reads no service/cache/data state and changes nothing.

The existing installer MUST hold its canonical lock and bind candidate/previous
paths to its intent CAS, receipts, current pointer and storage marker before
using this plan, then recheck those bindings and these hashes before mutation.
This module cannot establish that an arbitrary root-owned release is selected.
A staged candidate need not have a receipt yet. Existing receipts, when present,
are checked against their source pins; --previous requires a receipt. A
retired-failed/retired-clean receipt is valid source custody, NOT permission to restart it.
No lock, account creation, subprocess, environment override or allow flag.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import stat
import sys

LIMIT = 8 * 1024 * 1024
MAX_FILES = 10000
MAX_TOTAL = 64 * 1024 * 1024
KINDS = ('units', 'services', 'daemons', 'oneshots', 'builds', 'networks', 'targets', 'persistent', 'files')
IDENTITIES = {name: (780 + i, 'webservices-lab-' + name)
              for i, name in enumerate(('platform', 'apps', 'homeassistant', 'finance', 'ci-runner', 'workloads', 'test-runners'))}
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}')
HEX = re.compile(r'[a-f0-9]{64}')
TARGETS = ('webservices-core.target', 'webservices-apps.target', 'webservices-observability.target', 'webservices.target')
SUFFIX = {'.container': ('services', '.service'), '.build': ('builds', '-build.service'),
          '.network': ('networks', '-network.service'), '.target': ('targets', '.target')}


class Refused(ValueError):
    """Metadata-only error: do not disclose source bodies or foreign file data."""


def require(ok, message):
    if not ok:
        raise Refused(message)


def canonical(value):
    require(isinstance(value, (str, Path)), 'invalid absolute path')
    text = str(value); path = Path(text)
    require(path.is_absolute() and text == str(path) and '..' not in path.parts
            and not text.startswith('//'), 'noncanonical absolute path')
    return path


def sha(body):
    return hashlib.sha256(body).hexdigest()


def strict(body):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def finite(text):
        value = float(text)
        require(math.isfinite(value), 'nonfinite JSON')
        return value
    try:
        return json.loads(body, object_pairs_hook=pairs, parse_float=finite,
                          parse_constant=lambda _: require(False, 'nonfinite JSON'))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused('invalid bounded JSON') from error


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_policy(path, info, actor=None):
    require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, 'unsafe authority directory')
    # Only these exact actor-home ancestors may be actor-owned. Never relax
    # /home itself, the sealed source, or any arbitrary actor-writable prefix.
    allowed = set()
    if actor is not None:
        uid, user = actor
        home = Path('/home') / user
        allowed = {home, home / '.config', home / '.config/containers',
                   home / '.config/containers/systemd', home / '.config/systemd',
                   home / '.config/systemd/user'}
    require(info.st_uid == 0 or (path in allowed and info.st_uid == actor[0]),
            'authority directory custody changed')
    require(not info.st_mode & 0o7000, 'special authority directory permissions')


def walk_directory(path, actor=None):
    """Return anchored fd and ancestor pins; missing paths never skip custody."""
    path = canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pins = []
    try:
        directory_policy(Path('/'), os.fstat(fd), actor)
        pins.append((Path('/'), identity(os.fstat(fd))))
        base = Path('/')
        for part in path.parts[1:]:
            base /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            directory_policy(base, os.fstat(fd), actor)
            pins.append((base, identity(os.fstat(fd))))
        return fd, pins
    except BaseException:
        os.close(fd)
        raise


def unchanged(pins):
    for path, pin in pins:
        require(identity(path.lstat()) == pin, 'authority ancestor changed during read')


def read_file(path, *, owner=0, actor=None, missing=False, private=False):
    """Bounded descriptor read; no symlinks, hardlinks, special/writable files.

    Missing destinations validate every existing ancestor, even when an earlier
    directory is absent. No caller-supplied path or ownership policy override.
    """
    path = canonical(path)
    if missing:
        # Walk component-by-component so a missing directory is distinguished
        # from an unsafe existing ancestor. lstat never follows a final link.
        for parent in reversed(path.parents):
            if parent == Path('/'):
                directory_policy(parent, parent.lstat(), actor)
                continue
            try:
                info = parent.lstat()
            except FileNotFoundError:
                # Recheck the whole existing prefix through descriptors.
                fd, pins = walk_directory(parent.parent, actor)
                try: unchanged(pins)
                finally: os.close(fd)
                return None
            directory_policy(parent, info, actor)
    fd, pins = walk_directory(path.parent, actor)
    try:
        try:
            child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            require(missing, 'missing sealed source file')
            unchanged(pins)
            return None
        try:
            before = os.fstat(child)
            mode = stat.S_IMODE(before.st_mode)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                    and mode in ((0o600,) if private else (0o400, 0o444, 0o600, 0o644))
                    and before.st_size <= LIMIT, 'unsafe selected file custody or size')
            body = bytearray()
            while len(body) <= LIMIT:
                block = os.read(child, min(65536, LIMIT + 1 - len(body)))
                if not block: break
                body.extend(block)
            require(len(body) == before.st_size and len(body) <= LIMIT
                    and identity(before) == identity(os.fstat(child))
                    and identity(path.lstat()) == identity(before), 'selected file changed during read')
            unchanged(pins)
            return bytes(body)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def children(path):
    fd, pins = walk_directory(path)
    try:
        names = sorted(os.listdir(fd))
        require(len(names) <= MAX_FILES, 'oversized source inventory')
        unchanged(pins)
        return names
    finally:
        os.close(fd)


def safe_name(value):
    require(isinstance(value, str) and NAME.fullmatch(value), 'invalid selected name')
    # A forged source cannot turn host control/lanes/original namespaces into
    # application selection. No template instances, escaped IDs or globs either.
    words = set(re.split(r'[-_.]+', value.lower()))
    require(not words.intersection({'p0', 'broker', 'lanes', 'lane', 'obelisks', 'control',
                                    'hostctl', 'dispatch', 'worklanes', 'auto', 'namespace', 'unit'})
            and not value.startswith(('webservices', 'platform-zero')),
            'protected namespace is not selectable')
    return value


def sections(body):
    result = {}; section = None
    try:
        text = body.decode('utf-8')
    except UnicodeError as error:
        raise Refused('nontext selected unit') from error
    require('\x00' not in text and '\r' not in text, 'invalid unit text')
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')): continue
        require(not line.endswith('\\'), 'continued selected directive unsupported')
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]; continue
        require(section is not None and '=' in line, 'malformed selected unit')
        key, value = line.split('=', 1)
        result.setdefault((section, key), []).append(value)
    require(not any(section == 'Install' and key in ('Alias', 'Also', 'RequiredBy', 'UpheldBy')
                    for section, key in result), 'foreign installation alias')
    return result


def only(config, section, key, default=None):
    rows = config.get((section, key), [])
    require(len(rows) <= 1, 'duplicate selection directive')
    return rows[0] if rows else default


def words(config, section, key):
    rows = [word for row in config.get((section, key), []) for word in row.split()]
    require(len(rows) == len(set(rows)), 'duplicate selected dependency')
    return set(rows)


def listed(value):
    require(isinstance(value, list) and all(isinstance(v, str) for v in value)
            and len(value) == len(set(value)), 'invalid declared service list')
    return set(value)


def inventory(bundle, *, previous=False):
    """Pure sealed-source plan. No passwd, installed-file, journal or data read."""
    bundle = canonical(bundle)
    require(bundle != Path('/'), 'root is not a release')
    inputs = {name: read_file(bundle / name) for name in ('bundle.json', 'stack.ir.json', 'podman-domains.json')}
    metadata = strict(inputs['bundle.json'])
    ir = strict(inputs['stack.ir.json'])
    domains = strict(inputs['podman-domains.json'])
    require(isinstance(metadata, dict) and metadata.get('backend') == 'podman'
            and isinstance(ir, dict) and type(ir.get('schemaVersion')) is int and ir['schemaVersion'] == 1
            and isinstance(domains, dict) and type(domains.get('schemaVersion')) is int
            and domains['schemaVersion'] == 1 and domains.get('deploymentMode') == 'standalone'
            and 'venue' not in domains, 'unsupported native source authority')
    services = ir.get('services'); rows = domains.get('domains')
    require(isinstance(services, dict) and services and isinstance(rows, list) and rows,
            'empty selected source graph')
    plan = {'rootful': {'uid': 0, 'user': 'root'}}
    for row in rows:
        require(isinstance(row, dict), 'invalid selected domain')
        name = row.get('name'); scope = 'rootless-' + str(name)
        require(isinstance(name, str) and name in IDENTITIES and type(row.get('uid')) is int
                and (row['uid'], row.get('user')) == IDENTITIES[name] and scope not in plan,
                'unreviewed domain identity')
        plan[scope] = {'uid': row['uid'], 'user': row['user']}
    require(set(children(bundle / 'quadlet')) == set(plan), 'source manager inventory differs')
    expected = {scope: {} for scope in plan}; membership = {}; selected = {}; running = 0
    network_ir = ir.get('networks', {})
    require(isinstance(network_ir, dict), 'invalid selected network authority')
    for name in network_ir: safe_name(name)
    used_networks = {scope: set() for scope in plan}
    for name, service in services.items():
        safe_name(name)
        require(isinstance(service, dict), 'invalid selected service')
        role = service.get('lifecycle'); placement = service.get('placement')
        require(role in ('daemon', 'oneshot', 'on-demand') and placement in ('rootful', 'rootless')
                and type(service.get('quadletManaged', False)) is bool, 'unknown selected service policy')
        scope = 'rootful' if placement == 'rootful' else 'rootless-' + str(service.get('rootlessDomain'))
        require(scope in plan, 'service has unselected domain')
        target = service.get('target', 'apps')
        require(target in ('core', 'apps', 'observability'), 'unknown selected target')
        selected[name] = (scope, service)
        if role != 'on-demand':
            running += 1
            membership.setdefault((scope, target), set()).add('webservices-' + name + '.service')
        networks = service.get('networks', [])
        require(isinstance(networks, (list, dict)), 'invalid selected service networks')
        networks = list(networks)
        require(all(isinstance(n, str) and n in network_ir for n in networks)
                and len(networks) == len(set(networks)), 'undeclared selected network')
        used_networks[scope].update(networks)
        # Previous-only stop/removal authority reflects its actual sealed
        # artifacts, not a newer compiler's emission policy. Historically the
        # un-managed on-demand build pair was absent. This never relaxes the
        # candidate closure or grants previous-only start/retry permission.
        if previous and role == 'on-demand' and service.get('quadletManaged') is not True:
            prefix = bundle / 'quadlet' / scope / ('webservices-' + name)
            container_exists = os.path.lexists(str(prefix) + '.container')
            build_exists = os.path.lexists(str(prefix) + '.build')
            require(container_exists == build_exists if 'build' in service else not container_exists,
                    'partial historical on-demand source pair')
            if not container_exists:
                continue
        managed = role != 'on-demand' or service.get('quadletManaged') is True or 'build' in service
        if managed:
            expected[scope]['webservices-' + name + '.container'] = ('services', role, name)
        if 'build' in service:
            require(isinstance(service['build'], dict), 'invalid selected build recipe')
            expected[scope]['webservices-' + name + '.build'] = ('builds', None, name)
    require(running, 'empty required selected graph')
    for row in rows:
        names = {name for name, (scope, _) in selected.items() if scope == 'rootless-' + row['name']}
        daemons = {name for name in names if services[name]['lifecycle'] == 'daemon'}
        require(listed(row.get('services')) == names and listed(row.get('persistentServices')) == daemons,
                'declared domain roles differ from IR')
    total = 0; count = 0
    for scope, entry in plan.items():
        for target in TARGETS: expected[scope][target] = ('targets', None, None)
        for name in used_networks[scope]: expected[scope]['webservices-' + name + '.network'] = ('networks', None, name)
        # The generator also emits its exact cross-domain egress bridge for
        # standalone actors. It is not a control/lane unit or a venue-only
        # service. Require an actual selected container reference; its network
        # identity is checked below just like declared application networks.
        if scope != 'rootful' and any(
                'webservices-p0-egress.network' in sections(read_file(bundle / 'quadlet' / scope / filename)).get(('Container', 'Network'), [])
                for filename in expected[scope] if filename.endswith('.container')):
            expected[scope]['webservices-p0-egress.network'] = ('networks', None, 'p0-egress')
        names = children(bundle / 'quadlet' / scope)
        require(set(names) == set(expected[scope]), 'unexpected or missing selected source file')
        entry.update({kind: [] for kind in KINDS if kind != 'files'}); entry['files'] = {}
        configs = {}
        for filename in names:
            path = bundle / 'quadlet' / scope / filename
            require(path.suffix in SUFFIX, 'unsupported source suffix')
            kind, role, name = expected[scope][filename]
            body = read_file(path); count += 1; total += len(body)
            require(count <= MAX_FILES and total <= MAX_TOTAL, 'oversized selected source graph')
            config = sections(body)
            configs[path.relative_to(bundle).as_posix()] = config
            unit = path.stem + SUFFIX[path.suffix][1]
            entry[kind].append(unit); entry['units'].append(unit)
            require(len(entry['units']) == len(set(entry['units'])), 'colliding selected generated unit IDs')
            relative = path.relative_to(bundle).as_posix()
            entry['files'][relative] = {'sha256': sha(body), 'kind': path.suffix[1:], 'unit': unit}
            if kind == 'services':
                service = services[name]
                require(only(config, 'Container', 'ContainerName') == name, 'selected container identity differs')
                if 'build' in service and 'frozenBuildImage' not in service:
                    image = 'webservices-' + name + '.build'
                else:
                    image = service.get('image')
                    require(isinstance(image, str) and image and not any(c.isspace() for c in image),
                            'missing selected image identity')
                    if re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                        require(service.get('updatePolicy', 'pinned') == 'pinned', 'mutable local image policy')
                    elif '/' not in image: image = 'docker.io/library/' + image
                    elif not any(c in image.split('/', 1)[0] for c in '.:') and image.split('/', 1)[0] != 'localhost':
                        image = 'docker.io/' + image
                require(only(config, 'Container', 'Image') == image, 'selected container image differs from IR')
                wanted = None if role == 'on-demand' else 'webservices-' + service.get('target', 'apps') + '.target'
                require(only(config, 'Install', 'WantedBy') == wanted, 'selected container role target differs')
                if role == 'oneshot':
                    require(only(config, 'Service', 'Type') == 'oneshot'
                            and only(config, 'Service', 'RemainAfterExit') == 'yes'
                            and only(config, 'Service', 'Restart') == 'no', 'required oneshot policy differs')
                else:
                    require(only(config, 'Service', 'Type') != 'oneshot', 'daemon/on-demand role differs')
                if role != 'on-demand': entry['persistent'].append(unit)
                if role == 'daemon': entry['daemons'].append(unit)
                if role == 'oneshot': entry['oneshots'].append(unit)
            elif kind == 'builds':
                require(only(config, 'Build', 'ImageTag') == 'localhost/webservices/' + name + ':bundle'
                        and only(config, 'Install', 'WantedBy') is None, 'selected build identity differs')
            elif kind == 'networks':
                prefix = 'webservices_' + (scope.removeprefix('rootless-') + '_' if scope != 'rootful' else '')
                require(only(config, 'Network', 'NetworkName') == prefix + name
                        and only(config, 'Install', 'WantedBy') is None, 'selected network identity differs')
            else:
                subgroup = filename.removeprefix('webservices-').removesuffix('.target')
                top = filename == 'webservices.target'
                desired = set(TARGETS) - {'webservices.target'} if top else membership.get((scope, subgroup), set())
                wanted = ('multi-user.target' if scope == 'rootful' else 'default.target') if top else 'webservices.target'
                require(words(config, 'Unit', 'Wants') == desired, 'selected target membership differs')
                require(only(config, 'Install', 'WantedBy') == wanted
                        and only(config, 'Unit', 'PartOf') == (None if top else 'webservices.target'),
                        'selected target installation policy differs')
        # Foreign dependency/alias directives cannot smuggle protected units into
        # exact start/stop propagation. Explicit source dependencies must remain
        # wholly inside the selected scope, including ordering-only references.
        for relative, config in configs.items():
            allowed = set(entry['units'])
            for (section, key), values in config.items():
                if section == 'Unit' and key in ('Requires', 'Wants', 'Requisite', 'BindsTo', 'PartOf', 'Conflicts',
                                                 'Upholds', 'PropagatesStopTo', 'StopPropagatedFrom', 'OnFailure', 'OnSuccess',
                                                 'JoinsNamespaceOf', 'After', 'Before'):
                    refs = {v for line in values for v in line.split()}
                    require(refs <= allowed, 'foreign selected unit dependency')
        for kind in KINDS:
            if kind != 'files': entry[kind].sort()
    # Whole-sweep hash/name recheck: do not return a mixed source snapshot.
    require(set(children(bundle / 'quadlet')) == set(plan), 'source scopes changed during inventory')
    for scope, entry in plan.items():
        require(set(children(bundle / 'quadlet' / scope)) == {Path(p).name for p in entry['files']},
                'source file set changed during inventory')
        for relative, info in entry['files'].items():
            require(sha(read_file(bundle / relative)) == info['sha256'], 'source changed during inventory')
    require(all(read_file(bundle / name) == body for name, body in inputs.items()),
            'source metadata changed during inventory')
    return dict(sorted(plan.items()))


def receipt_binding(bundle, plan, *, required=False):
    """Check available receipt source pins, not selection/current/marker/CAS."""
    raw = read_file(bundle / 'installation-receipt.json', missing=True, private=True)
    if raw is None:
        require(not required, 'previous selection requires a sealed receipt')
        return None
    value = strict(raw)
    require(isinstance(value, dict) and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1
            and value.get('release') == str(bundle)
            and value.get('phase') in ('preparing', 'units-selected', 'building', 'starting', 'active', 'failed', 'retired-failed', 'retired-clean'),
            'invalid selected source receipt')
    pins = value.get('inputs')
    require(isinstance(pins, dict) and {'bundle.json', 'stack.ir.json', 'podman-domains.json'} <= set(pins),
            'receipt missing source authority pins')
    for relative, digest in pins.items():
        require(isinstance(relative, str) and relative and str(Path(relative)) == relative
                and not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                'receipt source pin escapes release')
        # Do not read encrypted/private payloads just to make an inventory.
        # The journal owner remains responsible for its full canonical pins.
        if relative not in ('bundle.json', 'stack.ir.json', 'podman-domains.json'): continue
        require(isinstance(digest, str) and HEX.fullmatch(digest)
                and sha(read_file(bundle / relative)) == digest, 'receipt source hash changed')
    readiness = value.get('readiness')
    if readiness is not None:
        require(isinstance(readiness, dict) and readiness.get('renderedInputs') == {
            relative: info['sha256'] for entry in plan.values() for relative, info in entry['files'].items()},
            'receipt rendered source hashes changed')
    return {'sha256': sha(raw), 'phase': value['phase']}


def source_plan(bundle, *, previous=False):
    names = ('bundle.json', 'stack.ir.json', 'podman-domains.json')
    pins = {name: sha(read_file(bundle / name)) for name in names}
    plan = inventory(bundle, previous=previous)
    receipt = receipt_binding(bundle, plan, required=previous)
    require(pins == {name: sha(read_file(bundle / name)) for name in names},
            'source authority changed during selection')
    return {'bundle': str(bundle), 'inputs': pins, 'scopes': plan, 'receipt': receipt}


def selection(bundle, previous=None):
    bundle = canonical(bundle); previous = canonical(previous) if previous is not None else None
    require(previous != bundle, 'candidate and previous must be separate explicit releases')
    sources = {'candidate': source_plan(bundle)}
    if previous is not None:
        sources['previous'] = source_plan(previous, previous=True)
    union = {}
    for source in sources.values():
        plan = source['scopes']
        for scope, entry in plan.items():
            out = union.setdefault(scope, {'uid': entry['uid'], 'user': entry['user'],
                                          **{kind: [] for kind in KINDS}})
            require((out['uid'], out['user']) == (entry['uid'], entry['user']), 'previous scope identity drift')
            for kind in KINDS:
                out[kind] = sorted(set(out[kind]) | set(entry[kind]))
    return {'schemaVersion': 1, 'scopes': dict(sorted(union.items())), 'sources': sources,
            'selectionAuthority': 'caller-canonical-lock-journal-CAS-receipt-current-marker',
            'applicationAcceptance': False}


def destination(scope, entry, relative):
    filename = Path(relative).name
    if scope == 'rootful':
        parent = Path('/etc/systemd/system') if filename.endswith('.target') else Path('/etc/containers/systemd')
    else:
        home = Path('/home') / entry['user']
        parent = home / ('.config/systemd/user' if filename.endswith('.target') else '.config/containers/systemd')
    return parent / filename


def validate_installed(bundle, previous=None):
    """Validate exact candidate/previous destination union, never enumerate it.

    Absent destinations pass; present ones must match either selected release's
    exact bytes/hash AND expected owner/perms/no-link ancestry. No foreign unit
    bodies, similarly named files or other load-path overrides are discovered.
    The caller must separately reject loaded drop-ins/aliases/jobs through its
    canonical lifecycle/readiness owner before any unit operation.
    """
    result = selection(bundle, previous)
    expected = {}
    for source in result['sources'].values():
        for scope, entry in source['scopes'].items():
            for relative, info in entry['files'].items():
                path = destination(scope, entry, relative)
                item = expected.setdefault(path, {'uid': entry['uid'], 'user': entry['user'], 'hashes': set()})
                require((item['uid'], item['user']) == (entry['uid'], entry['user']), 'destination identity collision')
                item['hashes'].add(info['sha256'])
    absent = 0; identical = 0; checked = {}
    for path, item in sorted(expected.items()):
        actor = (item['uid'], item['user']) if item['uid'] else None
        if actor:
            try: account = pwd.getpwnam(item['user'])
            except KeyError: account = None
            # Missing accounts are normal before first installation, but an
            # existing actor account must have the exact fixed UID/home.
            if account is not None:
                require(account.pw_uid == item['uid'] and account.pw_dir == '/home/' + item['user'],
                        'installed actor account identity drift')
        body = read_file(path, owner=item['uid'], actor=actor, missing=True)
        if body is None: absent += 1
        else:
            require(not actor or account is not None, 'installed actor file has no bound account')
            require(sha(body) in item['hashes'], 'selected destination conflicts with sealed sources')
            identical += 1
        checked[str(path)] = {'uid': item['uid'], 'user': item['user'],
                              'sha256': sha(body) if body is not None else None}
    # Detect destination and source changes across the whole sweep as well.
    for path, pin in checked.items():
        actor = (pin['uid'], pin['user']) if pin['uid'] else None
        body = read_file(Path(path), owner=pin['uid'], actor=actor, missing=True)
        require((sha(body) if body is not None else None) == pin['sha256'],
                'installed destination changed during validation')
        if actor:
            try: account = pwd.getpwnam(pin['user'])
            except KeyError: account = None
            require((account is None and body is None) or (account is not None
                    and account.pw_uid == pin['uid'] and account.pw_dir == '/home/' + pin['user']),
                    'installed actor identity changed during validation')
    require(selection(bundle, previous) == result, 'selected source changed during installed validation')
    return {'schemaVersion': 1, 'validatedDestinations': len(expected), 'absent': absent,
            'byteIdentical': identical, 'destinations': checked,
            'applicationAcceptance': False, 'plan': result}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--scope')
    parser.add_argument('--kind', choices=KINDS)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--json', action='store_true')
    modes.add_argument('--validate-installed', action='store_true')
    args = parser.parse_args(argv)
    if args.json or args.validate_installed:
        if args.scope is not None or args.kind is not None: parser.error('JSON/validation modes do not take scope/kind')
    elif args.scope is None or args.kind is None:
        parser.error('exact --scope and --kind are required')
    try:
        if args.validate_installed:
            print(json.dumps(validate_installed(args.bundle, args.previous), sort_keys=True))
        else:
            plan = selection(args.bundle, args.previous)
            if args.json: print(json.dumps(plan, sort_keys=True))
            else:
                require(args.scope in plan['scopes'], 'unselected scope')
                for name in plan['scopes'][args.scope][args.kind]: print(name)
    except (ValueError, OSError) as error:
        # Never echo exception strings from JSON, OS paths or source contents.
        message = str(error) if isinstance(error, Refused) else 'unsafe or unavailable selected metadata'
        print('native-selection: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
