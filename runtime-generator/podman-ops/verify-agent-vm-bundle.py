#!/usr/bin/env python3
"""Fail-closed, read-only binding of a generated Latium bundle to its site VM pin.

The selected control/guest installers remain the only source-role mutation paths.
This check does not pretend that a stack activation has installed either role.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import os
import re
import stat
import subprocess


def strict(path, *, include_bytes=False, limit=65536):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError('Duplicate agent VM authority key')
            value[key] = item
        return value
    # Open only bundle inputs; never follow an ancestor/final link or read a
    # bind source. Installed root ownership/marker/CAS remain installer duties.
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError('Missing, linked or oversized agent VM input')
            body = stream.read(limit + 1)
    except OSError as error:
        raise ValueError('Missing or linked agent VM input') from error
    finally:
        os.close(fd)
    if len(body) > limit:
        raise ValueError('Oversized agent VM input')
    decoded = json.loads(body, object_pairs_hook=pairs)
    return (decoded, body) if include_bytes else decoded


def canonical_path(value):
    """Lexical admission only: do not resolve/stat any host bind source."""
    if (not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./@-]+', value)
            or value.startswith('//') or str(PurePosixPath(value)) != value
            or '..' in PurePosixPath(value).parts):
        raise ValueError('Standalone noncanonical bind/storage path')
    return PurePosixPath(value)


def overlaps(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def standalone_identities(domains):
    rows = domains.get('domains')
    if not isinstance(rows, list) or not rows:
        raise ValueError('Standalone journal UID scope needs domain identities')
    identities = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('name'), str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', row['name'])
                or row['name'] == 'rootful' or row['name'] in identities
                or type(row.get('uid')) is not int or row['uid'] <= 0
                or row['uid'] in identities.values()):
            raise ValueError('Standalone journal UID scope needs unique fixed identities')
        identities[row['name']] = row['uid']
    return identities


def standalone_journal_scope(services, domains):
    identities = standalone_identities(domains)
    expected_uid = '|'.join(str(v) for v in sorted({0, *identities.values()}))
    environment = services['alloy'].get('environment', {})
    if not isinstance(environment, dict) or environment.get('STACK_LOG_UID_REGEX') != expected_uid:
        raise ValueError('Standalone journal UID scope mismatch')
    pairs = []
    for name, service in sorted(services.items()):
        # Preserve the owning collector's financial exclusion independently of
        # its content filters: even the selected shared main DB stays private.
        if 'firefly' in name or name == 'postgres':
            continue
        unit = 'webservices-' + name + '[.]service'
        if service.get('placement', 'rootful') == 'rootful':
            pairs.append(unit + ';')
        else:
            uid = identities.get(service.get('rootlessDomain'))
            if uid is None:
                raise ValueError('Standalone journal unit scope has unknown domain')
            pairs.append('user@' + str(uid) + '[.]service;' + unit)
    expected_unit = '^(' + '|'.join(pairs) + ')$'
    if environment.get('STACK_LOG_UNIT_REGEX') != expected_unit:
        raise ValueError('Standalone journal unit scope mismatch')


def standalone_mount(mount):
    if isinstance(mount, str):
        parts = mount.split(':')
        if len(parts) not in (2, 3) or not all(parts):
            raise ValueError('Standalone ambiguous mount')
        source, target = parts[:2]
        options = parts[2].split(',') if len(parts) == 3 else []
        if (len(set(options)) != len(options) or any(o not in
                ('ro', 'rw', 'z', 'Z', 'U', 'bind', 'rbind', 'nodev', 'noexec', 'nosuid') for o in options)
                or ('ro' in options and 'rw' in options)):
            raise ValueError('Standalone ambiguous mount options')
        read_only = 'ro' in options
    elif isinstance(mount, dict):
        if (set(mount) - {'source', 'target', 'read_only', 'type'}
                or type(mount.get('read_only', False)) is not bool
                or mount.get('type', 'bind') not in ('bind', 'volume')):
            raise ValueError('Standalone ambiguous mount object')
        source, target = mount.get('source'), mount.get('target')
        read_only = mount.get('read_only', False)
        options = ['ro'] if read_only else []
    else:
        raise ValueError('Standalone invalid mount')
    if not isinstance(source, str) or not source or not isinstance(target, str):
        raise ValueError('Standalone invalid mount endpoints')
    canonical_path(target.rstrip('/') or '/')
    return source, target.rstrip('/') or '/', read_only, options


NATIVE_FINANCE_SOURCE = '/var/lib/webservices-native-finance'
NATIVE_FINANCE_TARGET = '/run/p0-finance'


def native_finance_reference(ir):
    """Exact source descriptor only, NEVER physical custody or execution permission.

    Old releases without this feature remain unchanged. No parent/prefix/alias,
    other service, writable bind or site-editable identity value is admitted.
    """
    services = ir.get('services', {})
    selected = []
    for name, service in services.items():
        for mount in service.get('volumes', []):
            source, target, ro, options = standalone_mount(mount)
            touches = source.startswith('/') and overlaps(canonical_path(source), PurePosixPath(NATIVE_FINANCE_SOURCE))
            if touches or target == NATIVE_FINANCE_TARGET or target.startswith(NATIVE_FINANCE_TARGET + '/'):
                if (name != 'keycloak-configure' or source != NATIVE_FINANCE_SOURCE
                        or target != NATIVE_FINANCE_TARGET or not ro or options != ['ro']
                        or service.get('placement') != 'rootful' or service.get('lifecycle') != 'oneshot'):
                    raise ValueError('Exact readonly Root native finance reference required')
                selected.append(name)
        environment = service.get('environment', {})
        if 'FIREFLY_NATIVE_OWNERSHIP_FILE' in environment and (name != 'keycloak-configure'
                or environment['FIREFLY_NATIVE_OWNERSHIP_FILE'] != NATIVE_FINANCE_TARGET + '/input.json'):
            raise ValueError('Native finance metadata reference cannot be site editable')
    if not selected:
        if any('FIREFLY_NATIVE_OWNERSHIP_FILE' in s.get('environment', {}) for s in services.values()):
            raise ValueError('Native finance readonly reference mount missing')
        return None
    if (selected != ['keycloak-configure'] or services['keycloak-configure'].get('environment', {}).get(
            'FIREFLY_NATIVE_OWNERSHIP_FILE') != NATIVE_FINANCE_TARGET + '/input.json'
            or not {'postgres', 'keycloak', 'firefly-identity-check'} <= services.keys()):
        raise ValueError('Native finance reference selected cohort differs')
    return dict(schemaVersion=1, kind='native-finance-reference-descriptor', service='keycloak-configure',
                placement='rootful', lifecycle='oneshot', source=NATIVE_FINANCE_SOURCE,
                target=NATIVE_FINANCE_TARGET, readOnly=True, file='input.json',
                publisher='ops/native-finance-ownership.py', origin='root-native-finance-ownership')


def standalone_boundaries(ir, domains, scope):
    services, volumes = ir.get('services'), ir.get('volumes', {})
    if not isinstance(services, dict) or not isinstance(volumes, dict):
        raise ValueError('Standalone service/volume inventory missing')
    for name, service in services.items():
        if (not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,95}', name) or not isinstance(service, dict)
                or service.get('placement', 'rootful') not in ('rootful', 'rootless')
                or not isinstance(service.get('volumes', []), list)):
            raise ValueError('Standalone invalid selected service')
    if any(s.get('placement') == 'rootless' for s in services.values()):
        identities = standalone_identities(domains)
        if any(s.get('rootlessDomain') not in identities for s in services.values()
               if s.get('placement') == 'rootless'):
            raise ValueError('Standalone service has unknown selected domain')
    paths = {}
    for name, volume in volumes.items():
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or not isinstance(volume, dict)):
            raise ValueError('Standalone invalid named volume')
        if 'hostPath' in volume:
            paths[name] = canonical_path(volume['hostPath'])
            if not paths[name].is_relative_to(scope) or paths[name] == scope:
                raise ValueError('Standalone volume escapes selected storage scope')
    # Classification is lexical source proof only. Actual Root publisher/CAS,
    # inode/ACL/mount custody is observed after arm before original consumption.
    native_finance_reference(ir)
    protected = {}
    for name in ('caddy_certs', 'caddy_ca', 'mail_tls'):
        if name in volumes:
            if name not in paths:
                raise ValueError('Standalone trust volume needs scoped hostPath')
            protected[name] = paths[name]
    if 'caddy' in services:
        if (services['caddy'].get('placement') != 'rootful'
                or not {'caddy_certs', 'caddy_ca'} <= protected.keys()):
            raise ValueError('Standalone signing store requires selected rootful Caddy')
    if 'mailserver' in services and ('caddy' not in services or
            not {'caddy_certs', 'caddy_ca', 'mail_tls'} <= protected.keys()):
        raise ValueError('Standalone mail delegation requires selected trust volumes')
    if len(set(protected.values())) != len(protected) or any(
            overlaps(a, b) for n, a in protected.items() for m, b in protected.items() if n != m):
        raise ValueError('Standalone trust storage roots overlap')
    for name in ('caddy_ca', 'mail_tls'):
        if name in protected and (volumes[name].get('rootlessStrategy') != 'shared'
                                  or volumes[name].get('rootlessAccess') != 'read-only'):
            raise ValueError('Standalone public trust/delegation must be host read-only')
    if 'caddy_certs' in protected and (volumes['caddy_certs'].get('rootlessStrategy', 'copy') != 'copy'
                                      or 'rootlessAccess' in volumes['caddy_certs']):
        raise ValueError('Standalone signing store cannot grant rootless access')
    managed = [PurePosixPath(p) for p in ('/run/p0-control', '/run/p0-lanes',
               '/run/platform-zero', '/var/lib/platform-zero')]
    mounts = {}
    for name, service in services.items():
        mounts[name] = []
        for mount in service.get('volumes', []):
            source, target, ro, options = standalone_mount(mount)
            logical = source if source in volumes else None
            if logical:
                source_path = paths.get(source)
                if source_path is None:
                    raise ValueError('Standalone named volume lacks hostPath')
            elif source.startswith('/'):
                source_path = canonical_path(source)
            else:
                # Generated config binds and the selected user-runtime Podman
                # socket are the only supported non-absolute bind spellings.
                if source.startswith('./'):
                    canonical_path('/' + source[2:])
                    if not source.startswith(('./configs/', './build/', './repos/', './stack.')) and source != './repos':
                        raise ValueError('Standalone unreviewed relative bind')
                elif source == '%t/podman/podman.sock' and service.get('placement') == 'rootless':
                    pass
                else:
                    raise ValueError('Standalone unresolved bind or named volume')
                source_path = None
            if source_path is not None:
                if (any(overlaps(source_path, p) for p in managed)
                        or any(p in ('lanes', 'worklanes', 'worklane', '.worklane', 'p0-lanes', 'p0-control')
                               for p in source_path.parts)):
                    raise ValueError('Standalone host cannot mount managed control sockets or lanes')
                if (source_path.is_relative_to('/var/run') or source_path.is_relative_to('/proc')
                        or source_path.is_relative_to('/dev/fd')):
                    raise ValueError('Standalone noncanonical host bind alias')
                if overlaps(source_path, PurePosixPath('/var/log/webservices/caddy')):
                    raise ValueError('Standalone private ingress log root cannot reuse old host logs')
            for authority, root in protected.items():
                if logical != authority and (source_path is None or not overlaps(source_path, root)):
                    continue
                # Aliased names still carry the declared hostPath authority,
                # even where a generic rootless copier would create a copy.
                exact = source_path == root
                publisher = name == 'caddy' and service.get('placement') == 'rootful'
                if authority in ('caddy_ca', 'mail_tls') and logical and not publisher:
                    policy = volumes[logical]
                    if (policy.get('rootlessStrategy') != 'shared'
                            or policy.get('rootlessAccess') != 'read-only'):
                        raise ValueError('Standalone trust/delegation alias must remain host read-only')
                if authority == 'caddy_certs':
                    if not (publisher and exact and target == '/certs' and not set(options) - {'ro', 'rw'}):
                        raise ValueError('Standalone signing store consumer boundary')
                elif authority == 'caddy_ca':
                    if publisher and exact and target == '/ca' and not set(options) - {'ro', 'rw'}:
                        pass
                    elif (not ro or set(options) != {'ro'} or source_path not in
                          (root, root / 'caddy-ca.crt')):
                        raise ValueError('Standalone public trust consumer must be read-only')
                elif not (name == 'mailserver' and exact and target == '/caddy-mail'
                          and ro and set(options) == {'ro'}):
                    raise ValueError('Standalone mail leaf consumer boundary')
            mounts[name].append((source_path, target, ro))
    if 'caddy' in services:
        if not any(p == protected['caddy_certs'] and t == '/certs' for p, t, _ in mounts['caddy']):
            raise ValueError('Standalone signing store mount missing from selected Caddy')
        if not any(p == protected['caddy_ca'] and t == '/ca' for p, t, _ in mounts['caddy']):
            raise ValueError('Standalone public trust publisher mount missing')
    if 'mailserver' in services:
        mail = services['mailserver']
        if mail.get('placement') == 'rootless':
            identities = standalone_identities(domains)
            if mail.get('rootlessDomain') not in identities:
                raise ValueError('Standalone mail leaf has unknown selected domain')
        elif mail.get('placement') != 'rootful':
            raise ValueError('Standalone mail leaf has unknown placement')
        if (protected['mail_tls'], '/caddy-mail', True) not in mounts['mailserver']:
            raise ValueError('Standalone mail leaf delegation mount missing')
    if 'alloy' in services:
        standalone_journal_scope(services, domains)
    return mounts


def verify_live_ops(bundle, metadata):
    """Validate emitted helper bytes; missing legacy maps grant no execution."""
    if 'liveOps' not in metadata:
        return None
    pins = metadata['liveOps']
    if (not isinstance(pins, dict) or not 0 < len(pins) <= 256
            or any(not isinstance(name, str) or not re.fullmatch(r'ops/[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                   or not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{64}', sha)
                   for name, sha in pins.items())):
        raise ValueError('Invalid emitted native helper pins')
    ops = bundle / 'ops'
    if not stat.S_ISDIR(ops.lstat().st_mode): raise ValueError('Native helper directory is linked or absent')
    expected = {name.removeprefix('ops/') for name in pins}
    if {path.name for path in ops.iterdir()} != expected:
        raise ValueError('Native helper namespace differs from pins')
    for name, sha in sorted(pins.items()):
        path = bundle / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 8 * 1024 * 1024:
                raise ValueError('Unsafe emitted native helper')
            digest = hashlib.sha256(); length = 0
            while True:
                body = os.read(fd, 65536)
                if not body: break
                length += len(body)
                if length > 8 * 1024 * 1024: raise ValueError('Native helper grew during verification')
                digest.update(body)
            # A legitimate first read may update atime (notably after the
            # generator chmods normalized output). Keep every security/content
            # identity field, including nanosecond mtime/ctime, but not atime.
            def identity(info):
                return tuple(getattr(info, field) for field in (
                    'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                    'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
            if (digest.hexdigest() != sha or identity(os.fstat(fd)) != identity(before)
                    or identity(path.lstat()) != identity(before)):
                raise ValueError('Emitted native helper SHA/inode changed')
        finally: os.close(fd)
    if {path.name for path in ops.iterdir()} != expected:
        raise ValueError('Native helper namespace changed during verification')
    return pins


def standalone_metadata_source(bundle, control=None):
    """Canonical source/profile custody only; NEVER application mount admission.

    Used by the metadata-privacy owner, whose only mutation is0755->0700 on
    its held Root FD. Normal verify() still enforces every application boundary.
    """
    manifest, manifest_bytes = strict(bundle / 'site/manifest.json', include_bytes=True)
    if manifest.get('deploymentMode') != 'standalone' or control is not None or 'agentVmSpec' in manifest:
        raise ValueError('Standalone metadata source cannot manage control/guest roles')
    for name in ('site/agent-vm.json', 'site/agent-vm.provenance.json',
                 'maintenance-workspaces.json', 'software-workspaces.json'):
        path = bundle / name
        if path.exists() or path.is_symlink():
            raise ValueError('Standalone host includes managed role inputs')
    domains = strict(bundle / 'podman-domains.json')
    metadata = strict(bundle / 'bundle.json')
    verify_live_ops(bundle, metadata)
    provenance, provenance_bytes = strict(bundle / 'source-provenance.json', include_bytes=True)
    ir, ir_bytes = strict(bundle / 'stack.ir.json', include_bytes=True, limit=8 * 1024 * 1024)
    if (domains.get('deploymentMode') != 'standalone' or 'venue' in domains
            or metadata.get('deploymentMode') != 'standalone' or metadata.get('backend') != 'podman'
            or provenance.get('manifestSha256') != hashlib.sha256(manifest_bytes).hexdigest()
            or metadata.get('sourceProvenanceSha256') != hashlib.sha256(provenance_bytes).hexdigest()
            or metadata.get('irSha256') != hashlib.sha256(ir_bytes).hexdigest()):
        raise ValueError('Standalone host provenance/profile binding mismatch')
    state_root = manifest.get('installerStateRoot', '/var/lib/webservices')
    if (not isinstance(state_root, str)
            or not re.fullmatch(r'/var/lib/(?:webservices|stack-[a-z0-9-]{1,48})', state_root)
            or domains.get('installerStateRoot', '/var/lib/webservices') != state_root):
        raise ValueError('Standalone installer state root binding mismatch')
    scope = manifest.get('storageScope')
    if (not isinstance(scope, dict) or set(scope) != {'root', 'dataClass'}
            or scope.get('dataClass') not in ('synthetic', 'production')
            or not isinstance(scope.get('root'), str)
            or not re.fullmatch(r'/[A-Za-z0-9_./-]+', scope['root'])
            or scope['root'] == '/' or '..' in Path(scope['root']).parts
            or str(Path(scope['root'])) != scope['root'] or domains.get('storageScope') != scope):
        raise ValueError('Standalone storage scope binding mismatch')
    if Path(state_root).is_relative_to(scope['root']) or Path(scope['root']).is_relative_to(state_root):
        raise ValueError('Installer metadata and application scope overlap')
    return manifest, domains, ir, scope


def verify(bundle, control=None):
    site = bundle / 'site'
    manifest, manifest_bytes = strict(site / 'manifest.json', include_bytes=True)
    mode = manifest.get('deploymentMode')
    if mode is not None and mode != 'standalone':
        raise ValueError('Unknown deployment mode')
    if mode == 'standalone':
        manifest, domains, ir, scope = standalone_metadata_source(bundle, control)
        mounts = standalone_boundaries(ir, domains, canonical_path(scope['root']))
        services = ir['services']
        if 'caddy' in services:
            ca = ir.get('volumes', {}).get('caddy_ca', {}).get('hostPath')
            log_root = domains.get('caddyLogRoot')
            if (not isinstance(ca, str) or not Path(ca).is_absolute() or '..' in Path(ca).parts
                    or log_root != str(Path(ca).parent / '_logs' / 'caddy')
                    or (PurePosixPath(log_root), '/var/log/caddy', False) not in mounts['caddy']):
                raise ValueError('Standalone private ingress log root mismatch')
        return {'site': manifest.get('site'), 'agentVm': 'not-managed',
                'deploymentMode': 'standalone', 'rolesActivated': False}
    if manifest.get('site') != 'latium':
        return {'site': manifest.get('site'), 'agentVm': 'not-applicable'}
    if manifest.get('agentVmSpec') != 'agent-vm.json':
        raise ValueError('Latium requires exact site-owned agent-vm.json')
    vm_path = site / 'agent-vm.json'
    metadata = strict(site / 'agent-vm.provenance.json')
    vm, body = strict(vm_path, include_bytes=True)
    digest = hashlib.sha256(body).hexdigest()
    pins = vm.get('runtime')
    if (set(metadata) != {'schemaVersion', 'path', 'sha256', 'controlCommit'}
            or type(metadata['schemaVersion']) is not int or metadata['schemaVersion'] != 1
            or metadata['path'] != 'agent-vm.json' or metadata['sha256'] != digest
            or not isinstance(pins, dict) or metadata['controlCommit'] != pins.get('controlCommit')):
        raise ValueError('Agent VM bundle provenance mismatch')
    required = {'schemaVersion', 'name', 'network', 'networkConfig', 'vcpus', 'memoryMiB',
                'osGiB', 'workGiB', 'swapGiB', 'cloudImage', 'debianSnapshot', 'packages',
                'runtime', 'projectLanes', 'gpuDevices', 'reserves'}
    domains = strict(bundle / 'podman-domains.json')
    venue = domains.get('venue')
    port_override = vm.get('servicePorts')
    if venue is None:
        if port_override is not None or set(vm) != required:
            raise ValueError('Legacy guest cannot use unbound service ports')
    else:
        mapping = venue.get('portMap') if isinstance(venue, dict) else None
        if (set(vm) != required | {'servicePorts', 'diskRoot'} or not isinstance(mapping, dict)
                or vm.get('name') != vm.get('network','') + '-agents'
                or vm.get('diskRoot') != '/mnt/lab_debian/agent_vm/' + vm.get('name','')
                or not isinstance(port_override, dict) or set(port_override) != {'https','imap','smtp'}
                or not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}', vm.get('network',''))
                or any(type(port_override[key]) is not int or port_override[key] != mapping.get(source)
                       for key, source in (('https','443'),('imap','993'),('smtp','587')))):
            raise ValueError('Guest private service ports differ from venue authority')
    if (set(vm) not in (required, required | {'servicePorts', 'diskRoot'})
            or type(vm['schemaVersion']) is not int or vm['schemaVersion'] != 1
            or (venue is None and vm['name'] != 'p0-agents')
            or vm['projectLanes'] != [] or vm['gpuDevices'] != []
            or any(type(vm[k]) is not int or vm[k] != v for k, v in
                   {'vcpus': 8, 'memoryMiB': 12288, 'osGiB': 80, 'workGiB': 100, 'swapGiB': 4}.items())
            or set(pins) != {'controlCommit', 'worklaneCommit', 'manifestSha256', 'image',
                             'archiveFilename', 'archiveSha256', 'importBudgetBytes'}
            or not all(isinstance(pins.get(k), str) and re.fullmatch('[a-f0-9]{40}', pins[k])
                       for k in ('controlCommit', 'worklaneCommit'))):
        raise ValueError('Invalid empty CPU agent VM pins')
    if control is not None:
        control = control.resolve(strict=True)
        git = ['git', '-c', 'safe.directory=' + str(control), '-C', str(control)]
        head = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip()
        if head != pins['controlCommit'] or subprocess.check_output(
                [*git, 'status', '--porcelain'], text=True).strip():
            raise ValueError('Reviewed control checkout differs from site pin')
        source = control / 'ops/agent_vm_spec.py'
        if source.is_symlink() or not source.is_file():
            raise ValueError('Pinned control VM validator unavailable')
        module_spec = importlib.util.spec_from_file_location('p0_site_vm_validator', source)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        module.load(vm_path)
    return {'site': 'latium', 'agentVmSha256': digest, 'controlCommit': pins['controlCommit'],
            'controlSourceValidated': control is not None, 'rolesActivated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.bundle, args.control_checkout), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'agent VM bundle preflight refused: ' + type(error).__name__ + '\n')


if __name__ == '__main__':
    main()
