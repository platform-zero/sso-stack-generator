#!/usr/bin/env python3
"""Import explicit hash-bound release images into only their selected authority stores."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess


def protected(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Image input must be root-owned regular non-writable file')


def validate(bundle, inputs):
    protected(inputs)
    data = json.loads(inputs.read_text())
    if data.get('schemaVersion') != 1 or not isinstance(data.get('images'), list):
        raise ValueError('Invalid image input manifest')
    ir = json.loads((bundle / 'stack.ir.json').read_text())
    domains = {d['name']: d for d in json.loads((bundle / 'podman-domains.json').read_text())['domains']}
    rows = []
    seen = set()
    for row in data['images']:
        image = row['image']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or image in seen:
            raise ValueError('Unique immutable image IDs required')
        seen.add(image)
        filename = row['archiveFilename']
        if not isinstance(filename, str) or Path(filename).name != filename or filename in ('', '.', '..'):
            raise ValueError('Image archive must be a sibling filename')
        archive = inputs.parent / filename
        protected(archive)
        digest = hashlib.sha256()
        with archive.open('rb') as source:
            for chunk in iter(lambda: source.read(8 * 1024 * 1024), b''):
                digest.update(chunk)
        if digest.hexdigest() != row['archiveSha256']:
            raise ValueError('Release image archive hash mismatch')
        authorities = set()
        for service in ir['services'].values():
            if service.get('image') == image:
                if service.get('updatePolicy') != 'pinned':
                    raise ValueError('Offline image must use pinned update policy')
                domain = service.get('rootlessDomain') if service.get('placement') == 'rootless' else None
                if domain is not None and domain not in domains:
                    raise ValueError('Unknown image authority')
                authorities.add(domains[domain]['user'] if domain is not None else 'root')
        if not authorities:
            raise ValueError('Image input is not selected by this composition')
        rows.append((image, archive, sorted(authorities)))
    required = {s['image'] for s in ir['services'].values() if s.get('image', '').startswith('sha256:')}
    if not required.issubset(seen):
        raise ValueError('Selected local image is missing a release input')
    return rows


def rootful_command(bundle):
    """Never import/pull a venue's rootful image through the shared store."""
    metadata = json.loads((bundle / 'podman-domains.json').read_text())
    venue = metadata.get('venue')
    if venue is None:
        return ['podman']
    if not isinstance(venue, dict) or set(venue) != {
            'schemaVersion', 'unitPrefix', 'rootfulStateRoot', 'rootfulRuntimeRoot',
            'rootfulGraphRoot', 'rootfulRunRoot', 'rootfulVolumeRoot',
            'pgSsdRoot', 'vectorDbsRoot', 'controlSocketRoot', 'logRoot', 'portMap'} or type(venue['schemaVersion']) is not int or venue['schemaVersion'] != 1:
        raise ValueError('Invalid isolated image-store authority')
    prefix = venue['unitPrefix']
    if not isinstance(prefix, str) or not re.fullmatch(r'p0test-[a-z0-9-]{1,24}', prefix):
        raise ValueError('Invalid isolated image-store namespace')
    state, graph, run = (venue[k] for k in ('rootfulStateRoot', 'rootfulGraphRoot', 'rootfulRunRoot'))
    if (venue['rootfulRuntimeRoot'] != '/run/' + prefix or
            venue['controlSocketRoot'] != '/run/' + prefix + '-control' or
            not isinstance(venue['portMap'], dict) or len(venue['portMap']) != 51 or
            state != '/var/lib/' + prefix or run != '/run/' + prefix + '-podman'
            or not isinstance(graph, str) or not re.fullmatch(
                r'/mnt/stack/p0-existing-host-venue-[a-z0-9-]{1,24}/rootful-graph', graph)):
        raise ValueError('Isolated rootful store roots differ from declared venue')
    for value in (state, graph, run):
        path = Path(value)
        if any(parent.is_symlink() for parent in path.parents) or path.is_symlink():
            raise ValueError('Linked rootful store ancestor')
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Rootful store directory not exclusively owned')
    config = Path(state) / 'containers-storage.conf'
    protected(config)
    info = config.lstat()
    expected = (f'[storage]\ndriver = "overlay"\nrunroot = "{run}"\n'
                f'graphroot = "{graph}"\n').encode()
    if info.st_nlink != 1 or info.st_mode & 0o077 or config.read_bytes() != expected:
        raise ValueError('Rootful storage configuration does not bind exact isolated graph')
    network_dir=Path(state)/'networks'
    network_conf=Path(state)/'containers.conf'
    protected(network_conf)
    if network_dir.is_symlink():raise ValueError('Linked rootful netavark directory')
    info=network_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077:
        raise ValueError('Isolated rootful netavark directory missing')
    info=network_conf.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=0 or info.st_mode & 0o077 or
            network_conf.read_bytes()!=('[network]\nnetwork_config_dir = "'+str(network_dir)+'"\n').encode()):
        raise ValueError('Isolated rootful netavark configuration differs')
    return ['env', 'TMPDIR=' + graph, 'CONTAINERS_STORAGE_CONF=' + str(config),
            'CONTAINERS_CONF=' + str(network_conf), 'podman',
            '--root', graph, '--runroot', run, '--network-config-dir', str(network_dir)]


def frozen_aliases(bundle, metadata):
    """Retain exact producer tags used by dynamic, non-Quadlet consumers too."""
    if bundle is None:
        return {}
    ir = json.loads((bundle / 'stack.ir.json').read_text())
    domains = {d['name']: d['user'] for d in metadata['domains']}
    result = {}
    for name, service in ir['services'].items():
        if 'build' not in service or 'frozenBuildImage' not in service:
            continue
        image = service.get('image')
        if (ir.get('quadletBuildImagesFrozen') is not True or
                not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or
                service['frozenBuildImage'] != image or service.get('updatePolicy') != 'pinned' or
                not re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', name)):
            raise ValueError('Invalid frozen build image/tag authority')
        user = domains[service['rootlessDomain']] if service.get('placement') == 'rootless' else 'root'
        result.setdefault((image, user), set()).add('localhost/webservices/' + name + ':bundle')
    return result


def frozen_image_ids(bundle, metadata=None):
    """Exact per-store offline identities, including non-producer consumers."""
    ir_path = Path(bundle) / 'stack.ir.json'
    if not ir_path.exists():
        return {}
    ir = json.loads(ir_path.read_text())
    selected = [s for s in ir['services'].values() if 'frozenBuildImage' in s]
    if not selected:
        return {}
    metadata = metadata or json.loads((Path(bundle) / 'podman-domains.json').read_text())
    frozen_aliases(Path(bundle), metadata)
    domains = {d['name']: d['user'] for d in metadata['domains']}
    result = {}
    for service in selected:
        image = service.get('image')
        if (ir.get('quadletBuildImagesFrozen') is not True or
                not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or
                image != service['frozenBuildImage'] or service.get('updatePolicy') != 'pinned'):
            raise ValueError('Invalid frozen imported image authority')
        domain = service.get('rootlessDomain') if service.get('placement') == 'rootless' else None
        if domain is not None and domain not in domains:
            raise ValueError('Unselected frozen image consumer authority')
        user = domains[domain] if domain is not None else 'root'
        result[user + '|' + image] = image
    return result


def selected_image_ids(bundle):
    """Keep the registry and imported local sources distinct but jointly exact."""
    path = Path(bundle) / 'site/global.settings/registry-image-ids.json'
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing selected registry identity source')
    result = json.loads(path.read_text())
    if (not isinstance(result, dict) or not result or
            any(not isinstance(k, str) or k.count('|') != 1 or not all(k.split('|')) or
                not isinstance(v, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', v) for k, v in result.items())):
        raise ValueError('Invalid selected registry identity source')
    for key, image in frozen_image_ids(bundle).items():
        if key in result and result[key] != image:
            raise ValueError('Conflicting registry/imported image identity')
        result[key] = image
    return result


def install(rows, bundle=None):
    os.chdir('/')
    metadata = json.loads((bundle / 'podman-domains.json').read_text()) if bundle is not None else {}
    aliases = frozen_aliases(bundle, metadata)
    domains = {d['user']: d for d in metadata.get('domains', [])}
    root_command = rootful_command(bundle) if bundle is not None else ['podman']
    for image, archive, authorities in rows:
        for user in authorities:
            if user == 'root':
                command = root_command
            else:
                account = pwd.getpwnam(user)
                command = ['runuser', '-u', user, '--', 'env', '-u', 'CONTAINERS_STORAGE_CONF',
                           f'HOME={account.pw_dir}', f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                           f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus', 'podman']
                if bundle is not None:
                    if user not in domains:
                        raise ValueError('Unselected rootless image authority')
                    graph = Path(domains[user]['graphRoot'])
                    info = graph.lstat()
                    if (not graph.is_absolute() or graph.is_symlink() or any(p.is_symlink() for p in graph.parents) or
                            not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_mode & 0o077):
                        raise ValueError('Image import scratch must be the private selected graph')
                    command.insert(command.index('podman'), 'TMPDIR=' + str(graph))
            def inspect(ref=image):
                result = subprocess.run(command + ['image', 'inspect', ref, '--format', '{{.Id}}'],
                                        capture_output=True, text=True, timeout=30)
                return result.returncode == 0 and result.stdout.strip().removeprefix('sha256:') == image[7:]
            if not inspect():
                with archive.open('rb') as source:
                    subprocess.run(command + ['load'], stdin=source, capture_output=True, check=True, timeout=300)
                if not inspect():
                    raise ValueError('Imported image differs from the pinned configuration ID')
            for alias in sorted(aliases.get((image, user), ())):
                present = subprocess.run(command + ['image', 'exists', alias], capture_output=True, timeout=30)
                if present.returncode == 0:
                    if not inspect(alias):
                        raise ValueError('Frozen local tag collision; refusing to replace another image')
                elif present.returncode == 1:
                    subprocess.run(command + ['tag', image, alias], capture_output=True, check=True, timeout=30)
                    if not inspect(alias):
                        raise ValueError('Frozen local tag differs after exact import')
                else:
                    raise ValueError('Frozen local tag inventory unavailable; no tag mutation')
            print(json.dumps({'image': image, 'authority': user, 'verified': True}))


def prepare_registry(bundle, *, runner=subprocess.run):
    """Populate exact selected registry references serially before service startup."""
    os.chdir('/')
    metadata = json.loads((bundle / 'podman-domains.json').read_text())
    domains = metadata['domains']
    authorities = [('rootful', 'root')] + [('rootless-' + d['name'], d['user']) for d in domains]
    ledger_path = bundle / '.registry-image-ids.json'
    expected_path = bundle / 'site/global.settings/registry-image-ids.json'
    expected_ids = {}
    manifest = bundle / 'site/manifest.json'
    if manifest.exists():
        declared = json.loads(manifest.read_text()).get('imageIdentityPinsPath')
        if declared is not None and (declared != 'global.settings/registry-image-ids.json' or not expected_path.is_file()):
            raise ValueError('Declared frozen site identities missing or unsupported path')
    if expected_path.exists() or expected_path.is_symlink():
        info = expected_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe site image identity pins')
        expected_ids = json.loads(expected_path.read_text())
        if (not isinstance(expected_ids, dict) or not expected_ids
                or any(not isinstance(k, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', v)
                       for k, v in expected_ids.items())):
            raise ValueError('Invalid site image identity pins')
    # Imported outputs must already exist; never use registry fallback for them.
    expected_ids.update(frozen_image_ids(bundle, metadata))
    if ledger_path.exists() or ledger_path.is_symlink():
        protected(ledger_path)
        ledger = json.loads(ledger_path.read_text())
        if not isinstance(ledger, dict):
            raise ValueError('Invalid installed image identity ledger')
    else:
        ledger = {}
    for label, user in authorities:
        images = set()
        for path in (bundle / 'quadlet' / label).glob('*.container'):
            lines = [line[6:] for line in path.read_text().splitlines() if line.startswith('Image=')]
            if len(lines) != 1:
                raise ValueError('Ambiguous selected container image')
            image = lines[0]
            if image.endswith('.build'):
                continue
            # Respect the site's exact approved version references as well as
            # digests. Do not silently replace them or resolve implicit/latest.
            if (not re.fullmatch(r'(?:sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+)', image)
                    or image.rsplit(':', 1)[-1].lower() == 'latest'):
                raise ValueError('Registry preparation refuses implicit/latest or invalid references')
            images.add(image)
        if user == 'root':
            command = rootful_command(bundle)
        else:
            account = pwd.getpwnam(user)
            command = ['runuser', '-u', user, '--', 'env', '-u', 'CONTAINERS_STORAGE_CONF', f'HOME={account.pw_dir}',
                       f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                       f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus', 'podman']
        for image in sorted(images):
            result = runner(command + ['image', 'exists', image], capture_output=True, text=True, timeout=30)
            if result.returncode not in (0, 1):
                raise ValueError('Selected image inventory failed')
            if result.returncode == 1:
                if image.startswith('sha256:'):
                    raise ValueError('Offline selected image missing; no registry fallback')
                runner(command + ['pull', image], capture_output=True, text=True, check=True, timeout=1800)
                result = runner(command + ['image', 'exists', image], capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise ValueError('Selected registry image not present after preparation')
            inspected = runner(command + ['image', 'inspect', '--format', '{{.Id}}', image],
                               capture_output=True, text=True, check=True, timeout=30).stdout.strip()
            # Native Podman .Id emits the same SHA256 configuration identity
            # without its algorithm prefix on some supported versions.
            if re.fullmatch(r'[0-9a-f]{64}', inspected):
                inspected = 'sha256:' + inspected
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', inspected):
                raise ValueError('Invalid selected image configuration identity')
            key = user + '|' + image
            if expected_ids and (key not in expected_ids or expected_ids[key] != inspected):
                raise ValueError('Selected image differs from frozen site identity; no substitution')
            if key in ledger and ledger[key] != inspected:
                raise ValueError('Selected image configuration identity changed; reviewed input required')
            ledger[key] = inspected
            temporary = ledger_path.with_name('.registry-image-ids.tmp')
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'w') as stream:
                    json.dump(ledger, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, ledger_path)
                directory = os.open(bundle, os.O_DIRECTORY); os.fsync(directory); os.close(directory)
            finally:
                temporary.unlink(missing_ok=True)
            print(json.dumps({'image': image, 'imageId': inspected, 'authority': user, 'prepared': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--prepare-registry', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root required for protected release image inputs')
    try:
        if args.inputs is None and not args.prepare_registry:
            raise ValueError('Protected release image inputs required')
        rows = validate(args.bundle, args.inputs) if args.inputs else []
        if not args.validate_only:
            install(rows, args.bundle)
            if args.prepare_registry:
                prepare_registry(args.bundle)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'[pinned-images] rejected: {type(exc).__name__}; no image fallback\n')


if __name__ == '__main__':
    main()
