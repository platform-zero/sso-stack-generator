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


def install(rows):
    os.chdir('/')
    for image, archive, authorities in rows:
        for user in authorities:
            if user == 'root':
                command = ['podman']
            else:
                account = pwd.getpwnam(user)
                command = ['runuser', '-u', user, '--', 'env',
                           f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                           f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus', 'podman']
            def inspect():
                result = subprocess.run(command + ['image', 'inspect', image, '--format', '{{.Id}}'],
                                        capture_output=True, text=True, timeout=30)
                return result.returncode == 0 and result.stdout.strip().removeprefix('sha256:') == image[7:]
            if not inspect():
                with archive.open('rb') as source:
                    subprocess.run(command + ['load'], stdin=source, capture_output=True, check=True, timeout=300)
                if not inspect():
                    raise ValueError('Imported image differs from the pinned configuration ID')
            print(json.dumps({'image': image, 'authority': user, 'verified': True}))


def prepare_registry(bundle, *, runner=subprocess.run):
    """Populate exact selected registry references serially before service startup."""
    os.chdir('/')
    domains = json.loads((bundle / 'podman-domains.json').read_text())['domains']
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
            command = ['podman']
        else:
            account = pwd.getpwnam(user)
            command = ['runuser', '-u', user, '--', 'env', f'HOME={account.pw_dir}',
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
            install(rows)
            if args.prepare_registry:
                prepare_registry(args.bundle)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'[pinned-images] rejected: {type(exc).__name__}; no image fallback\n')


if __name__ == '__main__':
    main()
