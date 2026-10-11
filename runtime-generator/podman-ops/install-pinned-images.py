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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root required for protected release image inputs')
    try:
        rows = validate(args.bundle, args.inputs)
        if not args.validate_only:
            install(rows)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'[pinned-images] rejected: {type(exc).__name__}; no image fallback\n')


if __name__ == '__main__':
    main()
