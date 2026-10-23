#!/usr/bin/env python3
"""Package only selected immutable images, never application state or a whole store.

The source is an explicitly selected root-owned Buildah cache. No container is
built/started, no image deleted, and no default Podman/lane authority is selected.
An interrupted output remains pending and is never accepted as a release input.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tarfile
import time
import tempfile

GIB = 1024**3
ID = re.compile(r'sha256:[a-f0-9]{64}')


def owned_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute canonical directory required')
    for p in (path, *path.parents):
        info = p.lstat()
        if not stat.S_ISDIR(info.st_mode) or p.is_symlink():
            raise ValueError('linked or non-directory storage authority')
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('source/output directory must be root-private')
    return path


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(8 * 1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_oci(path, image):
    """Read/hash members in place; never extract an archive to the filesystem."""
    with tarfile.open(path, 'r:') as archive:
        members = {}
        for member in archive.getmembers():
            name = member.name
            if name in members or name.startswith('/') or '..' in Path(name).parts:
                raise ValueError('ambiguous or escaping OCI member')
            if not member.isfile() and not member.isdir():
                raise ValueError('linked/nonregular OCI member')
            members[name] = member
        def read_json(name):
            member = members.get(name)
            if member is None or not member.isfile() or member.size > 2 * 1024**2:
                raise ValueError('missing/oversized OCI metadata')
            with archive.extractfile(member) as source:
                return json.load(source)
        def blob_name(digest):
            if not isinstance(digest, str) or not ID.fullmatch(digest):
                raise ValueError('OCI requires SHA-256 descriptors')
            return 'blobs/sha256/' + digest.split(':')[1]
        if read_json('oci-layout') != {'imageLayoutVersion': '1.0.0'}:
            raise ValueError('unsupported OCI layout')
        index = read_json('index.json')
        if index.get('schemaVersion') != 2 or len(index.get('manifests', [])) != 1:
            raise ValueError('exactly one OCI image required')
        manifest = read_json(blob_name(index['manifests'][0]['digest']))
        if manifest.get('schemaVersion') != 2:
            raise ValueError('unsupported OCI manifest schema')
        config_digest = manifest['config']['digest']
        if config_digest != image:
            raise ValueError('exported configuration ID differs from selected image')
        config = read_json(blob_name(config_digest))
        if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
            raise ValueError('unsupported release image platform')
        descriptors = [index['manifests'][0], manifest['config'], *manifest['layers']]
        expected = {'index.json', 'oci-layout', *(blob_name(d['digest']) for d in descriptors)}
        if any(member.isfile() and name not in expected for name, member in members.items()):
            raise ValueError('unselected file in release image archive')
        for descriptor in descriptors:
            name = blob_name(descriptor['digest'])
            member = members.get(name)
            if (type(descriptor.get('size')) is not int or descriptor['size'] < 0
                    or member is None or member.size != descriptor['size'] or not member.isfile()):
                raise ValueError('missing/wrong-size OCI blob')
            digest = hashlib.sha256()
            with archive.extractfile(member) as source:
                for block in iter(lambda: source.read(8 * 1024**2), b''):
                    digest.update(block)
            if digest.hexdigest() != descriptor['digest'].split(':')[1]:
                raise ValueError('OCI blob digest mismatch')


def check_reserves(path):
    for mount, reserve in (('/', 50), ('/mnt/stack', 100), (path, 50)):
        info = os.statvfs(mount)
        if info.f_bavail * info.f_frsize < reserve * GIB:
            raise ValueError('image packaging filesystem reserve reached')
    memory = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemAvailable:'))
    if memory < 16 * GIB:
        raise ValueError('image packaging memory reserve reached')


def export(command, image, archive, root, seconds, runroot):
    # Do not inherit operator secrets, root's registry login or remote authorities.
    fd, auth = tempfile.mkstemp(prefix='release-export-auth-', dir=runroot)
    with os.fdopen(fd, 'w') as target:
        target.write('{"auths":{}}\n')
    temporary = root / 'transfer-tmp'
    temporary.mkdir(mode=0o700, exist_ok=True)
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(runroot), 'TMPDIR': str(temporary),
                   'REGISTRY_AUTH_FILE': auth, 'LANG': 'C.UTF-8'}
    try:
        process = subprocess.Popen(['nice', '-n', '10', 'ionice', '-c', '2', '-n', '7', *command,
                                   'push', '--quiet', '--format', 'oci', image, 'oci-archive:' + str(archive)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
    except BaseException:
        os.unlink(auth)
        raise
    try:
        deadline = time.monotonic() + seconds
        while process.poll() is None:
            check_reserves(root)
            if time.monotonic() >= deadline:
                raise ValueError('selected image export deadline exceeded')
            time.sleep(1)
        if process.returncode:
            raise ValueError('selected image export failed; pending output retained')
        check_reserves(root)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        os.unlink(auth)


def package(bundle, store, runroot, output, seconds):
    if os.geteuid() != 0:
        raise ValueError('root packaging operator required')
    bundle = Path(bundle).absolute()
    inputs = [bundle, *bundle.parents, bundle / 'site', *(bundle / name for name in (
        'bundle.json', 'stack.ir.json', 'source-provenance.json', 'site/manifest.json'))]
    if any(path.is_symlink() for path in inputs):
        raise ValueError('linked bundle inputs refused')
    store = owned_directory(store)
    runroot = owned_directory(runroot)
    output = Path(output)
    owned_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise ValueError('fresh output directory required; pending outputs cannot be replayed')
    ir_path = bundle / 'stack.ir.json'
    provenance_path = bundle / 'source-provenance.json'
    metadata = json.loads((bundle / 'bundle.json').read_text())
    provenance = json.loads(provenance_path.read_text())
    if (metadata.get('backend') != 'podman' or metadata.get('irSha256') != digest_file(ir_path)
            or metadata.get('sourceProvenanceSha256') != digest_file(provenance_path)
            or provenance.get('manifestSha256') != digest_file(bundle / 'site/manifest.json')):
        raise ValueError('selected image bundle hash binding mismatch')
    ir = json.loads(ir_path.read_text())
    required = sorted({s['image'] for s in ir['services'].values()
                       if s.get('image', '').startswith('sha256:')})
    if not required or any(not ID.fullmatch(image) for image in required):
        raise ValueError('exact selected immutable image set required')
    if store == Path('/var/lib/containers/storage') or 'software_lab' in str(store) or 'stack_lab' in str(store):
        raise ValueError('default/lane stores are not release packaging sources')
    cache_file = store / 'overlay-images/images.json'
    info = cache_file.lstat()
    if (cache_file.parent.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise ValueError('untrusted source image inventory')
    cache = json.loads(cache_file.read_text())
    available = {row['id'] for row in cache}
    if any(image.split(':')[1] not in available for image in required):
        raise ValueError('explicit source cache does not contain every selected image')
    check_reserves(output.parent)
    output.mkdir(mode=0o700)
    pending = output / 'PENDING'
    pending.write_text('Only image-inputs.json after full verification is releasable.\n')
    command = ['buildah', '--root', str(store), '--runroot', str(runroot), '--storage-driver', 'overlay']
    rows = []
    for image in required:
        partial = output / (image.split(':')[1] + '.oci.partial')
        export(command, image, partial, output, seconds, runroot)
        partial.chmod(0o600)
        verify_oci(partial, image)
        with partial.open('rb') as source:
            os.fsync(source.fileno())
        archive = partial.with_suffix('.tar')
        partial.rename(archive)
        rows.append({'image': image, 'archiveFilename': archive.name,
                     'archiveSha256': digest_file(archive), 'archiveBytes': archive.stat().st_size})
    body = {'schemaVersion': 1, 'images': rows}
    path = output / 'image-inputs.json.partial'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as target:
        json.dump(body, target, indent=2); target.write('\n'); target.flush(); os.fsync(target.fileno())
    path.rename(output / 'image-inputs.json')
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
        pending.unlink()
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(json.dumps({'scope': 'selected OCI image artifacts only; no application/recovery acceptance',
                      'imageCount': len(rows), 'sourceImagesDeleted': False, 'containersStarted': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'source-store', 'run-root', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--image-timeout', type=int, default=600)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError('image export interrupted; pending output retained')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(3600)
    try:
        if not 1 <= args.image_timeout <= 3600:
            raise ValueError('image timeout must be bounded to one hour')
        package(args.bundle, args.source_store, args.run_root, args.output, args.image_timeout)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        # Error messages describe structure, not credentials or archive bodies.
        print('release image packaging refused: ' + str(error), file=__import__('sys').stderr)
        return 1
    finally:
        signal.alarm(0)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
