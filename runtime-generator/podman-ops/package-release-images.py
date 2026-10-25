#!/usr/bin/env python3
"""Package source-bound selected immutable OCI images, never application state.

Use hash-pinned offline supply, or an explicitly marked dedicated export cache.
No build/start/delete, default store, tag fallback, or installer admission bypass.
An interrupted output is retained and must never be replayed as a release input.
"""
import argparse
import contextlib
import gzip
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
HEX = re.compile(r'[a-f0-9]{64}')
OCI = 'application/vnd.oci.image.'
MAX_METADATA = 2 * 1024**2
MAX_LAYER = 64 * GIB
MAX_ARCHIVE = 256 * GIB
TERM_GRACE = 5
KILL_GRACE = 5
GROUP_POLL = 0.05


@contextlib.contextmanager
def defer_interrupts():
    # Record repeated cancellation without interrupting spawn ownership/teardown.
    # Do NOT leave signals blocked across Popen: exec would inherit that mask.
    signals = {signal.SIGINT, signal.SIGTERM, signal.SIGALRM}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    handlers = {number: signal.getsignal(number) for number in signals}
    received = []
    def remember(signum, frame):
        received.append(signum)
    try:
        for number in signals:
            signal.signal(number, remember)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, signals)
            for number, handler in handlers.items():
                signal.signal(number, handler)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    if received:
        raise InterruptedError('image export interrupted; owned cleanup completed')


def leader_exited(process):
    # WNOWAIT retains the leader (including its PID/PGID reservation) until the
    # last group signal has been sent. Popen.poll() would reap it prematurely.
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def quiesce_export(process):
    # start_new_session pins this group to our unreaped direct child. Never
    # signal a group after reaping that child: its numeric PGID could be reused.
    leader_exited(process)  # Refuse to signal if waitable-child ownership was lost.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + TERM_GRACE
    while group_exists(process.pid) and time.monotonic() < deadline:
        time.sleep(GROUP_POLL)
    # An exited leader is deliberately still waitable; surviving descendants
    # must receive KILL even when their leader has already exited successfully.
    leader_exited(process)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + KILL_GRACE
    process.wait(timeout=KILL_GRACE)
    while group_exists(process.pid):
        if time.monotonic() >= deadline:
            raise ValueError('owned exporter group did not quiesce; pending output retained')
        time.sleep(GROUP_POLL)


def check_partial(archive, root):
    check_reserves(root)
    if os.path.lexists(archive):
        path = plain_file(archive)
        if path.stat().st_size > MAX_ARCHIVE:
            raise ValueError('oversized partial OCI archive')


def strict_json(source):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.load(source, object_pairs_hook=pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON')))


def plain_file(path, private=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute file path required')
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted file ancestor')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError('root-owned unlinked protected regular file required')
    return path


def read_document(path):
    path = plain_file(path)
    if path.stat().st_size > MAX_METADATA:
        raise ValueError('oversized input metadata')
    with path.open('r') as source:
        result = strict_json(source)
    if not isinstance(result, dict):
        raise ValueError('JSON object required')
    return result


def snapshot(path):
    path = plain_file(path)
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, digest_file(path))


def assert_unchanged(proof):
    if any(snapshot(path) != before for path, before in proof.items()):
        raise ValueError('source/input CAS changed during packaging')


def owned_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute canonical directory required')
    for p in (path, *path.parents):
        info = p.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022):
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


def verify_oci(path, image, guard=lambda: None):
    """Bind archive -> manifest -> exact config -> ordered uncompressed DiffIDs.

    Layers are never extracted. Gzip is streamed and bounded; zstd and foreign
    layers fail closed (no optional decoder or network fallback).
    """
    if not isinstance(image, str) or not ID.fullmatch(image):
        raise ValueError('immutable selected configuration ID required')
    if Path(path).stat().st_size > MAX_ARCHIVE:
        raise ValueError('oversized OCI archive')
    with tarfile.open(path, 'r:') as archive:
        members = {}; next_header = 0
        for member in archive:
            guard()
            name = member.name
            if (len(members) >= 4096 or name in members or not name
                    or name.startswith('/') or '..' in Path(name).parts
                    or str(Path(name)) != name):
                raise ValueError('ambiguous or escaping OCI member')
            if ((not member.isfile() and not member.isdir()) or member.pax_headers or member.sparse
                    or member.offset != next_header or member.offset_data != member.offset + 512
                    or (member.isdir() and member.size != 0)):
                raise ValueError('linked/nonregular or extended OCI member')
            next_header = member.offset_data + ((member.size + 511) // 512) * 512
            members[name] = member
        # tarfile stops at the first EOF block. Do not hide another archive or
        # unrelated state in the ignored suffix of the hash-bound artifact.
        archive.fileobj.seek(archive.offset)
        for block in iter(lambda: archive.fileobj.read(8 * 1024**2), b''):
            guard()
            if block.strip(b'\0'):
                raise ValueError('unselected trailing OCI archive content')

        def read_json(name):
            member = members.get(name)
            if member is None or not member.isfile() or member.size > MAX_METADATA:
                raise ValueError('missing/oversized OCI metadata')
            with archive.extractfile(member) as source:
                result = strict_json(source)
            if not isinstance(result, dict):
                raise ValueError('OCI metadata object required')
            return result

        def blob_name(digest):
            if not isinstance(digest, str) or not ID.fullmatch(digest):
                raise ValueError('OCI requires SHA-256 descriptors')
            return 'blobs/sha256/' + digest[7:]

        def checked(descriptor, media):
            if (not isinstance(descriptor, dict) or descriptor.get('mediaType') not in media
                    or 'urls' in descriptor or 'data' in descriptor or 'artifactType' in descriptor):
                raise ValueError('unsupported/external OCI descriptor')
            name = blob_name(descriptor.get('digest'))
            member = members.get(name)
            if (type(descriptor.get('size')) is not int or descriptor['size'] < 0
                    or member is None or member.size != descriptor['size'] or not member.isfile()):
                raise ValueError('missing/wrong-size OCI blob')
            digest = hashlib.sha256()
            with archive.extractfile(member) as source:
                for block in iter(lambda: source.read(8 * 1024**2), b''):
                    guard(); digest.update(block)
            if digest.hexdigest() != descriptor['digest'][7:]:
                raise ValueError('OCI blob digest mismatch')
            return name

        if read_json('oci-layout') != {'imageLayoutVersion': '1.0.0'}:
            raise ValueError('unsupported OCI layout')
        index = read_json('index.json')
        manifests = index.get('manifests')
        if (type(index.get('schemaVersion')) is not int or index['schemaVersion'] != 2
                or not isinstance(manifests, list) or len(manifests) != 1
                or index.get('mediaType', OCI + 'index.v1+json') != OCI + 'index.v1+json'
                or 'subject' in index or 'artifactType' in index):
            raise ValueError('exactly one OCI image required')
        manifest_name = checked(manifests[0], {OCI + 'manifest.v1+json'})
        platform = manifests[0].get('platform')
        if platform is not None and platform != {'os': 'linux', 'architecture': 'amd64'}:
            raise ValueError('unsupported manifest platform')
        manifest = read_json(manifest_name)
        if (type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2
                or manifest.get('mediaType', OCI + 'manifest.v1+json') != OCI + 'manifest.v1+json'
                or 'subject' in manifest or 'artifactType' in manifest):
            raise ValueError('unsupported OCI manifest schema')
        config_name = checked(manifest['config'], {OCI + 'config.v1+json'})
        config_digest = manifest['config']['digest']
        if config_digest != image:
            raise ValueError('exported configuration ID differs from selected image')
        config = read_json(config_name)
        if (config.get('os') != 'linux' or config.get('architecture') != 'amd64'
                or config.get('variant') not in (None, '')):
            raise ValueError('unsupported release image platform')
        layers = manifest.get('layers')
        rootfs = config.get('rootfs')
        if (not isinstance(layers, list) or len(layers) > 1024
                or not isinstance(rootfs, dict) or rootfs.get('type') != 'layers'
                or not isinstance(rootfs.get('diff_ids'), list)
                or len(rootfs['diff_ids']) != len(layers)
                or any(not isinstance(d, str) or not ID.fullmatch(d) for d in rootfs['diff_ids'])):
            raise ValueError('OCI rootfs DiffID count/type mismatch')
        expected = {'index.json', 'oci-layout', manifest_name, config_name}
        unpacked_total = 0
        for descriptor, diff_id in zip(layers, rootfs['diff_ids']):
            name = checked(descriptor, {OCI + 'layer.v1.tar', OCI + 'layer.v1.tar+gzip'})
            expected.add(name)
            digest = hashlib.sha256(); unpacked = 0
            with archive.extractfile(members[name]) as raw:
                source = gzip.GzipFile(fileobj=raw) if descriptor['mediaType'].endswith('+gzip') else raw
                try:
                    for block in iter(lambda: source.read(8 * 1024**2), b''):
                        guard(); unpacked += len(block); unpacked_total += len(block)
                        if unpacked > MAX_LAYER or unpacked_total > MAX_ARCHIVE:
                            raise ValueError('uncompressed OCI layer limit exceeded')
                        digest.update(block)
                finally:
                    if source is not raw:
                        source.close()
            if digest.hexdigest() != diff_id[7:]:
                raise ValueError('OCI rootfs DiffID mismatch')
        allowed_dirs = {'blobs', 'blobs/sha256'}
        if any((member.isfile() and name not in expected) or
               (member.isdir() and name not in allowed_dirs) for name, member in members.items()):
            raise ValueError('unselected file or directory in release image archive')
        return {'manifestDigest': manifests[0]['digest'], 'configId': config_digest,
                'diffIds': rootfs['diff_ids']}


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
    # Explicit storage configuration prevents system additional-image stores
    # from becoming an implicit protected-cache/layer fallback authority.
    files = []; process = None
    def private_config(prefix, body):
        with defer_interrupts():
            fd, path = tempfile.mkstemp(prefix=prefix, dir=runroot)
            files.append(path)
            with os.fdopen(fd, 'w') as target:
                target.write(body)
        return path
    try:
        graph = command[command.index('--root') + 1]
        storage = private_config('release-export-storage-',
                                 '[storage]\ndriver = "overlay"\ngraphroot = ' + json.dumps(graph) +
                                 '\nrunroot = ' + json.dumps(str(runroot)) +
                                 '\n[storage.options]\nadditionalimagestores = []\n')
        containers = private_config('release-export-containers-', '[engine]\n')
        auth = private_config('release-export-auth-', '{"auths":{}}\n')
        temporary = root / 'transfer-tmp'
        if not temporary.exists():
            temporary.mkdir(mode=0o700)
        owned_directory(temporary)
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(runroot), 'TMPDIR': str(temporary),
                       'REGISTRY_AUTH_FILE': auth, 'LANG': 'C.UTF-8',
                       'CONTAINERS_STORAGE_CONF': storage, 'CONTAINERS_CONF': containers}
        check_partial(archive, root)
        with defer_interrupts():
            process = subprocess.Popen(['nice', '-n', '10', 'ionice', '-c', '2', '-n', '7', *command,
                                       'push', '--quiet', '--format', 'oci', image, 'oci-archive:' + str(archive)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, env=environment, start_new_session=True)
        deadline = time.monotonic() + seconds
        while not leader_exited(process):
            check_partial(archive, root)
            if time.monotonic() >= deadline:
                raise ValueError('selected image export deadline exceeded')
            time.sleep(1)
        check_partial(archive, root)
    finally:
        with defer_interrupts():
            try:
                if process is not None:
                    quiesce_export(process)
            finally:
                for path in files:
                    os.unlink(path)
    if process.returncode:
        raise ValueError('selected image export failed; pending output retained')
    check_partial(archive, root)


def bundle_selection(bundle):
    bundle = owned_directory(bundle)
    names = ('bundle.json', 'stack.ir.json', 'source-provenance.json',
             'site/manifest.json', 'podman-domains.json')
    proof = {bundle / name: snapshot(bundle / name) for name in names}
    metadata, ir, provenance, manifest, domains = [read_document(bundle / name) for name in names]
    if (metadata.get('backend') != 'podman' or metadata.get('irSha256') != proof[bundle / 'stack.ir.json'][-1]
            or metadata.get('sourceProvenanceSha256') != proof[bundle / 'source-provenance.json'][-1]
            or provenance.get('manifestSha256') != proof[bundle / 'site/manifest.json'][-1]):
        raise ValueError('selected image bundle hash binding mismatch')
    if (provenance.get('generatorDirty') is not False or provenance.get('siteDirty') is not False
            or any(not isinstance(provenance.get(k), str) or not re.fullmatch(r'[a-f0-9]{40}', provenance[k])
                   for k in ('generatorCommit', 'siteCommit'))
            or not isinstance(provenance.get('modules'), list)
            or any(not isinstance(row, dict) or row.get('dirty') is not False
                   or not isinstance(row.get('commit'), str) or not re.fullmatch(r'[a-f0-9]{40}', row['commit'])
                   for row in provenance['modules'])
            or ir.get('modules') != [{k: v for k, v in row.items() if k != 'dirty'}
                                     for row in provenance['modules']]):
        raise ValueError('clean committed owning source provenance required')
    domain_rows = domains['domains']
    users = {row['name']: row['user'] for row in domain_rows}
    if (len(users) != len(domain_rows) or len(set(users.values())) != len(users)
            or any(not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,63}', user)
                   or user == 'root' for user in users.values())):
        raise ValueError('unique selected domain authorities required')
    modes = [document.get('deploymentMode') for document in (metadata, manifest, domains)]
    standalone = 'standalone' in modes
    if standalone and modes != ['standalone'] * 3:
        raise ValueError('standalone source/bundle/domain profile differs')
    selected = {}; producers = {}
    for name, service in ir['services'].items():
        if 'build' in service and (standalone or service.get('lifecycle') != 'on-demand'
                                  or service.get('quadletManaged') is True):
            if (ir.get('quadletBuildImagesFrozen') is not True
                    or not isinstance(service.get('image'), str) or not ID.fullmatch(service['image'])
                    or service.get('frozenBuildImage') != service['image']):
                raise ValueError('managed discovery builds must be frozen in site source first')
            producers[name] = service['image']
        image = service.get('image', '')
        if 'frozenBuildImage' in service and (not isinstance(image, str) or not ID.fullmatch(image)
                                            or service['frozenBuildImage'] != image
                                            or ir.get('quadletBuildImagesFrozen') is not True):
            raise ValueError('frozen consumer/config ID differs')
        if not image.startswith('sha256:'):
            continue
        if not ID.fullmatch(image) or service.get('updatePolicy') != 'pinned':
            raise ValueError('exact selected pinned immutable image set required')
        if service.get('placement') == 'rootless':
            if service.get('rootlessDomain') not in users:
                raise ValueError('unknown selected rootless image authority')
            user = users[service['rootlessDomain']]
        elif service.get('placement') == 'rootful':
            user = 'root'
        else:
            raise ValueError('explicit selected image placement required')
        selected.setdefault(image, set()).add(user)
    if not selected:
        raise ValueError('exact selected immutable image set required')
    pins_sha = None
    if producers:
        relative = manifest.get('localBuildImagePinsPath')
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
                or '..' in Path(relative).parts or str(Path(relative)) != relative):
            raise ValueError('canonical frozen local build pins path required')
        pins_path = bundle / 'site' / relative
        proof[pins_path] = snapshot(pins_path)
        pins = read_document(pins_path)
        if (set(pins) != {'schemaVersion', 'images'} or type(pins.get('schemaVersion')) is not int
                or pins['schemaVersion'] != 1 or pins.get('images') != producers):
            raise ValueError('frozen site producer pins differ from selected recipes')
        pins_sha = proof[pins_path][-1]
    selected = {image: sorted(users) for image, users in sorted(selected.items())}
    binding = {'bundleIrSha256': proof[bundle / 'stack.ir.json'][-1],
               'sourceProvenanceSha256': proof[bundle / 'source-provenance.json'][-1],
               'siteManifestSha256': proof[bundle / 'site/manifest.json'][-1],
               'domainMetadataSha256': proof[bundle / 'podman-domains.json'][-1],
               'localBuildPinsSha256': pins_sha}
    assert_unchanged(proof)
    return binding, selected, proof


def pinned_document(path, expected):
    if not isinstance(expected, str) or not HEX.fullmatch(expected):
        raise ValueError('explicit reviewed metadata SHA-256 required')
    before = snapshot(path)
    if before[-1] != expected:
        raise ValueError('reviewed metadata hash mismatch')
    document = read_document(path)
    if snapshot(path) != before:
        raise ValueError('metadata CAS changed')
    return document, {Path(path): before}


def supply_rows(path, expected, binding, selected):
    if os.path.lexists(Path(path).parent / 'PENDING'):
        raise ValueError('supply is pending; interrupted output is not a release input')
    document, proof = pinned_document(path, expected)
    if (set(document) != {'schemaVersion', 'purpose', 'binding', 'imageAuthorities', 'images'}
            or type(document.get('schemaVersion')) is not int or document['schemaVersion'] != 1
            or document.get('purpose') != 'release-image-supply' or document.get('binding') != binding
            or document.get('imageAuthorities') != selected or not isinstance(document.get('images'), list)):
        raise ValueError('supply scope/source binding differs from frozen selection')
    rows = {}
    for row in document['images']:
        if not isinstance(row, dict) or set(row) != {'image', 'archiveFilename', 'archiveSha256', 'archiveBytes'}:
            raise ValueError('invalid supply archive row')
        image = row['image']; filename = row['archiveFilename']
        if (not isinstance(image, str) or image not in selected or image in rows
                or not isinstance(filename, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}\.tar', filename)
                or type(row['archiveBytes']) is not int or not 0 < row['archiveBytes'] <= MAX_ARCHIVE
                or not isinstance(row['archiveSha256'], str) or not HEX.fullmatch(row['archiveSha256'])):
            raise ValueError('unique exact selected supply archives required')
        archive = plain_file(Path(path).parent / filename)
        if archive.stat().st_size != row['archiveBytes']:
            raise ValueError('supplied archive size/hash mismatch')
        before = snapshot(archive)
        if before[2] != row['archiveBytes'] or before[-1] != row['archiveSha256']:
            raise ValueError('supplied archive size/hash mismatch')
        proof[archive] = before; rows[image] = archive
    if set(rows) != set(selected) or len(set(rows.values())) != len(rows):
        raise ValueError('supply requires exactly every selected image archive')
    return rows, proof


def cache_source(store, runroot, receipt, expected, binding, selected):
    store = Path(store)
    if (any(parent == Path('/var/lib/containers/storage') for parent in (store, *store.parents))
            or any(word in str(store).lower() for word in ('software_lab', 'stack_lab', 'obelisks', 'lane'))):
        raise ValueError('protected/default/lane stores are not release packaging sources')
    store = owned_directory(store); runroot = owned_directory(runroot)
    if store == runroot or store in runroot.parents or runroot in store.parents:
        raise ValueError('source graph and run root must be disjoint')
    if any(runroot.iterdir()):
        raise ValueError('fresh dedicated empty export run root required')
    marker = store / '.release-image-source.json'
    inventory = store / 'overlay-images/images.json'
    # Check marker before touching a graph inventory; no auto-adoption of caches.
    marker_proof = snapshot(marker)
    marker_data = read_document(marker)
    if (type(marker_data.get('schemaVersion')) is not int
            or marker_data != {'schemaVersion': 1, 'purpose': 'selected-release-export-cache', 'graphRoot': str(store)}):
        raise ValueError('dedicated selected release cache marker required')
    document, proof = pinned_document(receipt, expected)
    # Reject every scope field before any inventory stat, hash or content read.
    if (set(document) != {'schemaVersion', 'purpose', 'binding', 'imageAuthorities', 'graphRoot',
                         'runRoot', 'sourceMarkerSha256', 'inventorySha256'}
            or type(document.get('schemaVersion')) is not int or document['schemaVersion'] != 1
            or document.get('purpose') != 'release-image-export' or document.get('binding') != binding
            or document.get('imageAuthorities') != selected or document.get('graphRoot') != str(store)
            or document.get('runRoot') != str(runroot) or document.get('sourceMarkerSha256') != marker_proof[-1]
            or not isinstance(document.get('inventorySha256'), str)
            or not HEX.fullmatch(document['inventorySha256'])):
        raise ValueError('export receipt scope/marker/source binding mismatch')
    plain_file(inventory)
    if inventory.stat().st_size > MAX_METADATA:
        raise ValueError('oversized source inventory')
    inventory_proof = snapshot(inventory)
    if document['inventorySha256'] != inventory_proof[-1]:
        raise ValueError('export receipt inventory hash mismatch')
    with inventory.open() as source:
        cache = strict_json(source)
    if (not isinstance(cache, list) or any(not isinstance(row, dict) or not isinstance(row.get('id'), str)
                                          or not HEX.fullmatch(row['id']) for row in cache)
            or len(cache) != len(selected) or {row['id'] for row in cache} != {image[7:] for image in selected}):
        raise ValueError('source cache must contain exactly selected immutable IDs; no unrelated cache export')
    proof.update({marker: marker_proof, inventory: inventory_proof})
    assert_unchanged(proof)
    return store, runroot, proof


def package(bundle, store, runroot, output, seconds, *, source_receipt=None,
            source_receipt_sha256=None, supply_inputs=None, supply_sha256=None,
            qualified_artifacts=None):
    if os.geteuid() != 0:
        raise ValueError('root packaging operator required')
    if not 1 <= seconds <= 3600:
        raise ValueError('image timeout must be bounded to one hour')
    binding, selected, proof = bundle_selection(bundle)
    bundle = Path(bundle); output = Path(output)
    if not output.is_absolute() or '..' in output.parts or output.name in ('', '.', '..'):
        raise ValueError('absolute fresh output path required')
    owned_directory(output.parent)
    if os.path.lexists(output):
        raise ValueError('fresh output directory required; pending outputs cannot be replayed')
    if qualified_artifacts is not None:
        if any(value is not None for value in (store, runroot, source_receipt, source_receipt_sha256,
                                               supply_inputs, supply_sha256)):
            raise ValueError('qualified artifact packaging cannot combine input authorities')
        qualified_artifacts.verify(binding, selected)
        source_proof = qualified_artifacts.proof
        source_roots = qualified_artifacts.roots
        input_sha = qualified_artifacts.report_sha256
        mode = 'qualified-artifact-rebind'
    elif supply_inputs is not None:
        if any(value is not None for value in (store, runroot, source_receipt, source_receipt_sha256)):
            raise ValueError('offline supply cannot combine with a cache authority')
        supplied, source_proof = supply_rows(supply_inputs, supply_sha256, binding, selected)
        source_roots = [Path(supply_inputs).parent]
        input_sha = supply_sha256
        mode = 'offline-supply'
    else:
        if supply_sha256 is not None or any(value is None for value in (store, runroot, source_receipt, source_receipt_sha256)):
            raise ValueError('export needs explicit source store, run root and hash-pinned receipt')
        store, runroot, source_proof = cache_source(store, runroot, source_receipt,
                                                   source_receipt_sha256, binding, selected)
        source_roots = [store, runroot, Path(source_receipt).parent]
        input_sha = source_receipt_sha256
        mode = 'dedicated-cache-export'
    authorities = [bundle, *source_roots]
    if (any(output == root or root in output.parents or output in root.parents for root in authorities)
            or any(left == right or left in right.parents or right in left.parents
                   for i, left in enumerate(authorities) for right in authorities[i + 1:])):
        raise ValueError('output and all input authorities must be disjoint')
    proof.update(source_proof)
    assert_unchanged(proof)
    check_reserves(output.parent)
    output.mkdir(mode=0o700)
    pending = output / 'PENDING'
    write_json(pending, {'status': 'pending', 'binding': binding, 'inputSha256': input_sha})
    sync_directory(output)
    sync_directory(output.parent)
    deadline = time.monotonic() + 3600
    def guard():
        if time.monotonic() >= deadline:
            raise ValueError('overall packaging deadline exceeded')
        if qualified_artifacts is not None:
            qualified_artifacts.guard()
        check_reserves(output)
    rows = []; oci_proofs = {}
    for image in selected:
        guard(); assert_unchanged(proof)
        partial = output / (image[7:] + '.oci.partial')
        if qualified_artifacts is not None:
            qualified_artifacts.copy(image, partial, guard)
        elif supply_inputs is not None:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as target, supplied[image].open('rb') as source:
                copied = 0
                for block in iter(lambda: source.read(8 * 1024**2), b''):
                    guard(); copied += len(block)
                    if copied > min(MAX_ARCHIVE, proof[supplied[image]][2]):
                        raise ValueError('oversized partial OCI archive')
                    target.write(block)
                target.flush(); os.fsync(target.fileno())
        else:
            command = ['buildah', '--root', str(store), '--runroot', str(runroot), '--storage-driver', 'overlay']
            export(command, image, partial, output, seconds, runroot)
        plain_file(partial)
        partial.chmod(0o600)
        before = snapshot(partial)
        if supply_inputs is not None and before[-1] != proof[supplied[image]][-1]:
            raise ValueError('staged archive differs from hash-pinned supply')
        oci_proofs[image] = verify_oci(partial, image, guard)
        if snapshot(partial) != before:
            raise ValueError('staged archive CAS changed')
        assert_unchanged(proof)
        with partial.open('rb') as source:
            os.fsync(source.fileno())
        archive = partial.with_suffix('.tar')
        if os.path.lexists(archive):
            raise ValueError('archive publication collision')
        partial.rename(archive)
        proof[archive] = snapshot(archive)
        if proof[archive][2] != before[2] or proof[archive][-1] != before[-1]:
            raise ValueError('published archive CAS changed')
        rows.append({'image': image, 'archiveFilename': archive.name,
                     'archiveSha256': before[-1], 'archiveBytes': before[2]})
        sync_directory(output)
    guard(); assert_unchanged(proof)
    if qualified_artifacts is not None:
        qualified_artifacts.verify(binding, selected)
        qualification = output / 'source-qualification.json'
        write_json(qualification, qualified_artifacts.report)
        proof[qualification] = snapshot(qualification)
        if proof[qualification][-1] != input_sha:
            raise ValueError('qualified artifact source report changed')
    path = output / 'image-inputs.json.partial'
    write_json(path, {'schemaVersion': 1, 'images': rows})
    proof[path] = snapshot(path)
    frozen = {'schemaVersion': 1, 'purpose': 'source-bound-release-images', 'binding': binding,
              'imageAuthorities': selected, 'inputSha256': input_sha, 'inputMode': mode,
              'packagerSha256': digest_file(Path(__file__)), 'ociProofs': oci_proofs,
              'imageInputsSha256': proof[path][-1],
              'activationAuthorized': False, 'acceptedIntegratedInstalls': 0}
    proof_path = output / 'release-image-proof.json'
    write_json(proof_path, frozen)
    proof[proof_path] = snapshot(proof_path)
    guard(); assert_unchanged(proof)
    if qualified_artifacts is not None:
        qualified_artifacts.verify(binding, selected)
    # Publish the installer-facing filename last. PENDING is conservative after
    # a crash between publication and unlink; integration must require it absent.
    path.rename(output / 'image-inputs.json')
    sync_directory(output)
    pending.unlink()
    sync_directory(output)
    print(json.dumps({'scope': 'source-bound selected OCI artifacts only; not installed/owner proof',
                      'imageCount': len(rows), 'sourceImagesDeleted': False, 'containersStarted': False,
                      'acceptedIntegratedInstalls': 0}))


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as target:
        json.dump(body, target, indent=2); target.write('\n'); target.flush(); os.fsync(target.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--describe-selection', action='store_true',
                        help='Print binding and selected authorities only; no export or output mutation')
    for name in ('source-store', 'run-root', 'output', 'source-receipt', 'source-receipt-sha256',
                 'supply-inputs', 'supply-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--image-timeout', type=int, default=600)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError('image export interrupted; pending output retained')
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(3600)
    try:
        if not 1 <= args.image_timeout <= 3600:
            raise ValueError('image timeout must be bounded to one hour')
        if args.describe_selection:
            if any(getattr(args, name) is not None for name in ('source_store', 'run_root', 'output',
                    'source_receipt', 'source_receipt_sha256', 'supply_inputs', 'supply_sha256')):
                raise ValueError('description cannot combine with packaging flags')
            binding, selected, _ = bundle_selection(args.bundle)
            print(json.dumps({'binding': binding, 'imageAuthorities': selected}, indent=2))
        else:
            if args.output is None:
                raise ValueError('fresh output required')
            package(args.bundle, args.source_store, args.run_root, args.output, args.image_timeout,
                    source_receipt=args.source_receipt, source_receipt_sha256=args.source_receipt_sha256,
                    supply_inputs=args.supply_inputs, supply_sha256=args.supply_sha256)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError,
            tarfile.TarError, subprocess.SubprocessError):
        # Do not echo parser errors containing bytes from untrusted metadata.
        print('release image packaging refused: invalid or changed inputs, archive, authority, or reserves; '
              'pending output (if any) retained', file=__import__('sys').stderr)
        return 1
    finally:
        signal.alarm(0)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
