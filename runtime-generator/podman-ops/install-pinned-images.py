#!/usr/bin/env python3
"""Import explicit hash-bound release images into only their selected authority stores."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import zlib


def protected(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError('Image input must be root-owned unlinked regular non-writable file')


def validate(bundle, inputs):
    bundle, inputs = Path(bundle).absolute(), Path(inputs).absolute()
    documents = [read_json(bundle / name) for name in
                 ('bundle.json', 'podman-domains.json', 'site/manifest.json') if (bundle / name).exists()]
    if any(d.get('deploymentMode') == 'standalone' for d in documents):
        return validate_standalone(bundle, inputs)
    protected(inputs)
    data = read_json(inputs)
    if type(data.get('schemaVersion')) is not int or data['schemaVersion'] != 1 or not isinstance(data.get('images'), list):
        raise ValueError('Invalid image input manifest')
    ir = read_json(bundle / 'stack.ir.json')
    domains = {d['name']: d for d in read_json(bundle / 'podman-domains.json')['domains']}
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


def strict_json(source):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.load(source, object_pairs_hook=pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))


def read_json(path):
    ancestry(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 2 * 1024**2:
        raise ValueError('Bounded unlinked JSON regular file required')
    fd = open_regular(path)
    with os.fdopen(fd, 'r') as source:
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError('JSON source changed before opening')
        result = strict_json(source)
        if (identity(os.fstat(source.fileno())) != identity(before) or
                identity(path.lstat()) != identity(before)):
            raise ValueError('JSON source changed while reading')
    if not isinstance(result, dict):
        raise ValueError('JSON object required')
    return result


def ancestry(path, private=False):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute canonical image input path required')
    for parent in path.parents:
        info = parent.lstat()
        # Sticky root-owned ancestors allow isolated /tmp fixtures, never a
        # writable control directory or a linked ancestor.
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or
                (private and (info.st_uid != 0 or (info.st_mode & 0o022 and not sticky)))):
            raise ValueError('Unsafe image input control ancestry')
        if private and parent == path.parent and info.st_mode & 0o077:
            raise ValueError('Image input control directory must be root-private')


def open_regular(path, private=False):
    """Pin every directory FD: O_NOFOLLOW on the leaf alone is insufficient."""
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute canonical file path required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open('/', flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory); directory = child
            info = os.fstat(directory)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if private and (info.st_uid != 0 or (info.st_mode & 0o022 and not sticky)):
                raise ValueError('Unsafe opened image control ancestor')
        if private and os.fstat(directory).st_mode & 0o077:
            raise ValueError('Opened image control directory must be private')
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_mode, info.st_nlink)


def capture(path, private=False):
    ancestry(path, private)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('Unlinked regular image/source file required')
    if private:
        protected(path)
    fd = open_regular(path, private)
    with os.fdopen(fd, 'rb') as source:
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError('Image input changed before opening')
        digest = hashlib.sha256()
        for block in iter(lambda: source.read(8 * 1024**2), b''):
            digest.update(block)
        if (identity(os.fstat(source.fileno())) != identity(before) or
                identity(path.lstat()) != identity(before)):
            raise ValueError('Image input changed while reading')
    return identity(before), digest.hexdigest()


def data_directory(path):
    """Opaque data namespace pin, never Root control/store authority."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return identity(os.fstat(fd))
    finally:
        os.close(fd)


class ValidatedRows(list):
    """Public list result retaining source/proof/archive CAS authority."""
    def __init__(self, rows, bundle, inputs, captures, data_directories=None):
        super().__init__(rows)
        self.bundle, self.inputs, self.captures = bundle, inputs, captures
        self.data_directories = data_directories or {}
        self.expected = [(image, archive, tuple(users)) for image, archive, users in rows]

    def recheck(self):
        if [(i, p, tuple(u)) for i, p, u in self] != self.expected:
            raise ValueError('Validated image scope changed')
        if os.path.lexists(self.inputs.parent / 'PENDING'):
            raise ValueError('Release image package is pending')
        for path, before in self.data_directories.items():
            if os.path.lexists(path / 'PENDING') or data_directory(path) != before:
                raise ValueError('Opaque archive data namespace changed or pending')
        for path, (before, private) in self.captures.items():
            if capture(path, private) != before:
                raise ValueError('Release image/source CAS changed')

    def check_fd(self, image, archive, source):
        before = self.captures.get(archive)
        if (before is None or identity(os.fstat(source.fileno())) != before[0][0] or
                not any(i == image and p == archive for i, p, _ in self.expected)):
            raise ValueError('Opened archive differs from declared image CAS')
        self.recheck()


def package_verifier():
    # Trusted bundled owning implementation; never write a bytecode cache.
    source = Path(__file__).with_name('package-release-images.py')
    spec = importlib.util.spec_from_file_location('_release_image_verifier', source)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        # Compile the hash-bound source itself, not a timestamp-valid .pyc.
        with os.fdopen(open_regular(source.absolute()), 'rb') as stream:
            exec(compile(stream.read(), str(source), 'exec'), module.__dict__)
    finally:
        sys.dont_write_bytecode = previous
    return module


def validate_standalone(bundle, inputs):
    captures = {}
    def remember(path, private=False):
        captures[path] = (capture(path, private), private)
        return captures[path][0][1]
    def document(path, private=False):
        if path.lstat().st_size > 2 * 1024**2:
            raise ValueError('Oversized release metadata')
        remember(path, private)
        return read_json(path)
    if os.path.lexists(inputs.parent / 'PENDING'):
        raise ValueError('Release image package is pending')
    data = document(inputs, True)
    proof = document(inputs.parent / 'release-image-proof.json', True)
    metadata, ir, provenance, manifest, domains = [document(bundle / name) for name in
        ('bundle.json', 'stack.ir.json', 'source-provenance.json', 'site/manifest.json', 'podman-domains.json')]
    sha = lambda name: captures[bundle / name][0][1]
    if ([d.get('deploymentMode') for d in (metadata, manifest, domains)] != ['standalone'] * 3 or
            metadata.get('backend') != 'podman' or metadata.get('irSha256') != sha('stack.ir.json') or
            metadata.get('sourceProvenanceSha256') != sha('source-provenance.json') or
            provenance.get('manifestSha256') != sha('site/manifest.json')):
        raise ValueError('Standalone bundle/source hash binding differs')
    if (provenance.get('generatorDirty') is not False or provenance.get('siteDirty') is not False or
            any(not isinstance(provenance.get(k), str) or not re.fullmatch(r'[a-f0-9]{40}', provenance[k])
                for k in ('generatorCommit', 'siteCommit')) or
            not isinstance(provenance.get('modules'), list) or
            any(not isinstance(row, dict) or row.get('dirty') is not False or
                not isinstance(row.get('commit'), str) or not re.fullmatch(r'[a-f0-9]{40}', row['commit'])
                for row in provenance['modules']) or
            ir.get('modules') != [{k: v for k, v in row.items() if k != 'dirty'} for row in provenance['modules']]):
        raise ValueError('Clean owning source provenance required')
    users = {d['name']: d['user'] for d in domains['domains']}
    if (len(users) != len(domains['domains']) or len(set(users.values())) != len(users) or
            any(not isinstance(u, str) or u == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,63}', u)
                for u in users.values())):
        raise ValueError('Unique selected image store authorities required')
    selected, producers = {}, {}
    for name, service in ir['services'].items():
        image = service.get('image', '')
        if 'build' in service or 'frozenBuildImage' in service:
            if (ir.get('quadletBuildImagesFrozen') is not True or not isinstance(image, str) or
                    not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or service.get('frozenBuildImage') != image):
                raise ValueError('Every selected build recipe must be frozen')
            if 'build' in service:
                producers[name] = image
        if not isinstance(image, str):
            raise ValueError('Invalid image reference')
        if not image.startswith('sha256:'):
            continue
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or service.get('updatePolicy') != 'pinned':
            raise ValueError('Exact pinned immutable image selection required')
        if service.get('placement') == 'rootless' and service.get('rootlessDomain') in users:
            user = users[service['rootlessDomain']]
        elif service.get('placement') == 'rootful':
            user = 'root'
        else:
            raise ValueError('Unselected image placement/store')
        selected.setdefault(image, set()).add(user)
    pins_sha = None
    if producers:
        relative = manifest.get('localBuildImagePinsPath')
        if (not isinstance(relative, str) or not relative or Path(relative).is_absolute() or
                '..' in Path(relative).parts or str(Path(relative)) != relative):
            raise ValueError('Canonical frozen producer pins path required')
        pins_path = bundle / 'site' / relative
        pins = document(pins_path)
        if (set(pins) != {'schemaVersion', 'images'} or type(pins.get('schemaVersion')) is not int or
                pins['schemaVersion'] != 1 or pins['images'] != producers):
            raise ValueError('Frozen producer pins do not cover exact selected recipes')
        pins_sha = captures[pins_path][0][1]
    binding = {'bundleIrSha256': sha('stack.ir.json'), 'sourceProvenanceSha256': sha('source-provenance.json'),
               'siteManifestSha256': sha('site/manifest.json'), 'domainMetadataSha256': sha('podman-domains.json'),
               'localBuildPinsSha256': pins_sha}
    selected = {image: sorted(authorities) for image, authorities in sorted(selected.items())}
    packager_sha = remember(bundle / 'ops/package-release-images.py')
    if packager_sha != remember(Path(__file__).absolute().with_name('package-release-images.py')):
        raise ValueError('Bundled packager differs from trusted verifier')
    keys = {'schemaVersion', 'purpose', 'binding', 'imageAuthorities', 'inputSha256', 'inputMode',
            'packagerSha256', 'ociProofs', 'imageInputsSha256', 'activationAuthorized', 'acceptedIntegratedInstalls'}
    if (not selected or set(proof) != keys or type(proof.get('schemaVersion')) is not int or proof['schemaVersion'] != 1 or
            proof['purpose'] != 'source-bound-release-images' or proof['binding'] != binding or
            proof['imageAuthorities'] != selected or proof['imageInputsSha256'] != captures[inputs][0][1] or
            proof['packagerSha256'] != packager_sha or proof['inputMode'] not in ('offline-supply', 'dedicated-cache-export', 'qualified-artifact-rebind', 'qualified-artifact-references') or
            not isinstance(proof['inputSha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', proof['inputSha256']) or
            proof['activationAuthorized'] is not False or type(proof['acceptedIntegratedInstalls']) is not int or
            proof['acceptedIntegratedInstalls'] != 0 or not isinstance(proof['ociProofs'], dict) or
            set(proof['ociProofs']) != set(selected)):
        raise ValueError('Protected release proof does not bind exact selected source/images')
    references = None
    if proof['inputMode'] in ('qualified-artifact-rebind', 'qualified-artifact-references'):
        qualification_path = inputs.parent / 'source-qualification.json'
        qualification = document(qualification_path, True)
        owner = bundle / 'ops/qualified-image-supply.py'
        owner_sha = remember(owner)
        if (owner_sha != remember(Path(__file__).absolute().with_name('qualified-image-supply.py'))
                or captures[qualification_path][0][1] != proof['inputSha256']
                or type(qualification.get('schemaVersion')) is not int or qualification['schemaVersion'] != 1
                or qualification.get('qualifierSha256') != owner_sha
                or qualification.get('binding') != binding
                or qualification.get('ociProofs') != proof['ociProofs']
                or not isinstance(qualification.get('producerCopyClosures'), dict)
                or set(qualification['producerCopyClosures']) != set(producers)
                or qualification.get('activationAuthorized') is not False
                or type(qualification.get('acceptedIntegratedInstalls')) is not int
                or qualification['acceptedIntegratedInstalls'] != 0):
            raise ValueError('Qualified artifact report/owner/source binding differs')
        references = qualification.get('archiveReferences')
        if proof['inputMode'] == 'qualified-artifact-references':
            if not isinstance(references, dict) or len(references) != len(selected):
                raise ValueError('Exact qualified opaque archive references required')
        elif references is not None:
            raise ValueError('Copied package cannot combine external archive references')
    if (set(data) != {'schemaVersion', 'images'} or type(data.get('schemaVersion')) is not int or
            data['schemaVersion'] != 1 or not isinstance(data.get('images'), list)):
        raise ValueError('Invalid standalone image input manifest')
    rows, seen, filenames = [], set(), set()
    data_directories = {}; reference_paths = set()
    verifier = package_verifier()
    for row in data['images']:
        if not isinstance(row, dict) or set(row) != {'image', 'archiveFilename', 'archiveSha256', 'archiveBytes'}:
            raise ValueError('Exact archive input schema required')
        image, filename = row['image'], row['archiveFilename']
        if not isinstance(image, str) or image not in selected or image in seen:
            raise ValueError('Unselected or duplicate image input')
        if (not isinstance(filename, str) or Path(filename).name != filename or filename in ('', '.', '..') or
                filename in filenames or filename in (inputs.name, 'release-image-proof.json', 'PENDING')):
            raise ValueError('Unique sibling archive filename required')
        if references is None:
            archive = inputs.parent / filename
        else:
            value = references.get(filename)
            if (not isinstance(value, str) or not Path(value).is_absolute() or '..' in Path(value).parts
                    or str(Path(value)) != value or value in reference_paths
                    or any(word in value.lower() for word in ('lane', 'stack_lab', 'software_lab', 'obelisks'))):
                raise ValueError('Canonical unique opaque archive DATA reference required')
            archive = Path(value); reference_paths.add(value)
            runtime_roots = [Path('/var/lib/containers/storage'), Path('/run/containers/storage')]
            scope = domains.get('storageScope', {}).get('root')
            if isinstance(scope, str) and Path(scope).is_absolute(): runtime_roots.append(Path(scope))
            for domain in domains['domains']:
                for key in ('graphRoot', 'runRoot', 'volumeRoot', 'stateRoot'):
                    root = domain.get(key)
                    if isinstance(root, str) and Path(root).is_absolute(): runtime_roots.append(Path(root))
            if any(archive == root or root in archive.parents for root in runtime_roots):
                raise ValueError('Runtime/store paths cannot become opaque archive supply')
            pin = data_directory(archive.parent)
            if os.path.lexists(archive.parent / 'PENDING'):
                raise ValueError('Referenced archive data is pending')
            if archive.parent in data_directories and data_directories[archive.parent] != pin:
                raise ValueError('Referenced archive namespace changed')
            data_directories[archive.parent] = pin
        if archive.lstat().st_size > verifier.MAX_ARCHIVE:
            raise ValueError('Oversized release archive')
        archive_sha = remember(archive, references is None)
        if (archive_sha != row['archiveSha256'] or type(row['archiveBytes']) is not int or
                row['archiveBytes'] != captures[archive][0][0][2]):
            raise ValueError('Release archive hash/size differs')
        # Real closure verification, not producer assertions; no extraction.
        if verifier.verify_oci(archive, image) != proof['ociProofs'][image]:
            raise ValueError('Actual OCI config/ordered DiffIDs differ from protected proof')
        rows.append((image, archive, selected[image]))
        seen.add(image); filenames.add(filename)
    if seen != set(selected) or (references is not None and set(references) != filenames):
        raise ValueError('Release inputs do not cover exact selected image scope')
    result = ValidatedRows(rows, bundle, inputs, captures, data_directories)
    result.recheck()
    return result


def native_store_owner():
    spec = importlib.util.spec_from_file_location('_pinned_native_root_store',
            Path(__file__).with_name('native-rootful-store.py'))
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def record_native_root_image(bundle, image, kind, proof_sha):
    if 'rootfulStore' not in read_json(bundle / 'podman-domains.json'):
        return
    owner = native_store_owner().Store(bundle)
    try:
        owner.record_image_source(image, kind, proof_sha)
    finally:
        owner.close()


def reserve_native_rootful_store(bundle):
    if 'rootfulStore' not in read_json(bundle / 'podman-domains.json'):
        return
    owner = native_store_owner().Store(bundle)
    try:
        owner.verify(); owner.reserve()
    finally:
        owner.close()


def rootful_command(bundle):
    """Never import/pull an isolated native/venue image through the shared store."""
    metadata = read_json(bundle / 'podman-domains.json')
    if 'rootfulStore' in metadata:
        owner = native_store_owner().Store(bundle)
        try:
            return owner.command()
        finally:
            owner.close()
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
            not isinstance(venue['portMap'], dict) or len(venue['portMap']) != 50 or
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
    ir = read_json(bundle / 'stack.ir.json')
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


def image_load_timeout(archive_bytes):
    """Finite preparation deadline for pinned SDK archives under 4GiB/200%.

    Image import is not application readiness. Allow a 300s setup budget plus
    4MiB/s of archive input (the selected Android SDK archive exceeds 4GiB),
    capped at the same 30 minutes as registry pulls. Identity verification,
    private scratch, resource limits and no-fallback policy remain mandatory.
    """
    if type(archive_bytes) is not int or archive_bytes < 0:
        raise ValueError('Invalid image archive byte size')
    quantum = 4 * 1024 * 1024
    return min(1800, 300 + (archive_bytes + quantum - 1) // quantum)


def install(rows, bundle=None):
    bundle = Path(bundle).absolute() if bundle is not None else None
    validated = isinstance(rows, ValidatedRows)
    if validated:
        if bundle is None or Path(bundle).absolute() != rows.bundle:
            raise ValueError('Validated images require their exact candidate bundle')
        rows.recheck()
    elif bundle is not None and any(
            read_json(bundle / name).get('deploymentMode') == 'standalone'
            for name in ('bundle.json', 'podman-domains.json', 'site/manifest.json') if (bundle / name).exists()):
        raise ValueError('Standalone image installation requires validated release proof')
    def dispatch(command, **kwargs):
        if validated:
            rows.recheck()
            if 'stdin' in kwargs:
                rows.check_fd(image, archive, kwargs['stdin'])
        return subprocess.run(command, **kwargs)
    os.chdir('/')
    metadata = read_json(bundle / 'podman-domains.json') if bundle is not None else {}
    aliases = frozen_aliases(bundle, metadata)
    domains = {d['user']: d for d in metadata.get('domains', [])}
    root_command = rootful_command(bundle) if bundle is not None else ['podman']
    for image, archive, authorities in rows:
        for user in authorities:
            if user == 'root':
                if bundle is not None:
                    record_native_root_image(bundle, image, 'qualified-local-archive',
                        rows.captures[archive][0][1] if validated else None)
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
                result = dispatch(command + ['image', 'inspect', ref, '--format', '{{.Id}}'],
                                        capture_output=True, text=True, timeout=30)
                return result.returncode == 0 and result.stdout.strip().removeprefix('sha256:') == image[7:]
            if not inspect():
                if user == 'root' and bundle is not None:
                    reserve_native_rootful_store(bundle)
                fd = open_regular(archive)
                with os.fdopen(fd, 'rb') as source:
                    dispatch(command + ['load'], stdin=source, capture_output=True, check=True,
                                   timeout=image_load_timeout(os.fstat(source.fileno()).st_size))
                if not inspect():
                    raise ValueError('Imported image differs from the pinned configuration ID')
            for alias in sorted(aliases.get((image, user), ())):
                present = dispatch(command + ['image', 'exists', alias], capture_output=True, timeout=30)
                if present.returncode == 0:
                    if not inspect(alias):
                        raise ValueError('Frozen local tag collision; refusing to replace another image')
                elif present.returncode == 1:
                    dispatch(command + ['tag', image, alias], capture_output=True, check=True, timeout=30)
                    if not inspect(alias):
                        raise ValueError('Frozen local tag differs after exact import')
                else:
                    raise ValueError('Frozen local tag inventory unavailable; no tag mutation')
            if validated:
                rows.recheck()
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
            key = user + '|' + image
            if user == 'root' and 'rootfulStore' in metadata:
                if key not in expected_ids:
                    raise ValueError('Native owned registry store requires frozen configuration identity before import')
                proof = hashlib.sha256((image + '\n' + expected_ids[key] + '\n').encode()).hexdigest()
                record_native_root_image(bundle, expected_ids[key], 'frozen-registry-reference', proof)
            result = runner(command + ['image', 'exists', image], capture_output=True, text=True, timeout=30)
            if result.returncode not in (0, 1):
                raise ValueError('Selected image inventory failed')
            if result.returncode == 1:
                if image.startswith('sha256:'):
                    raise ValueError('Offline selected image missing; no registry fallback')
                if user == 'root':
                    reserve_native_rootful_store(bundle)
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
    parser.add_argument('--validate-rootful-store', action='store_true')
    parser.add_argument('--require-runtime', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root required for protected release image inputs')
    try:
        if args.validate_rootful_store:
            if args.inputs is not None or args.prepare_registry or args.validate_only:
                raise ValueError('Native engine validation is a separate bounded operation')
            owner = native_store_owner().Store(args.bundle)
            try:
                if args.require_runtime:
                    owner.runtime_selected()
                else:
                    owner.verify()
            finally:
                owner.close()
            return
        if args.require_runtime:
            raise ValueError('Runtime requirement needs native engine validation')
        if args.inputs is None and not args.prepare_registry:
            raise ValueError('Protected release image inputs required')
        rows = validate(args.bundle, args.inputs) if args.inputs else []
        if not args.validate_only:
            if args.inputs is not None:
                install(rows, args.bundle)
            if args.prepare_registry:
                prepare_registry(args.bundle)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError,
            UnicodeError, EOFError, tarfile.TarError, zlib.error, subprocess.SubprocessError) as exc:
        parser.exit(1, f'[pinned-images] rejected: {type(exc).__name__}; no image fallback\n')


if __name__ == '__main__':
    main()
