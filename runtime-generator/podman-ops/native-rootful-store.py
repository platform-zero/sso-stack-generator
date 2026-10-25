#!/usr/bin/env python3
"""Native Root engine context ownership. Internal library, not a dispatcher.

Controls and engine metadata/data are private under /var/lib. Never derive
engine authority from operator-writable ancestors, generic links, opaque
archives or the shared default store. No policy or mount/namespace operation.
Actual graph-filesystem allocation must preserve its 50 GiB capacity floor.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

MARKER = '.native-rootful-store.json'
KEYS = {'schemaVersion', 'kind', 'scopeRoot', 'scopeMarkerSha256', 'stateRoot',
        'dataRoot', 'graphRoot', 'runRoot', 'networkRoot'}


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def path(value):
    require(isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            and str(Path(value)) == value and '..' not in Path(value).parts and value != '/',
            'Noncanonical native engine context path')
    return Path(value)


def definition(metadata):
    value = metadata.get('rootfulStore')
    if 'rootfulStore' not in metadata:
        return None
    require(isinstance(value, dict) and set(value) == KEYS and type(value['schemaVersion']) is int
            and value['schemaVersion'] == 1 and value['kind'] == 'standalone-owned-rootful-store'
            and metadata.get('deploymentMode') == 'standalone' and 'venue' not in metadata,
            'Native engine context schema differs')
    scope = metadata.get('storageScope')
    require(isinstance(scope, dict) and set(scope) == {'root', 'dataClass'}
            and scope['dataClass'] in ('synthetic', 'production') and value['scopeRoot'] == scope['root'],
            'Native engine source scope differs')
    base, state = path(scope['root']), path(metadata.get('installerStateRoot'))
    require(re.fullmatch(r'/var/lib/stack-[a-z0-9-]{1,48}', str(state)), 'Native engine metadata authority differs')
    control = state / 'rootful-store'
    require(value['stateRoot'] == str(control) and value['graphRoot'] == str(control / 'graph')
            and value['dataRoot'] == str(control / 'graph')
            and value['runRoot'] == '/run/' + state.name + '-podman'
            and value['networkRoot'] == str(control / 'networks')
            and isinstance(value['scopeMarkerSha256'], str)
            and re.fullmatch(r'[0-9a-f]{64}', value['scopeMarkerSha256']), 'Native engine roots/marker differ')
    for row in metadata.get('domains', []):
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            other = path(row[key]); data = path(value['dataRoot']).parent
            require(not data.is_relative_to(other) and not other.is_relative_to(data),
                    'Native engine and actor data authorities overlap')
    return dict(value)


def config_bytes(value):
    storage = ('[storage]\ndriver = "overlay"\nrunroot = "' + value['runRoot']
               + '"\ngraphroot = "' + value['graphRoot'] + '"\n').encode()
    engine = ('[network]\nnetwork_config_dir = "' + value['networkRoot'] + '"\n').encode()
    return {'containers-storage.conf': storage, 'containers.conf': engine,
            'empty-auth.json': b'{"auths":{}}\n'}


def imports_document(body, context_sha):
    value = json.loads(body)
    require(isinstance(value, dict) and set(value) == {'schemaVersion', 'contextSha256', 'images'}
            and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
            and value['contextSha256'] == context_sha and isinstance(value['images'], dict)
            and len(value['images']) <= 1024, 'Native engine image-source schema differs')
    for image, sources in value['images'].items():
        require(isinstance(image, str) and re.fullmatch(r'[0-9a-f]{64}', image)
                and isinstance(sources, list) and 1 <= len(sources) <= 128,
                'Native engine image-source identity/bound differs')
        for source in sources:
            require(isinstance(source, dict) and set(source) == {'kind', 'proofSha256', 'sourceMetadataSha256'}
                    and source['kind'] in ('qualified-local-archive', 'frozen-registry-reference')
                    and all(isinstance(source[key], str) and re.fullmatch(r'[0-9a-f]{64}', source[key])
                            for key in ('proofSha256', 'sourceMetadataSha256')), 'Native engine image-source proof differs')
    return value


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode))


def file_pin(info):
    # Reads may update atime. Identity, ownership, contents and mutation clocks
    # are admission/CAS data; atime is not an authority field.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def mount_id(fd):
    rows = [line.split(':', 1)[1].strip() for line in Path('/proc/self/fdinfo/' + str(fd)).read_text().splitlines()
            if line.startswith('mnt_id:')]
    require(len(rows) == 1 and rows[0].isdigit(), 'Native engine held mount identity unavailable')
    return int(rows[0])


def directory(value, *, private=False):
    """Caller closes returned FD. No-follow each component; no DAC repair."""
    target = path(str(value)); fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in target.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            if private:
                info = os.fstat(fd)
                require(info.st_uid == 0 and info.st_gid == 0 and not info.st_mode & 0o022
                        and not os.listxattr(fd), 'Native engine private ancestry differs')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(fd, name, limit=1024 * 1024):
    require(name and '/' not in name and name not in ('.', '..'), 'Native engine control name differs')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(child)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o077 and not os.listxattr(child)
                and 0 <= before.st_size <= limit, 'Native engine private control differs')
        with os.fdopen(os.dup(child), 'rb') as stream:
            body = stream.read(limit + 1)
        require(len(body) == before.st_size and file_pin(os.fstat(child)) == file_pin(before)
                and file_pin(os.stat(name, dir_fd=fd, follow_symlinks=False)) == file_pin(before), 'Native engine control CAS changed')
        return body
    finally:
        os.close(child)


def create_at(fd, name, body):
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(child, 0o600)  # NEW exclusive inode only; never repair an existing path.
        with os.fdopen(os.dup(child), 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(child)


def replace_at(fd, name, expected, body):
    require(read_at(fd, name) == expected, 'Native engine private control CAS changed')
    import secrets
    temporary = '.native-engine-' + secrets.token_hex(16)
    create_at(fd, temporary, body)
    require(read_at(fd, name) == expected, 'Native engine private control CAS changed before publication')
    os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)


def lock_held(root):
    named = root / '.install.lock'
    info = os.fstat(9)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o077 and identity(info) == identity(named.lstat())
            and not named.is_symlink(), 'Native engine canonical FD9 lock differs')
    probe = os.open(named, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(probe, fcntl.LOCK_UN)
        raise ValueError('Native engine canonical lock is not held')
    finally:
        os.close(probe)


class Store:
    def __init__(self, bundle):
        self.bundle = path(str(bundle)); self.opened = []; self.pointer = None
        try:
            if re.fullmatch(r'/var/lib/stack-[a-z0-9-]{1,48}/current', str(self.bundle)):
                parent = directory(self.bundle.parent, private=True); self.opened.append(parent)
                held = os.open('current', os.O_PATH | os.O_NOFOLLOW, dir_fd=parent); self.opened.append(held)
                info = os.fstat(held); target = os.readlink('current', dir_fd=parent)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                        'Native engine canonical current pointer differs')
                selected = Path(target) if target.startswith('/') else self.bundle.parent / target
                require(selected.parent == self.bundle.parent / 'releases'
                        and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}', selected.name),
                        'Native engine canonical current target differs')
                self.pointer = (parent, held, file_pin(info), target, self.bundle.parent)
                self.bundle = selected
            base = directory(self.bundle, private=True); self.opened.append(base)
            # Public immutable source is not a private secret control.
            child = os.open('podman-domains.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=base)
            try:
                info = os.fstat(child)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and not info.st_mode & 0o022 and info.st_size <= 1024 * 1024,
                        'Native engine source metadata differs')
                with os.fdopen(os.dup(child), 'rb') as stream:
                    raw = stream.read(1024 * 1024 + 1)
                require(len(raw) == info.st_size, 'Native engine source metadata bound changed')
                self.metadata = json.loads(raw); self.metadata_sha = digest(raw)
                require(file_pin(os.fstat(child)) == file_pin(info)
                        and file_pin(os.stat('podman-domains.json', dir_fd=base, follow_symlinks=False)) == file_pin(info),
                        'Native engine source metadata changed')
            finally:
                os.close(child)
            self.value = definition(self.metadata)
            require(self.value is not None, 'No selected native engine context')
            self.context_sha = digest(canonical(self.value))
            if self.pointer is not None:
                require(self.pointer[4] == Path(self.metadata['installerStateRoot']),
                        'Native engine pointer/source metadata authority differs')
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.pointer is not None:
                parent, held, pin, target, _ = self.pointer
                require(file_pin(os.fstat(held)) == pin
                        and file_pin(os.stat('current', dir_fd=parent, follow_symlinks=False)) == pin
                        and os.readlink('current', dir_fd=parent) == target,
                        'Native engine canonical current pointer CAS changed')
        finally:
            for fd in reversed(self.opened):
                os.close(fd)
            self.opened = []; self.pointer = None

    def reserve(self):
        memory = [int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemAvailable:')]
        require(len(memory) == 1 and memory[0] >= 16 * 1024**3, 'Native engine RAM reserve refused')
        for target, floor in ((Path('/'), 50), (Path(self.value['scopeRoot']), 100),
                              (Path(self.metadata['installerStateRoot']), 50)):
            space = os.statvfs(target)
            require(space.f_bavail * space.f_frsize >= floor * 1024**3 and space.f_favail >= 64,
                    'Native engine physical reserve refused')

    def verify(self):
        require(os.geteuid() == 0, 'Native engine Root ownership required')
        fds = []
        try:
            scope = directory(self.value['scopeRoot']); fds.append(scope)
            require(digest(read_at(scope, '.stack-installation.json')) == self.value['scopeMarkerSha256'],
                    'Native engine parent scope marker changed')
            state = directory(self.value['stateRoot'], private=True); fds.append(state)
            receipt = json.loads(read_at(state, 'custody.json'))
            require(receipt.get('schemaVersion') == 1 and receipt.get('phase') in ('ready-image-only', 'runtime-admitted')
                    and receipt.get('runtimeContainersAdmitted') is (receipt.get('phase') == 'runtime-admitted')
                    and receipt.get('context') == self.value and receipt.get('contextSha256') == self.context_sha,
                    'Native engine creation custody differs')
            for name, body in config_bytes(self.value).items():
                require(read_at(state, name) == body, 'Native engine configuration differs')
            graph = directory(self.value['graphRoot'], private=True); fds.append(graph)
            run = directory(self.value['runRoot'], private=True); fds.append(run)
            network = directory(self.value['networkRoot'], private=True); fds.append(network)
            for fd in (state, graph, run, network):
                info = os.fstat(fd)
                require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
                        and not os.listxattr(fd), 'Native engine private directory differs')
            require(receipt['dataIdentity'] == identity(os.fstat(graph))
                    and mount_id(graph) == mount_id(state)
                    and identity(os.fstat(run)) == receipt['runIdentity']
                    and identity(os.fstat(network)) == receipt['networkIdentity'],
                    'Native engine private data/run/network identity changed')
            imports_document(read_at(state, 'imports.json'), self.context_sha)
            marker = json.loads(read_at(graph, MARKER))
            require(marker == receipt['dataMarker'] and marker['contextSha256'] == self.context_sha,
                    'Native engine data marker differs')
            require(os.fstat(graph).st_dev == os.fstat(state).st_dev,
                    'Native engine graph is not on its private metadata filesystem')
            named_data = directory(self.value['dataRoot']); fds.append(named_data)
            require(identity(os.fstat(named_data)) == receipt['dataIdentity']
                    and identity(os.stat(self.value['scopeRoot'], follow_symlinks=False)) == identity(os.fstat(scope)),
                    'Native engine named data/scope CAS changed')
            # Capacity gates belong to affected allocation/import operations;
            # readonly custody, clean stop and cleanup must remain possible.
            return receipt
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def command(self):
        self.verify()
        state = self.value['stateRoot']
        return ['/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C',
                'HOME=' + state, 'USER=root', 'LOGNAME=root',
                'XDG_CONFIG_HOME=' + state + '/xdg', 'XDG_RUNTIME_DIR=' + self.value['runRoot'],
                'REGISTRY_AUTH_FILE=' + state + '/empty-auth.json', 'TMPDIR=' + self.value['graphRoot'],
                'CONTAINERS_STORAGE_CONF=' + state + '/containers-storage.conf',
                'CONTAINERS_CONF=' + state + '/containers.conf', '/usr/bin/podman',
                '--root', self.value['graphRoot'], '--runroot', self.value['runRoot'],
                '--network-config-dir', self.value['networkRoot']]

    def record_image_source(self, image, kind, proof_sha):
        """Record source intent BEFORE import, not opaque-payload action authority.

        An interrupted load remains attributable. A future cleanup still needs
        its own fresh inventory, offline review, held FDs/CAS and stopped lease.
        """
        root = Path(self.metadata['installerStateRoot']); lock_held(root); self.verify()
        image = image.removeprefix('sha256:')
        require(re.fullmatch(r'[0-9a-f]{64}', image) and isinstance(proof_sha, str)
                and re.fullmatch(r'[0-9a-f]{64}', proof_sha)
                and kind in ('qualified-local-archive', 'frozen-registry-reference'),
                'Native engine image source identity differs')
        fd = directory(self.value['stateRoot'], private=True)
        try:
            original = read_at(fd, 'imports.json'); record = imports_document(original, self.context_sha)
            source = dict(kind=kind, proofSha256=proof_sha, sourceMetadataSha256=self.metadata_sha)
            sources = record['images'].setdefault(image, [])
            if source not in sources:
                require(len(sources) < 128 and len(record['images']) <= 1024, 'Native engine image-source bound exceeded')
                sources.append(source); sources.sort(key=lambda item: canonical(item))
                body = canonical(record); imports_document(body, self.context_sha)
                replace_at(fd, 'imports.json', original, body)
        finally:
            os.close(fd)

    def runtime_selected(self):
        """Read-only systemd startup guard; custody/history is not selection."""
        receipt = self.verify()
        require(receipt['phase'] == 'runtime-admitted', 'Native engine has no runtime custody')
        root = Path(self.metadata['installerStateRoot']); fds = []
        try:
            base = directory(root, private=True); fds.append(base)
            release = directory(self.bundle, private=True); fds.append(release)
            raw = read_at(base, '.install-intent.json'); intent = json.loads(raw)
            require(read_at(release, 'installation-receipt.json') == raw
                    and intent.get('phase') in ('units-selected', 'building', 'starting', 'active')
                    and intent.get('release') == str(self.bundle)
                    and intent.get('inputs', {}).get('podman-domains.json') == self.metadata_sha,
                    'Native engine startup requires live selected dual records/source')
            require(read_at(base, '.install-intent.json') == raw, 'Native engine selected startup CAS changed')
            return receipt
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def admit_runtime(self):
        """Record real canonical preparing entry, not caller/security authorization."""
        root = Path(self.metadata['installerStateRoot']); lock_held(root)
        receipt = self.verify()
        require(self.bundle.parent == root / 'releases', 'Native runtime admission requires installed immutable source')
        fds = []
        try:
            base = directory(root, private=True); fds.append(base)
            release = directory(self.bundle, private=True); fds.append(release)
            raw = read_at(base, '.install-intent.json'); intent = json.loads(raw)
            require(read_at(release, 'installation-receipt.json') == raw
                    and intent.get('phase') == 'preparing' and intent.get('release') == str(self.bundle)
                    and intent.get('inputs', {}).get('podman-domains.json') == self.metadata_sha
                    and (intent.get('nativeSeafilePreparation') is None or
                         intent.get('nativeSeafilePreparation', {}).get('scopeMarkerSha256') == self.value['scopeMarkerSha256']),
                    'Native runtime admission requires exact canonical preparing dual records/source')
            if receipt['phase'] == 'runtime-admitted':
                return receipt  # Existing custody is eligibility only; live binding checked above.
            state = directory(self.value['stateRoot'], private=True); fds.append(state)
            original = read_at(state, 'custody.json')
            require(json.loads(original) == receipt, 'Native engine custody changed before runtime admission')
            updated = dict(receipt, phase='runtime-admitted', runtimeContainersAdmitted=True,
                           runtimeAdmission=dict(release=str(self.bundle), preparingIntentSha256=digest(raw)))
            require(read_at(base, '.install-intent.json') == raw, 'Native preparing admission CAS changed')
            replace_at(state, 'custody.json', original, canonical(updated))
            return self.verify()
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def prepare(self, storage):
        """First creation only. Interrupted/foreign paths refuse; no adoption or repair."""
        require(os.geteuid() == 0, 'Native engine Root initialization required')
        root = Path(self.metadata['installerStateRoot']); lock_held(root); self.reserve()
        scope, operator, expected = storage.authority(self.bundle)
        storage.marker(scope, expected); storage.safe_parent(scope, operator)
        marker_body = (json.dumps(expected, sort_keys=True) + '\n').encode()
        require(digest(marker_body) == self.value['scopeMarkerSha256'], 'Native engine parent source marker differs')
        state_path = Path(self.value['stateRoot'])
        if state_path.exists() or state_path.is_symlink():
            return self.verify()
        run_path = Path(self.value['runRoot'])
        require(all(not item.exists() and not item.is_symlink() for item in (state_path, run_path)),
                'Native engine initialization requires absent new roots')
        fds = []
        try:
            scope_fd = directory(scope); fds.append(scope_fd)
            scope_identity = identity(os.fstat(scope_fd))
            metadata_fd = directory(root, private=True); fds.append(metadata_fd)
            run_parent = directory('/run', private=True); fds.append(run_parent)
            os.mkdir(state_path.name, 0o700, dir_fd=metadata_fd)
            state = os.open(state_path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=metadata_fd); fds.append(state)
            for name in ('graph', 'networks'):
                os.mkdir(name, 0o700, dir_fd=state)
            os.mkdir(run_path.name, 0o700, dir_fd=run_parent)
            run = os.open(run_path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run_parent); fds.append(run)
            network = os.open('networks', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state); fds.append(network)
            data = os.open('graph', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state); fds.append(data)
            for new in (state, run, network, data):
                os.fchown(new, 0, 0); os.fchmod(new, 0o700)  # NEW exclusive inodes only.
            import secrets
            data_marker = dict(schemaVersion=1, kind='source-created-native-engine-data', contextSha256=self.context_sha,
                               scopeMarkerSha256=self.value['scopeMarkerSha256'], nonce=secrets.token_hex(32))
            create_at(data, MARKER, canonical(data_marker))
            for name, body in config_bytes(self.value).items():
                create_at(state, name, body)
            origin = dict(schemaVersion=1, phase='source-created-private-engine-data', context=self.value,
                          contextSha256=self.context_sha, dataMarker=data_marker, dataIdentity=identity(os.fstat(data)),
                          runIdentity=identity(os.fstat(run)), networkIdentity=identity(os.fstat(network)),
                          sourceMetadataSha256=self.metadata_sha, runtimeContainersAdmitted=False)
            create_at(state, 'initialization.json', canonical(origin))
            create_at(state, 'imports.json', canonical(dict(schemaVersion=1, contextSha256=self.context_sha, images={})))
            require(identity(os.stat(scope, follow_symlinks=False)) == scope_identity
                    and identity(os.stat(self.value['dataRoot'], follow_symlinks=False)) == origin['dataIdentity'],
                    'Native engine held data/scope CAS changed')
            require(mount_id(data) == mount_id(state), 'Native engine unexpected graph mount')
            receipt = dict(origin, phase='ready-image-only')
            create_at(state, 'custody.json', canonical(receipt))
            return self.verify()
        finally:
            for fd in reversed(fds):
                os.close(fd)


def load_storage():
    spec = importlib.util.spec_from_file_location('_native_root_engine_storage',
        Path(__file__).with_name('grant-rootless-volume-parent-traverse.py'))
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module
