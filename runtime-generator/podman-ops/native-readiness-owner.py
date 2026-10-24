#!/usr/bin/env python3
"""Read-only owner callbacks for install-journal.update, under inherited lock FD9.

seal_selection(root, release, prior_intent): preparing -> units-selected, BEFORE
any bootstrap/required oneshot. capture_images(...): building -> starting, AFTER
image preparation. verify_active_transition(...): starting -> active. The first
two return readiness metadata to embed unchanged in BOTH journal records. The
last returns whole-graph observation metadata, NOT an admission token. No CLI,
lock creation, journal write, restart, retry, cache mutation or alternate daemon.
Errors MUST leave failed/pending disposition with the existing journal owner.
"""
import errno
import fcntl
import grp
import importlib.util
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import sys
import time


def load(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # No pycache writes while importing the read-only owner dependencies.
    # The journal entrypoint must itself use -B before importing THIS module.
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


r = load('_native_owner_graph', 'verify-native-readiness.py')
storage = load('_native_owner_storage', 'grant-rootless-volume-parent-traverse.py')
images = load('_native_owner_images', 'install-pinned-images.py')
journal = load('_native_owner_journal', 'install-journal.py')
projections = load('_native_owner_runtime_projections', 'verify-native-runtime-projections.py')
rootful_environment = load('_native_owner_rootful_environment', 'native-rootful-env-owner.py')
runtime_units = load('_native_owner_runtime_units', 'native-runtime-env-units.py')
require = r.require
Refused = r.Refused


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def root_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe root authority directory')


def read_file(path, *, owner=0, private=False, directories=None, limit=8 * 1024 * 1024):
    """No-link descriptor walk, exact custody exceptions, no ancestor relaxation.

    directories maps EXACT validated directory paths to (uid, gid, mode). It is
    constructed only from canonical storage/account custody, not caller input.
    Everything else is root-owned and non-group/other-writable.
    """
    path = r.canonical(path); directories = directories or {}
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    opened = [(Path('/'), identity(os.fstat(fd)))]; base = Path('/')
    try:
        root_directory(os.fstat(fd))
        for part in path.parts[1:-1]:
            base /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if base in directories:
                require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == directories[base],
                        'bound custody directory changed')
            else:
                root_directory(info)
            opened.append((base, identity(info)))
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(child)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                    and not before.st_mode & 0o022 and before.st_size <= limit
                    and (not private or stat.S_IMODE(before.st_mode) == 0o600), 'unsafe bound file')
            result = bytearray()
            while len(result) <= limit:
                block = os.read(child, min(65536, limit + 1 - len(result)))
                if not block: break
                result.extend(block)
            require(len(result) == before.st_size and len(result) <= limit
                    and identity(before) == identity(os.fstat(child)), 'bound file changed during read')
            require(identity(path.lstat()) == identity(before), 'bound pathname changed during read')
            # Also catch ancestor renames/replacement while the descriptor was held.
            for directory, pin in opened:
                require(identity(directory.lstat()) == pin, 'bound ancestor changed during read')
            return bytes(result)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def lock_held(root):
    """Verify the EXISTING inherited flock; never acquire/release FD9's lock.

    fdinfo associates the flock with this open-file-description (including a
    lock inherited from the shell). A competing descriptor must be excluded.
    Merely calling flock(9, LOCK_EX) would silently acquire an absent lock.
    """
    root = r.canonical(root)
    r.read_owned(root / '.install.lock', private=True, limit=65536)
    named = (root / '.install.lock').lstat(); inherited = os.fstat(9)
    require(identity(named) == identity(inherited), 'inherited lock FD9 identity mismatch')
    require(stat.S_IMODE(inherited.st_mode) == 0o600 and inherited.st_uid == 0
            and inherited.st_nlink == 1 and stat.S_ISREG(inherited.st_mode), 'unsafe installer lock')
    with open('/proc/self/fdinfo/9', encoding='ascii') as source:
        body = source.read(65537)
    locks = [line.split() for line in body.splitlines() if line.startswith('lock:')]
    require(len(body) <= 65536 and len(locks) == 1 and len(locks[0]) >= 9
            and locks[0][2:5] == ['FLOCK', 'ADVISORY', 'WRITE'], 'FD9 has no exclusive inherited flock')
    devino = locks[0][6].split(':')
    require(len(devino) == 3 and int(devino[0], 16) == os.major(inherited.st_dev)
            and int(devino[1], 16) == os.minor(inherited.st_dev)
            and int(devino[2]) == inherited.st_ino, 'FD9 flock inode mismatch')
    fd = os.open(root / '.install.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd)) == identity(inherited), 'installer lock replaced')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            require(error.errno in (errno.EAGAIN, errno.EACCES), 'installer flock unavailable')
        else:
            # This only locks the competing description; never touches FD9.
            fcntl.flock(fd, fcntl.LOCK_UN)
            raise Refused('installer lock was not held')
    finally:
        os.close(fd)
    return True


def boot_id():
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as source:
        value = source.read(128).strip()
    require(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value), 'invalid kernel boot identity')
    return value


def directory_pin(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not path.is_symlink(), 'linked custody directory')
    return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def check_acl(path, allowed, remaining=lambda: 120, *, operator_uid=None, public=False):
    """Keep exact execute-only named ACLs; do not read private file bodies."""
    require(remaining() >= 10, 'insufficient deadline for canonical ACL query')
    acl = storage.entries(path, numeric=True)
    require(acl.get(('other', '')) in (('---', '--x', 'r-x') if public else ('---',)), 'public storage custody')
    for (kind, name), rights in acl.items():
        rights = rights.split('#', 1)[0].strip()
        if name:
            require(kind == 'user' and name.isdigit() and
                    ((int(name) == operator_uid and rights == 'rwx') or
                     (int(name) in allowed and rights == '--x')),
                    'foreign or non-execute storage ACL')
    return acl


def storage_binding(release, *, remaining=lambda: 120):
    """Reuse the canonical marker/safe-parent authority, without chmod/adoption."""
    require(remaining() >= 10, 'insufficient storage authority deadline')
    scope, operator, expected = storage.authority(release)
    storage.marker(scope, expected)
    require(remaining() >= 10, 'insufficient canonical parent query deadline')
    storage.safe_parent(scope, operator)
    # Canonical marker/operator authority, not a literal username/group or
    # historical fixture UID. This host's primary operator GID is 1000;
    # there is no group named 'stack'. Never create/adopt one to pass a gate.
    require(directory_pin(scope) == (operator.pw_uid, operator.pw_gid, 0o2770), 'storage scope custody differs')
    rows = expected['domains']; allowed = {row['uid'] for row in rows}
    require(allowed and len(allowed) == len(rows) and operator.pw_uid not in allowed,
            'unreviewed actor UID')
    # Existing canonical subid authority, not a new mapping or cache discovery.
    allowed.update(storage.namespace_root_id(row['user']) for row in rows)
    custody = {scope: directory_pin(scope)}
    for row in rows:
        account = pwd.getpwnam(row['user'])
        require(account.pw_uid == row['uid'] and account.pw_dir == '/home/' + row['user'],
                'selected actor identity changed')
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            path = r.canonical(row[key])
            require(path.is_relative_to(scope) and path != scope, 'private root escapes scope')
            require(directory_pin(path) == (row['uid'], account.pw_gid, 0o700), 'private actor root custody differs')
            custody[path] = directory_pin(path)
            for parent in path.parents:
                if parent == scope: break
                require(parent.is_relative_to(scope), 'private root ancestry escaped')
                require(remaining() >= 10, 'insufficient canonical parent query deadline')
                storage.safe_parent(parent, operator)
                check_acl(parent, allowed, remaining, operator_uid=operator.pw_uid,
                          public=parent == scope / 'volumes')
                custody[parent] = directory_pin(parent)
    check_acl(scope, allowed, remaining, operator_uid=operator.pw_uid)
    # The actual mounted storage parent is operator-owned 2775 with authored
    # ACLs. Reuse canonical operator-only-writer checks and pin its identity;
    # do not change it, unmask ACLs, or permit arbitrary writable ancestors.
    for parent in scope.parents:
        require(remaining() >= 10, 'insufficient ancestor custody query deadline')
        storage.safe_parent(parent, operator)
        custody[parent] = directory_pin(parent)
    marker = read_file(scope / storage.MARKER, private=True, directories=custody, limit=65536)
    require(r.strict(marker) == expected, 'storage marker changed')
    marker_stat = (scope / storage.MARKER).lstat()
    return ({'scope': str(scope), 'markerSha256': r.sha(marker), 'authority': expected,
             'markerIdentity': [marker_stat.st_dev, marker_stat.st_ino, marker_stat.st_uid,
                                marker_stat.st_gid, marker_stat.st_mode, marker_stat.st_nlink],
             'directoryIdentities': {str(p): [p.lstat().st_dev, p.lstat().st_ino] for p in sorted(custody)},
             'custody': {str(k): list(v) for k, v in sorted(custody.items())}}, custody)


def inventory(release):
    """Descriptor-bound exact flat Quadlet inventory, including empty scopes."""
    def children(path):
        path = r.canonical(path)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_directory(os.fstat(fd))
            for component in path.parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child; root_directory(os.fstat(fd))
            names = os.listdir(fd)
            require(len(names) <= 10000, 'oversized rendered inventory')
            return [path / name for name in sorted(names)]
        finally:
            os.close(fd)
    result = {}
    for scope in children(release / 'quadlet'):
        root_directory(scope.lstat())
        require(scope.name == 'rootful' or re.fullmatch(r'rootless-[a-z][a-z0-9-]{0,63}', scope.name),
                'foreign rendered manager')
        for path in children(scope):
            name = str(path.relative_to(release)); r.relative(name)
            require(path.suffix in ('.container', '.build', '.network', '.target'), 'foreign rendered input')
            result[name] = read_file(path)
    require(result, 'empty rendered inventory')
    return result


def pointer(root, release, *, directories=None, owners=(0,)):
    """Only exact native metadata current pointers may be links."""
    root = r.canonical(root); release = r.canonical(release); directories = directories or {}
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    base = Path('/')
    try:
        for component in root.parts[1:]:
            base /= component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if base in directories:
                require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == directories[base],
                        'pointer custody directory changed')
            else:
                root_directory(info)
        before = os.stat('current', dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISLNK(before.st_mode) and before.st_uid in owners
                and before.st_nlink == 1, 'invalid native current pointer')
        require(os.readlink('current', dir_fd=fd) == str(release), 'native current pointer changed')
        require(identity(before) == identity(os.stat('current', dir_fd=fd, follow_symlinks=False))
                and identity(os.fstat(fd)) == identity(root.lstat()), 'native current pointer raced')
    finally:
        os.close(fd)
    return True


def finance_actor(descriptor):
    """Canonical finance reader, from selected source + exact NSS/sub-ID custody.

    No account creation, supplemental-group grant, caller GID or permission flag.
    Host Root remains the physical metadata owner; only this private primary
    group can read the rootless transport. Historical rootful profiles are not
    remapped or adopted.
    """
    if descriptor is None or descriptor.get('placement', 'rootful') == 'rootful': return None
    require(descriptor.get('placement') == 'rootless', 'Unknown finance authority placement')
    selected = load('_finance_actor_identities', 'native-selection.py')
    uid, user = selected.IDENTITIES['platform']
    require(descriptor.get('actor') == dict(domain='platform', uid=uid, user=user)
            and descriptor.get('consumer') == dict(user='1000:0', uid=1000, gid=0, namespace='canonical-rootless-default')
            and descriptor.get('transport') == 'root-owned-platform-group-readonly-v1', 'Exact selected finance reader required')
    account, group = pwd.getpwnam(user), grp.getgrnam(user)
    require((account.pw_uid, account.pw_name, account.pw_dir) == (uid, user, '/home/' + user)
            and pwd.getpwuid(uid).pw_name == user and account.pw_gid == group.gr_gid > 0
            and grp.getgrgid(group.gr_gid).gr_name == user and set(group.gr_mem) <= {user}
            and all(other.pw_name == user for other in pwd.getpwall() if other.pw_gid == group.gr_gid),
            'Canonical finance account/primary-group custody differs')
    subordinate = storage.namespace_root_id(user)
    text = Path('/proc/sys/kernel/overflowuid').read_text().strip()
    require(text.isdigit() and 0 < int(text) < 2**32 - 1, 'Unknown kernel overflow UID')
    return dict(uid=uid, gid=group.gr_gid, user=user, home=account.pw_dir,
                subuidStart=subordinate, overflowUid=int(text))


def finance_transport(descriptor):
    actor = finance_actor(descriptor)
    if actor is None: return None
    return dict(kind='root-owned-platform-group-readonly-v1', actorUid=actor['uid'], actorGid=actor['gid'],
                actorUser=actor['user'], consumerUid=1000, consumerGid=0, overflowUid=actor['overflowUid'])


def finance_original_reference(native, intent, descriptor, release, issuer):
    """Read-only current source/actor binding of the ORIGINAL native receipt."""
    actor = finance_actor(descriptor)
    require(actor is not None and type(native) is dict, 'Original rootless finance receipt required')
    readiness = intent['readiness']; scope = 'rootless-platform'; source = {}
    for name, key in (('keycloak-configure', 'configure'), ('keycloak', 'keycloak'), ('postgres', 'postgres')):
        source[key] = dict(readiness['loadedInputs'][scope]['webservices-' + name + '.service'],
                           image=readiness['images'][scope]['webservices-' + name + '.service']['configId'])
    image_user = native.get('source', {}).get('imageUser')
    require(image_user in ('1000', '1000:0'), 'Original pinned configure image USER missing')
    source.update(authority=actor, imageUser=image_user,
                  financeScriptSha256=r.sha(read_file(release / 'runtime/configs/keycloak/configure-finance.sh')),
                  runtimeScriptSha256=r.sha(read_file(release / 'runtime/configs/keycloak/configure-runtime.sh')))
    # Load only the source-pinned publisher's pure receipt validator. It cannot
    # query/start/replay an engine or synthesize a missed original invocation.
    owner = load('_finance_original_source_validator', 'native-finance-ownership.py')
    owner.original_receipt(native, source, issuer)


def finance_file_profile(descriptor=None):
    actor = finance_actor(descriptor)
    return (dict(gid=0, directoryMode=0o755, fileMode=0o444) if actor is None else
            dict(gid=actor['gid'], directoryMode=0o750, fileMode=0o440))


def finance_reference_files(descriptor=None):
    """Exact nonsecret dynamic directory/file FD custody, no prefix adoption."""
    profile = finance_file_profile(descriptor)
    slot = Path('/var/lib/webservices-native-finance')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    pins = []; path = Path('/')
    try:
        root_directory(os.fstat(fd)); pins.append((path, identity(os.fstat(fd))))
        for part in slot.parts[1:]:
            path /= part
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child; root_directory(os.fstat(fd))
            pins.append((path, identity(os.fstat(fd))))
        directory = os.fstat(fd)
        require(directory.st_uid == 0 and directory.st_gid == profile['gid']
                and stat.S_IMODE(directory.st_mode) == profile['directoryMode']
                and not os.listxattr(fd) and set(os.listdir(fd)) == {'input.json'}, 'Unknown Root finance reference directory')
        leaf = os.open('input.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == profile['gid']
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == profile['fileMode']
                    and before.st_size <= 65536 and not os.listxattr(leaf), 'Unknown Root finance reference file')
            body = os.pread(leaf, 65537, 0)
            def mount_id(number):
                text = Path('/proc/self/fdinfo/' + str(number)).read_text()
                rows = [line.split()[1] for line in text.splitlines() if line.startswith('mnt_id:')]
                require(len(rows) == 1 and rows[0].isdigit(), 'Unknown Root finance reference mount')
                return int(rows[0])
            dm, fm = mount_id(fd), mount_id(leaf)
            require(dm == fm and len(body) == before.st_size and identity(before) == identity(os.fstat(leaf))
                    == identity(os.stat('input.json', dir_fd=fd, follow_symlinks=False)), 'Root finance reference raced/remounted')
            for named, pin in pins: require(identity(named.lstat()) == pin, 'Root finance reference ancestor replaced')
            return dict(directory=dict(path=str(slot), identity=list(identity(directory)), mountId=dm),
                        input=dict(path=str(slot / 'input.json'), identity=list(identity(before)), mountId=fm,
                                   sha256=r.sha(body), content=r.strict(body)))
        finally: os.close(leaf)
    finally: os.close(fd)


def verify_native_finance_reference(root, release, intent):
    """Current Root-CAS observation only, NOT fresh identity/source permission.

    Missing legacy descriptor returns None. A selected not-yet-armed source is
    deferred until the canonical arm transaction; full active admission below
    requires the actual typed Root reference, never a caller/env override.
    """
    profile = load('_native_finance_reference_profile', 'verify-agent-vm-bundle.py')
    raw_ir = read_file(release / 'stack.ir.json')
    require(r.sha(raw_ir) == intent['inputs']['stack.ir.json'], 'Finance reference source IR differs')
    ir = r.strict(raw_ir)
    domains = None
    if ir.get('services', {}).get('keycloak-configure', {}).get('placement') == 'rootless':
        raw_domains = read_file(release / 'podman-domains.json')
        require(r.sha(raw_domains) == intent['inputs']['podman-domains.json'], 'Finance actor source metadata differs')
        domains = r.strict(raw_domains)
    descriptor = profile.native_finance_reference(ir, domains)
    if descriptor is None:
        require('nativeFinanceReference' not in intent, 'Legacy source cannot adopt finance reference ownership')
        return None
    proof = intent.get('nativeFinanceReference')
    if proof is None: return dict(status='deferred', bindingSha256=None)
    require(type(proof) is dict and set(proof) == {'schemaVersion', 'kind', 'status', 'root', 'release', 'inputs',
            'intentSha256', 'descriptor', 'publisher', 'directory', 'input'}
            and type(proof['schemaVersion']) is int and proof['schemaVersion'] == 1
            and proof['kind'] == 'root-native-finance-reference' and proof['status'] == 'completed'
            and proof['root'] == str(root) and proof['release'] in (str(release), intent.get('previousRelease'))
            and proof['inputs'] == intent['inputs']
            and proof['descriptor'] == descriptor and type(proof['intentSha256']) is str
            and r.HEX.fullmatch(proof['intentSha256']), 'Unknown Root finance reference origin')
    lock_held(root); private_root = directory_pin(root)
    require(private_root[0] == 0 and private_root[2] == 0o700 and intent.get('release') == str(release),
            'Finance reference requires exact private Root metadata owner')
    pointer(root, release)
    raw = read_file(root / '.install-intent.json', private=True)
    require(r.strict(raw) == intent and read_file(release / 'installation-receipt.json', private=True) == raw,
            'Finance reference current Root dual CAS differs')
    publisher = proof['publisher']; metadata = r.strict(read_file(release / 'bundle.json'))
    require(type(publisher) is dict and set(publisher) == {'path', 'sha256', 'origin'}
            and publisher['path'] == descriptor['publisher'] and publisher['origin'] == descriptor['origin']
            and publisher['sha256'] == metadata.get('liveOps', {}).get(descriptor['publisher'])
            and r.sha(read_file(release / descriptor['publisher'])) == publisher['sha256'], 'Finance Root publisher source differs')
    observed = finance_reference_files(descriptor)
    require(observed == {key: proof[key] for key in ('directory', 'input')}, 'Original Root finance reference inode/ACL/mount/bytes differ')
    content = observed['input']['content']
    require(content.get('kind') == 'root-native-finance-input' and content.get('root') == str(root)
            and content.get('release') == proof['release'] and content.get('intentSha256') == proof['intentSha256']
            and content.get('sourceSha256') == r.sha(read_file(release / 'runtime/configs/keycloak/configure-finance.sh')),
            'Finance Root reference consumer source/CAS differs')
    # Actual native original provenance is held in the protected paired Root
    # records; the dynamic file transports it, never grants source permission.
    native = intent.get('nativeFinanceOwnershipReceipt')
    if descriptor['placement'] == 'rootless':
        require(content.get('transport') == finance_transport(descriptor), 'Root-issued finance reader transport differs')
    else:
        require('transport' not in content, 'Historical finance transport cannot be reclassified')
    if content.get('status') == 'retained':
        require(type(native) is dict and native.get('kind') == 'root-native-finance-ownership'
                and native.get('status') == 'completed' and native.get('original', {}).get('kind') ==
                'original-live-systemd-cid-keycloak-native-link'
                and content.get('nativeFinanceOwnership') == native.get('nativeFinanceOwnership'), 'Finance original native origin differs')
        if descriptor['placement'] == 'rootless':
            finance_original_reference(native, intent, descriptor, release, content.get('issuer'))
    else:
        require(content.get('status') == 'fresh' and content.get('nativeFinanceOwnership') is None
                and type(intent.get('financeOwnershipCustody')) is dict, 'Finance fresh original arm missing')
    require(finance_reference_files(descriptor) == observed and read_file(root / '.install-intent.json', private=True) == raw
            and read_file(release / 'installation-receipt.json', private=True) == raw
            and directory_pin(root) == private_root, 'Finance reference current CAS raced')
    pointer(root, release)
    return dict(kind='root-native-finance-reference-observation', status='completed',
                bindingSha256=r.sha(r.frozen(proof).encode()), root=str(root), release=str(release),
                intentSha256=r.sha(raw), reference=r.strict(r.frozen(proof)),
                activationAuthorized=False, readinessAuthorized=False, journalWritten=False)


class Selection:
    def __init__(self, root, release, prior_intent, phase):
        self.root = r.canonical(root); self.release = r.canonical(release)
        require(self.root != Path('/') and self.release.parent == self.root / 'releases', 'release escapes journal root')
        require(isinstance(prior_intent, dict) and prior_intent.get('schemaVersion') == 1
                and type(prior_intent.get('schemaVersion')) is int
                and prior_intent.get('phase') == phase and prior_intent.get('release') == str(self.release),
                'prior intent phase/release differs')
        # Deep copy so callers cannot mutate a comparison authority mid-sweep.
        self.prior = r.strict(r.frozen(prior_intent)); self.cas = None
        self.plan = None; self.custody = {}; self.deadline = time.monotonic() + 120

    def left(self):
        left = self.deadline - time.monotonic()
        require(left > 0, 'native owner observation deadline exceeded')
        return left

    def snapshot(self):
        self.left(); lock_held(self.root)
        raw = read_file(self.root / '.install-intent.json', private=True)
        require(r.strict(raw) == self.prior and (self.cas is None or r.sha(raw) == self.cas), 'intent/CAS changed')
        require(read_file(self.release / 'installation-receipt.json', private=True) == raw, 'receipt/intent byte mismatch')
        self.cas = r.sha(raw)
        pointer(self.root, self.release)
        pins = self.prior.get('inputs')
        require(isinstance(pins, dict) and set(pins) == set(journal.CORE_INPUTS + journal.PINNED_INPUTS),
                'expanded canonical input pins required')
        bodies = {}
        for name, digest in pins.items():
            try:
                body = read_file(self.release / name)
            except FileNotFoundError:
                require(digest is None and name not in journal.CORE_INPUTS, 'missing canonical input')
                continue
            require(isinstance(digest, str) and r.HEX.fullmatch(digest) and r.sha(body) == digest, 'canonical input hash changed')
            bodies[name] = body
        self.ir = r.strict(bodies['stack.ir.json']); self.domains = r.strict(bodies['podman-domains.json'])
        manifest = r.strict(bodies['site/manifest.json'])
        require(manifest.get('deploymentMode') == 'standalone'
                and manifest.get('installerStateRoot', '/var/lib/webservices') == str(self.root)
                and self.domains.get('installerStateRoot') == str(self.root)
                and manifest.get('storageScope') == self.domains.get('storageScope'), 'native site/root scope mismatch')
        self.rendered = inventory(self.release)
        rendered_pins = {k: r.sha(v) for k, v in self.rendered.items()}
        plan = r.derive_plan(self.ir, self.domains, self.rendered)
        require(self.plan is None or self.plan == plan, 'selected graph changed')
        self.plan = plan
        storage_pin, self.custody = storage_binding(self.release, remaining=self.left)
        scope = r.canonical(storage_pin['scope'])
        require(not scope.is_relative_to(self.root) and not self.root.is_relative_to(scope), 'metadata/storage overlap')
        rootful = rootful_environment.verify_environment(self.root, self.release, self.prior)
        require(rootful.get('kind') == 'rootful-persistent-environment-observation'
                and isinstance(rootful.get('bindingSha256'), str) and r.HEX.fullmatch(rootful['bindingSha256'])
                and rootful.get('activationAuthorized') is False and rootful.get('readinessAuthorized') is False,
                'actual persistent Root environment observation required')
        prepared = runtime_units.verify_prepared_units(self.root, self.release, self.prior)
        require(prepared.get('kind') == 'native-prepared-runtime-env-unit-observation'
                and prepared.get('status') == 'completed'
                and prepared.get('resetAuthorized') is False
                and isinstance(prepared.get('sourceSha256'), str) and r.HEX.fullmatch(prepared['sourceSha256'])
                and isinstance(prepared.get('selectionSourceSha256'), str)
                and r.HEX.fullmatch(prepared['selectionSourceSha256'])
                and prepared.get('runningEnvironmentChecked') is False
                and prepared.get('journalWritten') is False
                and prepared.get('activationAuthorized') is False and prepared.get('readinessAuthorized') is False,
                'actual persistent runtime-unit source observation required')
        copies_binding = None
        if self.prior.get('phase') in ('building', 'starting', 'active'):
            copies = runtime_units.verify_running_copies(self.root, self.release, self.prior)
            require(copies.get('kind') == 'root-runtime-copy-observation-verified'
                    and copies.get('status') == 'completed'
                    and copies.get('runningEnvironmentChecked') is True
                    and copies.get('resetAuthorized') is False
                    and isinstance(copies.get('bindingSha256'), str) and r.HEX.fullmatch(copies['bindingSha256'])
                    and copies.get('sourceSha256') == prepared['sourceSha256']
                    and copies.get('selectionSourceSha256') == prepared['selectionSourceSha256']
                    and copies.get('copyCustodySha256') == prepared.get('copyCustodySha256')
                    and copies.get('journalWritten') is False
                    and copies.get('activationAuthorized') is False and copies.get('readinessAuthorized') is False,
                    'actual Root-issued restored runtime copies required')
            copies_binding = copies['bindingSha256']
        readiness = self.prior.get('readiness')
        if readiness is not None:
            require(isinstance(readiness, dict) and readiness.get('bootId') == boot_id()
                    and type(readiness.get('startMonotonicUSec')) is int
                    and 0 < readiness['startMonotonicUSec'] <= int(time.monotonic() * 1_000_000)
                    and readiness.get('renderedInputs') == rendered_pins
                    and readiness.get('storageBinding') == storage_pin
                    and readiness.get('rootfulEnvironmentBindingSha256') == rootful['bindingSha256']
                    and readiness.get('runtimeUnitSourceSha256') == prepared['selectionSourceSha256']
                    and ('runtimeCopiesBindingSha256' not in readiness
                         or readiness['runtimeCopiesBindingSha256'] == copies_binding),
                    'stored readiness selection changed')
        require(read_file(self.root / '.install-intent.json', private=True) == raw
                and read_file(self.release / 'installation-receipt.json', private=True) == raw,
                'journal changed during selection read')
        pointer(self.root, self.release); lock_held(self.root); self.left()
        result = {'intentSha256': self.cas, 'release': str(self.release), 'inputs': pins,
                  'renderedInputs': rendered_pins, 'storageBinding': storage_pin, 'readiness': readiness,
                  'rootfulEnvironmentBindingSha256': rootful['bindingSha256'],
                  'runtimeUnitSourceSha256': prepared['selectionSourceSha256'],
                  'runtimeCopiesBindingSha256': copies_binding}
        finance = verify_native_finance_reference(self.root, self.release, self.prior)
        if finance is not None: result['nativeFinanceReferenceBindingSha256'] = finance['bindingSha256']
        return result

    def account(self, scope):
        if scope == 'rootful': return None
        rows = [d for d in self.domains['domains'] if 'rootless-' + d['name'] == scope]
        require(len(rows) == 1, 'unselected runtime account')
        row = rows[0]; account = pwd.getpwnam(row['user'])
        require(account.pw_uid == row['uid'] and 780 <= account.pw_uid <= 786
                and account.pw_dir == '/home/' + row['user'], 'runtime account custody changed')
        return account

    def actor_custody(self, account, path):
        """Allow actor-owned directories ONLY below its exact home/runtime root."""
        result = dict(self.custody)
        home = Path(account.pw_dir); runtime = Path('/run/user') / str(account.pw_uid)
        row = next(d for d in self.domains['domains'] if d['user'] == account.pw_name)
        state = r.canonical(row['stateRoot'])
        for parent in reversed(path.parents):
            if any(parent == base or parent.is_relative_to(base) for base in (home, runtime, state)):
                pin = directory_pin(parent)
                require(pin[0] == account.pw_uid and pin[1] == account.pw_gid and not pin[2] & 0o022,
                        'foreign runtime/account ancestor')
                result[parent] = pin
        return result

    def installed_sources(self):
        """Check ALL selected sources before early bootstrap, including targets."""
        for name, body in self.rendered.items():
            _, scope, filename = Path(name).parts
            account = self.account(scope); uid = account.pw_uid if account else 0
            if account:
                base = Path(account.pw_dir) / ('.config/systemd/user' if name.endswith('.target')
                                               else '.config/containers/systemd')
            else:
                base = Path('/etc/systemd/system' if name.endswith('.target') else '/etc/containers/systemd')
            path = base / filename
            custody = self.actor_custody(account, path) if account else {}
            require(read_file(path, owner=uid, directories=custody) == body,
                    'installed selected source differs before bootstrap/observation')
            self.left()
        return True

    def commands(self):
        result = {}
        for scope in sorted({u.scope for u in self.plan}):
            account = self.account(scope)
            if account is None:
                result[scope] = (['systemctl'], images.rootful_command(self.release)); continue
            row = next(d for d in self.domains['domains'] if d['user'] == account.pw_name)
            config = Path(account.pw_dir) / '.config/containers/storage.conf'
            expected = ('[storage]\ndriver = "overlay"\ngraphroot = "' + row['graphRoot'] + '"\n').encode()
            require(read_file(config, owner=account.pw_uid, private=True,
                              directories=self.actor_custody(account, config)) == expected,
                    'selected rootless storage configuration differs')
            network = config.with_name('containers.conf')
            expected_network = (b'[network]\ndefault_rootless_network_cmd = "pasta"\n'
                                b'pasta_options = ["--map-host-loopback", "169.254.1.2"]\n')
            require(read_file(network, owner=account.pw_uid, private=True,
                              directories=self.actor_custody(account, network)) == expected_network,
                    'selected rootless runtime configuration differs')
            state = r.canonical(row['stateRoot'])
            actor_release = state / 'releases' / self.release.name
            pointer(state, actor_release, directories=self.custody, owners=(0, account.pw_uid))
            for unit in (u for u in self.plan if u.scope == scope):
                source = actor_release / unit.source
                require(r.sha(read_file(source, owner=account.pw_uid,
                                       directories=self.actor_custody(account, source))) == unit.source_sha256,
                        'selected actor release source differs')
            prefix = ['runuser', '-u', account.pw_name, '--', 'env', '-i',
                      'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LANG=C', 'HOME=' + account.pw_dir,
                      'XDG_RUNTIME_DIR=/run/user/' + str(account.pw_uid),
                      'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(account.pw_uid) + '/bus']
            result[scope] = (prefix + ['systemctl', '--user'], prefix + ['podman',
                             '--root', row['graphRoot'], '--runroot', '/run/user/' + str(account.pw_uid) + '/containers'])
        return result

    def run(self, argv, *, timeout):
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'},
                                    cwd='/', timeout=min(timeout, self.left(), 20), pass_fds=(9,))
        except (OSError, subprocess.SubprocessError):
            raise Refused('bounded selected query failed') from None
        require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024, 'selected query refused')
        self.left()
        return result

    def source_identity(self, unit, source, fragment):
        account = self.account(unit.scope); uid = account.pw_uid if account else 0
        source_path = ((Path(account.pw_dir) / '.config/containers/systemd') if account
                       else Path('/etc/containers/systemd')) / Path(unit.source).name
        generator = ((Path('/run/user') / str(uid) / 'systemd/generator') if account
                     else Path('/run/systemd/generator'))
        fragment_path = generator / unit.name
        require(source == str(source_path) and fragment == str(fragment_path), 'foreign source/loaded fragment path')
        custody = self.actor_custody(account, source_path) if account else {}
        require(r.sha(read_file(source_path, owner=uid, directories=custody)) == unit.source_sha256,
                'installed source differs from reviewed release')
        custody = self.actor_custody(account, fragment_path) if account else {}
        body = read_file(fragment_path, owner=uid, directories=custody)
        # Generated systemd fragments can wrap long commands. Hash ORIGINAL
        # bytes, but unfold systemd continuations for scalar identity parsing.
        config = r.sections(body.replace(bytes((92, 10)), b' '))
        require(r.only(config, 'Unit', 'SourcePath') == source, 'loaded fragment source differs')
        command = r.only(config, 'Service', 'ExecStart')
        require(isinstance(command, str), 'missing loaded execution identity')
        args = shlex.split(command)
        ref = unit.image
        if ref.endswith('.build'):
            build = unit.source.removesuffix('.container') + '.build'
            tags = r.sections(self.rendered[build]).get(('Build', 'ImageTag'), [])
            require(len(tags) == 1, 'ambiguous loaded build identity')
            ref = tags[0]
        require(args and args[0] == '/usr/bin/podman' and 'run' in args
                and [a for a in args if a.startswith('--cidfile')] == ['--cidfile=%t/%N.cid']
                and args.count(ref) == 1, 'loaded container/CID/image execution identity differs')
        return {'source': source, 'sourceSha256': unit.source_sha256,
                'fragment': fragment, 'fragmentSha256': r.sha(body)}

    def runtime_matches(self, unit, props, container):
        account = self.account(unit.scope); uid = account.pw_uid if account else 0
        runtime = Path('/run/user') / str(uid) if account else Path('/run')
        cid = runtime / (unit.name.removesuffix('.service') + '.cid')
        custody = self.actor_custody(account, cid) if account else {}
        body = read_file(cid, owner=uid, directories=custody, limit=128)
        require(body.decode('ascii').strip() == container['id'], 'selected CID receipt differs')
        require(container['conmonPid'] == r.natural(props['MainPID']), 'conmon/MainPID mismatch')
        expected = self.prior['readiness']['images'][unit.scope][unit.name]['configId']
        require(normalize_image(container['image']) == expected, 'running selected image differs')
        pid = container['conmonPid']
        before = process_fields(pid, uid)
        require(before['cgroup'] == props['ControlGroup'] and props['ControlGroup'].endswith('/' + unit.name),
                'conmon is outside selected service cgroup')
        require(process_fields(pid, uid) == before, 'conmon process identity changed')
        require(read_file(cid, owner=uid, directories=custody, limit=128) == body, 'CID receipt changed')
        return True


def process_fields(pid, uid):
    """Kernel scalar role proof only. Never return cmdline/environ/inspect bodies."""
    require(type(pid) is int and pid > 0, 'invalid selected process')
    def read(name):
        path = Path('/proc') / str(pid) / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            body = os.read(fd, 65537)
            require(len(body) <= 65536, 'oversized process scalar projection')
            return body.decode('ascii')
        finally:
            os.close(fd)
    status = read('status')
    rows = [line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
    require(len(rows) == 1 and rows[0] == [str(uid)] * 4, 'foreign conmon process UID')
    groups = read('cgroup').splitlines()
    require(len(groups) == 1 and groups[0].startswith('0::/'), 'unsupported conmon cgroup authority')
    fields = read('stat').rsplit(')', 1)[1].split()
    require(len(fields) >= 20 and fields[19].isdigit(), 'missing conmon start identity')
    return {'uid': uid, 'cgroup': groups[0][3:], 'startTicks': int(fields[19])}


def normalize_image(value):
    require(isinstance(value, str) and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', value), 'invalid selected image config ID')
    return 'sha256:' + value.removeprefix('sha256:')


def seal_selection(root, release, prior_intent):
    selection = Selection(root, release, prior_intent, 'preparing')
    require('readiness' not in prior_intent, 'cannot reseal a prior readiness attempt')
    # This validates ALL declared domains, including empty/on-demand-only roles;
    # selected service targets alone cannot supply private projection custody.
    projections.verify_prepared(root, release, prior_intent)
    # Capture BEFORE inventory work; installer must not launch bootstrap until
    # this returned metadata is durably in BOTH units-selected journal records.
    boot = boot_id(); start = int(time.monotonic() * 1_000_000)
    binding = selection.snapshot()
    selection.installed_sources()
    require(boot_id() == boot, 'boot changed while sealing selection')
    require(selection.snapshot() == binding, 'selection changed while sealing')
    return {'schemaVersion': 1, 'bootId': boot, 'startMonotonicUSec': start,
            'renderedInputs': binding['renderedInputs'], 'storageBinding': binding['storageBinding'],
            'rootfulEnvironmentBindingSha256': binding['rootfulEnvironmentBindingSha256'],
            'runtimeUnitSourceSha256': binding['runtimeUnitSourceSha256']}


def capture_images(root, release, prior_intent):
    selection = Selection(root, release, prior_intent, 'building')
    projected = projections.verify_prepared(root, release, prior_intent)
    binding = selection.snapshot(); proof = prior_intent.get('readiness')
    require(isinstance(proof, dict) and set(proof) == {'schemaVersion', 'bootId', 'startMonotonicUSec',
            'renderedInputs', 'storageBinding', 'rootfulEnvironmentBindingSha256', 'runtimeUnitSourceSha256'}
            and proof['schemaVersion'] == 1 and binding['runtimeCopiesBindingSha256'] is not None,
            'unsealed, missing Root runtime copies, or already captured readiness')
    selection.installed_sources()
    commands = selection.commands(); queries = r.SelectedQueries(selection.plan, commands, selection.run)
    pins_body = None
    if prior_intent['inputs']['site/global.settings/registry-image-ids.json'] is not None:
        pins_body = read_file(selection.release / 'site/global.settings/registry-image-ids.json')
    pins = r.strict(pins_body) if pins_body is not None else {}
    require(isinstance(pins, dict) and all(isinstance(k, str) and k.count('|') == 1
            and isinstance(v, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', v) for k, v in pins.items()),
            'invalid reviewed image supply')
    captured = {}; loaded = {}; reviewed = True
    for scope in sorted(commands):
        selected = [u for u in selection.plan if u.scope == scope]
        units = queries.units(scope, tuple(u.name for u in selected), selection.left())
        require(set(units) == {u.name for u in selected}, 'loaded selected inventory incomplete')
        account = selection.account(scope); user = account.pw_name if account else 'root'
        for unit in selected:
            service = selection.ir['services'][unit.container]; ref = unit.image
            frozen = service.get('frozenBuildImage')
            if 'build' in service and frozen is None:
                build = unit.source.removesuffix('.container') + '.build'
                tags = r.sections(selection.rendered[build]).get(('Build', 'ImageTag'), [])
                require(len(tags) == 1 and re.fullmatch(r'localhost/webservices/[a-zA-Z0-9_.-]+:bundle', tags[0]),
                        'ambiguous local build recipe tag')
                ref = tags[0]; expected = None
            elif frozen is not None:
                require(selection.ir.get('quadletBuildImagesFrozen') is True and frozen == service.get('image')
                        and service.get('updatePolicy') == 'pinned', 'invalid frozen build supply')
                expected = normalize_image(frozen)
            else:
                expected = pins.get(user + '|' + ref)
                require(not pins or expected is not None or ref.startswith('sha256:'),
                        'reviewed registry supply omits selected store/image')
                if ref.startswith('sha256:'):
                    expected = normalize_image(ref)
            result = selection.run([*commands[scope][1], 'image', 'inspect', '--format', '{{.Id}}', '--', ref],
                                   timeout=selection.left())
            config_id = normalize_image(result.stdout.strip())
            require(expected is None or expected == config_id, 'reviewed selected image mismatch')
            image_reviewed = expected is not None
            reviewed = reviewed and image_reviewed
            captured.setdefault(scope, {})[unit.name] = {'reference': ref, 'configId': config_id,
                                                        'supplyReviewed': image_reviewed}
            props = units[unit.name]
            require(props['LoadState'] == 'loaded' and props['DropInPaths'] == '', 'unloaded or overridden selected source')
            loaded.setdefault(scope, {})[unit.name] = selection.source_identity(unit, props['SourcePath'], props['FragmentPath'])
    require(selection.snapshot() == binding, 'selection changed while capturing image identities')
    require(projections.verify_prepared(root, release, prior_intent)['bindingSha256'] == projected['bindingSha256'],
            'private projection changed while capturing images')
    return dict(proof, images=captured, loadedInputs=loaded, imageSupplyReviewed=reviewed,
                runtimeCopiesBindingSha256=binding['runtimeCopiesBindingSha256'])


def verify_active_transition(root, release, prior_intent):
    selection = Selection(root, release, prior_intent, 'starting')
    projected = projections.verify_running(root, release, prior_intent)
    binding = selection.snapshot(); proof = prior_intent.get('readiness')
    if 'nativeFinanceReferenceBindingSha256' in binding:
        require(type(binding['nativeFinanceReferenceBindingSha256']) is str
                and r.HEX.fullmatch(binding['nativeFinanceReferenceBindingSha256']),
                'Selected finance reference has not been Root-published')
        require(prior_intent.get('nativeFinanceOwnershipReceipt', {}).get('kind') == 'root-native-finance-ownership'
                and prior_intent['nativeFinanceOwnershipReceipt'].get('status') == 'completed'
                and prior_intent.get('nativeFinanceReference', {}).get('input', {}).get('content', {}).get('status') == 'retained',
                'Original successful native finance frame absent; fresh transport is not readiness')
    require(isinstance(proof, dict) and set(proof) == {'schemaVersion', 'bootId', 'startMonotonicUSec',
            'renderedInputs', 'storageBinding', 'rootfulEnvironmentBindingSha256', 'runtimeUnitSourceSha256',
            'runtimeCopiesBindingSha256', 'images', 'loadedInputs', 'imageSupplyReviewed'}
            and proof['schemaVersion'] == 1 and type(proof['imageSupplyReviewed']) is bool,
            'starting readiness metadata incomplete')
    expected_scopes = {u.scope for u in selection.plan}
    require(set(proof['images']) == expected_scopes and set(proof['loadedInputs']) == expected_scopes,
            'stored readiness exceeds selected managers')
    reviewed = True
    for scope in expected_scopes:
        expected_names = {u.name for u in selection.plan if u.scope == scope}
        require(set(proof['images'][scope]) == expected_names and set(proof['loadedInputs'][scope]) == expected_names,
                'stored readiness differs from selected services')
        for unit in (u for u in selection.plan if u.scope == scope):
            image = proof['images'][scope][unit.name]
            require(set(image) == {'reference', 'configId', 'supplyReviewed'} and type(image['supplyReviewed']) is bool
                    and normalize_image(image['configId']) == image['configId'], 'invalid captured image identity')
            reviewed = reviewed and image['supplyReviewed']
    require(reviewed == proof['imageSupplyReviewed'], 'image supply review flag inconsistent')
    commands = selection.commands(); queries = r.SelectedQueries(selection.plan, commands, selection.run)
    def recheck():
        require(projections.verify_running(root, release, prior_intent)['bindingSha256'] == projected['bindingSha256'],
                'private projection or restored environment changed during graph observation')
        require(selection.snapshot() == binding and selection.commands() == commands, 'active selection/store changed')
        selection.installed_sources()
        # Required oneshots can have removed their containers. Bind their
        # invocation's loaded source AND keep every captured store/reference
        # fixed throughout observation, not only the live daemon images.
        for unit in selection.plan:
            pin = proof['images'][unit.scope][unit.name]
            ref = pin['reference']
            expected_ref = unit.image
            if expected_ref.endswith('.build'):
                build = unit.source.removesuffix('.container') + '.build'
                tags = r.sections(selection.rendered[build]).get(('Build', 'ImageTag'), [])
                require(len(tags) == 1, 'ambiguous sealed build tag')
                expected_ref = tags[0]
            require(ref == expected_ref, 'stored image reference differs from sealed source')
            value = selection.run([*commands[unit.scope][1], 'image', 'inspect', '--format', '{{.Id}}', '--', ref],
                                  timeout=selection.left())
            require(normalize_image(value.stdout.strip()) == pin['configId'], 'captured store image changed')
        require(selection.snapshot() == binding, 'selection changed during store recheck')
        return binding
    def source_matches(unit, source, fragment):
        return selection.source_identity(unit, source, fragment) == proof['loadedInputs'][unit.scope][unit.name]
    result = r.verify_graph(selection.plan, query_units=queries.units, query_containers=queries.containers,
                            recheck=recheck, source_matches=source_matches, runtime_matches=selection.runtime_matches,
                            attempt_start_us=proof['startMonotonicUSec'], stable_seconds=10,
                            timeout_seconds=min(120, selection.left()), poll_seconds=1)
    recheck(); selection.left()
    return dict(result, imageSupplyReviewed=reviewed, immutableSupplyAcceptance=False,
                runtimeProjectionBindingSha256=projected['bindingSha256'],
                rootfulEnvironmentBindingSha256=proof['rootfulEnvironmentBindingSha256'],
                runtimeUnitSourceSha256=proof['runtimeUnitSourceSha256'],
                runtimeCopiesBindingSha256=proof['runtimeCopiesBindingSha256'],
                intentSha256=selection.cas)
