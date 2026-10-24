#!/usr/bin/env python3
"""Root-owned public trust and narrowly delegated mail leaf credentials.

Never mount/copy the CA private store into an application actor. No key material
or OpenSSL diagnostic output is logged. Derived generations are atomic, not
backups; obsolete generations are removed after publication.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import signal
import ssl
import stat
import subprocess
import time


@contextmanager
def deferred_termination():
    # A service stop must not release the installer lock while our native child
    # still runs. Wait for the bounded child, then abort before the next action.
    pending = []
    def stop(signum, frame): pending.append(signum)
    previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        for s in previous: signal.signal(s, stop)
        yield
    finally:
        for s, handler in previous.items(): signal.signal(s, handler)
        if pending: raise InterruptedError('Runtime trust operation interrupted')


def command(args, data=None, pass_fds=()):
    with deferred_termination():
        result = subprocess.run(args, input=data, capture_output=True, timeout=20, pass_fds=pass_fds)
    if result.returncode: raise ValueError('Runtime trust validation/permission operation refused')
    return result.stdout


def canonical(path):
    if (not path.is_absolute() or '..' in path.parts or str(path) != os.path.normpath(str(path))
            or str(path).startswith('//')):
        raise ValueError('Noncanonical trust path')
    return path


def directory(path, unsealed=False):
    canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o002 or (info.st_mode & 0o020 and not unsealed):
            raise ValueError('Runtime trust directory is not root-controlled')
        return fd
    except BaseException:
        os.close(fd); raise


def read_at(root, relative, unsealed=False, limit=2 * 1024 * 1024, mode=None):
    fd = directory(root, unsealed=unsealed)
    try:
        parts = Path(relative).parts
        if (not parts or str(Path(relative)) != relative
                or any(p in ('/', '.', '..') for p in parts)):
            raise ValueError('Invalid trust artifact path')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unsafe trust artifact ancestry')
        return read_regular(fd, parts[-1], limit, mode)
    finally: os.close(fd)


def read_regular(parent, name, limit=2 * 1024 * 1024, mode=None):
    if not name or Path(name).name != name or name in ('.', '..'):
        raise ValueError('Invalid trust artifact name')
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(child)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_size > limit or info.st_mode & 0o022
                or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
            raise ValueError('Unsafe trust artifact')
        chunks = []; remaining = limit + 1
        while remaining:
            block = os.read(child, min(remaining, 65536))
            if not block: break
            chunks.append(block); remaining -= len(block)
        body = b''.join(chunks)
        after = os.fstat(child)
        if (len(body) > limit or len(body) != info.st_size
                or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            raise ValueError('Trust artifact changed while reading')
        return body
    finally: os.close(child)


def child_directory(parent, name, create=False):
    if not name or Path(name).name != name or name in ('.', '..'):
        raise ValueError('Invalid trust directory name')
    if create:
        try: os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError: pass
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(child)
    if info.st_uid != 0 or info.st_mode & 0o022:
        os.close(child); raise ValueError('Unsafe trust child directory')
    return child


def certificates_only(data):
    pattern = rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----'
    blocks = re.findall(pattern, data)
    if not blocks or re.sub(pattern, b'', data).strip(): raise ValueError('Public trust contains non-certificate material')
    for block in blocks: command(['openssl', 'x509', '-noout'], block)


def seal_directory(path, mode):
    # These exact root-owned derived directories may still have the scope
    # creator's inherited writable ACL. Revoke it here, never on ancestors.
    fd = directory(path, unsealed=True)
    try:
        command(['setfacl', '-b', '-k', '/proc/self/fd/' + str(fd)], pass_fds=(fd,))
        os.fchmod(fd, mode)
    finally: os.close(fd)


def prepare(private, public, target):
    # Validate all derived public artifacts BEFORE altering permissions.
    fd = directory(public, unsealed=True)
    try:
        if set(os.listdir(fd)) - {'caddy-ca.crt'}: raise ValueError('Unexpected public trust artifact')
    finally: os.close(fd)
    if (public / 'caddy-ca.crt').is_symlink(): raise ValueError('Linked public trust artifact')
    if (public / 'caddy-ca.crt').exists(): certificates_only(read_at(public, 'caddy-ca.crt', unsealed=True))
    seal_directory(private, 0o700)
    # Revoke historical writable/default actor ACLs. Only root/Caddy publishes.
    seal_directory(public, 0o755)
    fd = directory(public)
    try:
        try: child = os.open('caddy-ca.crt', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError: pass
        else:
            try:
                read_regular(fd, 'caddy-ca.crt')
                command(['setfacl', '-b', '/proc/self/fd/' + str(child)], pass_fds=(child,))
                os.fchmod(child, 0o644)
            finally: os.close(child)
    finally: os.close(fd)
    if target is not None:
        fd = directory(target); os.close(fd)


def validate_leaf(cert, key, hostname):
    certificates_only(cert)
    if not re.fullmatch(rb'-----BEGIN ((?:EC |RSA )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]+-----END \1-----', key.strip()):
        raise ValueError('Mail delegation requires exactly one unencrypted leaf key')
    command(['openssl', 'x509', '-noout', '-checkend', '60'], cert)
    start = command(['openssl', 'x509', '-noout', '-startdate'], cert).decode().strip()
    if not start.startswith('notBefore=') or ssl.cert_time_to_seconds(start.split('=', 1)[1]) > time.time():
        raise ValueError('Mail leaf is not yet valid')
    names = command(['openssl', 'x509', '-noout', '-ext', 'subjectAltName'], cert).decode()
    if hostname not in re.findall(r'DNS:([A-Za-z0-9.*-]+)', names): raise ValueError('Mail leaf hostname mismatch')
    if b'CA:TRUE' in command(['openssl', 'x509', '-noout', '-ext', 'basicConstraints'], cert):
        raise ValueError('CA signing credential cannot be delegated as a mail leaf')
    public = command(['openssl', 'x509', '-pubkey', '-noout'], cert)
    cert_key = command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], public)
    actual_key = command(['openssl', 'pkey', '-pubout', '-outform', 'DER'], key)
    if cert_key != actual_key: raise ValueError('Mail certificate/key mismatch')


def read_leaf(private, hostname):
    for issuer in ('acme-v02.api.letsencrypt.org-directory', 'acme.zerossl.com-v2-dv90', 'local'):
        base = f'certificates/{issuer}/{hostname}/{hostname}'
        try:
            cert, key = read_at(private, base + '.crt'), read_at(private, base + '.key')
        except FileNotFoundError: continue
        validate_leaf(cert, key, hostname)
        return cert, key
    raise FileNotFoundError('Selected mail hostname leaf certificate is not issued yet')


def reader(fd, uid, is_dir=False):
    # ACL tools receive only a pinned descriptor, never a re-resolved host path.
    info = os.fstat(fd)
    if (info.st_uid != 0 or (not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
            or (is_dir and not stat.S_ISDIR(info.st_mode))):
        raise ValueError('Unsafe mail reader artifact')
    path = '/proc/self/fd/' + str(fd)
    command(['setfacl', '-b', '-k', path] if is_dir else ['setfacl', '-b', path], pass_fds=(fd,))
    os.fchmod(fd, 0o700 if is_dir else 0o600)
    access = 'r-x' if is_dir else 'r--'
    if uid != 0:
        command(['setfacl', '-m', f'u:{uid}:{access},m::{access}', path], pass_fds=(fd,))


def validate_publication(target):
    """Validate the whole bounded derived namespace before replacing/deleting."""
    fd = os.dup(target) if type(target) is int else directory(target)
    try:
        if set(os.listdir(fd)) - {'.publish.lock', 'generations', 'current', '.reload-receipt.json'}:
            raise ValueError('Unexpected leaf artifact')
        current_generation(fd); reload_receipt(fd)
        try: lock = os.open('.publish.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError: pass
        else:
            try:
                info = os.fstat(lock)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError('Unsafe leaf lock')
            finally: os.close(lock)
        try: child = child_directory(fd, 'generations')
        except FileNotFoundError: return
        try:
            names = os.listdir(child)
            if len(names) > 8: raise ValueError('Unexpected leaf generation count')
            for name in names:
                if not re.fullmatch(r'[a-f0-9]{64}', name): raise ValueError('Unexpected leaf generation')
                genfd = child_directory(child, name)
                try:
                    if set(os.listdir(genfd)) != {'cert.pem', 'key.pem'}:
                        raise ValueError('Unknown leaf generation contents')
                    if hashlib.sha256(read_regular(genfd, 'cert.pem')).hexdigest() != name:
                        raise ValueError('Leaf generation hash mismatch')
                    read_regular(genfd, 'key.pem')
                finally: os.close(genfd)
        finally: os.close(child)
    finally: os.close(fd)


def publish(target, cert, key, uid):
    if type(uid) is not int or uid < 0: raise ValueError('Invalid mail reader identity')
    fd = directory(target)
    try:
        lock = os.open('.publish.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        try:
            info = os.fstat(lock)
            if (info.st_uid or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or not stat.S_ISREG(info.st_mode)): raise ValueError('Unsafe leaf lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            validate_publication(fd)
            parent = child_directory(fd, 'generations', create=True)
            try:
                name = hashlib.sha256(cert).hexdigest()
                child = child_directory(parent, name, create=True)
                try:
                    for filename, content in (('cert.pem', cert), ('key.pem', key)):
                        try: previous = read_regular(child, filename)
                        except FileNotFoundError:
                            out = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
                            with os.fdopen(out, 'wb') as stream:
                                stream.write(content); stream.flush(); os.fsync(stream.fileno())
                        else:
                            if previous != content: raise ValueError('Leaf generation collision')
                        item = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=child)
                        try: reader(item, uid)
                        finally: os.close(item)
                    reader(child, uid, True); os.fsync(child)
                finally: os.close(child)
                reader(parent, uid, True); reader(fd, uid, True)
                current_generation(fd)
                temporary = '.current-' + str(os.getpid())
                os.symlink('generations/' + name, temporary, dir_fd=fd)
                os.replace(temporary, 'current', src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
                for old in os.listdir(parent):
                    if old == name: continue
                    if not re.fullmatch(r'[a-f0-9]{64}', old): raise ValueError('Unexpected obsolete leaf generation')
                    oldfd = child_directory(parent, old)
                    try:
                        if set(os.listdir(oldfd)) != {'cert.pem', 'key.pem'}: raise ValueError('Unknown obsolete leaf contents')
                        for filename in ('cert.pem', 'key.pem'):
                            read_regular(oldfd, filename); os.unlink(filename, dir_fd=oldfd)
                    finally: os.close(oldfd)
                    os.rmdir(old, dir_fd=parent)
                os.fsync(parent); os.fsync(fd)
                return name
            finally: os.close(parent)
        finally: os.close(lock)
    finally: os.close(fd)


def storage_binding(bundle):
    spec = importlib.util.spec_from_file_location('storage_trust_binding', Path(__file__).with_name('grant-rootless-volume-parent-traverse.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    scope, operator, expected = module.authority(bundle); module.marker(scope, expected)
    return module, scope, operator, expected


def grant_public_parents(bundle, public):
    module, scope, operator, expected = storage_binding(bundle)
    # Shared named volumes need their OWN ancestry, not a private domain's
    # volumeRoot. Never touch anything above the claimed scope or grant r/w.
    paths = list(reversed([p for p in public.parent.parents if p.is_relative_to(scope)])) + [public.parent]
    for path in paths:
        module.safe_parent(path, operator)
        for row in expected['domains']: module.exact_execute(path, row['user'])


def binding(bundle):
    module, scope, operator, expected = storage_binding(bundle)
    ir = strict_json(read_at(bundle, 'stack.ir.json', limit=8 * 1024 * 1024))
    module.safe_parent(scope, operator)
    mail_selected = 'mailserver' in ir['services']
    names = ['caddy_certs', 'caddy_ca'] + (['mail_tls'] if mail_selected else [])
    paths = [module.normal_path(ir['volumes'][name]['hostPath']) for name in names]
    if any(not p.is_relative_to(scope) or p == scope for p in paths): raise ValueError('Trust storage escapes scope')
    if any(a.is_relative_to(b) for a in paths for b in paths if a != b) or len(set(paths)) != len(paths):
        raise ValueError('Trust storage roots overlap')
    if any(ir['volumes'][name].get('rootlessAccess') != 'read-only' for name in names[1:]):
        raise ValueError('Trust/delegation reader policy missing')
    if not mail_selected: return paths + [None], None, None
    mail = ir['services']['mailserver']
    if mail.get('placement') == 'rootful':
        uid = 0
    elif mail.get('placement') == 'rootless':
        uid = next(r['uid'] for r in expected['domains'] if r['name'] == mail['rootlessDomain'])
    else: raise ValueError('Unknown mail service authority')
    values = [shlex.split(line.split('=', 1)[1])[0] for line in read_at(bundle, 'runtime/stack.env').decode().splitlines() if line.startswith('DOMAIN=')]
    if len(values) != 1 or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,240}[a-z0-9]', values[0]): raise ValueError('Invalid mail domain authority')
    return paths, uid, 'mail.' + values[0]


def strict_json(body):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value: raise ValueError('Duplicate trust authority key')
            value[key] = item
        return value
    return json.loads(body, object_pairs_hook=pairs)


def current_generation(target):
    """The sole allowed leaf link is our root-owned, exact relative selector."""
    fd = os.dup(target) if type(target) is int else directory(target)
    try:
        try: info = os.stat('current', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: return None
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise ValueError('Unrecognized mail leaf selection')
        link = os.readlink('current', dir_fd=fd)
        if not re.fullmatch(r'generations/[a-f0-9]{64}', link):
            raise ValueError('Unrecognized mail leaf selection')
        name = link.split('/')[1]
        parent = child_directory(fd, 'generations')
        try:
            child = child_directory(parent, name)
            try:
                cert = read_regular(child, 'cert.pem'); read_regular(child, 'key.pem')
                if hashlib.sha256(cert).hexdigest() != name:
                    raise ValueError('Mail leaf selection hash changed')
            finally: os.close(child)
        finally: os.close(parent)
        return name
    finally: os.close(fd)


def installer_root(bundle):
    canonical(bundle)
    if (bundle.parent.name != 'releases' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', bundle.name)):
        raise ValueError('Exact immutable installed release required')
    return bundle.parent.parent


@contextmanager
def installer_lock(root, inherited=None):
    """Share installer's flock, not a second admission mechanism.

    Internal calls inherit shell fd 9. Locking the same open description does
    not deadlock or release the parent's lock on close. External mode opens the
    same inode independently and never steals, creates or replaces a lock.
    """
    parent = directory(root); fd = None
    try:
        pathfd = os.open('.install.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(pathfd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('Unsafe installer lock')
            if inherited is not None:
                other = os.fstat(inherited)
                if (other.st_dev, other.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('Installer lock descriptor mismatch')
                fd = os.dup(inherited)
            else:
                fd = os.dup(pathfd)
        finally: os.close(pathfd)
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False; return
        selected = os.stat('.install.lock', dir_fd=parent, follow_symlinks=False)
        if (selected.st_dev, selected.st_ino, selected.st_nlink) != (info.st_dev, info.st_ino, 1):
            raise ValueError('Installer lock identity changed')
        yield True
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def selected_authority(bundle, internal=False, expected=''):
    """Read-only use of the install journal; no phase advance/replay."""
    root = installer_root(bundle)
    body = read_at(root, '.install-intent.json', mode=0o600)
    digest = hashlib.sha256(body).hexdigest()
    if expected and (not re.fullmatch(r'[a-f0-9]{64}', expected) or digest != expected):
        raise ValueError('Selected installer intent CAS mismatch')
    intent = strict_json(body)
    phase = 'building' if internal else 'active'
    steps = ['preparing', 'units-selected', 'building'] + ([] if internal else ['starting', 'active'])
    if (not isinstance(intent, dict)
            or set(intent) != {'schemaVersion', 'release', 'inputs', 'phase', 'previousRelease', 'steps', 'resumedFrom'}
            or type(intent.get('schemaVersion')) is not int or intent.get('schemaVersion') != 1
            or intent.get('release') != str(bundle) or intent.get('phase') != phase or intent.get('steps') != steps):
        raise ValueError('Selected installer journal is not authorized for trust operation')
    for key in ('previousRelease', 'resumedFrom'):
        claim = intent[key]
        if claim is not None and (not isinstance(claim, str) or installer_root(Path(claim)) != root):
            raise ValueError('Unknown installer release claim')
    # Current is an existing installer-owned selector, never a path supplied to
    # --bundle. Refuse aliases/escapes rather than resolving arbitrary links.
    parent = directory(root)
    try:
        info = os.stat('current', dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or os.readlink('current', dir_fd=parent) != str(bundle)):
            raise ValueError('Selected installer pointer mismatch')
    finally: os.close(parent)
    receipt = read_at(bundle, 'installation-receipt.json', mode=0o600)
    if receipt != body: raise ValueError('Selected installation receipt mismatch')
    # Reuse the existing journal's pin vocabulary. Rotation cannot expand it or
    # admit historical three-file receipts that omit scope/actor authority.
    spec = importlib.util.spec_from_file_location('trust_install_journal', Path(__file__).with_name('install-journal.py'))
    journal = importlib.util.module_from_spec(spec); spec.loader.exec_module(journal)
    pins = intent.get('inputs')
    if not isinstance(pins, dict) or set(pins) != set(journal.CORE_INPUTS + journal.PINNED_INPUTS):
        raise ValueError('Complete installed input pins required')
    for name, wanted in pins.items():
        if wanted is None and name in journal.CORE_INPUTS:
            raise ValueError('Core installed input cannot be absent')
        try: data = read_at(bundle, name, limit=8 * 1024 * 1024)
        except FileNotFoundError:
            if wanted is None: continue
            raise ValueError('Missing selected input pin') from None
        if (not isinstance(wanted, str) or not re.fullmatch(r'[a-f0-9]{64}', wanted)
                or hashlib.sha256(data).hexdigest() != wanted):
            raise ValueError('Selected input pin mismatch')
    metadata = strict_json(read_at(bundle, 'podman-domains.json'))
    manifest = strict_json(read_at(bundle, 'site/manifest.json'))
    if (manifest.get('deploymentMode') != 'standalone' or metadata.get('deploymentMode') != 'standalone'
            or manifest.get('installerStateRoot', '/var/lib/webservices') != str(root)
            or metadata.get('installerStateRoot', '/var/lib/webservices') != str(root)
            or 'venue' in metadata):
        raise ValueError('Selected native host installer authority required')
    # binding() also verifies bundle hashes, exact scope marker and identities.
    paths, uid, hostname = binding(bundle)
    if read_at(root, '.install-intent.json', mode=0o600) != body:
        raise ValueError('Selected installer intent changed during validation')
    return {'intentSha256': digest, 'paths': paths, 'uid': uid, 'hostname': hostname}


# Deliberately two non-shell commands, executed as the selected manager actor.
# Owning generator must emit these in [Service]; runtime never installs them.
MAIL_RELOAD = (
    '/usr/bin/podman exec --user 0 mailserver postfix reload',
    '/usr/bin/podman exec --user 0 mailserver dovecot reload',
)
MAIL_UNIT = 'webservices-mailserver.service'


def mail_actor(bundle, uid):
    if type(uid) is not int or uid < 0: raise ValueError('Unknown selected mail actor UID')
    ir = strict_json(read_at(bundle, 'stack.ir.json', limit=8 * 1024 * 1024))
    mail = ir['services']['mailserver']
    if mail.get('placement') == 'rootful' and uid == 0:
        label, owner, command_prefix = 'rootful', 0, ['systemctl']
        installed = Path('/etc/containers/systemd/webservices-mailserver.container')
    elif mail.get('placement') == 'rootless' and type(uid) is int and uid > 0:
        _, _, _, expected = storage_binding(bundle)
        rows = [r for r in expected['domains'] if r['name'] == mail.get('rootlessDomain') and r['uid'] == uid]
        if len(rows) != 1: raise ValueError('Exact selected mail actor required')
        row = rows[0]; account = pwd.getpwnam(row['user'])
        if account.pw_uid != uid or account.pw_dir != '/home/' + row['user']:
            raise ValueError('Selected mail actor identity changed')
        label, owner = 'rootless-' + row['name'], uid
        command_prefix = ['runuser', '-u', row['user'], '--', 'env',
                          'HOME=' + account.pw_dir, 'XDG_RUNTIME_DIR=/run/user/' + str(uid),
                          'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(uid) + '/bus',
                          'systemctl', '--user']
        installed = Path(account.pw_dir) / '.config/containers/systemd/webservices-mailserver.container'
    else: raise ValueError('Unknown selected mail actor')
    source = read_at(bundle, 'quadlet/' + label + '/webservices-mailserver.container')
    section = None; reloads = []; containers = []
    for line in source.decode().splitlines():
        line = line.strip()
        if line.startswith('['): section = line
        if section == '[Service]' and line.startswith('ExecReload='): reloads.append(line.split('=', 1)[1])
        if section == '[Container]' and line.startswith('ContainerName='): containers.append(line.split('=', 1)[1])
    if containers != ['mailserver']: raise ValueError('Selected mail container authority mismatch')
    return {'command': command_prefix, 'source': source, 'installed': installed, 'owner': owner,
            'reloadConfigured': tuple(reloads) == MAIL_RELOAD, 'unit': MAIL_UNIT}


def installed_source(actor):
    """The one installed Quadlet may belong to its fixed rootless actor."""
    path, owner = actor['installed'], actor['owner']
    canonical(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError('Unsafe installed mail unit ancestry')
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1
                    or info.st_mode & 0o022 or info.st_size != len(actor['source'])
                    or os.read(child, len(actor['source']) + 1) != actor['source']):
                raise ValueError('Installed mail unit does not match selected release')
        finally: os.close(child)
    finally: os.close(fd)


def active_mail(actor):
    installed_source(actor)
    fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'SourcePath',
              'DropInPaths', 'NeedDaemonReload', 'CanReload', 'Job',
              'PropagatesReloadTo', 'OnFailure', 'OnSuccess')
    args = actor['command'] + ['--no-ask-password', 'show', actor['unit'], '--all']
    for field in fields: args += ['-p', field]
    props = {}
    for line in command(args).decode().splitlines():
        if '=' not in line: raise ValueError('Unknown selected mail unit state')
        key, value = line.split('=', 1)
        if key not in fields or key in props: raise ValueError('Unknown selected mail unit state')
        props[key] = value
    if (set(props) != set(fields) or props['Id'] != MAIL_UNIT or props['LoadState'] != 'loaded'
            or props['SourcePath'] != str(actor['installed']) or props['DropInPaths']
            or props['NeedDaemonReload'] != 'no' or props['PropagatesReloadTo']
            or props['OnFailure'] or props['OnSuccess']):
        raise ValueError('Unknown selected mail unit ownership/state')
    if props['ActiveState'] in ('inactive', 'failed', 'activating', 'deactivating', 'reloading'):
        return 'mailserver-not-active'
    if props['ActiveState'] != 'active' or props['SubState'] != 'running':
        raise ValueError('Unknown selected mail activity state')
    if props['Job'] not in ('', '0'):
        if not re.fullmatch(r'[1-9][0-9]*', props['Job']): raise ValueError('Unknown selected mail job state')
        return 'mailserver-job-pending'
    if not actor['reloadConfigured'] or props['CanReload'] == 'no': return 'mail-reload-not-configured'
    if props['CanReload'] != 'yes': raise ValueError('Unknown selected mail reload capability')
    return None


def reload_receipt(target):
    fd = os.dup(target) if type(target) is int else directory(target)
    try:
        try: value = strict_json(read_regular(fd, '.reload-receipt.json', mode=0o600))
        except FileNotFoundError: return None
    finally: os.close(fd)
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'generation', 'intentSha256', 'uid', 'sourceSha256'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or type(value['uid']) is not int or value['uid'] < 0
            or any(not isinstance(value[k], str) or not re.fullmatch(r'[a-f0-9]{64}', value[k])
                   for k in ('generation', 'intentSha256', 'sourceSha256'))):
        raise ValueError('Unknown mail reload receipt')
    return value


def write_reload_receipt(target, receipt):
    fd = directory(target); name = '.reload-receipt-' + str(os.getpid())
    try:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(out, 'wb') as stream:
                stream.write((json.dumps(receipt, sort_keys=True) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, '.reload-receipt.json', src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
        finally:
            try: os.unlink(name, dir_fd=fd)
            except FileNotFoundError: pass
    finally: os.close(fd)


def rotation_result(reason=None, **metadata):
    return dict({'changed': False, 'deferred': reason is not None, 'reason': reason,
                 'mailLeafPublished': False, 'reloaded': False, 'privateStoreShared': False}, **metadata)


def rotate_mail(bundle, expected=''):
    """Caller holds installer_lock throughout; publish/reload only active selection."""
    authority = selected_authority(bundle, expected=expected)
    paths, uid, hostname = authority['paths'], authority['uid'], authority['hostname']
    cas = authority['intentSha256']
    if paths[2] is None: return rotation_result('mailserver-not-selected', intentSha256=cas)
    actor = mail_actor(bundle, uid)
    reason = active_mail(actor)
    if reason: return rotation_result(reason, intentSha256=cas)
    certificates_only(read_at(paths[1], 'caddy-ca.crt'))
    validate_publication(paths[2])
    previous = current_generation(paths[2]); acknowledged = reload_receipt(paths[2])
    try: cert, key = read_leaf(paths[0], hostname)
    except FileNotFoundError: return rotation_result('mail-leaf-not-issued', intentSha256=cas)
    name = hashlib.sha256(cert).hexdigest()
    receipt = {'schemaVersion': 1, 'generation': name, 'intentSha256': cas, 'uid': uid,
               'sourceSha256': hashlib.sha256(actor['source']).hexdigest()}
    selected_authority(bundle, expected=cas)
    if previous == name and acknowledged == receipt:
        return rotation_result(generation=name, intentSha256=cas)
    name = publish(paths[2], cert, key, uid)
    metadata = {'changed': previous != name, 'mailLeafPublished': True, 'generation': name, 'intentSha256': cas}
    selected_authority(bundle, expected=cas)
    reason = active_mail(actor)  # A stopped/queued unit is never revived.
    if reason: return rotation_result(reason, **metadata)
    # reload (NOT restart/reload-or-restart) cannot activate a stopped unit;
    # fail rather than replacing a concurrent stop job. Failure leaves no ack,
    # so the next authorized active tick retries even if publication succeeded.
    try:
        command(actor['command'] + ['--no-ask-password', '--job-mode=fail', 'reload', actor['unit']])
    except (ValueError, subprocess.SubprocessError):
        return rotation_result('mail-reload-failed', **metadata)
    selected_authority(bundle, expected=cas)
    reason = active_mail(actor)
    if reason: return rotation_result(reason, **metadata)
    if current_generation(paths[2]) != name: raise ValueError('Mail generation changed during reload')
    write_reload_receipt(paths[2], receipt)
    return rotation_result(reloaded=True, **metadata)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--bundle', required=True, type=Path)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument('--prepare', action='store_true'); operations.add_argument('--publish-mail', action='store_true')
    operations.add_argument('--rotate-mail', action='store_true')
    parser.add_argument('--expected-intent', default='')
    parser.add_argument('--installer-lock-fd', type=int, default=9)
    args = parser.parse_args()
    if os.geteuid() != 0: raise ValueError('Root trust operation required')
    if args.expected_intent and not args.rotate_mail: raise ValueError('CAS flag is external rotation only')
    with installer_lock(installer_root(args.bundle), None if args.rotate_mail else args.installer_lock_fd) as locked:
        if not locked:
            if not args.rotate_mail: raise ValueError('Installer internal lock unavailable')
            print(json.dumps(rotation_result('installer-busy'))); return
        if args.rotate_mail:
            result = rotate_mail(args.bundle, args.expected_intent)
            print(json.dumps(result, sort_keys=True))
            if result.get('reason') == 'mail-reload-failed': raise SystemExit(1)
            return
        authority = selected_authority(args.bundle, internal=True)
        paths, uid, hostname = authority['paths'], authority['uid'], authority['hostname']
        if args.prepare:
            prepare(*paths); grant_public_parents(args.bundle, paths[1])
            print(json.dumps({'trustPrepared': True, 'privateStoreShared': False})); return
        if paths[2] is None:
            print(json.dumps(rotation_result('mailserver-not-selected'))); return
        deadline = time.monotonic() + 120
        while True:
            try: cert, key = read_leaf(paths[0], hostname); break
            except FileNotFoundError:
                if time.monotonic() >= deadline: raise ValueError('Mail leaf issuance timeout') from None
                time.sleep(2)
        certificates_only(read_at(paths[1], 'caddy-ca.crt'))
        selected_authority(args.bundle, internal=True, expected=authority['intentSha256'])
        before = current_generation(paths[2])
        name = publish(paths[2], cert, key, uid)
        print(json.dumps(rotation_result(changed=before != name, mailLeafPublished=True, generation=name)))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, IndexError, StopIteration, subprocess.SubprocessError):
        raise SystemExit('Runtime trust operation refused; inspect private scoped evidence')
