#!/usr/bin/env python3
"""Root-owned public trust and narrowly delegated mail leaf credentials.

Never mount/copy the CA private store into an application actor. No key material
or OpenSSL diagnostic output is logged. Derived generations are atomic, not
backups; obsolete generations are removed after publication.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time


def command(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    if result.returncode: raise ValueError('Runtime trust validation/permission operation refused')
    return result.stdout


def directory(path, unsealed=False):
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


def read_at(root, relative, unsealed=False):
    fd = directory(root, unsealed=unsealed)
    try:
        parts = Path(relative).parts
        if not parts or any(p in ('/', '.', '..') for p in parts): raise ValueError('Invalid trust artifact path')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or info.st_size > 2 * 1024 * 1024 or info.st_mode & 0o022):
                raise ValueError('Unsafe trust artifact')
            return os.read(child, info.st_size + 1)
        finally: os.close(child)
    finally: os.close(fd)


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
        command(['setfacl', '-b', '-k', str(path)])
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
    if (public / 'caddy-ca.crt').exists():
        command(['setfacl', '-b', str(public / 'caddy-ca.crt')]); (public / 'caddy-ca.crt').chmod(0o644)
    if target is not None:
        fd = directory(target); os.close(fd)


def validate_leaf(cert, key, hostname):
    certificates_only(cert)
    if not re.fullmatch(rb'-----BEGIN ((?:EC |RSA )?PRIVATE KEY)-----\s+[A-Za-z0-9+/=\r\n]+-----END \1-----', key.strip()):
        raise ValueError('Mail delegation requires exactly one unencrypted leaf key')
    command(['openssl', 'x509', '-noout', '-checkend', '60'], cert)
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


def reader(path, uid, is_dir=False):
    command(['setfacl', '-b', '-k', str(path)] if is_dir else ['setfacl', '-b', str(path)])
    path.chmod(0o700 if is_dir else 0o600)
    access = 'r-x' if is_dir else 'r--'
    if uid != 0:
        command(['setfacl', '-m', f'u:{uid}:{access},m::{access}', str(path)])


def publish(target, cert, key, uid):
    fd = directory(target)
    try:
        lock = os.open('.publish.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            info = os.fstat(lock)
            if info.st_uid or info.st_nlink != 1 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode): raise ValueError('Unsafe leaf lock')
            fcntl.flock(lock, fcntl.LOCK_EX)
            if set(os.listdir(fd)) - {'.publish.lock', 'generations', 'current'}: raise ValueError('Unexpected leaf artifact')
            generations = target / 'generations'
            generations.mkdir(mode=0o700, exist_ok=True)
            parent = directory(generations); os.close(parent)
            name = hashlib.sha256(cert).hexdigest(); generation = generations / name
            generation.mkdir(mode=0o700, exist_ok=True)
            child = directory(generation)
            try:
                if set(os.listdir(child)) - {'cert.pem', 'key.pem'}: raise ValueError('Unexpected leaf generation')
                for filename, content in (('cert.pem', cert), ('key.pem', key)):
                    path = generation / filename
                    if path.exists():
                        if read_at(generation, filename) != content: raise ValueError('Leaf generation collision')
                    else:
                        out = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
                        with os.fdopen(out, 'wb') as stream: stream.write(content); stream.flush(); os.fsync(stream.fileno())
                    reader(path, uid)
                os.fsync(child)
            finally: os.close(child)
            reader(generation, uid, True); reader(generations, uid, True); reader(target, uid, True)
            current = target / 'current'
            if current.exists() or current.is_symlink():
                if (not current.is_symlink() or current.lstat().st_uid != 0
                        or not re.fullmatch(r'generations/[a-f0-9]{64}', os.readlink(current))):
                    raise ValueError('Unrecognized mail leaf selection')
            temporary = '.current-' + str(os.getpid())
            os.symlink('generations/' + name, temporary, dir_fd=fd)
            os.replace(temporary, 'current', src_dir_fd=fd, dst_dir_fd=fd); os.fsync(fd)
            for old in generations.iterdir():
                if old.name == name: continue
                if not re.fullmatch(r'[a-f0-9]{64}', old.name): raise ValueError('Unexpected obsolete leaf generation')
                oldfd = directory(old)
                try:
                    if set(os.listdir(oldfd)) != {'cert.pem', 'key.pem'}: raise ValueError('Unknown obsolete leaf contents')
                    for filename in ('cert.pem', 'key.pem'):
                        read_at(old, filename); os.unlink(filename, dir_fd=oldfd)
                finally: os.close(oldfd)
                old.rmdir()
            return name
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
    ir = json.loads((bundle / 'stack.ir.json').read_text())
    mail_selected = 'mailserver' in ir['services']
    names = ['caddy_certs', 'caddy_ca'] + (['mail_tls'] if mail_selected else [])
    paths = [Path(ir['volumes'][name]['hostPath']) for name in names]
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
    values = [shlex.split(line.split('=', 1)[1])[0] for line in (bundle / 'runtime/stack.env').read_text().splitlines() if line.startswith('DOMAIN=')]
    if len(values) != 1 or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,240}[a-z0-9]', values[0]): raise ValueError('Invalid mail domain authority')
    return paths, uid, 'mail.' + values[0]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--prepare', action='store_true'); parser.add_argument('--publish-mail', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.prepare == args.publish_mail: raise ValueError('Root and exactly one trust operation required')
    paths, uid, hostname = binding(args.bundle)
    if args.prepare:
        prepare(*paths); grant_public_parents(args.bundle, paths[1])
        print(json.dumps({'trustPrepared': True, 'privateStoreShared': False})); return
    if paths[2] is None:
        print(json.dumps({'mailLeafPublished': False, 'reason': 'mailserver-not-selected'})); return
    deadline = time.monotonic() + 120
    while True:
        try: cert, key = read_leaf(paths[0], hostname); break
        except FileNotFoundError:
            if time.monotonic() >= deadline: raise ValueError('Mail leaf issuance timeout') from None
            time.sleep(2)
    certificates_only(read_at(paths[1], 'caddy-ca.crt'))
    name = publish(paths[2], cert, key, uid)
    print(json.dumps({'mailLeafPublished': True, 'generation': name, 'privateStoreShared': False}))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, StopIteration, subprocess.SubprocessError):
        raise SystemExit('Runtime trust operation refused; inspect private scoped evidence')
