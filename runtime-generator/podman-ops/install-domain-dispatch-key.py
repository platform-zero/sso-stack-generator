#!/usr/bin/env python3
"""CAS-preserve unrelated SSH keys when installing one forced domain key."""
import argparse,os,pwd,re,stat,tempfile
from pathlib import Path


def install_key(path: Path, user: str, domain: str, public_key: str) -> bool:
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', domain):
        raise ValueError('Invalid domain')
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+ p0-' + re.escape(domain), public_key):
        raise ValueError('Unexpected scoped public key')
    account = pwd.getpwnam(user)
    if account.pw_uid == 0 or not path.is_absolute() or path != Path(account.pw_dir) / '.ssh/authorized_keys':
        raise ValueError('Unexpected authorized-key destination')
    parent = path.parent
    if parent.exists() or parent.is_symlink():
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or info.st_mode & 0o077:
            raise ValueError('Unmanaged SSH directory')
    else:
        parent.mkdir(mode=0o700)
        os.chown(parent, account.pw_uid, account.pw_gid)
    exact = ('restrict,command="/usr/local/libexec/p0-domain-dispatch ' + domain + '" ' + public_key).encode()
    before = b''
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, account.pw_uid) or info.st_mode & 0o077:
            raise ValueError('Unsafe authorized-key file')
        before = path.read_bytes()
    lines = before.splitlines()
    scoped = [line for line in lines if line.endswith((' p0-' + domain).encode())]
    if any(line != exact for line in scoped) or len(scoped) > 1:
        raise ValueError('Conflicting domain key authority; no replacement')
    if exact in lines:
        return False
    if before and not before.endswith(b'\n'):
        raise ValueError('Unterminated authored SSH keys cannot be rewritten')
    body = before + exact + b'\n'
    fd, temp = tempfile.mkstemp(prefix='.p0-domain-key-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchown(output.fileno(), account.pw_uid, account.pw_gid)
            os.fchmod(output.fileno(), 0o600)
            output.write(body); output.flush(); os.fsync(output.fileno())
        # Refuse an unexpected concurrent change instead of overwriting it.
        if (path.read_bytes() if path.exists() else b'') != before:
            raise ValueError('SSH key authority changed during installation')
        os.replace(temp, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        return True
    finally:
        Path(temp).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', required=True)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--public-key-file', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root installation required')
    key = args.public_key_file.read_text().strip().split()
    if len(key) < 2:
        parser.error('Invalid domain public key')
    account = pwd.getpwnam(args.user)
    public = key[0] + ' ' + key[1] + ' p0-' + args.domain
    changed = install_key(Path(account.pw_dir) / '.ssh/authorized_keys', args.user, args.domain, public)
    print('domain key installed' if changed else 'exact domain key already installed')


if __name__ == '__main__':main()
