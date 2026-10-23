#!/usr/bin/env python3
"""Exact legacy or bundle-bound standalone storage ownership/traversal.

Never chmod a shared parent, adopt nonempty unclaimed data, replace an authored
ACL, broaden an ACL mask or grant access above the declared storage scope.
"""
import argparse
import grp
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

ROOTLESS_PARENT = Path('/mnt/stack/rootless')
MARKER = '.stack-installation.json'


def entries(path):
    result = subprocess.run(['getfacl', '-cp', '--', str(path)], capture_output=True,
                            text=True, check=True, timeout=10)
    return {tuple(line.split(':', 2)[:2]): line.split(':', 2)[2] for line in result.stdout.splitlines()
            if line.startswith(('user:', 'group:', 'mask:', 'other:')) and line.count(':') >= 2}


def exact_execute(path, user):
    before = entries(path)
    existing = before.get(('user', user))
    if existing is not None:
        if existing != '--x':
            raise ValueError('Authored user ACL cannot be replaced')
        return False
    mask = before.get(('mask', ''))
    if mask is not None and 'x' not in mask:
        raise ValueError('Existing ACL mask cannot be broadened implicitly')
    if mask is None:
        old = before.get(('group', ''), '---')
        mask = ''.join(c if c in old or c == 'x' else '-' for c in 'rwx')
    # Do NOT let setfacl recalculate a mask and unmask authored group/user rights.
    subprocess.run(['setfacl', '--no-mask', '-m', 'u:' + user + ':--x,m::' + mask,
                    '--', str(path)], check=True, timeout=10)
    after = entries(path)
    if (after.get(('user', user)) != '--x' or after.get(('mask', '')) != mask
            or any(after.get(k) != v for k, v in before.items() if k != ('mask', ''))):
        raise ValueError('Unexpected ancestor ACL change')
    return True


def grant(domain, user, volume_root):
    # Preserve the original closed legacy authority; arbitrary paths/users do not
    # become valid merely because standalone now has a separate bundle contract.
    if os.geteuid() != 0 or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', domain) or user != 'webservices-' + domain:
        raise ValueError('Exact selected rootless domain required')
    if volume_root != ROOTLESS_PARENT / domain or volume_root.is_symlink() or ROOTLESS_PARENT.is_symlink():
        raise ValueError('Unexpected volume root authority')
    for path in (ROOTLESS_PARENT.parent, ROOTLESS_PARENT, volume_root):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_mode & 0o002:
            raise ValueError('Unsafe rootless volume ancestor')
    info = ROOTLESS_PARENT.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Shared rootless parent must be root-controlled')
    pwd.getpwnam(user)
    return exact_execute(ROOTLESS_PARENT, user)


def normal_path(value):
    if (not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            or value == '/' or '..' in Path(value).parts or str(Path(value)) != value):
        raise ValueError('Noncanonical storage authority')
    return Path(value)


def check_chain(path):
    for item in (*reversed(path.parents), path):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if not stat.S_ISDIR(info.st_mode) or item.is_symlink():
                raise ValueError('Linked or non-directory storage ancestor')


def authority(bundle):
    if os.geteuid() != 0 or bundle.is_symlink():
        raise ValueError('Root and an exact bundle are required')
    helper = Path(__file__).with_name('verify-agent-vm-bundle.py')
    spec = importlib.util.spec_from_file_location('stack_storage_role_binding', helper)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.verify(bundle)
    manifest = module.strict(bundle / 'site/manifest.json')
    metadata = module.strict(bundle / 'podman-domains.json')
    ir = module.strict(bundle / 'stack.ir.json', limit=8 * 1024 * 1024)
    scope_config = manifest.get('storageScope')
    if (manifest.get('deploymentMode') != 'standalone' or not isinstance(scope_config, dict)
            or set(scope_config) != {'root', 'dataClass'}
            or scope_config['dataClass'] not in ('synthetic', 'production')
            or metadata.get('storageScope') != scope_config):
        raise ValueError('Missing hash-bound standalone storage scope')
    scope = normal_path(scope_config['root'])
    operator_uid = bundle.stat().st_uid
    # Installed immutable releases belong to root, not to the operator who
    # prepared an existing empty storage scope. Its owner remains authoritative.
    if operator_uid == 0 and scope.is_dir() and not scope.is_symlink():
        operator_uid = scope.stat().st_uid
    operator = pwd.getpwuid(operator_uid)
    rows = []
    for row in metadata['domains']:
        name, user, uid = row.get('name'), row.get('user'), row.get('uid')
        if (not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name)
                or not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', user)
                or type(uid) is not int or uid <= 0 or uid == operator.pw_uid):
            raise ValueError('Invalid or operator-owned domain identity')
        identity = {'name': name, 'user': user, 'uid': uid}
        for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
            path = normal_path(row.get(key))
            if not path.is_relative_to(scope) or path == scope:
                raise ValueError('Domain storage escapes selected scope')
            check_chain(path)
            identity[key] = str(path)
        try:
            account = pwd.getpwnam(user)
            if account.pw_uid != uid or account.pw_dir != '/home/' + user:
                raise ValueError('Existing domain identity drift')
        except KeyError:
            pass
        rows.append(identity)
    if not rows or len({r['user'] for r in rows}) != len(rows) or len({r['uid'] for r in rows}) != len(rows):
        raise ValueError('Missing or duplicate domain identities')
    for a in rows:
        for b in rows:
            if a is b: continue
            for ka in ('stateRoot', 'graphRoot', 'volumeRoot'):
                for kb in ('stateRoot', 'graphRoot', 'volumeRoot'):
                    if Path(a[ka]).is_relative_to(b[kb]) or Path(b[kb]).is_relative_to(a[ka]):
                        raise ValueError('Overlapping private domain roots')
    roots = {r[k] for r in rows for k in ('stateRoot', 'graphRoot', 'volumeRoot')}
    for volume in ir.get('volumes', {}).values():
        if volume.get('hostPath'):
            path = normal_path(volume['hostPath'])
            if not path.is_relative_to(scope) or path == scope:
                raise ValueError('Volume storage escapes selected scope')
            check_chain(path)
    check_chain(scope)
    expected = {'schemaVersion': 1, 'kind': 'standalone-stack-storage', 'site': manifest['site'],
                'scope': scope_config, 'domains': sorted(rows, key=lambda r: r['name']), 'roots': sorted(roots)}
    return scope, operator, expected


def marker(scope, expected):
    path = scope / MARKER
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != 0
            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 65536):
        raise ValueError('Unsafe storage ownership marker')
    if json.loads(path.read_text()) != expected:
        raise ValueError('Storage scope identity/ownership drift')


def safe_parent(path, operator):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid not in (0, operator.pw_uid)
            or info.st_mode & 0o007):
        raise ValueError('Storage parents must remain private and operator-controlled')
    for (kind, name), permissions in entries(path).items():
        if 'w' not in permissions or kind == 'mask': continue
        if kind == 'user':
            uid = info.st_uid if not name else pwd.getpwnam(name).pw_uid
            if uid not in (0, operator.pw_uid): raise ValueError('Foreign writable parent ACL')
        if kind == 'group':
            gid = info.st_gid if not name else grp.getgrnam(name).gr_gid
            if gid not in (0, operator.pw_gid): raise ValueError('Foreign writable parent group')


def prepare_scope(bundle, *, dry_run=False):
    scope, operator, expected = authority(bundle)
    if (scope / MARKER).exists() or (scope / MARKER).is_symlink():
        marker(scope, expected); safe_parent(scope, operator); return False
    # A new empty installation may create accounts, but cannot adopt retained
    # service accounts, their configuration or a pre-existing data tree.
    for row in expected['domains']:
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try: lookup(row['user'])
            except KeyError: continue
            raise ValueError('Unclaimed existing service identity')
    if scope.exists():
        safe_parent(scope, operator)
        count = 0
        for base, dirs, files in os.walk(scope, followlinks=False):
            count += len(dirs)
            if files or count > 4096: raise ValueError('Nonempty unclaimed storage scope')
            for name in dirs:
                child = Path(base) / name
                if child.is_symlink() or child.is_mount(): raise ValueError('Linked/mounted unclaimed subtree')
                safe_parent(child, operator)
    elif not scope.parent.is_dir():
        raise ValueError('Storage scope parent must already exist')
    if dry_run: return False
    scope.mkdir(mode=0o700, exist_ok=True)
    safe_parent(scope, operator)
    # An anonymous same-filesystem inode leaves no partial marker after an
    # interrupted write. Publish only a fully fsynced record, with no overwrite.
    directory = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = os.open(scope, os.O_RDWR | os.O_TMPFILE, 0o600)
    try:
        with os.fdopen(fd, 'w', closefd=False) as out:
            json.dump(expected, out, sort_keys=True); out.write('\n'); out.flush(); os.fsync(fd)
        os.link('/proc/self/fd/' + str(fd), MARKER, src_dir_fd=directory,
                dst_dir_fd=directory, follow_symlinks=True)
        os.fsync(directory)
    finally:
        os.close(fd); os.close(directory)
    return True


def grant_standalone(bundle, domain, user, volume_root):
    scope, operator, expected = authority(bundle); marker(scope, expected)
    row = next((r for r in expected['domains'] if r['name'] == domain and r['user'] == user), None)
    if row is None or str(volume_root) != row['volumeRoot'] or pwd.getpwnam(user).pw_uid != row['uid']:
        raise ValueError('Unselected domain storage request')
    # No permissions are changed above scope, including a private operator home.
    if any(not p.stat().st_mode & 0o001 for p in scope.parents):
        raise ValueError('External storage ancestors are not traversable')
    parents = {scope}
    for key in ('stateRoot', 'graphRoot', 'volumeRoot'):
        for parent in Path(row[key]).parents:
            if parent == scope: break
            parents.add(parent)
    changed = False
    for parent in sorted(parents, key=lambda p: len(p.parts)):
        if parent.stat().st_mode & 0o001: continue
        if parent.stat().st_uid == row['uid'] and parent.stat().st_mode & 0o100: continue
        safe_parent(parent, operator)
        changed = exact_execute(parent, user) or changed
    return changed


def prepare_ci_ssh(bundle):
    scope, operator, expected = authority(bundle); marker(scope, expected)
    # This is a reviewed host fixture directory, never a free --path authority.
    ir = json.loads((bundle / 'stack.ir.json').read_text())
    domain = ir['services']['forgejo-runner']['rootlessDomain']
    row = next(r for r in expected['domains'] if r['name'] == domain)
    account = pwd.getpwnam(row['user'])
    state = os.open(row['stateRoot'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try: os.mkdir('forgejo-runner-ssh', mode=0o700, dir_fd=state)
        except FileExistsError: pass
        fd = os.open('forgejo-runner-ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state)
        try:
            info = os.fstat(fd)
            if info.st_uid != account.pw_uid:
                if info.st_uid not in (0, operator.pw_uid) or os.listdir(fd):
                    raise ValueError('Cannot adopt pre-existing SSH authority')
                os.fchown(fd, account.pw_uid, account.pw_gid)
            os.fchmod(fd, 0o700)
        finally: os.close(fd)
    finally: os.close(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain'); parser.add_argument('--user')
    parser.add_argument('--volume-root', type=Path)
    parser.add_argument('--bundle', type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--prepare-scope', action='store_true')
    modes.add_argument('--validate-scope', action='store_true')
    modes.add_argument('--prepare-ci-ssh', action='store_true')
    args = parser.parse_args()
    try:
        if args.prepare_scope or args.validate_scope or args.prepare_ci_ssh:
            if not args.bundle or args.domain or args.user or args.volume_root: raise ValueError('Invalid preparation mode')
            if args.prepare_scope or args.validate_scope: prepare_scope(args.bundle, dry_run=args.validate_scope)
            else: prepare_ci_ssh(args.bundle)
        else:
            if not all((args.domain, args.user, args.volume_root)): raise ValueError('Incomplete domain request')
            if args.bundle: grant_standalone(args.bundle, args.domain, args.user, args.volume_root)
            else: grant(args.domain, args.user, args.volume_root)
        print('selected storage authority/traversal verified; no broad parent chmod or account takeover')
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, StopIteration):
        parser.exit(1, 'selected storage authority/traversal refused\n')


if __name__ == '__main__': main()
