"""Explicit immutable source contexts and rootless image production.

No repository discovery, private files, credentials or historical trees are
implicitly copied. Runtime staging is a separate Root-owned byte copier.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .model import ContractError, canonical, fields, identifier, load_json

LIMIT = 8 * 1024 * 1024
TOTAL = 64 * 1024 * 1024


def member(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or str(path) != name or len(path.parts) > 12
            or any(part.startswith('.') or part in ('historical', 'private', 'secrets') for part in path.parts)
            or not re.fullmatch(r'[a-zA-Z0-9_/-][a-zA-Z0-9_./-]*', name)):
        raise ContractError('unsafe explicit build input')
    return path


def regular(root, name):
    path = member(name)
    for parent in path.parents:
        ancestor = root / parent
        if ancestor.is_symlink() or not ancestor.is_dir():
            raise ContractError('build source ancestor changed')
    source = root / path
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > LIMIT:
            raise ContractError('unsupported build source object')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            content = stream.read(LIMIT + 1)
        if len(content) > LIMIT:
            raise ContractError('build source exceeds byte limit')
        return content, bool(observed.st_mode & 0o111)
    finally:
        os.close(fd)


def base_images(recipe):
    stages, bases = set(), []
    for line in recipe.decode().splitlines():
        words = line.strip().split()
        if words and words[0].upper() == 'FROM':
            if len(words) not in (2, 4) or (len(words) == 4 and words[2].upper() != 'AS'):
                raise ContractError('unsupported FROM statement')
            base = words[1]
            if base not in stages:
                if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}', base):
                    raise ContractError('build base must be immutable')
                bases.append(base)
            if len(words) == 4:
                stages.add(words[3])
    if not bases:
        raise ContractError('build recipe has no pinned base')
    return bases


def pack(source, output, name, includes):
    source, output = Path(source).resolve(), Path(output)
    identifier(name)
    if output.exists() or output.is_symlink():
        raise ContractError('build context output already exists')
    if len(set(includes)) != len(includes):
        raise ContractError('duplicate build include')
    payload = {}
    for include in includes:
        path = source / member(include)
        if path.is_symlink():
            raise ContractError('build source symlink')
        children = sorted(path.rglob('*')) if path.is_dir() else []
        if any(item.is_symlink() for item in children):
            raise ContractError('build subtree contains symlink')
        names = [str(item.relative_to(source)) for item in children if not item.is_dir()] if path.is_dir() else [include]
        for item in names:
            if item in payload or item == 'context.json':
                raise ContractError('overlapping or reserved build includes')
            payload[item] = regular(source, item)
    if 'Containerfile' not in payload or sum(len(value[0]) for value in payload.values()) > TOTAL:
        raise ContractError('missing recipe or context too large')
    bases = base_images(payload['Containerfile'][0])
    lock = {'schemaVersion': 1, 'kind': 'p0-build-context', 'id': name, 'recipe': 'Containerfile',
            'baseImages': bases, 'files': {key: {'sha256': hashlib.sha256(value[0]).hexdigest(), 'executable': value[1]}
                                          for key, value in sorted(payload.items())}}
    output.mkdir(mode=0o700)
    for key, (content, executable) in payload.items():
        target = output / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o755 if executable else 0o644)
    encoded = canonical(lock)
    (output / 'context.json').write_bytes(encoded)
    return {'schemaVersion': 1, 'context': str(output), 'sha256': hashlib.sha256(encoded).hexdigest(),
            'files': len(payload), 'installationCertified': False}


def verify(context, expected):
    context = Path(context)
    encoded = (context / 'context.json').read_bytes()
    if hashlib.sha256(encoded).hexdigest() != expected:
        raise ContractError('build context identity mismatch')
    lock = load_json(context / 'context.json')
    fields(lock, {'schemaVersion', 'kind', 'id', 'recipe', 'baseImages', 'files'})
    if type(lock['schemaVersion']) is not int or lock['schemaVersion'] != 1 or lock['kind'] != 'p0-build-context' or lock['recipe'] != 'Containerfile':
        raise ContractError('unsupported build context')
    identifier(lock['id'])
    if not isinstance(lock['files'], dict) or 'Containerfile' not in lock['files']:
        raise ContractError('missing context files')
    total = 0
    for name, identity in lock['files'].items():
        fields(identity, {'sha256', 'executable'})
        content, executable = regular(context, name)
        total += len(content)
        if hashlib.sha256(content).hexdigest() != identity['sha256'] or type(identity['executable']) is not bool or executable != identity['executable']:
            raise ContractError('build member changed')
    paths = list(context.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise ContractError('build context contains symlink')
    actual = {str(path.relative_to(context)) for path in paths if not path.is_dir()}
    if actual != set(lock['files']) | {'context.json'} or total > TOTAL:
        raise ContractError('unlisted build context member or byte limit')
    if lock['baseImages'] != base_images((context / 'Containerfile').read_bytes()):
        raise ContractError('build base lock disagrees with recipe')
    return lock


def trusted_context(context, lock):
    # Compiler/builder input is private Root-owned immutable supply, not a
    # mutable user working tree that could change after verification.
    if context.resolve() != context or context.parent != Path('/var/lib/p0-v2-build-inputs'):
        raise ContractError('image builds require immutable staged context')
    for path in (context, context / 'context.json', *(context / name for name in lock['files'])):
        observed = path.lstat()
        if observed.st_uid != 0 or observed.st_mode & 0o222:
            raise ContractError('build supply is writable or not Root-owned')


def build(runtime, context, expected):
    from .journal import Journal, operation_lock
    from .lifecycle import STORE_ROOT, verify_reserves
    context = Path(context)
    lock = verify(context, expected)
    trusted_context(context, lock)
    verify_reserves(extra_bytes=2 * 1024**3)
    tag = 'localhost/p0-' + lock['id'] + ':input-' + expected
    with operation_lock(runtime.state):
        if runtime.run(['/usr/bin/podman', 'info', '--format', '{{.Store.GraphRoot}}']).decode().strip() != STORE_ROOT:
            raise ContractError('unexpected image build store')
        journal = Journal(runtime.state / 'operations.sqlite3')
        operation = journal.create('build', expected)
        try:
            journal.transition(operation, 0, 'running')
            # Build output is retained by the bounded Runner but never rendered
            # as unsanitized diagnostics. No host sockets or added privileges.
            runtime.run(['/usr/bin/podman', 'build', '--pull=missing', '--timestamp=0',
                         '--label', 'io.platform-zero.build-input=' + expected, '--tag', tag,
                         '--file', str(context / 'Containerfile'), str(context)], timeout=600)
            digest = runtime.run(['/usr/bin/podman', 'image', 'inspect', '--format', '{{.Digest}}', tag]).decode().strip()
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
                raise ContractError('builder returned no immutable image digest')
            reference = tag.split(':input-', 1)[0] + '@' + digest
            observed = runtime.run(['/usr/bin/podman', 'image', 'inspect', '--format', '{{.Digest}}', reference]).decode().strip()
            if observed != digest:
                raise ContractError('local image digest reference did not resolve')
            journal.transition(operation, 1, 'succeeded')
            return {'schemaVersion': 1, 'operation': operation, 'inputSha256': expected,
                    'image': reference, 'sourceTag': tag, 'installationCertified': False}
        except Exception:
            journal.transition(operation, 1, 'indeterminate')
            raise
        finally:
            journal.close()
