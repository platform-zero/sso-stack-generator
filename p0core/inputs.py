"""Private explicit site inputs, resolved into the same selected graph identity.

Configuration bytes are a separate private supply artifact, never application
source/release content. Credentials use secret references, not this interface.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

from .model import Catalog, ContractError, canonical, fields, identifier

CONFIG_ROOT = Path('/etc/p0-v2/config')
CONFIG_LIMIT = 8 * 1024 * 1024


def configuration_bytes(descriptor):
    fields(descriptor, {'path', 'sha256'})
    if not isinstance(descriptor['path'], str) or not isinstance(descriptor['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', descriptor['sha256']):
        raise ContractError('invalid explicit configuration input')
    path = Path(descriptor['path'])
    if path.resolve() != path:
        raise ContractError('configuration input must have exact canonical path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or observed.st_size > CONFIG_LIMIT:
            raise ContractError('unsupported configuration input object')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            content = stream.read(CONFIG_LIMIT + 1)
        if len(content) > CONFIG_LIMIT or hashlib.sha256(content).hexdigest() != descriptor['sha256']:
            raise ContractError('configuration input changed')
        return content
    finally:
        os.close(fd)


def bindings(specifications):
    result = {}
    for spec in specifications:
        for mount in spec.get('mounts', []):
            if mount.get('kind') != 'config':
                continue
            name, checksum = identifier(mount['source']), mount.get('sha256')
            if not isinstance(checksum, str) or not re.fullmatch('[a-f0-9]{64}', checksum):
                raise ContractError('configuration mount needs explicit byte identity')
            if name in result and result[name] != checksum:
                raise ContractError('conflicting configuration ownership binding')
            result[name] = checksum
    return result


def resolve(catalog, targets, document):
    fields(document, {'schemaVersion'}, {'images', 'configs'})
    if type(document['schemaVersion']) is not int or document['schemaVersion'] != 1:
        raise ContractError('unsupported explicit inputs version')
    images, configs = document.get('images', {}), document.get('configs', {})
    if not isinstance(images, dict) or not isinstance(configs, dict) or set(images) - set(catalog.services):
        raise ContractError('unknown image input owner or malformed inputs')
    plan = catalog.plan(targets)
    selected = set(plan['services'])
    documents = []
    for original in catalog.modules.values():
        import json
        module = json.loads(canonical(original))
        for service in module['services']:
            if service['id'] not in selected:
                continue
            if service['id'] in images:
                service['image'] = images[service['id']]
            for mount in service.get('mounts', []):
                if mount.get('kind') == 'config' and mount['source'] in configs:
                    descriptor = configs[mount['source']]
                    configuration_bytes(descriptor)
                    mount['sha256'] = descriptor['sha256']
        documents.append(module)
    resolved = Catalog(documents)
    bindings(resolved.services[name].declaration for name in selected)
    return resolved


def pack_configurations(catalog, targets, document, destination):
    resolved = resolve(catalog, targets, document)
    plan = resolved.plan(targets)
    selected = bindings(resolved.services[name].declaration for name in plan['services'])
    payload = {}
    for name, checksum in selected.items():
        descriptor = document.get('configs', {}).get(name)
        if descriptor is None:
            raise ContractError('configuration bytes missing from explicit private inputs')
        payload[checksum] = configuration_bytes(descriptor)
    if not payload or sum(map(len, payload.values())) > 64 * 1024 * 1024:
        raise ContractError('empty or excessive private configuration supply')
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ContractError('configuration supply output already exists')
    destination.mkdir(mode=0o700)
    for checksum, content in payload.items():
        target = destination / checksum
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    lock = {'schemaVersion': 1, 'kind': 'p0-config-inputs', 'privateInput': True,
            'configs': selected, 'files': {checksum: checksum for checksum in payload}}
    encoded = canonical(lock)
    (destination / 'context.json').write_bytes(encoded)
    (destination / 'context.json').chmod(0o600)
    return {'schemaVersion': 1, 'scope': 'private-noncredential-configuration-only',
            'context': str(destination), 'sha256': hashlib.sha256(encoded).hexdigest(),
            'privateInput': True, 'installationCertified': False}


def verify_installed(specifications):
    selected = bindings(specifications)
    if not selected:
        return
    root = CONFIG_ROOT.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_mode & 0o022 or CONFIG_ROOT.resolve() != CONFIG_ROOT):
        raise ContractError('configuration root custody mismatch')
    for checksum in selected.values():
        path = CONFIG_ROOT / checksum
        observed = path.lstat()
        if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_nlink != 1
                or observed.st_mode & 0o222 or path.resolve() != path
                or hashlib.sha256(path.read_bytes()).hexdigest() != checksum):
            raise ContractError('installed configuration custody or bytes changed')
