#!/usr/bin/env python3
"""Prepare root-only, exact isolated maintenance inputs; no stack mutation.

This is a prerequisite for a future typed apply worker, not an approval or an
apply. Neither a lane nor a production host can manufacture synthetic authority.
"""
import argparse
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

OUTPUT = Path(os.environ.get('P0_MAINTENANCE_INPUTS', '/etc/platform-zero/maintenance-install.json'))
TRUSTED_BROKER = Path('/usr/local/libexec/p0-host-broker')
TRUSTED_VALIDATOR = Path('/usr/local/libexec/p0-verify-agent-vm-bundle')
DMI = Path(os.environ.get('P0_MACHINE_UUID_PATH', '/sys/class/dmi/id/product_uuid'))
MARKER = Path(os.environ.get('P0_ISOLATED_MARKER', '/etc/platform-zero/isolated-fixture.json'))


def protected(path, *, directory=False):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unmanaged maintenance input')
    if directory and not stat.S_ISDIR(info.st_mode):
        raise ValueError('Expected a protected directory')
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise ValueError('Expected a protected regular file')
    return info


def root_controlled_parents(path):
    for parent in path.parents:
        info=parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or info.st_uid!=0
                or info.st_mode&0o022):
            raise ValueError('Maintenance input has a writable or linked ancestor')


def file_sha256(path):
    protected(path)
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(part)
    return digest.hexdigest()


def strict_json(path):
    protected(path)
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise ValueError('Duplicate maintenance authority key')
            result[key] = value
        return result
    if path.stat().st_size > 65536: raise ValueError('Oversized maintenance authority')
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def prepare(bundle, control, images, release):
    if os.geteuid() != 0 or not re.fullmatch('[a-f0-9]{64}', release):
        raise ValueError('Exact root-selected release required')
    machine = DMI.read_text().strip().lower()
    if str(uuid.UUID(machine)) != machine or strict_json(MARKER) != {
            'schemaVersion': 1, 'scope': 'isolated-synthetic', 'machineUuid': machine}:
        raise ValueError('Actual isolated machine marker required')
    for path in (bundle, control):
        if not path.is_absolute():raise ValueError('Relative maintenance input refused')
        root_controlled_parents(path)
        protected(path, directory=True)
    if not images.is_absolute() or not OUTPUT.is_absolute() or not bundle.is_dir():
        raise ValueError('Unbound maintenance path')
    root_controlled_parents(images)
    protected(images)
    root_controlled_parents(OUTPUT)
    if OUTPUT.parent.is_symlink():raise ValueError('Linked maintenance destination')
    protected(OUTPUT.parent, directory=True)
    site = bundle / 'site'
    protected(site, directory=True)
    spec = strict_json(site / 'agent-vm.json')
    provenance = strict_json(site / 'agent-vm.provenance.json')
    metadata = strict_json(site / 'manifest.json')
    source = strict_json(bundle / 'source-provenance.json')
    if (not isinstance(source,dict) or source.get('generatorDirty') is not False
            or source.get('siteDirty') is not False
            or any(not isinstance(source.get(key),str) or not re.fullmatch('[a-f0-9]{40}',source[key])
                   for key in ('generatorCommit','siteCommit'))):
        raise ValueError('Dirty or unpinned final source refused')
    if metadata.get('site') != 'latium' or metadata.get('agentVmSpec') != 'agent-vm.json':
        raise ValueError('Only exact Latium guest site is supported')
    spec_sha = file_sha256(site / 'agent-vm.json')
    runtime = spec.get('runtime', {})
    commit = runtime.get('controlCommit') if isinstance(runtime, dict) else None
    if (not isinstance(commit, str) or not re.fullmatch('[a-f0-9]{40}', commit)
            or provenance != {'schemaVersion':1, 'path':'agent-vm.json',
                              'sha256':spec_sha, 'controlCommit':commit}):
        raise ValueError('Site/control guest authority mismatch')
    protected(control / '.git', directory=True)
    protected(control / 'ops', directory=True)
    protected(control / 'ops/agent_vm_spec.py')
    if (control / '.git/objects/info/alternates').exists() or (control / '.git/objects/info/alternates').is_symlink():
        raise ValueError('Shared or linked control object store refused')
    git = ['git', '-c', 'safe.directory=' + str(control), '-C', str(control)]
    top = subprocess.run([*git, 'rev-parse', '--show-toplevel'], capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    if top != str(control):raise ValueError('Control checkout escaped selected root')
    head = subprocess.run([*git, 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    dirty = subprocess.run([*git, 'status', '--porcelain'], capture_output=True, text=True, timeout=20, check=True).stdout.strip()
    if head != commit or dirty:
        raise ValueError('Reviewed control checkout not exactly selected')
    # The existing supported validator also runs the pinned control VM parser.
    protected(TRUSTED_BROKER)
    protected(TRUSTED_VALIDATOR)
    check = subprocess.run(['python3', str(TRUSTED_VALIDATOR), '--bundle', str(bundle),
                            '--control-checkout', str(control)], capture_output=True, text=True, timeout=35)
    if check.returncode:raise ValueError('Selected guest/control validator refused')
    image_sha = file_sha256(images)
    # Reuse the broker's exact staged-tree digest algorithm; no special casing
    # hidden files, modes, or links in this independent root preparation step.
    importer = TRUSTED_BROKER
    spec_module = importlib.util.spec_from_loader('p0_inputs_broker', SourceFileLoader('p0_inputs_broker', str(importer)))
    if not spec_module or not spec_module.loader:raise ValueError('Missing reviewed bundle authority')
    broker = importlib.util.module_from_spec(spec_module);spec_module.loader.exec_module(broker)
    if broker.tree_sha256(bundle) != release:
        raise ValueError('Selected bundle digest changed')
    broker.validate_bundle(bundle)
    data = {'schemaVersion':1, 'scope':'isolated-synthetic', 'machineUuid':machine,
            'release':release, 'controlCommit':commit, 'controlCheckout':str(control),
            'siteSpecSha256':spec_sha, 'imageInputs':str(images), 'imageInputsSha256':image_sha}
    raw = (json.dumps(data, sort_keys=True) + '\n').encode()
    if OUTPUT.exists() or OUTPUT.is_symlink():
        info = protected(OUTPUT)
        if stat.S_IMODE(info.st_mode) != 0o600 or OUTPUT.read_bytes() != raw:
            raise ValueError('Existing maintenance inputs require exact-CAS review')
        return {'ready':True, 'unchanged':True, 'release':release, 'machineUuid':machine}
    fd, temporary = tempfile.mkstemp(prefix='.maintenance-inputs-', dir=OUTPUT.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as target:
            target.write(raw);target.flush();os.fsync(target.fileno())
        # Parent is root-controlled; do not adopt or overwrite a raced file.
        if OUTPUT.exists() or OUTPUT.is_symlink():raise ValueError('Maintenance input destination changed')
        os.link(temporary, OUTPUT)
        sync = os.open(OUTPUT.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:os.fsync(sync)
        finally:os.close(sync)
    finally:Path(temporary).unlink(missing_ok=True)
    return {'ready':True, 'unchanged':False, 'release':release, 'machineUuid':machine}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path, required=True)
    parser.add_argument('--image-inputs', type=Path, required=True)
    parser.add_argument('--release', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.bundle, args.control_checkout, args.image_inputs, args.release)))
    except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
        parser.exit(1, 'isolated maintenance input preparation refused\n')


if __name__ == '__main__':main()
