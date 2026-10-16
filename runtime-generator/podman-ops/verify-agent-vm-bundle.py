#!/usr/bin/env python3
"""Fail-closed, read-only binding of a generated Latium bundle to its site VM pin.

The selected control/guest installers remain the only source-role mutation paths.
This check does not pretend that a stack activation has installed either role.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def strict(path, *, include_bytes=False):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise ValueError('Duplicate agent VM authority key')
            value[key] = item
        return value
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Missing, linked or oversized agent VM input')
    body = path.read_bytes()
    if len(body) > 65536:
        raise ValueError('Oversized agent VM input')
    decoded = json.loads(body, object_pairs_hook=pairs)
    return (decoded, body) if include_bytes else decoded


def verify(bundle, control=None):
    site = bundle / 'site'
    manifest = strict(site / 'manifest.json')
    if manifest.get('site') != 'latium':
        return {'site': manifest.get('site'), 'agentVm': 'not-applicable'}
    if manifest.get('agentVmSpec') != 'agent-vm.json':
        raise ValueError('Latium requires exact site-owned agent-vm.json')
    vm_path = site / 'agent-vm.json'
    metadata = strict(site / 'agent-vm.provenance.json')
    vm, body = strict(vm_path, include_bytes=True)
    digest = hashlib.sha256(body).hexdigest()
    pins = vm.get('runtime')
    if (set(metadata) != {'schemaVersion', 'path', 'sha256', 'controlCommit'}
            or type(metadata['schemaVersion']) is not int or metadata['schemaVersion'] != 1
            or metadata['path'] != 'agent-vm.json' or metadata['sha256'] != digest
            or not isinstance(pins, dict) or metadata['controlCommit'] != pins.get('controlCommit')):
        raise ValueError('Agent VM bundle provenance mismatch')
    required = {'schemaVersion', 'name', 'network', 'networkConfig', 'vcpus', 'memoryMiB',
                'osGiB', 'workGiB', 'swapGiB', 'cloudImage', 'debianSnapshot', 'packages',
                'runtime', 'projectLanes', 'gpuDevices', 'reserves'}
    domains = strict(bundle / 'podman-domains.json')
    venue = domains.get('venue')
    port_override = vm.get('servicePorts')
    if venue is None:
        if port_override is not None or set(vm) != required:
            raise ValueError('Legacy guest cannot use unbound service ports')
    else:
        mapping = venue.get('portMap') if isinstance(venue, dict) else None
        if (set(vm) != required | {'servicePorts', 'diskRoot'} or not isinstance(mapping, dict)
                or vm.get('name') != vm.get('network','') + '-agents'
                or vm.get('diskRoot') != '/mnt/lab_debian/agent_vm/' + vm.get('name','')
                or not isinstance(port_override, dict) or set(port_override) != {'https','imap','smtp'}
                or not re.fullmatch(r'p0-venue-[a-z0-9-]{1,24}', vm.get('network',''))
                or any(type(port_override[key]) is not int or port_override[key] != mapping.get(source)
                       for key, source in (('https','443'),('imap','993'),('smtp','587')))):
            raise ValueError('Guest private service ports differ from venue authority')
    if (set(vm) not in (required, required | {'servicePorts', 'diskRoot'})
            or type(vm['schemaVersion']) is not int or vm['schemaVersion'] != 1
            or (venue is None and vm['name'] != 'p0-agents')
            or vm['projectLanes'] != [] or vm['gpuDevices'] != []
            or any(type(vm[k]) is not int or vm[k] != v for k, v in
                   {'vcpus': 8, 'memoryMiB': 12288, 'osGiB': 80, 'workGiB': 100, 'swapGiB': 4}.items())
            or set(pins) != {'controlCommit', 'worklaneCommit', 'manifestSha256', 'image',
                             'archiveFilename', 'archiveSha256', 'importBudgetBytes'}
            or not all(isinstance(pins.get(k), str) and re.fullmatch('[a-f0-9]{40}', pins[k])
                       for k in ('controlCommit', 'worklaneCommit'))):
        raise ValueError('Invalid empty CPU agent VM pins')
    if control is not None:
        control = control.resolve(strict=True)
        git = ['git', '-c', 'safe.directory=' + str(control), '-C', str(control)]
        head = subprocess.check_output([*git, 'rev-parse', 'HEAD'], text=True).strip()
        if head != pins['controlCommit'] or subprocess.check_output(
                [*git, 'status', '--porcelain'], text=True).strip():
            raise ValueError('Reviewed control checkout differs from site pin')
        source = control / 'ops/agent_vm_spec.py'
        if source.is_symlink() or not source.is_file():
            raise ValueError('Pinned control VM validator unavailable')
        module_spec = importlib.util.spec_from_file_location('p0_site_vm_validator', source)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        module.load(vm_path)
    return {'site': 'latium', 'agentVmSha256': digest, 'controlCommit': pins['controlCommit'],
            'controlSourceValidated': control is not None, 'rolesActivated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--control-checkout', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.bundle, args.control_checkout), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'agent VM bundle preflight refused: ' + type(error).__name__ + '\n')


if __name__ == '__main__':
    main()
