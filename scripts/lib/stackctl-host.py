#!/usr/bin/env python3
"""Read-only host diagnosis and generated-bundle mutation inventory.

Never invokes Podman, a test runner, a renderer or an installer. In particular,
planning must not initialize container storage or decrypt deployment inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

REQUIRED = ('bash', 'flock', 'python3', 'podman', 'systemctl', 'systemd-analyze', 'jq', 'sops')
LIMIT = 8 * 1024 * 1024


def load(root, relative):
    path = root / relative
    # Do not follow any component, including a linked input directory.
    for component in (path, *path.parents):
        if component == root.parent:
            break
        if component.is_symlink():
            raise ValueError('linked bundle input refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError('invalid or oversized bundle input')
        body = source.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError('oversized bundle input')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate bundle input key')
            result[key] = value
        return result
    value = json.loads(body, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError('bundle input must be an object')
    return value, hashlib.sha256(body).hexdigest()


def inventory(bundle):
    root = Path(bundle).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError('plain bundle directory required')
    metadata, _ = load(root, 'bundle.json')
    ir, ir_sha = load(root, 'stack.ir.json')
    provenance, provenance_sha = load(root, 'source-provenance.json')
    manifest, manifest_sha = load(root, 'site/manifest.json')
    domains, _ = load(root, 'podman-domains.json')
    if (metadata.get('schemaVersion') != 1 or metadata.get('backend') != 'podman'
            or metadata.get('irSha256') != ir_sha
            or metadata.get('sourceProvenanceSha256') != provenance_sha
            or provenance.get('manifestSha256') != manifest_sha):
        raise ValueError('bundle provenance/hash binding mismatch')
    services = ir.get('services')
    rows = domains.get('domains')
    if not isinstance(services, dict) or not services or not isinstance(rows, list):
        raise ValueError('invalid service/domain inventory')
    identities = []
    seen = set()
    for row in rows:
        name = row.get('name')
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError('duplicate or missing domain identity')
        seen.add(name)
        required = ('user', 'stateRoot', 'graphRoot', 'volumeRoot')
        if any(not isinstance(row.get(key), str) or not row[key] for key in required):
            raise ValueError('incomplete domain resource inventory')
        if any(not row[key].startswith('/mnt/stack/') for key in required[1:]):
            raise ValueError('domain storage outside supported stack filesystem')
        identities.append({key: row[key] for key in ('name', *required)})
    details = []
    for name, service in sorted(services.items()):
        if not isinstance(service, dict): raise ValueError('invalid service detail inventory')
        persistent = []
        binds = []
        for mount in service.get('volumes', []):
            source = mount.split(':', 1)[0] if isinstance(mount, str) else mount.get('source', '')
            if source in ir.get('volumes', {}): persistent.append(source)
            elif source: binds.append(source)
        details.append({'name': name, 'module': service.get('module'),
                        'lifecycle': service.get('lifecycle', 'daemon'),
                        'placement': service.get('placement'), 'domain': service.get('rootlessDomain'),
                        'sourceBuild': bool(service.get('build')),
                        'emittedBuildProducer': bool(service.get('build')) and (manifest.get('deploymentMode') == 'standalone' or service.get('lifecycle') != 'on-demand' or service.get('quadletManaged') is True),
                        'namedDataVolumes': sorted(set(persistent)),
                        'otherMountSources': sorted(set(binds))})
    warnings = []
    if 'venue' in domains:
        warnings.append('Isolated experimental venue: ordinary native activation refuses this profile; do not bypass that gate.')
    if manifest.get('agentVmSpec'):
        warnings.append('Manifest declares a managed agent VM; this is not a standalone host-only installation contract.')
    return {'schemaVersion': 1, 'scope': 'read-only proposed resources; no activation authority',
            'backend': 'podman', 'site': manifest.get('site'),
            'source': {key: provenance.get(key) for key in ('generatorCommit', 'siteCommit', 'generatorDirty', 'siteDirty')},
            'components': manifest.get('components', []),
            'excludedComponents': manifest.get('excludedComponents', []),
            'services': sorted(services), 'serviceDetails': details, 'domains': identities,
            'deploymentMode': manifest.get('deploymentMode', 'managed'),
            'installerStateRoot': domains.get('installerStateRoot', '/var/lib/webservices'),
            'storageScope': manifest.get('storageScope'),
            'modules': [{key: row.get(key) for key in ('id', 'commit', 'dirty')}
                        for row in provenance.get('modules', [])],
            'lifecycleCounts': {kind: sum(row['lifecycle'] == kind for row in details)
                                for kind in sorted({row['lifecycle'] for row in details})},
            'warnings': warnings, 'privateInputsInspected': False, 'mutationsPerformed': False}


def markdown_inventory(value):
    # Metadata only. Never include environment values, store/key bodies or paths
    # from an operator's audit workspace.
    rows=value['serviceDetails']
    lines=['# Selected stack composition inventory','',
           '**Generated/source classification only; not application, SSO or recovery acceptance.**','',
           f"Site: `{value['site']}`; mode: `{value['deploymentMode']}`; modules: {len(value['modules'])}; services: {len(rows)}; domains: {len(value['domains'])}.",
           f"Requested groups: {len(value['components'])}; image recipes: {sum(r['sourceBuild'] for r in rows)}; emitted build producers: {sum(r['emittedBuildProducer'] for r in rows)}.",'',
           'Lifecycle counts: '+', '.join(f'{k}: {v}' for k,v in value['lifecycleCounts'].items())+'.','',
           '## Selected services','',
           '| Service | Owning module | Actor/domain | Lifecycle | Source build | Named data volumes | Other mount sources |',
           '|---|---|---|---|---|---|---|']
    for row in rows:
        cells=[row['name'],row['module'] or 'unspecified',row['domain'] or row['placement'] or 'unspecified',
               row['lifecycle'],'yes' if row['sourceBuild'] else 'no',', '.join(row['namedDataVolumes']) or '—',
               str(len(row['otherMountSources']))]
        lines.append('| '+' | '.join(str(cell).replace('|','\\|').replace('\n',' ') for cell in cells)+' |')
    lines+=['','## Selected module revisions','','| Module | Commit | Dirty |','|---|---|---|']
    for row in sorted(value['modules'],key=lambda r:r['id']):
        lines.append(f"| {row['id']} | `{row['commit']}` | {row['dirty']} |")
    lines+=['','Per-application functional/shared-login, persistence, backup/restore and rollback proof remains separate.',
            'Other mount sources include generated configs, runtime sockets and absolute binds; they are not silently excluded from the recovery scope.','']
    return '\n'.join(lines)


def doctor():
    tools = {name: shutil.which(name) is not None for name in REQUIRED}
    available = {}
    for mount in ('/', '/mnt/stack'):
        try:
            info = os.statvfs(mount)
            available[mount] = info.f_bavail * info.f_frsize
        except OSError:
            available[mount] = None
    memory = None
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            memory = int(line.split()[1]) * 1024
    reserves = {'memory': memory is not None and memory >= 16 * 1024**3,
                'root': available['/'] is not None and available['/'] >= 50 * 1024**3,
                'stack': available['/mnt/stack'] is not None and available['/mnt/stack'] >= 100 * 1024**3}
    return {'schemaVersion': 1, 'scope': 'prerequisites only; not installation or application readiness',
            'tools': tools, 'availableBytes': available, 'availableMemoryBytes': memory,
            'reserves': reserves, 'ok': all(tools.values()) and all(reserves.values()),
            'containerRuntimeInvoked': False, 'mutationsPerformed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('plan'); p.add_argument('--bundle', required=True)
    formats=p.add_mutually_exclusive_group();formats.add_argument('--json', action='store_true');formats.add_argument('--markdown',action='store_true')
    p = commands.add_parser('doctor'); p.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        result = inventory(args.bundle) if args.command == 'plan' else doctor()
    except (OSError, ValueError, KeyError, TypeError):
        print('stackctl: inspection refused; verify bundle integrity and prerequisite access', file=sys.stderr)
        return 1
    print(markdown_inventory(result) if args.command=='plan' and args.markdown else json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.command == 'plan' or result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
