#!/usr/bin/env python3
"""Read-only cumulative module planning; never installation/activation authority."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ID = re.compile(r'[a-z0-9][a-z0-9-]*\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')


def require(condition):
    if not condition:
        raise ValueError('Module ring planning refused')


def identifiers(value, nonempty=False):
    require(isinstance(value, list) and (bool(value) or not nonempty))
    require(all(isinstance(x, str) and ID.fullmatch(x) for x in value))
    require(len(set(value)) == len(value))
    return set(value)


def plan(manifest, lock, ir, policy):
    """Both module metadata and actual service dependencies close every ring."""
    require(all(isinstance(value, dict) for value in (manifest, lock, ir, policy)))
    require(manifest.get('schemaVersion') == 2 and lock.get('schemaVersion') == 2)
    require(policy.get('schemaVersion') == 1)
    selected = identifiers(manifest.get('modules'), True)
    require(not selected.intersection(identifiers(manifest.get('excludedModules', []))))
    require(not selected.intersection(identifiers(manifest.get('excludedComponents', []))))
    pins = {}; deps = {}
    require(isinstance(lock.get('modules'), list))
    for row in lock['modules']:
        require(isinstance(row, dict))
        name = row.get('id'); require(isinstance(name, str) and ID.fullmatch(name) and name not in pins)
        require(isinstance(row.get('commit'), str) and COMMIT.fullmatch(row['commit']))
        pins[name] = row['commit']; deps[name] = identifiers(row.get('dependencies', []))
    require(set(pins) == selected and all(d <= selected for d in deps.values()))
    actual = {}
    require(isinstance(ir.get('modules'), list))
    for row in ir['modules']:
        require(isinstance(row, dict))
        require(isinstance(row.get('id'), str) and row.get('id') not in actual)
        actual[row.get('id')] = row.get('commit')
    require(actual == pins)
    services = ir.get('services'); require(isinstance(services, dict) and bool(services))
    edges = []
    for name, service in services.items():
        require(isinstance(name, str) and ID.fullmatch(name) and isinstance(service, dict))
        owner = service.get('module'); require(owner in selected)
        dependencies = service.get('dependencies') or {}
        require(isinstance(dependencies, dict))
        for dependency, condition in dependencies.items():
            require(dependency in services and condition in ('started', 'healthy', 'completed'))
            provider = services[dependency].get('module'); require(provider in selected)
            if provider != owner:
                deps[owner].add(provider)
                edges.append({'consumer': name, 'provider': dependency, 'condition': condition})
    rings = policy.get('rings'); require(isinstance(rings, list) and bool(rings))
    assigned = set(); names = set()
    for ring in rings:
        require(isinstance(ring, dict))
        name = ring.get('name'); require(isinstance(name, str) and ID.fullmatch(name) and name not in names)
        names.add(name); roots = identifiers(ring.get('modules'), True)
        require(roots <= selected and not assigned.intersection(roots)); assigned |= roots
    require(assigned == selected)  # No implicit "everything else" or scope loss.
    cumulative = set(); result = []
    for ring in rings:
        before = set(cumulative); roots = set(ring['modules']); cumulative |= roots
        while True:
            expanded = cumulative.union(*(deps[name] for name in cumulative))
            if expanded == cumulative:
                break
            cumulative = expanded
        require(not cumulative.intersection(identifiers(ring.get('mustExclude', []))))
        active = sorted(name for name, service in services.items() if service['module'] in cumulative)
        require(all(set(services[name].get('dependencies') or {}) <= set(active) for name in active))
        derived = dict(manifest)
        derived['modules'] = sorted(cumulative)
        # Module selection is authoritative. Do not retain unrelated app component
        # names or silently add the broad legacy "core" service group.
        derived.pop('components', None)
        # This optional tool's source contract explicitly belongs to test-runners;
        # a foundation without that module must not reference its build artifact.
        if 'test-runners' not in cumulative:
            derived.pop('nativeAcceptanceImagePinsPath', None)
        result.append({'name': ring['name'], 'declaredModules': sorted(roots),
                       'addedModules': sorted(cumulative - before),
                       'dependencyPromotions': sorted(cumulative - before - roots),
                       'modules': sorted(cumulative), 'services': active, 'manifest': derived})
    require(cumulative == selected and set(result[-1]['services']) == set(services))
    return {'schemaVersion': 1, 'scope': 'CUMULATIVE ENGINEERING PLAN ONLY; not admission or counted acceptance',
            'activationAuthority': False, 'fullModulePins': dict(sorted(pins.items())),
            'fullServiceCount': len(services), 'serviceDependencyEdges': sorted(edges, key=lambda e: (e['consumer'], e['provider'])),
            'rings': result}


def read_json(path):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out); out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'module-lock', 'ir', 'policy', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    inputs = {'manifest': args.manifest, 'moduleLock': args.module_lock, 'ir': args.ir, 'policy': args.policy}
    before = {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in inputs.items()}
    value = plan(*(read_json(inputs[key]) for key in ('manifest', 'moduleLock', 'ir', 'policy')))
    require(before == {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in inputs.items()})
    value['inputSha256'] = before
    # Never overwrite source, a prior plan or a sealed output; no credentials read.
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
    print('Module ring plan created; no runtime or activation authority')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        frames = []; trace = error.__traceback__
        while trace:
            code = trace.tb_frame.f_code
            if Path(code.co_filename) == Path(__file__):
                frames.append(Path(__file__).name + ':' + str(trace.tb_lineno) + ':' + code.co_name)
            trace = trace.tb_next
        if frames:
            print('guard: ' + ' > '.join(frames[-12:]), file=sys.stderr)
        raise SystemExit('Module ring planning refused') from None
