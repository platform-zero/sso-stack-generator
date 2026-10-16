#!/usr/bin/env python3
"""Synthetic frozen-output generation; never import images or start applications."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('site', 'modules-dir', 'baseline-bundle', 'work-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700)
    site_root = args.work_dir / 'site'
    site_root.mkdir()
    manifest = json.loads(args.site.read_text())
    for field in ('stackConfig', 'secretStore', 'imageIdentityPinsPath',
                  'buildBaseIdentityPinsPath', 'agentVmSpec'):
        if field not in manifest:
            continue
        relative = Path(manifest[field])
        assert not relative.is_absolute() and '..' not in relative.parts
        target = site_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.site.parent / relative, target)
    manifest['localBuildImagePinsPath'] = 'global.settings/local-build-image-ids.json'
    site = site_root / 'manifest.json'
    site.write_text(json.dumps(manifest))
    baseline = json.loads((args.baseline_bundle / 'stack.ir.json').read_text())
    assert not baseline.get('quadletBuildImagesFrozen'), 'test requires unfrozen source baseline'
    builds = {name: service for name, service in baseline['services'].items()
              if 'build' in service and (service.get('lifecycle') != 'on-demand' or service.get('quadletManaged') is True)}
    assert builds
    images = {name: 'sha256:' + hashlib.sha256(('synthetic-only-' + name).encode()).hexdigest()
              for name in builds}
    shared_pairs = (('android-test-runner-api34', 'android-test-runner-api36'),
                    ('workload-spawner-api', 'workload-spawner-router'))
    for first, second in shared_pairs:
        assert first in images and second in images
        images[first] = images[second]
    assert len(set(images.values())) == len(images) - len(shared_pairs)
    pins = {'schemaVersion': 1, 'images': images}
    pins_path = site_root / manifest['localBuildImagePinsPath']
    pins_path.parent.mkdir(parents=True, exist_ok=True)
    pins_path.write_text(json.dumps(pins))
    output = args.work_dir / 'bundle'
    generator = Path(__file__).resolve().parents[1] / 'generate.sh'
    command = [str(generator), '--site', str(site), '--modules-dir', str(args.modules_dir),
               '--backend', 'podman', '--output', str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    actual = json.loads((output / 'stack.ir.json').read_text())
    assert actual['quadletBuildImagesFrozen'] is True
    assert actual['modules'] == baseline['modules']
    assert set(actual['services']) == set(baseline['services'])
    tags = {'localhost/webservices/' + name + ':bundle': image for name, image in images.items()}
    frozen_consumers = 0
    for name, service in actual['services'].items():
        old = baseline['services'][name]
        expected = images.get(name) if 'build' in old else tags.get(old.get('image'))
        if expected is not None:
            assert service['image'] == service['frozenBuildImage'] == expected
            assert service['updatePolicy'] == 'pinned'
            assert service.get('build') == old.get('build'), 'recipe metadata disappeared'
            frozen_consumers += 1
        else:
            assert service == old, 'unrelated service changed: ' + name
    assert json.loads((output / 'site' / manifest['localBuildImagePinsPath']).read_text()) == pins
    unmanaged_builds = sum('build' in service and name not in builds
                           for name, service in baseline['services'].items())
    assert (output / 'runtime-model.yml').read_text().count('\n    build:') == unmanaged_builds
    recipes = list((output / 'quadlet').glob('*/*.build'))
    assert len(recipes) == len(builds)
    for recipe in recipes:
        assert recipe.read_text().splitlines().count('RefuseManualStart=yes') == 1
        container_text = recipe.with_suffix('.container').read_text().splitlines()
        assert container_text.count('Pull=never') == 1
        image_lines = [line for line in container_text
                       if line.startswith('Image=')]
        assert len(image_lines) == 1 and image_lines[0][6:] in images.values()
    for container in (output / 'quadlet').glob('*/*.container'):
        assert not any(line.startswith('Image=') and line.endswith('.build')
                       for line in container.read_text().splitlines())
    native = next((p for p in (Path('/usr/libexec/podman/quadlet'), Path('/usr/lib/podman/quadlet'))
                   if p.is_file()), None)
    if native:
        for directory in sorted({recipe.parent for recipe in recipes}):
            env = dict(os.environ, QUADLET_UNIT_DIRS=str(directory))
            flags = [] if directory.name == 'rootful' else ['-user']
            result = subprocess.run([str(native), '-dryrun', '-no-kmsg-log', *flags], env=env,
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr[-2000:]
            assert result.stdout.splitlines().count('RefuseManualStart=yes') == len(list(directory.glob('*.build')))
            for recipe in directory.glob('*.build'):
                forbidden = recipe.stem + '-build.service'
                assert not any(forbidden in line.split('=', 1)[1].split()
                               for line in result.stdout.splitlines() if line.startswith(('Requires=', 'Wants=')))
    else:
        print('[frozen-build-test] native Quadlet unavailable: dry-run SKIPPED')
    before = snapshot(output)
    first = next(iter(images))
    invalid = [
        {'schemaVersion': True, 'images': images},
        {'schemaVersion': 1, 'images': {k: v for k, v in images.items() if k != first}},
        {'schemaVersion': 1, 'images': {**images, 'foreign-service': images[first]}},
        {'schemaVersion': 1, 'images': {**images, first: 'docker.io/example/image:mutable'}},
    ]
    for bad in invalid:
        pins_path.write_text(json.dumps(bad))
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        assert result.returncode != 0, 'invalid frozen identities accepted'
        assert snapshot(output) == before, 'invalid pins replaced previous complete bundle'
    pins_path.write_text('{"schemaVersion":1,"schemaVersion":1,"images":' + json.dumps(images) + '}')
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and snapshot(output) == before
    pins_path.write_text(json.dumps(pins))
    manifest['localBuildImagePinsPath'] = './global.settings/local-build-image-ids.json'
    site.write_text(json.dumps(manifest))
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0 and snapshot(output) == before
    print('[frozen-build-test] synthetic immutable IDs cover', len(builds), 'recipes and',
          frozen_consumers, 'consumers (shared SDK/spawner IDs); no startup builds; six hostile cases preserve complete bundle')


if __name__ == '__main__':
    main()
