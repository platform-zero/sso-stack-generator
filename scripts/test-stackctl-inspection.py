#!/usr/bin/env python3
"""Source-only checks that metadata commands do not activate any runtime."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent / 'lib/stackctl-host.py'
SPEC = importlib.util.spec_from_file_location('stackctl_host', SOURCE)
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


class Inspection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'site').mkdir()
        self.save('site/manifest.json', {'schemaVersion': 2, 'site': 'test', 'components': ['core'],
                                       'secretStore': 'never-read-private-store'})
        self.save('stack.ir.json', {'services': {'caddy': {}}})
        self.save('source-provenance.json', {'manifestSha256': self.sha('site/manifest.json'),
                                           'generatorCommit': 'a' * 40, 'siteCommit': 'b' * 40,
                                           'generatorDirty': False, 'siteDirty': False})
        self.save('podman-domains.json', {'schemaVersion': 1, 'domains': [
            {'name': 'apps', 'user': 'webservices-apps', 'stateRoot': '/mnt/stack/test/state',
             'graphRoot': '/mnt/stack/test/graph', 'volumeRoot': '/mnt/stack/test/volumes'}]})
        self.save('bundle.json', {'schemaVersion': 1, 'backend': 'podman',
                                 'irSha256': self.sha('stack.ir.json'),
                                 'sourceProvenanceSha256': self.sha('source-provenance.json')})

    def save(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def sha(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def test_inventory_is_read_only_and_does_not_invoke_runtime(self):
        before = {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in self.root.rglob('*')}
        with patch('subprocess.run', side_effect=AssertionError('runtime must not run')):
            result = HOST.inventory(self.root)
        after = {str(p): (p.stat().st_mtime_ns, p.stat().st_size) for p in self.root.rglob('*')}
        self.assertEqual(before, after)
        self.assertEqual(result['services'], ['caddy'])
        self.assertFalse(result['mutationsPerformed'])
        self.assertFalse(result['privateInputsInspected'])

    def test_changed_ir_refused(self):
        self.save('stack.ir.json', {'services': {'foreign': {}}})
        with self.assertRaises(ValueError): HOST.inventory(self.root)

    def test_changed_manifest_refused(self):
        self.save('site/manifest.json', {'site': 'other'})
        with self.assertRaises(ValueError): HOST.inventory(self.root)

    def test_linked_input_directory_refused(self):
        (self.root / 'site').rename(self.root / 'real-site')
        (self.root / 'site').symlink_to(self.root / 'real-site', target_is_directory=True)
        with self.assertRaises(ValueError): HOST.inventory(self.root)

    def test_linked_input_file_refused(self):
        (self.root / 'stack.ir.json').rename(self.root / 'real-ir.json')
        (self.root / 'stack.ir.json').symlink_to(self.root / 'real-ir.json')
        with self.assertRaises(ValueError): HOST.inventory(self.root)

    def test_duplicate_domain_refused(self):
        data = json.loads((self.root / 'podman-domains.json').read_text())
        data['domains'] += data['domains']
        self.save('podman-domains.json', data)
        with self.assertRaises(ValueError): HOST.inventory(self.root)

    def test_venue_and_vm_are_reported_as_nonportable_not_authorized(self):
        data = json.loads((self.root / 'podman-domains.json').read_text())
        data['venue'] = {'unitPrefix': 'p0test-demo'}
        self.save('podman-domains.json', data)
        result = HOST.inventory(self.root)
        self.assertTrue(result['warnings'])
        self.assertIn('no activation authority', result['scope'])

    def test_doctor_does_not_invoke_runtime_or_require_secrets(self):
        with patch('subprocess.run', side_effect=AssertionError('runtime must not run')):
            result = HOST.doctor()
        self.assertFalse(result['containerRuntimeInvoked'])
        self.assertFalse(result['mutationsPerformed'])

    def test_cli_is_available_through_existing_stackctl(self):
        result = subprocess.run(['bash', str(SOURCE.parents[1] / 'stackctl.sh'),
                                 'plan', '--bundle', str(self.root), '--json'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['services'], ['caddy'])


if __name__ == '__main__': unittest.main()
