import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p0core.model import Catalog, ContractError, canonical
from p0core.inputs import resolve, pack_configurations, verify_installed
from p0core.render import render
from p0core.bundle import build
from test_core import module, service


class InputTests(unittest.TestCase):
    def fixture(self, directory):
        path = Path(directory) / 'settings.json'
        path.write_bytes(b'{"publicSetting":"synthetic-private-input-canary"}')
        config = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        catalog = Catalog([module(service('app', mounts=[{'kind': 'config', 'source': 'settings', 'target': '/app/settings.json'}]),
                                  service('other', mounts=[{'kind': 'config', 'source': 'unrelated', 'target': '/other.json'}]))])
        return catalog, {'schemaVersion': 1, 'configs': {'settings': config}}

    def test_selected_bytes_are_in_graph_identity_not_release_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog, inputs = self.fixture(directory)
            selected = resolve(catalog, ['app'], inputs)
            plan, files = render(selected, ['app'])
            checksum = inputs['configs']['settings']['sha256']
            self.assertIn('Secret=p0-config-' + checksum, files['quadlet/rootless/p0-app.container'])
            self.assertIn('uid=0,gid=0,mode=0444', files['quadlet/rootless/p0-app.container'])
            lock = build(selected, ['app'], Path(directory) / 'release')
            self.assertNotIn(b'synthetic-private-input-canary', canonical(lock))
            self.assertNotIn(b'synthetic-private-input-canary', b''.join(path.read_bytes() for path in (Path(directory) / 'release').rglob('*') if path.is_file()))
            prior = plan['inputSha256']
            Path(inputs['configs']['settings']['path']).write_bytes(b'changed public setting')
            inputs['configs']['settings']['sha256'] = hashlib.sha256(b'changed public setting').hexdigest()
            self.assertNotEqual(resolve(catalog, ['app'], inputs).plan(['app'])['inputSha256'], prior)

    def test_unrelated_configuration_is_not_read_or_hashed_for_target(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog, inputs = self.fixture(directory)
            first = resolve(catalog, ['app'], inputs).plan(['app'])
            inputs['configs']['unrelated'] = {'path': '/not-readable-or-present', 'sha256': 'b' * 64}
            self.assertEqual(resolve(catalog, ['app'], inputs).plan(['app']), first)

    def test_private_configuration_supply_separate_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog, inputs = self.fixture(directory)
            output = Path(directory) / 'private-inputs'
            result = pack_configurations(catalog, ['app'], inputs, output)
            self.assertTrue(result['privateInput'])
            checksum = inputs['configs']['settings']['sha256']
            self.assertEqual((output / checksum).read_bytes(), Path(inputs['configs']['settings']['path']).read_bytes())
            self.assertEqual((output / checksum).stat().st_mode & 0o777, 0o600)
            self.assertEqual((output / 'context.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(result['sha256'], hashlib.sha256((output / 'context.json').read_bytes()).hexdigest())

    def test_missing_changed_or_nonroot_custody_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog, inputs = self.fixture(directory)
            with self.assertRaises(ContractError):
                render(catalog, ['app'])
            Path(inputs['configs']['settings']['path']).write_bytes(b'changed')
            with self.assertRaises(ContractError):
                resolve(catalog, ['app'], inputs)
            spec = service('app', mounts=[{'kind': 'config', 'source': 'settings', 'target': '/settings', 'sha256': 'a' * 64}])
            with patch('p0core.inputs.CONFIG_ROOT', Path(directory)):
                with self.assertRaises(ContractError):
                    verify_installed([spec])

    def test_native_config_supply_never_reads_credential_values(self):
        from p0core.inputs import ensure_materialized
        from types import SimpleNamespace
        checksum = 'a' * 64
        spec = service('app', mounts=[{'kind': 'config', 'source': 'settings', 'target': '/settings', 'sha256': checksum}])
        calls = []
        def missing(arguments):
            calls.append(arguments)
            return b''
        ensure_materialized(SimpleNamespace(run=missing), [spec])
        self.assertEqual(calls[-1][-1], '/etc/p0-v2/config/' + checksum)
        self.assertIn('create', calls[-1])
        def foreign(arguments):
            calls.append(arguments)
            return ('p0-config-' + checksum).encode() if 'ls' in arguments else b'foreign|owner'
        with self.assertRaises(ContractError):
            ensure_materialized(SimpleNamespace(run=foreign), [spec])
        self.assertFalse(any('--showsecret' in arguments for arguments in calls))

    def test_exact_service_secret_uid_is_namespace_custody_not_new_host_account(self):
        mount = {'kind': 'secret', 'source': 'password', 'target': '/run/secrets/password', 'uid': 1000, 'gid': 0}
        _, files = render(Catalog([module(service('app', mounts=[mount]))]), ['app'])
        self.assertIn('uid=1000,gid=0,mode=0400', files['quadlet/rootless/p0-app.container'])
        for invalid in (True, -1, 65536, '1000'):
            mount['uid'] = invalid
            with self.assertRaises(ContractError):
                render(Catalog([module(service('app', mounts=[mount]))]), ['app'])

    def test_image_binding_changes_same_graph_without_mutating_source(self):
        catalog = Catalog([module(service('app'))])
        inputs = {'schemaVersion': 1, 'images': {'app': 'localhost/custom@sha256:' + 'b' * 64}}
        resolved = resolve(catalog, ['app'], inputs)
        self.assertNotEqual(catalog.plan(['app']), resolved.plan(['app']))
        self.assertNotEqual(catalog.services['app'].image, resolved.services['app'].image)
