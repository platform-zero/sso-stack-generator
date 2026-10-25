import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from p0core.bundle import build, verify
from p0core.cli import main
from p0core.journal import Journal, operation_lock
from p0core.model import Catalog, ContractError, load_json
from p0core.render import render

IMAGE = 'docker.io/library/alpine@sha256:' + 'a' * 64


def module(*services, name='identity'):
    return {'schemaVersion': 1, 'id': name, 'services': list(services)}


def service(name, dependencies=(), **kwargs):
    return {'id': name, 'runtime': 'rootless', 'image': IMAGE,
            'requires': [{'service': target, 'kind': kind} for target, kind in dependencies], **kwargs}


class GraphTests(unittest.TestCase):
    def test_target_closure_is_ordered_without_unrelated_services(self):
        catalog = Catalog([module(service('postgres'), service('keycloak', [('postgres', 'ready')]),
                                  service('bookstack'))])
        self.assertEqual(catalog.plan(['keycloak'])['services'], ['postgres', 'keycloak'])
        self.assertEqual(catalog.plan(['keycloak'])['readinessEdges'],
                         [{'service': 'keycloak', 'requires': 'postgres'}])

    def test_unrelated_edits_do_not_invalidate_target(self):
        first = module(service('keycloak'), service('bookstack'))
        second = copy.deepcopy(first)
        second['services'][1]['image'] = IMAGE.replace('a' * 64, 'b' * 64)
        self.assertEqual(Catalog([first]).plan(['keycloak']), Catalog([second]).plan(['keycloak']))
        second['services'][0]['image'] = IMAGE.replace('a' * 64, 'c' * 64)
        self.assertNotEqual(Catalog([first]).plan(['keycloak']), Catalog([second]).plan(['keycloak']))

    def test_no_duplicate_service_owners(self):
        with self.assertRaises(ContractError):
            Catalog([module(service('keycloak')), module(service('keycloak'), name='other')])

    def test_missing_provider_refused(self):
        with self.assertRaises(ContractError):
            Catalog([module(service('keycloak', [('missing', 'ready')]))])

    def test_startup_cycle_refused_even_if_not_selected(self):
        with self.assertRaises(ContractError):
            Catalog([module(service('one', [('two', 'order')]),
                            service('two', [('one', 'ready')]), service('independent'))])

    def test_integration_is_not_startup_cycle_or_required_closure(self):
        catalog = Catalog([module(service('one', [('two', 'integration')]),
                                  service('two', [('one', 'integration')]))])
        self.assertEqual(catalog.plan(['one'])['services'], ['one'])
        self.assertEqual(len(catalog.plan(['one', 'two'])['integrations']), 2)

    def test_mutable_images_and_injection_ids_refused(self):
        for changes in ({'image': 'alpine:latest'}, {'id': 'bad\n[Service]'}, {'id': '../escape'},
                        {'runtime': 'host'}, {'extra': True}):
            item = service('one') | changes
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                Catalog([module(item)])

    def test_schema_bool_not_version(self):
        with self.assertRaises(ContractError):
            Catalog([module(service('one')) | {'schemaVersion': True}])

    def test_duplicate_json_keys_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'module.json'
            path.write_text('{"id":"one","id":"two"}')
            with self.assertRaises(ContractError):
                load_json(path)

    def test_manifest_symlink_escape_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / 'external.json'
            external.write_text(json.dumps(module(service('one'))))
            catalog = root / 'catalog'
            path = catalog / 'modules' / 'one'
            path.mkdir(parents=True)
            (path / 'module.json').symlink_to(external)
            with self.assertRaises(ContractError):
                Catalog.read(catalog)


class RenderTests(unittest.TestCase):
    def test_ready_not_faked_by_ordering(self):
        catalog = Catalog([module(service('db', probes=[{'kind': 'tcp', 'host': '127.0.0.1', 'port': 15432}]),
                                  service('app', [('db', 'ready')]))])
        plan, files = render(catalog, ['app'])
        self.assertIn('After=p0-db.service', files['quadlet/rootless/p0-app.container'])
        self.assertIn('readiness/db.json', files)
        self.assertEqual(len(plan['readinessEdges']), 1)
        self.assertNotIn('[Install]', files['quadlet/rootless/p0-app.container'])

    def test_ready_requires_actual_probe(self):
        with self.assertRaises(ContractError):
            render(Catalog([module(service('db'), service('app', [('db', 'ready')]))]), ['app'])

    def test_no_cross_user_systemd_ordering(self):
        db = service('db', runtime='rootful')
        _, files = render(Catalog([module(db, service('app', [('db', 'order')]))]), ['app'])
        self.assertNotIn('After=p0-db', files['quadlet/rootless/p0-app.container'])

    def test_dangerous_mounts_refused(self):
        for mount in ({'kind': 'bind', 'source': 'socket', 'target': '/run/podman'},
                      {'kind': 'config', 'source': '../escape', 'target': '/config'},
                      {'kind': 'config', 'source': 'settings', 'target': '/config', 'readOnly': False},
                      {'kind': 'volume', 'source': 'data', 'target': '/x/../run'}):
            with self.subTest(mount=mount), self.assertRaises(ContractError):
                render(Catalog([module(service('app', mounts=[mount]))]), ['app'])

    def test_public_upstream_refused(self):
        for endpoint in ({'port': 80, 'hostPort': 8000, 'bind': '0.0.0.0'},
                         {'port': 80, 'hostPort': 8000, 'bind': '0.0.0.0', 'public': True}):
            with self.assertRaises(ContractError):
                render(Catalog([module(service('app', endpoints=[endpoint]))]), ['app'])

    def test_unit_injection_refused_and_specifier_escaped(self):
        for argument in ('value\n[Service]', '$CREDENTIAL'):
            with self.assertRaises(ContractError):
                render(Catalog([module(service('app', command=[argument]))]), ['app'])
        _, files = render(Catalog([module(service('app', command=['echo', '%h']))]), ['app'])
        self.assertIn('"%%h"', files['quadlet/rootless/p0-app.container'])


class BundleTests(unittest.TestCase):
    def test_bundle_roundtrip_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'bundle'
            lock = build(Catalog([module(service('app'))]), ['app'], target)
            self.assertEqual(verify(target), lock)
            self.assertFalse(lock['installationCertified'])
            unit = target / 'quadlet/rootless/p0-app.container'
            unit.chmod(0o600)
            unit.write_text('tampered')
            with self.assertRaises(ContractError):
                verify(target)

    def test_extra_member_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'bundle'
            build(Catalog([module(service('app'))]), ['app'], target)
            extra = target / 'extra'
            extra.write_text('extra')
            with self.assertRaises(ContractError):
                verify(target)
            extra.unlink()
            extra.symlink_to('/etc/passwd')
            with self.assertRaises(ContractError):
                verify(target)

    def test_existing_destination_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'existing'
            destination.mkdir()
            with self.assertRaises(ContractError):
                build(Catalog([module(service('app'))]), ['app'], destination)
            self.assertEqual(list(destination.iterdir()), [])


class JournalTests(unittest.TestCase):
    def test_status_does_not_create_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            absent = Path(directory) / 'not-created'
            output = Journal.status(absent / 'operations.sqlite3')
            self.assertEqual(output['observed'], 'absent')
            self.assertFalse(absent.exists())

    def test_revision_terminal_and_indeterminate_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'operations.sqlite3'
            journal = Journal(path)
            identity = journal.create('install', 'a' * 64)
            journal.transition(identity, 0, 'running')
            with self.assertRaises(ContractError):
                journal.transition(identity, 0, 'succeeded')
            journal.transition(identity, 1, 'indeterminate')
            with self.assertRaises(ContractError):
                journal.transition(identity, 2, 'running')
            self.assertEqual(Journal.status(path)['observed'], 'live-journal')
            journal.close()
            output = Journal.status(path)
            self.assertEqual(output['operations'][0]['state'], 'indeterminate')
            self.assertFalse(output['installationCertified'])

    def test_operation_lock_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            with operation_lock(Path(directory)):
                with self.assertRaises(ContractError):
                    with operation_lock(Path(directory)):
                        pass

    def test_lock_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'operation.lock').symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                with operation_lock(Path(directory)):
                    pass

    def test_cli_failure_is_secret_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'DO-NOT-PRINT-THIS-SECRET'
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(['plan', '--catalog', str(secret), '--target', 'app']), 2)
            self.assertNotIn('DO-NOT-PRINT', output.getvalue())


if __name__ == '__main__':
    unittest.main()
