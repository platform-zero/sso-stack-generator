import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from p0core.bundle import build
from p0core.lifecycle import Lifecycle, OperationError
from p0core.model import Catalog, ContractError
from test_core import module, service, IMAGE


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.active = {}
    def __call__(self, arguments, timeout=30, input_bytes=None):
        self.calls.append(arguments)
        if arguments[0].endswith('systemctl'):
            if 'show' in arguments:
                name = next(value for value in arguments if value.endswith('.service'))
                active = self.active.get(name, False)
                return (f'LoadState=loaded\nActiveState={"active" if active else "inactive"}\n'
                        f'SubState={"running" if active else "dead"}\nResult=success\n').encode()
            if 'start' in arguments or 'stop' in arguments:
                self.active[arguments[-1]] = 'start' in arguments
        return b''


class LifecycleTests(unittest.TestCase):
    def prepare(self, root, declarations=None):
        catalog = Catalog([module(*(declarations or [service('app')]))])
        bundle = root / 'bundle'
        targets = [value['id'] for value in (declarations or [service('app')])]
        build(catalog, targets, bundle)
        identity = hashlib.sha256((bundle / 'bundle.json').read_bytes()).hexdigest()
        runner = FakeRunner()
        runtime = Lifecycle(root / 'state', root / 'quadlet', runner=runner, enforce_identity=False)
        return runtime, runner, bundle, identity

    def test_install_publishes_but_does_not_start(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            output = runtime.install(bundle, identity)
            self.assertEqual(output['state'], 'published-not-started')
            self.assertFalse(any('start' in arguments for arguments in runner.calls))
            self.assertFalse(output['installationCertified'])
            self.assertTrue((runtime.quadlet / 'p0-app.container').exists())

    def test_wrong_release_identity_no_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            with self.assertRaises(ContractError):
                runtime.install(bundle, '0' * 64)
            self.assertFalse(runtime.state.exists())
            self.assertEqual(runner.calls, [])

    def test_existing_unowned_unit_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.quadlet.mkdir(mode=0o700)
            path = runtime.quadlet / 'p0-app.container'
            path.write_text('protected')
            with self.assertRaises(ContractError):
                runtime.install(bundle, identity)
            self.assertEqual(path.read_text(), 'protected')
            self.assertEqual(runner.calls, [])

    def test_rootful_install_is_not_rootless_permission(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory), [service('edge', runtime='rootful')])
            with self.assertRaises(ContractError):
                runtime.install(bundle, identity)
            self.assertFalse(runtime.state.exists())

    def test_start_order_stop_exact_target_and_status_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory), [service('db'), service('app', [('db', 'order')])])
            runtime.install(bundle, identity)
            result = runtime.change('start', ['app'])
            self.assertEqual(result['services'], ['db', 'app'])
            result = runtime.change('stop', ['app'])
            self.assertEqual(result['services'], ['app'])
            self.assertTrue(runner.active['p0-db.service'])
            before = {path: path.stat().st_mtime_ns for path in runtime.state.rglob('*') if path.is_file()}
            calls = len(runner.calls)
            runtime.status()
            self.assertTrue(all('show' in value for value in runner.calls[calls:]))
            self.assertEqual(before, {path: path.stat().st_mtime_ns for path in runtime.state.rglob('*') if path.is_file()})

    def test_stop_dependency_with_retained_consumer_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory), [service('db'), service('app', [('db', 'order')])])
            runtime.install(bundle, identity)
            with self.assertRaises(ContractError):
                runtime.change('stop', ['db'])

    def test_changed_unit_refuses_control(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.install(bundle, identity)
            (runtime.quadlet / 'p0-app.container').write_text('changed')
            runner.calls.clear()
            with self.assertRaises(ContractError):
                runtime.change('start', ['app'])
            self.assertEqual(runner.calls, [])

    def test_partial_start_is_indeterminate_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.install(bundle, identity)
            with patch.object(runtime, '_wait_unit', side_effect=OperationError('test uncertain start')):
                with self.assertRaises(OperationError):
                    runtime.change('start', ['app'])
            from p0core.journal import Journal
            status = Journal.status(runtime.state / 'operations.sqlite3')
            self.assertEqual(status['operations'][-1]['state'], 'indeterminate')
            with self.assertRaises(ContractError):
                runtime.change('start', ['app'])

    def test_actual_quadlet_generator_accepts_resources_and_oneshot(self):
        generator = Path('/usr/lib/systemd/system-generators/podman-system-generator')
        if not generator.exists():
            self.skipTest('installed Quadlet generator unavailable')
        from p0core.render import render
        declaration = service('bootstrap', lifecycle='oneshot', networks=['identity'],
                              mounts=[{'kind': 'volume', 'source': 'db-data', 'target': '/data'}],
                              environment={'POSTGRES_PASSWORD_FILE': '/run/secrets/password'})
        _, files = render(Catalog([module(declaration)]), ['bootstrap'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                (root / Path(name).name).write_text(content)
            import os
            result = subprocess.run([str(generator), '--user', '--dryrun'], capture_output=True,
                                    env=dict(os.environ, QUADLET_UNIT_DIRS=str(root)), timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'p0-bootstrap.service', result.stdout)
            self.assertIn(b'Type=oneshot', result.stdout)
            self.assertNotIn(b'unsupported key', result.stderr)
            self.assertIn(IMAGE.encode(), result.stdout)
            self.assertNotIn(b'\\"docker.io/library/alpine', result.stdout)


if __name__ == '__main__':
    unittest.main()
