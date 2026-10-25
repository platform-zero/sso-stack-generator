import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from p0core.bundle import build
from p0core.lifecycle import Lifecycle, OperationError, Runner
from p0core.model import Catalog, ContractError
from test_core import module, service, IMAGE


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.active = {}
    def __call__(self, arguments, timeout=30, input_bytes=None):
        self.calls.append(arguments)
        if arguments[0].endswith('podman') and 'info' in arguments:
            return b'/mnt/stack/p0-v2/rootless/engine\n'
        if arguments[0].endswith('systemctl'):
            if 'show' in arguments:
                if '--property=MainPID,ControlGroup,Job' in arguments:
                    return b'MainPID=0\nControlGroup=\nJob=\n'
                name = next(value for value in arguments if value.endswith('.service'))
                active = self.active.get(name, False)
                return (f'LoadState=loaded\nActiveState={"active" if active else "inactive"}\n'
                        f'SubState={"running" if active else "dead"}\nResult=success\n').encode()
            if 'start' in arguments or 'stop' in arguments:
                self.active[arguments[-1]] = 'start' in arguments
        return b''


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.capacity = patch('p0core.lifecycle.verify_reserves')
        self.capacity.start()
        self.addCleanup(self.capacity.stop)

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

    def test_control_runner_uses_runtime_home_not_callers_private_cwd(self):
        with patch('p0core.lifecycle.subprocess.Popen', wraps=subprocess.Popen) as execute:
            Runner()(['/usr/bin/true'])
            self.assertEqual(execute.call_args.kwargs['cwd'], Path.home())
            self.assertEqual(execute.call_args.kwargs['env']['HOME'], str(Path.home()))
            self.assertNotIn('CONTAINERS_CONF', execute.call_args.kwargs['env'])

    def test_capacity_failure_prevents_engine_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            with patch('p0core.lifecycle.verify_reserves', side_effect=ContractError('reserve failure')):
                with self.assertRaises(ContractError):
                    runtime.install(bundle, identity, pull=True)
            self.assertEqual(runner.calls, [])
            self.assertEqual(list(runtime.quadlet.iterdir()), [])

    def test_unexpected_store_prevents_pull(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.run = lambda *_args, **_kwargs: b'/shared/default/store'
            with self.assertRaises(ContractError):
                runtime.install(bundle, identity, pull=True)
            self.assertEqual(list(runtime.quadlet.iterdir()), [])

    def test_secret_generation_no_value_in_result(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            captured = []
            def secret_runner(*args, **kwargs):
                if 'info' in args[0]:
                    return b'/mnt/stack/p0-v2/rootless/engine'
                captured.append((args, kwargs))
                return b''
            runtime.run = secret_runner
            output = runtime.generate_service_secret('database-password')
            self.assertEqual(output['created'], 'p0-database-password')
            self.assertNotIn(captured[0][1]['input_bytes'].decode(), str(output))

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

    def test_failed_unit_with_no_process_cgroup_or_job_is_stopped_not_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            state = {'LoadState': 'loaded', 'ActiveState': 'failed', 'SubState': 'failed', 'Result': 'exit-code'}
            self.assertTrue(runtime.stopped('app', state))
            with patch.object(runtime, 'observe', return_value=state):
                self.assertEqual(runtime._wait_unit('app', started=False, lifecycle='daemon'), state)
                with self.assertRaises(OperationError):
                    runtime._wait_unit('app', started=True, lifecycle='daemon')
            runtime.run = lambda *_args, **_kwargs: b'MainPID=1\nControlGroup=\nJob=\n'
            self.assertFalse(runtime.stopped('app', state))

    def test_stopped_resume_same_owned_release_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.install(bundle, identity)
            path = runtime.quadlet / 'p0-app.container'
            inode = path.stat().st_ino
            runtime.install(bundle, identity, resume_stopped=True)
            self.assertEqual(path.stat().st_ino, inode)
            runner.active['p0-app.service'] = True
            with self.assertRaises(ContractError):
                runtime.install(bundle, identity, resume_stopped=True)

    def test_stopped_resume_cannot_replace_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, runner, bundle, identity = self.prepare(root)
            runtime.install(bundle, identity)
            second = root / 'second'
            build(Catalog([module(service('app', command=['different']))]), ['app'], second)
            second_identity = hashlib.sha256((second / 'bundle.json').read_bytes()).hexdigest()
            with self.assertRaises(ContractError):
                runtime.install(second, second_identity, resume_stopped=True)

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

    def test_empty_engine_recovery_keeps_failed_attempt_and_needs_explicit_start(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.install(bundle, identity)
            with patch.object(runtime, '_wait_unit', side_effect=OperationError('failed')):
                with self.assertRaises(OperationError):
                    runtime.change('start', ['app'])
            runner.active['p0-app.service'] = False
            result = runtime.recover_empty_engine()
            self.assertTrue(result['requiresExplicitStart'])
            self.assertFalse(result['externalEffectsCertified'])
            from p0core.journal import Journal
            self.assertIn('indeterminate', [row['state'] for row in Journal.status(runtime.state / 'operations.sqlite3')['operations']])
            runtime.change('start', ['app'])

    def test_empty_engine_recovery_refuses_data_or_provisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory), [service('app', lifecycle='oneshot')])
            runtime.install(bundle, identity)
            with self.assertRaises(ContractError):
                runtime.recover_empty_engine()
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory))
            runtime.install(bundle, identity)
            def with_data(arguments, **kwargs):
                if arguments[:3] == ['/usr/bin/podman', 'volume', 'ls']:
                    return b'protected-volume'
                return runner(arguments, **kwargs)
            runtime.run = with_data
            with self.assertRaises(ContractError):
                runtime.recover_empty_engine()

    def test_resource_stop_requires_complete_explicit_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, identity = self.prepare(Path(directory), [service('db'), service('app', [('db', 'order')])])
            runtime.install(bundle, identity)
            with self.assertRaises(ContractError):
                runtime.change('stop', ['app'], resources=True)

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
