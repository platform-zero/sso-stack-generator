import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p0core.bundle import build
from p0core.journal import Journal
from p0core.lifecycle import Lifecycle, OperationError
from p0core.model import Catalog, ContractError
from p0core.upgrade import upgrade
from test_core import module, service, IMAGE
from test_lifecycle import FakeRunner


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        for target in ('p0core.lifecycle.verify_reserves', 'p0core.upgrade.verify_reserves'):
            mocked = patch(target)
            mocked.start()
            self.addCleanup(mocked.stop)

    def bundle(self, root, name, declarations):
        destination = root / name
        build(Catalog([module(*declarations)]), [item['id'] for item in declarations], destination)
        return destination, hashlib.sha256((destination / 'bundle.json').read_bytes()).hexdigest()

    def prepare(self, root, old=None, new=None):
        old = old or [service('app')]
        new = new or old + [service('peer')]
        first, before = self.bundle(root, 'first', old)
        second, after = self.bundle(root, 'second', new)
        runner = FakeRunner()
        runtime = Lifecycle(root / 'state', root / 'quadlet', runner=runner, enforce_identity=False)
        runtime.install(first, before)
        runner.calls.clear()
        return runtime, runner, second, before, after

    def test_stopped_extension_keeps_existing_inode_and_never_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, before, after = self.prepare(Path(directory))
            inode = (runtime.quadlet / 'p0-app.container').stat().st_ino
            result = upgrade(runtime, bundle, after, before)
            self.assertEqual(result['state'], 'upgraded-not-started')
            self.assertFalse(result['dataDeleted'])
            self.assertFalse(result['installationCertified'])
            self.assertEqual((runtime.quadlet / 'p0-app.container').stat().st_ino, inode)
            self.assertEqual((runtime.quadlet / 'p0-peer.container').stat().st_nlink, 1)
            self.assertFalse(any('start' in call for call in runner.calls))
            self.assertEqual(runtime._registry()['releaseSha256'], after)
            runtime.verify_owned(runtime._registry())

    def test_active_service_prevents_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, before, after = self.prepare(Path(directory))
            runner.active['p0-app.service'] = True
            with self.assertRaisesRegex(ContractError, 'every owned'):
                upgrade(runtime, bundle, after, before)
            self.assertFalse((runtime.quadlet / 'p0-peer.container').exists())
            self.assertEqual(runtime._registry()['releaseSha256'], before)

    def test_active_resource_prevents_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            old = [service('app', networks=['identity'])]
            runtime, runner, bundle, before, after = self.prepare(Path(directory), old)
            runner.active['p0-network-identity-network.service'] = True
            with self.assertRaisesRegex(ContractError, 'every owned'):
                upgrade(runtime, bundle, after, before)

    def test_stale_predecessor_and_unowned_matching_bytes_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, before, after = self.prepare(Path(directory))
            with self.assertRaisesRegex(ContractError, 'stale predecessor'):
                upgrade(runtime, bundle, after, '0' * 64)
            target = runtime.quadlet / 'p0-peer.container'
            target.write_bytes((bundle / 'quadlet/rootless/p0-peer.container').read_bytes())
            target.chmod(0o600)
            with self.assertRaisesRegex(ContractError, 'unowned Quadlet'):
                upgrade(runtime, bundle, after, before)
            self.assertTrue(target.exists())

    def test_existing_image_and_data_migration_refused(self):
        for changed in (dict(image='registry.invalid/other@sha256:' + 'f' * 64),
                        dict(mounts=[{'kind': 'volume', 'source': 'other', 'target': '/data'}])):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                old = [service('app')]
                new = [service('app', **changed), service('peer')]
                runtime, runner, bundle, before, after = self.prepare(root, old, new)
                with self.assertRaises(ContractError):
                    upgrade(runtime, bundle, after, before)
                self.assertEqual(runtime._registry()['releaseSha256'], before)

    def test_secret_default_uid_custody_tightening_can_replace_stopped_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            mount = {'kind': 'secret', 'source': 'ordinary-key', 'target': '/run/secrets/ordinary'}
            old = [service('app', mounts=[mount])]
            new = [service('app', mounts=[dict(mount, uid=0, gid=0)]), service('peer')]
            runtime, runner, bundle, before, after = self.prepare(Path(directory), old, new)
            old_inode = (runtime.quadlet / 'p0-app.container').stat().st_ino
            upgrade(runtime, bundle, after, before)
            self.assertNotEqual((runtime.quadlet / 'p0-app.container').stat().st_ino, old_inode)
            self.assertIn('mode=0400', (runtime.quadlet / 'p0-app.container').read_text())

    def test_reload_failure_kept_indeterminate_then_explicit_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, before, after = self.prepare(Path(directory))
            def fail(arguments, **kwargs):
                if 'daemon-reload' in arguments:
                    raise OperationError('synthetic reload refusal')
                return runner(arguments, **kwargs)
            runtime.run = fail
            with self.assertRaises(OperationError):
                upgrade(runtime, bundle, after, before)
            states = Journal.status(runtime.state / 'operations.sqlite3')['operations']
            self.assertIn('indeterminate', [item['state'] for item in states])
            runtime.run = runner
            with self.assertRaisesRegex(ContractError, 'unfinished upgrade'):
                upgrade(runtime, bundle, after, before)
            upgrade(runtime, bundle, after, before, resume=True)
            states = Journal.status(runtime.state / 'operations.sqlite3')['operations']
            self.assertIn('indeterminate', [item['state'] for item in states])
            runtime.change('start', ['peer'])

    def test_interrupted_link_publication_resumes_only_exact_owned_inodes(self):
        import os
        for foreign in (False, True):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as directory:
                runtime, runner, bundle, before, after = self.prepare(Path(directory))
                original = os.link
                def fail_after_link(*args, **kwargs):
                    original(*args, **kwargs)
                    raise OSError('synthetic interruption after link')
                with patch('p0core.upgrade.os.link', side_effect=fail_after_link):
                    with self.assertRaises(OSError):
                        upgrade(runtime, bundle, after, before)
                if foreign:
                    target = runtime.quadlet / 'p0-peer.container'
                    content = target.read_bytes()
                    target.unlink()
                    target.write_bytes(content)
                    target.chmod(0o600)
                    with self.assertRaises(ContractError):
                        upgrade(runtime, bundle, after, before, resume=True)
                    self.assertEqual(target.read_bytes(), content)
                else:
                    upgrade(runtime, bundle, after, before, resume=True)
                    runtime.verify_owned(runtime._registry())

    def test_resume_cannot_change_candidate_or_adopt_symlink_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, runner, bundle, before, after = self.prepare(Path(directory))
            with self.assertRaisesRegex(ContractError, 'recorded upgrade'):
                upgrade(runtime, bundle, after, before, resume=True)
            pointer = runtime.state / 'upgrade-current.json'
            pointer.symlink_to(runtime.state / 'selection.json')
            with self.assertRaises(OSError):
                upgrade(runtime, bundle, after, before, resume=True)

    def test_completed_intent_retained_when_next_extension_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, runner, bundle, before, after = self.prepare(root)
            upgrade(runtime, bundle, after, before)
            third, final = self.bundle(root, 'third', [service('app'), service('peer'), service('third')])
            upgrade(runtime, third, final, after)
            intents = list(runtime.state.glob('upgrade-*/intent.json'))
            self.assertEqual(len(intents), 2)
            self.assertTrue(all(json.loads(path.read_text())['state'] == 'complete' for path in intents))
