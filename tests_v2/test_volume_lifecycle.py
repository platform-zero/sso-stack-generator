"""Rootless orchestration with fake mapped stat/native adapter; no native stores."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from p0core.bundle import build
from p0core.journal import Journal
from p0core.lifecycle import Lifecycle
from p0core.model import Catalog, ContractError
from tests_v2.test_volumes import FakeAdapter, Crash


class VolumeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.p0-volume-life-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = {'id': 'app', 'runtime': 'rootless', 'requires': [],
                     'image': 'docker.io/library/alpine@sha256:' + 'a' * 64,
                     'mounts': [{'kind': 'volume', 'source': 'app-data', 'target': '/data',
                                 'custody': {'uid': 1000, 'gid': 1000, 'mode': '0700'}}]}
        graph = Catalog([{'schemaVersion': 1, 'id': 'apps', 'services': [self.spec]}])
        self.bundle = self.root / 'bundle'
        build(graph, ['app'], self.bundle)
        self.sha = hashlib.sha256((self.bundle / 'bundle.json').read_bytes()).hexdigest()
        self.runtime = Lifecycle(self.root / 'state', self.root / 'units', enforce_identity=False)
        self.runtime.state.mkdir(mode=0o700)
        self.adapter = FakeAdapter(self.root / 'engine', self.runtime.state / 'volume-custody')
        self.addCleanup(patch.stopall)
        patch('p0core.volumes.NativeAdapter', return_value=self.adapter).start()
        patch('p0core.volumes.host_stat', side_effect=self.adapter.host).start()
        patch('p0core.lifecycle.verify_reserves').start()

    def prepare(self, **kwargs):
        return self.runtime.prepare_volumes(self.bundle, self.sha, 'app-data', **kwargs)

    def test_explicit_prepare_then_admission_without_publication_or_effect_replay(self):
        result = self.prepare()
        self.assertEqual(result['state'], 'prepared-not-published')
        self.assertEqual(self.adapter.creates, 1)
        self.assertEqual(self.adapter.effects, ['chmod', 'chown'])
        self.assertFalse(self.runtime.quadlet.exists())
        before = (self.adapter.records / 'p0-app-data.json').read_bytes()
        admitted = self.runtime._admit_prepared_volumes([self.spec])
        self.assertEqual(admitted[0]['state'], 'prepared')
        self.assertEqual((self.adapter.records / 'p0-app-data.json').read_bytes(), before)
        self.assertEqual(self.adapter.creates, 1)
        self.assertEqual(self.adapter.effects, ['chmod', 'chown'])

    def test_publication_admission_never_prepares_a_missing_resource(self):
        self.adapter.records.mkdir(mode=0o700)
        with self.assertRaisesRegex(ContractError, 'volume-preparation-required'):
            self.runtime._admit_prepared_volumes([self.spec])
        self.assertEqual(self.adapter.creates, 0)
        self.assertEqual(list(self.adapter.records.iterdir()), [])

    def test_create_uncertainty_requires_exact_explicit_resume(self):
        self.adapter.fail_create = 'after'
        with self.assertRaises(Crash):
            self.prepare()
        with self.assertRaisesRegex(ContractError, 'exact explicit resume'):
            self.prepare()
        self.assertEqual(self.adapter.creates, 1)
        self.adapter.fail_create = None
        self.assertEqual(self.prepare(resume=True)['state'], 'prepared-not-published')
        self.assertEqual(self.adapter.creates, 1)
        journal = Journal(self.runtime.state / 'operations.sqlite3')
        try:
            states = journal.connection.execute("SELECT state FROM operations WHERE kind='volume-prepare' ORDER BY created").fetchall()
            self.assertEqual([row[0] for row in states], ['indeterminate', 'succeeded'])
        finally:
            journal.close()

    def test_bad_release_or_undeclared_resource_never_claims(self):
        for sha, resource in (('0' * 64, 'app-data'), (self.sha, 'other-data')):
            with self.subTest(sha=sha, resource=resource), self.assertRaises(ContractError):
                self.runtime.prepare_volumes(self.bundle, sha, resource)
        self.assertEqual(self.adapter.creates, 0)
        self.assertFalse(self.adapter.records.exists())


if __name__ == '__main__':
    unittest.main()
