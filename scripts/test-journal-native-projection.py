#!/usr/bin/env python3
"""Source-only canonical callback ordering; no native state or credentials."""
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'runtime-generator/podman-ops/install-journal.py'
spec = importlib.util.spec_from_file_location('journal_projection_tests', SOURCE)
j = importlib.util.module_from_spec(spec)
spec.loader.exec_module(j)


class ProjectionJournal(TestCase):
    def setUp(self):
        self.root = Path('/model/root')
        self.release = self.root / 'releases/candidate'
        self.intent_path = self.root / '.install-intent.json'
        self.receipt_path = self.release / 'installation-receipt.json'
        self.inputs = {'bundle.json': 'model-source-pin'}
        self.initial = dict(schemaVersion=1, phase='preparing', release=str(self.release), inputs=self.inputs)
        self.records = {self.intent_path: self.initial, self.receipt_path: self.initial}
        self.events = []
        self.pending = set()
        self.fail_projection = self.fail_env = False
        self.owner = ModuleType('model_projection_owner')
        self.env = ModuleType('model_env_owner')
        self.owner.prepare_custody = self.prepare
        self.owner.project_and_handoff = self.project
        self.env.copy_environment = self.copy_env
        patches = [patch.object(j, 'directory'), patch.object(j, 'standalone_profile', return_value=True),
                   patch.object(j, 'fingerprint', return_value=self.inputs),
                   patch.object(j, 'read', side_effect=lambda path: self.records.get(path)),
                   patch.object(j, 'write', side_effect=self.write),
                   patch.object(j.importlib.util, 'spec_from_file_location', side_effect=self.load_spec),
                   patch.object(j.importlib.util, 'module_from_spec', side_effect=lambda spec: spec.module),
                   patch.dict(sys.modules)]
        for context in patches:
            context.start()
            self.addCleanup(context.stop)

    def load_spec(self, name, path):
        module = self.owner if path.name == 'native-runtime-projection-owner.py' else self.env
        return SimpleNamespace(name=name, module=module, loader=SimpleNamespace(exec_module=lambda module: None))

    def write(self, path, value):
        self.events.append(('write', path))
        self.records[path] = value

    def prepare(self, root, release, prior, domain):
        self.assertEqual(self.records[self.intent_path], prior)
        self.assertEqual(self.records[self.receipt_path], prior)
        self.events.append(('prepare', domain))
        self.pending.add(domain)
        return {'domain': domain, 'retainedFdModel': True}

    def project(self, root, release, intent, domain):
        self.assertIn(domain, self.pending)
        self.pending.remove(domain)
        self.assertEqual(self.records[self.intent_path], intent)
        self.assertEqual(self.records[self.receipt_path], intent)
        self.assertEqual(intent['projectionCustody']['domain'], domain)
        self.events.append(('project', domain))
        if self.fail_projection:
            raise ValueError('model projection refusal')
        return {'domain': domain, 'environmentHandoff': {'status': 'canonical-owner-copy-required'}}

    def copy_env(self, root, release, intent, domain):
        self.assertEqual(self.records[self.intent_path], intent)
        self.assertEqual(self.records[self.receipt_path], intent)
        self.assertEqual(intent['domainRuntimeProjections'][domain]['domain'], domain)
        self.events.append(('environment', domain))
        if self.fail_env:
            raise ValueError('model env refusal')
        return {'status': 'completed', 'runtimeDeferred': True}

    def test_same_process_custody_precedes_projection_and_root_record_precedes_env(self):
        proof = j.project_domain(self.root, self.release, 'platform')
        self.assertEqual([event[0] for event in self.events],
                         ['prepare', 'write', 'write', 'project', 'write', 'write', 'environment', 'write', 'write'])
        self.assertFalse(self.pending)
        self.assertEqual(proof['environmentStoreHandoff']['status'], 'completed')
        self.assertEqual(self.records[self.intent_path], self.records[self.receipt_path])
        self.assertEqual(self.records[self.intent_path]['phase'], 'preparing')

    def test_second_domain_preserves_first_projection_and_handoff(self):
        first = j.project_domain(self.root, self.release, 'platform')
        j.project_domain(self.root, self.release, 'apps')
        projections = self.records[self.intent_path]['domainRuntimeProjections']
        self.assertEqual(set(projections), {'platform', 'apps'})
        self.assertEqual(projections['platform'], first)

    def test_replay_refuses_before_any_custody_or_mutation(self):
        j.project_domain(self.root, self.release, 'platform')
        before = list(self.events)
        with self.assertRaises(ValueError):
            j.project_domain(self.root, self.release, 'platform')
        self.assertEqual(self.events, before)

    def test_projection_failure_retains_preparing_custody_not_success(self):
        self.fail_projection = True
        with self.assertRaises(ValueError):
            j.project_domain(self.root, self.release, 'platform')
        value = self.records[self.intent_path]
        self.assertEqual(value['projectionCustody']['domain'], 'platform')
        self.assertNotIn('domainRuntimeProjections', value)
        self.assertFalse(any(event[0] == 'environment' for event in self.events))

    def test_env_failure_preserves_projection_without_completed_store_claim(self):
        self.fail_env = True
        with self.assertRaises(ValueError):
            j.project_domain(self.root, self.release, 'platform')
        value = self.records[self.intent_path]['domainRuntimeProjections']['platform']
        self.assertNotIn('environmentStoreHandoff', value)
        self.assertEqual(self.records[self.intent_path]['phase'], 'preparing')

    def test_mismatched_receipt_refuses_before_callbacks(self):
        self.records[self.receipt_path] = dict(self.initial, phase='failed')
        with self.assertRaises(ValueError):
            j.project_domain(self.root, self.release, 'platform')
        self.assertFalse(self.events)

    def test_changed_inputs_refuse_before_callbacks(self):
        with patch.object(j, 'fingerprint', return_value={}):
            with self.assertRaises(ValueError):
                j.project_domain(self.root, self.release, 'platform')
        self.assertFalse(self.events)

    def test_nonpreparing_phase_refuses_before_callbacks(self):
        value = dict(self.initial, phase='active')
        self.records[self.intent_path] = self.records[self.receipt_path] = value
        with self.assertRaises(ValueError):
            j.project_domain(self.root, self.release, 'platform')
        self.assertFalse(self.events)

    def test_foreign_release_parent_refuses(self):
        with self.assertRaises(ValueError):
            j.project_domain(self.root, Path('/foreign/releases/candidate'), 'platform')
        self.assertFalse(self.events)


if __name__ == '__main__':
    main()
