#!/usr/bin/env python3
"""Real all-eight-role temp-FD read-only Root copy consumer, NOT installed proof.

Reuse the existing genuine projector/copier/source verifier/unit publisher and
Root sealer fixture. Only numerical kernel/NSS/ACL/mount/boot facts and fixed
host-path translation are modelled, never a source/permission success shim.
The original 45 unit/restore tests are not inherited into this suite's runner.
"""
import argparse
import copy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Import the existing fixture without changing its file or test selection.
import importlib.util
spec = importlib.util.spec_from_file_location('copy_observer_real_fixture', ROOT / 'scripts/test-native-runtime-env-units.py')
f = importlib.util.module_from_spec(spec)
exec(compile(spec.loader.get_source(spec.name), str(spec.origin), 'exec'), f.__dict__)
u, p = f.u, f.p


class Observer(f.Units):
    def setUp(self):
        super().setUp()
        self.run_units()
        self.restore_all()
        for row in self.rows:
            state = Path(row['stateRoot'])
            (state / 'current').symlink_to(state / 'releases' / self.release.name)
        (self.install / 'current').symlink_to(self.release)
        self.running_intent['phase'] = 'building'
        self.running_intent['steps'] = ['preparing', 'units-selected', 'building']
        self.write_records(self.running_intent)
        original = u.v.Snapshot.absolute
        def absolute(snapshot, path, operator=None):
            return original(snapshot, self.host / 'run/user' if path == Path('/run/user') else path, operator)
        patch.object(u.v.Snapshot, 'absolute', new=absolute).start()
        self.issued = self.issue()  # real Root issuer, ONLY fixture preparation
        self.running_intent['nativeRuntimeEnvironmentCopies'] = copy.deepcopy(self.issued)
        self.write_records(self.running_intent)
        self.valid_intent = copy.deepcopy(self.running_intent)
        self.mutations.clear()

    def observe(self):
        return u.verify_running_copies(self.install, self.release, self.running_intent)

    def commit(self, intent):
        self.running_intent = copy.deepcopy(intent)
        self.write_records(self.running_intent)

    def cue(self, role='rootless-apps'):
        return Path(self.unit_custody['roles'][role]['custodyFile'])

    def replace_owned_file(self, path, uid, gid, mode):
        data = path.read_bytes()
        replacement = path.with_name(path.name + '.replacement')
        self.put(replacement, data)
        self.set_owner(replacement, uid, gid)
        replacement.chmod(mode)
        replacement.replace(path)

    def test_all_eight_real_copies_read_only_and_same_prepared_source_encodings(self):
        before = {path: (p.identity(path.stat()), path.read_bytes()) for path in
                  [self.install / '.install-intent.json', self.release / 'installation-receipt.json'] +
                  [self.cue(role) for role in self.unit_custody['roles']]}
        def forbidden(*args, **kwargs):
            self.fail('read-only observer attempted a mutation/issuance/restore')
        with patch.object(u.RunningSeal, 'issue', new=forbidden), \
             patch.object(u, 'restore', new=forbidden), \
             patch.dict(u._runtime, restore=forbidden, rename=forbidden), \
             patch.object(u.m, 'rename', new=forbidden), \
             patch.object(os, 'write', new=forbidden), \
             patch.object(os, 'fchown', new=forbidden), \
             patch.object(os, 'fchmod', new=forbidden), \
             patch.object(os, 'mkdir', new=forbidden), \
             patch.object(os, 'link', new=forbidden):
            result = self.observe()
            prepared = u.verify_prepared_units(self.install, self.release, self.running_intent)
        self.assertEqual(result['kind'], 'root-runtime-copy-observation-verified')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(self.issued['copies']), 8)
        self.assertIn('rootful', self.issued['copies'])
        self.assertEqual(result['sourceSha256'], prepared['sourceSha256'])
        self.assertEqual(result['selectionSourceSha256'], prepared['selectionSourceSha256'])
        self.assertEqual(result['copyCustodySha256'], prepared['copyCustodySha256'])
        self.assertNotEqual(self.issued['intentSha256'], result['intentSha256'])
        self.assertEqual(result['intentSha256'], p.sha(before[self.install / '.install-intent.json'][1]))
        self.assertTrue(result['runningEnvironmentChecked'])
        for key in ('activationAuthorized', 'readinessAuthorized', 'resetAuthorized', 'journalWritten'):
            self.assertIs(result[key], False)
        self.assertEqual(before, {path: (p.identity(path.stat()), path.read_bytes()) for path in before})
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.observe(), result)

    def test_real_building_starting_active_stable_physical_selection_with_fresh_record_cas(self):
        results = []
        for phase in ('building', 'starting', 'active'):
            intent = copy.deepcopy(self.running_intent)
            intent['phase'] = phase
            intent['steps'] = list(u.o.journal.PHASES[:u.o.journal.PHASES.index(phase) + 1])
            self.commit(intent)
            result = self.observe()
            prepared = u.verify_prepared_units(self.install, self.release, self.running_intent)
            self.assertEqual(result['sourceSha256'], prepared['sourceSha256'])
            self.assertEqual(result['selectionSourceSha256'], prepared['selectionSourceSha256'])
            results.append(result)
        self.assertEqual(len({row['bindingSha256'] for row in results}), 1)
        self.assertEqual(len({row['selectionSourceSha256'] for row in results}), 1)
        self.assertEqual(len({row['copyCustodySha256'] for row in results}), 1)
        self.assertEqual(len({row['sourceSha256'] for row in results}), 3)
        self.assertEqual(len({row['intentSha256'] for row in results}), 3)

    def test_missing_unsealed_or_wrong_typed_top_observation_refuses(self):
        variants = [('schemaVersion', True), ('schemaVersion', 1.0), ('kind', 'actor-stamp'),
                    ('status', 'pending'), ('release', str(self.install / 'releases/retired')),
                    ('inputs', {}), ('intentSha256', 'not-a-sha'), ('receiptSha256', 'f' * 64),
                    ('bootId', 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'), ('copies', {}),
                    ('activationAuthorized', 0), ('readinessAuthorized', True),
                    ('resetAuthorized', True), ('journalWritten', True), ('unknownPermit', False)]
        for key, value in variants:
            with self.subTest(key=key, value=value):
                intent = copy.deepcopy(self.valid_intent)
                intent['nativeRuntimeEnvironmentCopies'][key] = value
                self.commit(intent)
                with self.assertRaises(ValueError): self.observe()
        for proof in (None, {}, True):
            intent = copy.deepcopy(self.valid_intent)
            intent['nativeRuntimeEnvironmentCopies'] = proof
            self.commit(intent)
            with self.assertRaises(ValueError): self.observe()
        intent = copy.deepcopy(self.valid_intent)
        del intent['nativeRuntimeEnvironmentCopies']
        self.commit(intent)
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(self.mutations, [])

    def test_role_scope_path_copy_and_original_receipt_must_match_physical_records(self):
        variants = [('path', '/foreign/runtime-env-copy-custody.json'), ('copy', {}), ('receipt', {}),
                    ('extraPermit', False)]
        for key, value in variants:
            with self.subTest(key=key):
                intent = copy.deepcopy(self.valid_intent)
                intent['nativeRuntimeEnvironmentCopies']['copies']['rootless-apps'][key] = value
                self.commit(intent)
                with self.assertRaises(ValueError): self.observe()
        for role in ('rootful', 'rootless-apps'):
            intent = copy.deepcopy(self.valid_intent)
            del intent['nativeRuntimeEnvironmentCopies']['copies'][role]
            self.commit(intent)
            with self.assertRaises(ValueError): self.observe()
        intent = copy.deepcopy(self.valid_intent)
        intent['nativeRuntimeEnvironmentCopies']['copies']['rootless-foreign'] = {}
        self.commit(intent)
        with self.assertRaises(ValueError): self.observe()

    def test_nested_integer_boolean_aliases_never_equal_actual_custody(self):
        for key in ('copy', 'receipt'):
            intent = copy.deepcopy(self.valid_intent)
            target = intent['nativeRuntimeEnvironmentCopies']['copies']['rootful'][key]
            if key == 'copy': target['schemaVersion'] = True
            else: target['uid'] = False
            self.commit(intent)
            with self.assertRaises(ValueError): self.observe()

    def test_runtime_rootful_bytes_and_actor_replacement_inode_refuse_without_reissue(self):
        for role, name in (('rootful', 'edge.env'), ('rootless-apps', 'webapp.env')):
            spec = self.unit_custody['roles'][role]
            path = Path(spec['runtimeStore']) / name
            before = path.read_bytes()
            if role == 'rootful': path.write_bytes(b'FOREIGN\n')
            else: self.replace_owned_file(path, spec['uid'], spec['gid'], 0o600)
            with self.assertRaises(ValueError): self.observe()
            if role == 'rootful': path.write_bytes(before)
        self.assertEqual(self.mutations, [])

    def test_real_persistent_source_mutation_refuses(self):
        source = self.install / 'runtime-env/edge.env'
        source.write_bytes(b'FOREIGN\n')
        with self.assertRaises(ValueError): self.observe()

    def test_current_boot_and_runtime_anchor_custody_are_not_retrospectively_resealed(self):
        with patch.dict(u._runtime, _boot=lambda: 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'):
            with self.assertRaises(ValueError): self.observe()
        spec = self.unit_custody['roles']['rootless-apps']
        anchor = self.host / 'run/user' / str(spec['uid'])
        self.set_owner(anchor, 0, 0)
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(self.mutations, [])

    def test_missing_root_cue_or_runtime_remains_missing_no_restore(self):
        self.cue().unlink()
        with self.assertRaises(ValueError): self.observe()
        self.assertFalse(self.cue().exists())
        target = Path(self.unit_custody['roles']['rootful']['runtimeStore'])
        target.rename(target.with_name('inert-runtime'))
        with self.assertRaises((ValueError, OSError)): self.observe()
        self.assertFalse(target.exists())

    def test_root_cue_actor_ownership_mode_acl_symlink_and_hardlink_refuse(self):
        role = self.unit_custody['roles']['rootless-apps']
        path = self.cue()
        self.set_owner(path, role['uid'], role['gid'])
        with self.assertRaises(ValueError): self.observe()
        self.set_owner(path, 0, role['gid'])
        path.chmod(0o600)
        with self.assertRaises(ValueError): self.observe()
        path.chmod(0o440)
        self.acls[self.key(path)] = (b'foreign', b'')
        with self.assertRaises(ValueError): self.observe()
        self.acls.pop(self.key(path))
        other = path.with_name('retained-root-cue')
        path.rename(other); path.symlink_to(other)
        with self.assertRaises(OSError): self.observe()
        path.unlink(); other.rename(path)
        os.link(path, self.base / 'root-cue-hardlink')
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(self.mutations, [])

    def test_root_receipt_body_digest_and_original_inode_never_retrofitted(self):
        role = self.unit_custody['roles']['rootful']
        path = self.cue('rootful')
        self.replace_owned_file(path, 0, role['gid'], 0o400)
        with self.assertRaises(ValueError): self.observe()
        # Even updating private JSON to the newly observed receipt metadata is
        # not enough when its body is a different, otherwise valid boot record.
        value = p.strict(path.read_bytes())
        value['bootId'] = 'ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee'
        path.chmod(0o600); path.write_bytes(p.encoded(value)); path.chmod(0o400)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try: receipt = u.m.regular(fd, 0, role['gid'], 0o400)[1]
        finally: os.close(fd)
        intent = copy.deepcopy(self.valid_intent)
        intent['nativeRuntimeEnvironmentCopies']['copies']['rootful']['receipt'] = receipt
        self.commit(intent)
        with self.assertRaises(ValueError): self.observe()

    def test_actual_cue_replacement_between_sweeps_refuses(self):
        original = u.RunningSeal.cues
        changed = False
        def race(observer):
            nonlocal changed
            result = original(observer)
            if not changed:
                changed = True
                spec = self.unit_custody['roles']['rootless-apps']
                self.replace_owned_file(self.cue(), 0, spec['gid'], 0o440)
            return result
        with patch.object(u.RunningSeal, 'cues', new=race):
            with self.assertRaises(ValueError): self.observe()

    def test_real_current_root_record_cas_race_is_not_a_stable_binding_exclusion(self):
        original = u.PreparedUnits.verify
        changed = False
        def race(observer):
            nonlocal changed
            result = original(observer)
            if not changed:
                changed = True
                for path in (self.install / '.install-intent.json', self.release / 'installation-receipt.json'):
                    path.write_bytes(path.read_bytes() + b'\n')
            return result
        with patch.object(u.PreparedUnits, 'verify', new=race):
            with self.assertRaises(ValueError): self.observe()

    def test_nonroot_failed_retired_and_preparing_sources_cannot_consume_running_proof(self):
        with patch.object(os, 'geteuid', new=lambda: 1000):
            with self.assertRaises(ValueError): self.observe()
        for phase in ('preparing', 'units-selected', 'failed', 'retired-failed', 'retired-clean'):
            intent = copy.deepcopy(self.valid_intent)
            intent['phase'] = phase
            self.commit(intent)
            with self.assertRaises(ValueError): self.observe()

    def test_real_rendered_unit_source_mutation_refuses(self):
        path = self.host / 'etc/systemd/system' / u.UNIT
        path.write_bytes(path.read_bytes() + b'# unreviewed source edit\n')
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(self.mutations, [])

    def test_rootful_empty_still_requires_root_copy_and_receipt(self):
        self.assertEqual(self.unit_custody['roles']['rootful']['files'], {})
        result = self.observe()
        self.assertTrue(result['runningEnvironmentChecked'])
        path = self.cue('rootful')
        path.unlink()
        with self.assertRaises(ValueError): self.observe()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--group', type=int, choices=range(1, 9))
    group.add_argument('--match')
    args = parser.parse_args()
    names = [name for name in Observer.__dict__ if name.startswith('test_')]
    if args.group is not None: names = [name for index, name in enumerate(names) if index % 8 == args.group - 1]
    if args.match: names = [name for name in names if args.match in name]
    if not names: parser.error('no matching observer tests')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Observer(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
