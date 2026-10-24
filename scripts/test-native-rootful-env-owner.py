#!/usr/bin/env python3
"""Rootful persistent env: real temp FDs, synthetic NSS/ACL/mount/process facts.

The real seven-domain producer/copier/verifier and native source planner run.
Only subprocess boundary observations are fake; no host/native installation,
privileged ownership operations, secret-store access or installed acceptance.
Run --group 1..6 (original writer cases), --consumer-group 1..5 (read-only
consumer cases) sequentially with timeout120s for bounded model batches.
"""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


r = load('rootful_env_owner_tested', BASE / 'runtime-generator/podman-ops/native-rootful-env-owner.py')
f = load('rootful_env_fixture', BASE / 'scripts/test-native-install-files.py')
r.m = f.m; r.v = f.m.v; r.o, r.p = r.v.o, r.v.p
r.require, r.Refused = r.o.require, r.o.Refused
p, m = r.p, r.m
STOPPED = m.stopped


class Rootful(f.Files):
    def emit(self, release, ir, metadata):
        if release == self.release:
            environment = dict(DOMAIN='${DOMAIN}', ROOTFUL_TOKEN='${RUNNER80_TOKEN}',
                               NESTED='${ABSENT:-${DOMAIN}}', LITERAL='$$literal')
            name = self._testMethodName
            if name == 'test_no_declarations_no_aggregate_or_store' or name.startswith('test_verify_empty'): environment = {}
            if name == 'test_root_reference_refused': environment['LEAK'] = '${P0_DERIVATION_MASTER_KEY}'
            if name == 'test_stack_derivation_family_refused': environment['STACK_DERIVATION_SALT'] = 'not-app-material'
            if name == 'test_literal_master_collision_refused': environment['LEAK'] = 'root-master-sentinel'
            if name == 'test_missing_required_variable_refused': environment['MISSING'] = '${ABSENT:?metadata-only}'
            if name == 'test_owner_password_collision_refused': environment['LEAK'] = 'synthetic-owner-password'
            if name == 'test_health_input_aliases_use_projector_semantics':
                ir['services']['edge']['health'] = {'test': ['CMD-SHELL', 'test -n "$RUNNER80_TOKEN"']}
            ir['services']['edge']['environment'] = environment
            ir['services']['telemetry'] = dict(placement='rootful', lifecycle='daemon', target='observability',
                                              image='sha256:' + 'd' * 64,
                                              environment={} if not environment else {'PUBLIC': 'operational'})
        super().emit(release, ir, metadata)

    def setUp(self):
        super().setUp()
        self.store = self.install / 'runtime-env'; self.status = {}; self.jobs = ''
        self.commands = []
        # Use the REAL canonical stopped unit/alias/job checker. Only its
        # subprocess transport observations (and inherited actor process model)
        # are synthetic. There is never a production callback/success adapter.
        patch.object(m, 'stopped', STOPPED).start()
        def run(args, **kwargs):
            self.commands.append(list(args))
            if args[:2] == ['systemctl', 'show']:
                units = args[2:args.index('-p')]
                blocks = []
                for unit in units:
                    props = dict(Id=unit, Names=unit, LoadState='not-found', ActiveState='inactive', MainPID='0',
                                 Job='', DropInPaths='', SourcePath='', FragmentPath='')
                    props.update(self.status.get(unit, {}))
                    blocks.append('\n'.join(key + '=' + value for key, value in props.items()))
                return SimpleNamespace(returncode=0, stdout='\n\n'.join(blocks) + '\n')
            self.assertEqual(args, ['systemctl', 'list-jobs', '--no-legend', '--no-pager'])
            return SimpleNamespace(returncode=0, stdout=self.jobs)
        patch.object(subprocess, 'run', side_effect=run).start()
        self.addCleanup(self.close_rootful)
        if self._testMethodName == 'test_owner_password_collision_refused' or self._testMethodName.startswith('test_verify_owner_realm'):
            self.put(self.release / 'runtime/configs' / p.IDP_REALM,
                     p.encoded({'users': [{'credentials': [{'type': 'password', 'value': 'synthetic-owner-password'}]}]}))

    def close_rootful(self):
        for value in r._sessions.values(): value.close()
        r._sessions.clear()

    def prepare_env(self):
        self.custody = r.prepare_custody(self.install, self.release, self.prior)
        return self.custody

    def seal(self):
        self.intent = dict(self.prior, rootfulEnvCustody=self.custody)
        self.write_records(self.intent)

    def apply_env(self):
        return r.copy_environment(self.install, self.release, self.intent)

    def copy_env(self):
        self.prepare_env(); self.seal(); return self.apply_env()

    def reject_prepare(self):
        with self.assertRaises((ValueError, OSError, KeyError)): self.prepare_env()

    def reject_copy(self):
        with self.assertRaises((ValueError, OSError, KeyError)): self.apply_env()

    def test_fresh_exact_rootful_files_and_no_journal_or_runtime_write(self):
        self.prepare_env(); self.seal()
        before = (self.install / '.install-intent.json').read_bytes()
        proof = self.apply_env()
        self.assertEqual(set(proof['files']), {'edge.env', 'telemetry.env'})
        self.assertEqual((self.store / 'edge.env').read_bytes(),
                         b'DOMAIN=synthetic.invalid\nLITERAL=$literal\nNESTED=synthetic.invalid\nROOTFUL_TOKEN=selected-token\n')
        self.assertEqual((self.store / 'telemetry.env').read_bytes(), b'PUBLIC=operational\n')
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.assertEqual(proof['status'], 'completed'); self.assertTrue(proof['runtimeDeferred'])
        self.assertFalse(proof['activationAuthorized']); self.assertFalse(proof['readinessAuthorized'])
        self.assertEqual(proof['sourceCustodySha256'], p.sha(p.encoded(self.custody)))
        self.assertEqual(proof['store']['mode'], 0o700)
        self.assertTrue(all(pin['uid'] == pin['gid'] == 0 and pin['mode'] == 0o600 for pin in proof['files'].values()))
        self.assertNotIn('selected-token', p.encoded(proof).decode())
        self.assertFalse(any('/run/webservices' in str(path) for path, *_ in self.mutations))
        self.assertTrue(self.commands)

    def test_no_declarations_no_aggregate_or_store(self):
        (self.release / 'runtime/stack.env').unlink()
        result = self.copy_env()
        self.assertEqual(result['files'], {}); self.assertIsNone(result['store']); self.assertFalse(self.store.exists())

    def test_health_input_aliases_use_projector_semantics(self):
        self.copy_env()
        self.assertIn(b'P0_HEALTH_INPUT_RUNNER80_TOKEN=selected-token\n', (self.store / 'edge.env').read_bytes())

    def test_root_reference_refused(self): self.reject_prepare()
    def test_stack_derivation_family_refused(self): self.reject_prepare()
    def test_literal_master_collision_refused(self): self.reject_prepare()
    def test_missing_required_variable_refused(self): self.reject_prepare()
    def test_owner_password_collision_refused(self): self.reject_prepare()

    def test_metadata755_prepare_requires_sealer700_before_copy(self):
        self.install.chmod(0o755); self.prepare_env(); self.seal()
        self.reject_copy(); self.assertFalse(self.store.exists())

    def test_metadata755_exact_same_inode_tightening_allowed(self):
        self.install.chmod(0o755); self.prepare_env(); self.seal()
        self.install.chmod(0o700); self.apply_env()

    def test_existing_unproven_selected_refused_without_reading(self):
        self.mkdir(self.store); self.put(self.store / 'edge.env', b'synthetic-legacy\n')
        before = p.identity((self.store / 'edge.env').stat())
        self.prepare_env(); self.seal()
        with self.assertRaisesRegex(ValueError, 'complete-clean-reset dependency'): self.apply_env()
        self.assertEqual(before, p.identity((self.store / 'edge.env').stat()))

    def test_unselected_foreign_names_preserved_unread(self):
        self.mkdir(self.store); (self.store / 'sibling.env').symlink_to('/never-open')
        self.copy_env(); self.assertTrue((self.store / 'sibling.env').is_symlink())
        self.assertEqual(set(path.name for path in self.store.iterdir()), {'sibling.env', 'edge.env', 'telemetry.env'})

    def test_existing_store_default_acl_refused(self):
        self.mkdir(self.store); self.acls[self.key(self.store)] = (b'', b'invalid')
        self.prepare_env(); self.seal(); self.reject_copy()

    def test_existing_store_uid_refused(self):
        self.mkdir(self.store); self.set_owner(self.store, self.actor_app['uid'], self.accounts[self.actor_app['user']].pw_gid)
        self.prepare_env(); self.seal(); self.reject_copy()

    def test_store_symlink_refused(self):
        (self.install / 'runtime-env').symlink_to(self.base / 'foreign'); self.prepare_env(); self.seal(); self.reject_copy()

    def test_aggregate_bytes_drift(self):
        self.prepare_env(); self.seal(); (self.release / 'runtime/stack.env').write_bytes(b'DOMAIN=changed\n')
        self.reject_copy()

    def test_aggregate_inode_aba(self):
        self.prepare_env(); self.seal(); path = self.release / 'runtime/stack.env'; body = path.read_bytes()
        path.rename(self.release / 'runtime/retained'); self.put(path, body); self.reject_copy()

    def test_aggregate_symlink_refused(self):
        path = self.release / 'runtime/stack.env'; path.unlink(); path.symlink_to(self.base / 'missing')
        self.reject_prepare()

    def test_aggregate_hardlink_refused(self):
        os.link(self.release / 'runtime/stack.env', self.base / 'aggregate-alias'); self.reject_prepare()

    def test_aggregate_acl_refused(self):
        self.acls[self.key(self.release / 'runtime/stack.env')] = (b'invalid', b''); self.reject_prepare()

    def test_aggregate_uid_refused(self):
        self.set_owner(self.release / 'runtime/stack.env', self.actor_app['uid'], 0); self.reject_prepare()

    def test_aggregate_public_mode_refused(self):
        (self.release / 'runtime/stack.env').chmod(0o644); self.reject_prepare()

    def test_source_input_hash_drift_refused(self):
        self.prepare_env(); self.seal(); self.put(self.release / 'stack.ir.json', b'{}\n'); self.reject_copy()

    def test_exact_seal_no_extra_record_fields(self):
        self.prepare_env(); self.seal(); self.intent['unexpected'] = True; self.write_records(self.intent); self.reject_copy()

    def test_dual_record_mismatch_refused(self):
        self.prepare_env(); self.seal(); self.put(self.release / 'installation-receipt.json', b'{}\n'); self.reject_copy()

    def test_same_process_fd_required(self):
        with self.assertRaisesRegex(ValueError, 'same-process'):
            r.copy_environment(self.install, self.release, self.prior)

    def test_all_seven_environment_handoffs_required(self):
        self.prior['domainRuntimeProjections']['platform'].pop('environmentStoreHandoff')
        self.write_records(self.prior); self.reject_prepare()

    def test_rootful_active_unit_refused(self):
        self.status['webservices-edge.service'] = {'ActiveState': 'active', 'MainPID': '123'}; self.reject_prepare()

    def test_rootful_alias_refused(self):
        self.status['webservices-edge.service'] = {'Names': 'webservices-edge.service foreign.service'}; self.reject_prepare()

    def test_rootful_job_refused(self):
        self.jobs = '1 webservices-edge.service start waiting\n'; self.reject_prepare()

    def test_actor_not_offline_refused(self):
        with patch.object(r.o, 'inactive', side_effect=ValueError('synthetic actor process')): self.reject_prepare()

    def test_fd9_absence_refused(self):
        with patch.object(r.o, 'lock_held', side_effect=ValueError('synthetic missing FD9')): self.reject_prepare()

    def test_marker_drift_refused(self):
        self.prepare_env(); self.seal(); self.put(self.scope / r.o.storage.MARKER, b'{}\n'); self.reject_copy()

    def test_mount_custody_drift_refused(self):
        self.prepare_env(); self.seal()
        with patch.object(p, 'mount_id', return_value=92): self.reject_copy()

    def canonical_old_env(self):
        first = self.copy_env(); custody = copy.deepcopy(self.custody)
        # Root-owned receipt authority MODEL seeded from a real first copy.
        # This is not an installed or two-release lifecycle proof.
        previous = self.previous_source(phase='active', extra=False)
        value = p.strict((previous / 'installation-receipt.json').read_bytes())
        custody.update(release=str(previous), inputs=value['inputs'])
        oldproof = dict(first, release=str(previous), inputs=value['inputs'],
                        sourceCustodySha256=p.sha(p.encoded(custody)))
        value.update(rootfulEnvCustody=custody, rootfulEnvironmentStoreHandoff=oldproof)
        self.put(previous / 'installation-receipt.json', p.encoded(value))
        return first, previous

    def test_known_previous_root_receipt_exact_cas_replacement(self):
        first, _ = self.canonical_old_env()
        proof = self.copy_env()
        for name, record in first['files'].items():
            self.assertNotEqual(record['identity'][1], proof['files'][name]['identity'][1])
            self.assertEqual(record['sha256'], proof['files'][name]['sha256'])
        self.assertFalse(any(name.startswith('.rootful-env-') for name in os.listdir(self.store)))

    def test_known_previous_selected_inode_aba_refused(self):
        self.canonical_old_env(); target = self.store / 'edge.env'; body = target.read_bytes()
        target.rename(self.store / 'retained-old'); self.put(target, body)
        self.prepare_env(); self.seal(); self.reject_copy()

    def test_known_previous_proof_forged_hash_refused(self):
        _, previous = self.canonical_old_env()
        value = p.strict((previous / 'installation-receipt.json').read_bytes())
        value['rootfulEnvironmentStoreHandoff']['sourceCustodySha256'] = '0' * 64
        self.put(previous / 'installation-receipt.json', p.encoded(value))
        self.prepare_env(); self.seal(); self.reject_copy()

    def test_known_previous_exchange_race_restores_foreign_without_reading(self):
        self.canonical_old_env(); self.prepare_env(); self.seal()
        original = m.rename; fired = False
        def rename(parent, stage, name, exchange=False):
            nonlocal fired
            if exchange and not fired:
                fired = True; (self.store / name).rename(self.store / 'retained-original')
                self.put(self.store / name, b'synthetic-raced-foreign\n')
            return original(parent, stage, name, exchange=exchange)
        with patch.object(m, 'rename', side_effect=rename): self.reject_copy()
        self.assertEqual((self.store / 'edge.env').read_bytes(), b'synthetic-raced-foreign\n')
        self.assertTrue((self.store / 'retained-original').exists())
        self.assertTrue(any(name.startswith('.rootful-env-') for name in os.listdir(self.store)))

    def test_new_name_race_no_replace_retains_failure_stage(self):
        self.prepare_env(); self.seal(); original = m.rename; fired = False
        def rename(parent, stage, name, exchange=False):
            nonlocal fired
            if not fired:
                fired = True; self.put(self.store / name, b'synthetic-raced-foreign\n')
            return original(parent, stage, name, exchange=exchange)
        with patch.object(m, 'rename', side_effect=rename): self.reject_copy()
        self.assertEqual((self.store / 'edge.env').read_bytes(), b'synthetic-raced-foreign\n')
        self.assertTrue(any(name.startswith('.rootful-env-') for name in os.listdir(self.store)))

    def test_source_change_during_write_retains_stage_no_completion(self):
        self.prepare_env(); self.seal(); original = os.write; changed = False
        def write(fd, data):
            nonlocal changed
            result = original(fd, data)
            if not changed:
                changed = True; (self.release / 'runtime/stack.env').write_bytes(b'DOMAIN=drift\n')
            return result
        with patch.object(os, 'write', side_effect=write): self.reject_copy()
        self.assertTrue(any(name.startswith('.rootful-env-') for name in os.listdir(self.store)))

    def test_source_release_mount_alias_refused(self):
        original = p.child_open
        def opened(fd, name, flags):
            if self.fd_paths[fd] == self.install / 'releases' and name == self.release.name:
                raise OSError(18, 'synthetic source release mount alias')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=opened): self.reject_prepare()

    def completed_env(self):
        proof = self.copy_env()
        self.intent = dict(self.intent, rootfulEnvironmentStoreHandoff=proof)
        self.write_records(self.intent)
        return proof

    def select_phase(self, phase):
        for row in self.rows:
            state = Path(row['stateRoot']); pointer = state / 'current'
            pointer.unlink(missing_ok=True); pointer.symlink_to(state / 'releases' / self.release.name)
        pointer = self.install / 'current'; pointer.unlink(missing_ok=True); pointer.symlink_to(self.release)
        self.intent = dict(self.intent, phase=phase, steps=self.intent['steps'] + [phase])
        self.write_records(self.intent)

    def observe_env(self):
        return r.verify_environment(self.install, self.release, self.intent)

    def reject_observe(self):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)): self.observe_env()

    def test_verify_prepared_and_all_running_phases_stable_digest(self):
        self.completed_env(); baseline = self.observe_env()
        for phase in ('units-selected', 'building', 'starting', 'active'):
            self.select_phase(phase)
            with patch.object(r.Session, '__init__', side_effect=AssertionError('no writer constructor')), \
                 patch.object(m, 'stopped', side_effect=AssertionError('no stopped gate')), \
                 patch.object(r.o, 'inactive', side_effect=AssertionError('no inactive actor gate')), \
                 patch.object(subprocess, 'run', side_effect=AssertionError('no process/boot/API queries')):
                self.assertEqual(self.observe_env(), baseline)
        self.assertFalse(baseline['activationAuthorized']); self.assertFalse(baseline['readinessAuthorized'])

    def test_verify_candidate_pointer_required_at_ready(self):
        self.completed_env(); self.intent['phase'] = 'active'; self.write_records(self.intent); self.reject_observe()

    def test_verify_rootful_source_same_byte_inode_swap_refused(self):
        self.completed_env(); path = self.release / 'runtime/stack.env'; body = path.read_bytes()
        path.rename(self.release / 'runtime/retained-source'); self.put(path, body); self.reject_observe()

    def test_verify_rootful_source_bytes_drift_refused(self):
        self.completed_env(); (self.release / 'runtime/stack.env').write_bytes(b'DOMAIN=drift\n'); self.reject_observe()

    def test_verify_store_same_byte_inode_swap_refused(self):
        self.completed_env(); path = self.store / 'edge.env'; body = path.read_bytes()
        path.rename(self.store / 'retained-original'); self.put(path, body); self.reject_observe()

    def test_verify_store_directory_identity_swap_refused(self):
        self.completed_env(); self.store.rename(self.install / 'retained-store'); self.mkdir(self.store); self.reject_observe()

    def test_verify_selected_file_mode_acl_uid_hardlink_refused(self):
        self.completed_env(); path = self.store / 'edge.env'
        path.chmod(0o644); self.reject_observe(); path.chmod(0o600)
        self.acls[self.key(path)] = (b'invalid', b''); self.reject_observe(); self.acls.pop(self.key(path))
        self.set_owner(path, self.actor_app['uid'], 0); self.reject_observe(); self.set_owner(path, 0, 0)
        os.link(path, self.base / 'selected-alias'); self.reject_observe()

    def test_verify_selected_file_symlink_refused(self):
        self.completed_env(); path = self.store / 'edge.env'; path.unlink()
        path.symlink_to(self.release / 'runtime/stack.env'); self.reject_observe()

    def test_verify_unknown_store_names_unread_preserved_and_stable(self):
        self.completed_env(); first = self.observe_env()
        unknown = self.store / 'unselected.env'; unknown.symlink_to('/never-read')
        self.assertEqual(self.observe_env(), first); self.assertTrue(unknown.is_symlink())

    def test_verify_empty_no_aggregate_owner_or_rootful_store_reads(self):
        self.completed_env(); (self.release / 'runtime/stack.env').unlink()
        self.mkdir(self.store); (self.store / 'unselected.env').symlink_to('/never-open')
        original = p.child_open
        def opened(fd, name, flags):
            if self.fd_paths[fd] == self.install and name == 'runtime-env':
                raise AssertionError('empty rootful store must not open')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=opened), \
             patch.object(r.EnvironmentObservation, 'root_read', side_effect=AssertionError('empty source must not open')):
            first = self.observe_env(); self.select_phase('active'); self.assertEqual(self.observe_env(), first)

    def test_verify_missing_or_stale_completed_proof_refused(self):
        self.completed_env(); proof = self.intent.pop('rootfulEnvironmentStoreHandoff'); self.write_records(self.intent)
        self.reject_observe(); self.intent['rootfulEnvironmentStoreHandoff'] = proof
        proof['sourceCustodySha256'] = '0' * 64; self.write_records(self.intent); self.reject_observe()

    def test_verify_forged_completion_without_original_footprint_refused(self):
        self.completed_env(); self.intent['rootfulEnvCustody'].pop('projectionSources')
        self.intent['rootfulEnvironmentStoreHandoff']['sourceCustodySha256'] = p.sha(p.encoded(self.intent['rootfulEnvCustody']))
        self.write_records(self.intent); self.reject_observe()

    def test_verify_marker_scope_drift_refused(self):
        self.completed_env(); self.put(self.scope / r.o.storage.MARKER, b'{}\n'); self.reject_observe()

    def test_verify_account_subrange_drift_refused(self):
        self.completed_env()
        with patch.object(r.o.storage, 'namespace_root_id', return_value=999999): self.reject_observe()

    def test_verify_private_root_record_mismatch_refused(self):
        self.completed_env(); self.put(self.release / 'installation-receipt.json', b'{}\n'); self.reject_observe()

    def test_verify_candidate_input_hash_drift_refused(self):
        self.completed_env(); self.put(self.release / 'stack.ir.json', b'{}\n'); self.reject_observe()

    def test_verify_mount_alias_drift_refused(self):
        self.completed_env()
        with patch.object(p, 'mount_id', return_value=92): self.reject_observe()

    def test_verify_no_runtime_user_or_root_data_opened(self):
        self.completed_env(); self.select_phase('active'); original = r.o.open_absolute
        def absolute(path, operator=None):
            self.assertFalse(path == Path('/run') or path.is_relative_to('/run'))
            return original(path, operator)
        with patch.object(r.o, 'open_absolute', side_effect=absolute): self.observe_env()

    def test_verify_previous_source_stable_but_live_candidate_selected(self):
        self.canonical_old_env(); self.completed_env(); first = self.observe_env()
        self.select_phase('active')
        with patch.object(subprocess, 'run', side_effect=AssertionError('no online gate')):
            self.assertEqual(self.observe_env(), first)

    def test_verify_previous_source_original_inode_drift_refused(self):
        _, previous = self.canonical_old_env(); self.completed_env()
        path = previous / 'quadlet/rootful/webservices-edge.container'; body = path.read_bytes()
        path.rename(previous / 'retained-old-source'); self.put(path, body); self.reject_observe()

    def test_verify_metadata_rewrites_stable_but_in_call_cas_drift_refused(self):
        self.completed_env(); first = self.observe_env()
        self.intent['steps'].append('synthetic-later-journal-observation'); self.write_records(self.intent)
        self.assertEqual(self.observe_env(), first)
        original = r.EnvironmentObservation.sweep; count = 0
        def sweep(observation):
            nonlocal count
            result = original(observation); count += 1
            if count == 1:
                self.intent['steps'].append('synthetic-concurrent-record-write'); self.write_records(self.intent)
            return result
        with patch.object(r.EnvironmentObservation, 'sweep', sweep): self.reject_observe()

    def test_verify_owner_realm_original_source_pin_and_inode_swap(self):
        self.completed_env(); self.observe_env()
        path = self.release / 'runtime/configs' / p.IDP_REALM; body = path.read_bytes()
        path.rename(path.with_name('retained-realm')); self.put(path, body); self.reject_observe()

    def test_verify_all_seven_primary_account_gid_drift_refused(self):
        self.completed_env(); self.accounts[self.actor_app['user']].pw_gid += 1; self.reject_observe()

    def test_verify_sibling_payload_proof_rejected_before_unknown_read(self):
        self.completed_env(); unknown = self.store / 'runner80.env'; unknown.symlink_to('/never-read')
        proof = self.intent['rootfulEnvironmentStoreHandoff']
        proof['files']['runner80.env'] = copy.deepcopy(proof['files']['edge.env'])
        self.write_records(self.intent); self.reject_observe(); self.assertTrue(unknown.is_symlink())

    def test_verify_selected_file_race_between_samples_refused(self):
        self.completed_env(); original = r.EnvironmentObservation.sweep; count = 0
        def sweep(observation):
            nonlocal count
            result = original(observation); count += 1
            if count == 1: (self.store / 'edge.env').write_bytes(b'SYNTHETIC=failed-sample\n')
            return result
        with patch.object(r.EnvironmentObservation, 'sweep', sweep): self.reject_observe()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    selectors = parser.add_mutually_exclusive_group()
    selectors.add_argument('--group', type=int, choices=(1, 2, 3, 4, 5, 6), help='original 41 writer/CAS cases')
    selectors.add_argument('--consumer-group', type=int, choices=(1, 2, 3, 4, 5), help='new active-safe persistent consumer cases')
    args = parser.parse_args()
    names = [name for name in Rootful.__dict__ if name.startswith('test_')]
    if args.group is not None:
        names = [name for name in names if not name.startswith('test_verify_')]
        names = [name for index, name in enumerate(names) if index % 6 == args.group - 1]
    elif args.consumer_group is not None:
        names = [name for name in names if name.startswith('test_verify_')]
        names = [name for index, name in enumerate(names) if index % 5 == args.consumer_group - 1]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Rootful(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
