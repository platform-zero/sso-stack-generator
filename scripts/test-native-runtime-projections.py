#!/usr/bin/env python3
"""Real temp-FD / model UID, mount, ACL and lease tests, never installed proof.

The real producer and persistent copier create all seven seals. No privileged
ownership changes, live runtime directory, subprocess, service/image/app call,
installer or JVM. Mutations are confined to private temporary roots.
"""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


v = load('projection_verifier_tested', BASE / 'runtime-generator/podman-ops/verify-native-runtime-projections.py')
f = load('projection_verifier_fixture', BASE / 'scripts/test-native-runtime-projection-owner.py')
f.o, f.p = v.o, v.p
p, o, e = v.p, v.o, v.e


class Projections(f.Owner):
    # Inherit fixture helpers, not its unrelated test methods (suite below).
    def setUp(self):
        previous = os.umask(0o077); self.addCleanup(os.umask, previous)
        super().setUp()
        # External /tmp ancestors are synthetic authority in this UID model.
        # Freeze ONLY their native-source-plan identity scalars: unrelated peer
        # temp creation must not turn a source-plan fixture into a host audit.
        # Every inode and timestamp INSIDE our private fixture stays real.
        native_identity = o.native.identity
        frozen = {self.key(path): native_identity(path.lstat()) for path in self.base.parents}
        patch.object(o.native, 'identity', side_effect=lambda info:
                     frozen.get((info.st_dev, info.st_ino), native_identity(info))).start()
        # The real lazy import is routed to the SAME real verifier module whose
        # FD/account/ACL observations this fixture models, not a success shim.
        patch.object(o, '_retired_source_verifier', v).start()
        self.real_retired = self._testMethodName == 'test_retired_real_preproducer_empty_domain_flow'
        self.real_retired_domains = []
        self.manifest['installerStateRoot'] = str(self.install)
        self.ir['services'].pop('other')
        next(r for r in self.rows if r['name'] == 'platform')['services'] = []
        self.reseal()
        self.has_old = self._testMethodName.startswith(('test_previous_', 'test_retired_'))
        if self.has_old:
            self.previous = self.install / 'releases/previous'
            retired = self._testMethodName.startswith('test_retired_')
            self.old_source('retired-failed' if retired else 'active')
            if not retired or self.real_retired:
                (self.install / 'current').symlink_to('releases/previous')
            self.prior['previousRelease'] = None if retired else str(self.previous)
            self.write_records(self.prior)
        # Virtual ownership only; guard every ownership mutation to temp scope.
        def chown(fd, uid, gid):
            path = self.fd_paths[fd]
            self.assertTrue(path.is_relative_to(self.scope))
            s = self.raw_fstat(fd); self.virtual[s.st_dev, s.st_ino] = uid, gid
        patch.object(os, 'fchown', side_effect=chown).start()
        projections = {}
        for row in self.rows:
            if self.real_retired and row['name'] != 'platform':
                # Keep the expensive real lazy-bind producer/Copy regression
                # to one empty actor; other actors retain the isolated timing
                # model. No weakened/cached source verifier callback is used.
                (self.install / 'current').unlink(missing_ok=True)
            self.domain, self.row = row['name'], row
            self.state = Path(row['stateRoot']); self.slot = self.state / 'releases' / self.release.name
            self.destination = self.slot / 'runtime'
            self.mkdir(self.slot)
            self.set_owner(self.state / 'releases', row['uid'], self.accounts[row['user']].pw_gid)
            if self.has_old:
                previous = self.state / 'releases/previous'; self.mkdir(previous)
                self.set_owner(previous, row['uid'], self.accounts[row['user']].pw_gid)
                (self.state / 'current').symlink_to('releases/previous')
            self.prepare(); self.publish(); proof = self.run_owner()
            if self.real_retired and (self.install / 'current').is_symlink():
                self.real_retired_domains.append(row['name'])
            projections[self.domain] = proof
            self.intent = dict(self.new, domainRuntimeProjections=copy.deepcopy(projections))
            self.write_records(self.intent)
            handoff = e.copy_environment(self.install, self.release, self.intent, self.domain)
            projections[self.domain] = dict(proof, environmentStoreHandoff=handoff)
            self.prior = dict(self.intent, domainRuntimeProjections=copy.deepcopy(projections))
            self.write_records(self.prior)
        self.intent = self.prior
        if self._testMethodName.startswith('test_retired_') and not (self.install / 'current').is_symlink():
            # Isolated API negative/timing fixtures: produce real seals first
            # with root/current absent, then model protected retired current.
            # The original pre-producer failure is retained in session evidence.
            # ONLY test_retired_real_preproducer_empty_domain_flow exercises
            # the now-wired real producer+Copy source-only binding before an
            # empty platform actor projection (not all seven simultaneously).
            (self.install / 'current').symlink_to('releases/previous')
        self.domain = 'test-runners'; self.row = next(r for r in self.rows if r['name'] == self.domain)
        self.state = Path(self.row['stateRoot']); self.slot = self.state / 'releases' / self.release.name
        self.destination = self.slot / 'runtime'; self.store = self.state / 'runtime-env'
        self.target = self.destination / 'configs/app/public.json'
        self.proof = self.intent['domainRuntimeProjections'][self.domain]
        self.runtime_base = self.base / 'synthetic-run/user'
        self.mkdir(self.runtime_base)
        self.absolute_original = v.Snapshot.absolute
        def absolute(snapshot, path, operator=None):
            # Production has no alternate runtime-root option. Only this model
            # redirects its exact /run/user read to an isolated temp directory.
            actual = self.runtime_base if path == Path('/run/user') else path
            return self.absolute_original(snapshot, actual, operator)
        patch.object(v.Snapshot, 'absolute', absolute).start()
        # Any accidental service or external ACL subprocess is a test failure.
        patch.object(subprocess, 'run', side_effect=AssertionError('no subprocess queries')).start()
        patch.object(o, 'inactive', side_effect=AssertionError('no stopped-system gate')).start()
        patch.object(os, 'fchown', side_effect=AssertionError('verifier is read-only')).start()

    def old_source(self, phase):
        """Real previous-only source plan, seven matching allocations/roots.

        Historical Huly build={} has no unmanaged build pair: source/stop-only
        policy accepts it; no old activation callback or helper is executed.
        """
        self.mkdir(self.previous)
        old_manifest = copy.deepcopy(self.manifest)
        domains = copy.deepcopy(self.metadata)
        ir = dict(schemaVersion=1, services={
            'old-edge': dict(placement='rootful', lifecycle='daemon', target='core', image='sha256:' + 'a' * 64),
            'huly': dict(placement='rootless', rootlessDomain='apps', lifecycle='on-demand', build={})})
        for row in domains['domains']:
            row['services'] = ['huly'] if row['name'] == 'apps' else []
            row['persistentServices'] = []
            row['subuidStart'] = o.storage.namespace_root_id(row['user'])
        for name, value in (('site/manifest.json', old_manifest), ('podman-domains.json', domains), ('stack.ir.json', ir)):
            self.put(self.previous / name, p.encoded(value))
        for scope in ('rootful', *['rootless-' + row['name'] for row in self.rows]):
            for target in ('core', 'apps', 'observability'):
                wants = 'webservices-old-edge.service' if scope == 'rootful' and target == 'core' else ''
                self.put(self.previous / 'quadlet' / scope / ('webservices-' + target + '.target'),
                    ('[Unit]\nPartOf=webservices.target\nWants=' + wants + '\n[Install]\nWantedBy=webservices.target\n').encode())
            self.put(self.previous / 'quadlet' / scope / 'webservices.target',
                ('[Unit]\nWants=webservices-core.target webservices-apps.target webservices-observability.target\n'
                 '[Install]\nWantedBy=' + ('multi-user.target' if scope == 'rootful' else 'default.target') + '\n').encode())
        self.put(self.previous / 'quadlet/rootful/webservices-old-edge.container',
            ('[Container]\nContainerName=old-edge\nImage=sha256:' + 'a' * 64 + '\n'
             '[Service]\n[Install]\nWantedBy=webservices-core.target\n').encode())
        self.put(self.previous / 'old-helper-must-not-run.py', b'raise AssertionError("never execute previous helpers")\n')
        self.old_reseal(phase)

    def old_reseal(self, phase=None):
        manifest_hash = p.sha((self.previous / 'site/manifest.json').read_bytes())
        self.put(self.previous / 'source-provenance.json', p.encoded(dict(manifestSha256=manifest_hash, generatorCommit='a' * 40)))
        self.put(self.previous / 'bundle.json', p.encoded(dict(backend='podman', deploymentMode='standalone',
            sourceProvenanceSha256=p.sha((self.previous / 'source-provenance.json').read_bytes()),
            irSha256=p.sha((self.previous / 'stack.ir.json').read_bytes()))))
        prior = self.previous / 'installation-receipt.json'
        phase = phase or p.strict(prior.read_bytes())['phase']
        value = dict(schemaVersion=1, phase=phase, release=str(self.previous), inputs={name:
            p.sha((self.previous / name).read_bytes()) if (self.previous / name).exists() else None for name in p.INPUTS})
        self.put(prior, p.encoded(value))
        return value

    def old_document(self, name, change):
        path = self.previous / name
        value = p.strict(path.read_bytes()); change(value); self.put(path, p.encoded(value)); self.old_reseal()

    def run_verify(self, running=False):
        api = v.verify_running if running else v.verify_prepared
        return api(self.install, self.release, self.intent)

    def sync(self):
        self.write_records(self.intent)

    def selected(self, phase='units-selected'):
        for row in self.rows:
            state = Path(row['stateRoot']); link = state / 'current'
            link.unlink(missing_ok=True); link.symlink_to(state / 'releases' / self.release.name)
        link = self.install / 'current'; link.unlink(missing_ok=True); link.symlink_to(self.release)
        self.intent['phase'] = phase; self.sync()

    def restore(self):
        self.selected('starting')
        for row in self.rows:
            handoff = self.intent['domainRuntimeProjections'][row['name']]['environmentStoreHandoff']
            if not handoff['files']:
                continue
            account = self.accounts[row['user']]
            actor = self.runtime_base / str(row['uid']); store = actor / 'webservices'
            self.mkdir(store)
            for path in (actor, store):
                self.set_owner(path, row['uid'], account.pw_gid)
            for name in handoff['files']:
                self.put(store / name, (Path(handoff['stateStore']) / name).read_bytes())
                self.set_owner(store / name, row['uid'], account.pw_gid)
        return self.runtime_base / str(self.row['uid']) / 'webservices'

    def reject(self, running=False):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            self.run_verify(running)

    def test_preparing_old_pointers_all_seven_real_producer_copy(self):
        before = (self.install / '.install-intent.json').read_bytes()
        result = self.run_verify()
        self.assertEqual(result['domains'], sorted(o.native.IDENTITIES))
        self.assertFalse(result['activationAuthorized']); self.assertFalse(result['readinessAuthorized'])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())

    def test_preparing_selected_pointers(self):
        self.selected('preparing'); self.run_verify()

    def test_preparing_mixed_pointers_refused(self):
        (self.install / 'current').symlink_to(self.release); self.reject()

    def test_preparing_one_actor_selected_refused(self):
        (self.state / 'current').symlink_to(self.slot); self.reject()

    def test_selected_phase_requires_all_new(self):
        self.intent['phase'] = 'units-selected'; self.sync(); self.reject()

    def test_units_selected_and_building(self):
        self.selected(); self.run_verify()
        self.intent['phase'] = 'building'; self.sync(); self.run_verify()

    def test_prepared_active_without_runtime_data_is_source_only(self):
        self.selected('active')
        # Normal stop/start preserves the active receipt while logind may have
        # removed runtime tmpfs. Source-only observation must not restore/read it.
        for row in self.rows:
            self.assertFalse((self.runtime_base / str(row['uid']) / 'webservices').exists())
        before = (self.install / '.install-intent.json').read_bytes()
        result = self.run_verify(False)
        self.assertFalse(result['activationAuthorized']); self.assertFalse(result['readinessAuthorized'])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())

    def test_prepared_active_old_pointers_refused(self):
        self.intent['phase'] = 'active'; self.sync(); self.reject(False)

    def test_prepared_active_mixed_actor_pointers_refused(self):
        self.selected('active')
        link = self.state / 'current'; link.unlink(); link.symlink_to(self.state / 'releases/old')
        self.reject(False)

    def test_prepared_starting_is_source_only_without_runtime_data(self):
        self.selected('starting')
        before = (self.install / '.install-intent.json').read_bytes()
        for row in self.rows:
            self.assertFalse((self.runtime_base / str(row['uid']) / 'webservices').exists())
        result = self.run_verify(False)
        self.assertFalse(result['runningEnvironmentChecked'])
        self.assertFalse(result['activationAuthorized'])
        self.assertFalse(result['readinessAuthorized'])
        self.assertEqual(before, (self.install / '.install-intent.json').read_bytes())
        self.reject(True)  # source-only success is not restored runtime proof

    def test_prepared_source_does_not_admit_failed_or_retired(self):
        for phase in ('failed', 'retired-failed', 'retired-clean'):
            with self.subTest(phase=phase):
                self.selected(phase); self.reject(False)

    def test_running_restored_fresh_inodes_and_active(self):
        self.restore(); self.run_verify(True)
        self.intent['phase'] = 'active'; self.sync(); self.run_verify(True)

    def test_running_requires_starting_or_active(self):
        self.selected(); self.reject(True)

    def test_running_missing_restored_environment(self):
        self.selected('starting'); self.reject(True)

    def test_running_wrong_restored_bytes(self):
        store = self.restore(); self.put(store / 'runner80.env', b'SYNTHETIC=wrong\n'); self.reject(True)

    def test_running_wrong_restored_owner(self):
        store = self.restore(); self.set_owner(store / 'runner80.env', 0, 0); self.reject(True)

    def test_running_wrong_restored_acl(self):
        store = self.restore(); self.acls[self.key(store / 'runner80.env')] = (b'invalid', b''); self.reject(True)

    def test_running_selected_symlink(self):
        store = self.restore(); path = store / 'runner80.env'; path.unlink(); path.symlink_to(self.store / path.name)
        self.reject(True)

    def test_running_selected_hardlink(self):
        store = self.restore(); path = store / 'runner80.env'; path.unlink(); os.link(self.store / path.name, path)
        self.reject(True)

    def test_running_unselected_names_preserved_unread(self):
        store = self.restore(); unknown = store / 'unselected.env'; unknown.symlink_to('/never-open')
        sibling = self.store / 'unselected.env'; sibling.symlink_to('/never-open')
        self.run_verify(True); self.assertTrue(unknown.is_symlink()); self.assertTrue(sibling.is_symlink())

    def test_empty_scopes_require_proofs_but_no_runtime_store(self):
        for row in self.rows:
            if not row['services']:
                proof = self.intent['domainRuntimeProjections'][row['name']]
                self.assertEqual(proof['environmentStoreHandoff']['files'], {})
                self.assertIsNone(proof['environmentStoreHandoff']['store'])
                self.assertFalse((Path(row['stateRoot']) / 'runtime-env').exists())
        self.run_verify()

    def test_empty_scope_never_reads_aggregate_or_config_files(self):
        # All selected nonempty source contents already exist in actor runtime;
        # verification must not reopen root aggregate/master/config input.
        original = p.child_open
        def opened(fd, name, flags):
            parent = self.fd_paths[fd]
            self.assertNotEqual(parent / name, self.release / 'runtime')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=opened):
            self.run_verify()

    def test_missing_domain_refused(self):
        self.intent['domainRuntimeProjections'].pop('platform'); self.sync(); self.reject()

    def test_duplicate_domain_inventory_refused(self):
        self.metadata['domains'][0] = copy.deepcopy(self.metadata['domains'][1])
        self.put(self.release / 'podman-domains.json', p.encoded(self.metadata))
        self.intent['inputs']['podman-domains.json'] = p.sha((self.release / 'podman-domains.json').read_bytes())
        self.sync(); self.reject()

    def test_missing_empty_handoff_refused(self):
        self.intent['domainRuntimeProjections']['platform'].pop('environmentStoreHandoff'); self.sync(); self.reject()

    def test_forged_completed_only_json_refused(self):
        self.proof['environmentStoreHandoff'] = {'status': 'completed'}; self.sync(); self.reject()

    def test_last_domain_custody_substitution_refused(self):
        self.proof['projectionCustody'] = copy.deepcopy(self.intent['domainRuntimeProjections']['platform']['projectionCustody'])
        self.sync(); self.reject()

    def test_source_bytes_drift(self):
        self.target.write_bytes(b'{"different":true}\n'); self.reject()

    def test_source_original_inode_aba(self):
        body = self.target.read_bytes(); self.target.rename(self.target.with_name('retained'))
        self.put(self.target, body); self.set_owner(self.target, self.row['uid'], self.accounts[self.row['user']].pw_gid)
        self.target.with_name('retained').unlink(); self.reject()

    def test_source_extra_file(self):
        self.put(self.destination / 'service-env/foreign.env', b'SYNTHETIC=extra\n'); self.reject()

    def test_source_missing_file(self):
        self.target.unlink(); self.reject()

    def test_source_symlink(self):
        self.target.unlink(); self.target.symlink_to(self.release / 'runtime/configs/app/public.json'); self.reject()

    def test_source_hardlink(self):
        os.link(self.target, self.base / 'synthetic-alias'); self.reject()

    def test_source_acl_drift(self):
        self.acls[self.key(self.target)] = (b'invalid', b''); self.reject()

    def test_source_default_acl_drift(self):
        self.acls[self.key(self.destination / 'configs')] = (b'', b'invalid'); self.reject()

    def test_source_mode_drift(self):
        self.target.chmod(0o600); self.reject()

    def test_source_uid_drift(self):
        self.set_owner(self.target, 0, 0); self.reject()

    def test_source_mount_drift(self):
        with patch.object(p, 'mount_id', return_value=92): self.reject()

    def test_source_projection_metadata_replaced(self):
        self.put(self.destination / 'projection.json', b'{}\n'); self.reject()

    def test_persistent_bytes_drift(self):
        (self.store / 'runner80.env').write_bytes(b'SYNTHETIC=wrong\n'); self.reject()

    def test_persistent_original_inode_drift(self):
        target = self.store / 'runner80.env'; body = target.read_bytes(); target.rename(self.store / 'unselected-retained')
        self.put(target, body); self.set_owner(target, self.row['uid'], self.accounts[self.row['user']].pw_gid)
        self.reject()

    def test_persistent_store_acl_drift(self):
        self.acls[self.key(self.store)] = (b'invalid', b''); self.reject()

    def test_persistent_hash_authority_forged(self):
        self.proof['environmentStoreHandoff']['files']['runner80.env']['sha256'] = '0' * 64
        self.sync(); self.reject()

    def test_source_hash_authority_forged(self):
        self.proof['files']['configs/app/public.json'] = '0' * 64; self.sync(); self.reject()

    def test_root_receipt_differs(self):
        self.put(self.release / 'installation-receipt.json', b'{}\n'); self.reject()

    def test_root_input_drift(self):
        self.put(self.release / 'bundle.json', b'{"drift":1}\n'); self.reject()

    def test_marker_drift(self):
        self.put(self.scope / o.storage.MARKER, b'{}\n'); self.reject()

    def test_lease_refusal(self):
        with patch.object(o, 'lock_held', side_effect=ValueError('synthetic absent lease')): self.reject()

    def test_account_drift(self):
        self.accounts[self.row['user']].pw_gid += 1; self.reject()

    def test_selected_pointer_wrong_target(self):
        self.selected(); (self.state / 'current').unlink(); (self.state / 'current').symlink_to(self.state / 'releases/foreign')
        self.reject()

    def test_running_inode_changes_between_sweeps(self):
        store = self.restore(); original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1:
                target = store / 'runner80.env'; body = target.read_bytes(); target.rename(store / 'unselected-retained')
                self.put(target, body); self.set_owner(target, self.row['uid'], self.accounts[self.row['user']].pw_gid)
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject(True)

    def test_previous_original_relative_pointer_set(self):
        self.run_verify()
        self.selected('preparing'); self.run_verify()

    def test_previous_old_pointer_inode_aba_refused(self):
        link = self.state / 'current'; link.rename(self.state / 'retained-pointer')
        link.symlink_to('releases/previous'); self.reject()

    def test_previous_arbitrary_pointer_set_refused(self):
        link = self.install / 'current'; link.unlink(); link.symlink_to('releases/foreign'); self.reject()

    def test_retired_real_preproducer_empty_domain_flow(self):
        self.assertTrue(self.real_retired)
        self.assertEqual(self.real_retired_domains, ['platform'])
        self.assertIsNone(self.intent['previousRelease'])
        self.assertEqual(set(self.intent['domainRuntimeProjections']), set(o.native.IDENTITIES))
        self.run_verify()
        self.assertIsNone(self.intent['previousRelease'])
        self.assertEqual((self.install / 'current').readlink(), Path('releases/previous'))

    def test_retired_failed_source_with_no_previous_claim_before_custody(self):
        self.assertIsNone(self.intent['previousRelease'])
        self.assertNotIn('nativeUnitFileCustody', self.intent)
        self.install.chmod(0o755)
        result = self.run_verify()
        self.assertFalse(result['activationAuthorized'])
        self.assertIsNone(self.intent['previousRelease'])
        snap = v.Snapshot(self.install, self.release, self.intent, False, v.time.monotonic() + 120)
        try:
            observed = snap.sweep()
            source = observed['stop-only-previous-source']
            self.assertEqual(source['release'], str(self.previous))
            self.assertEqual(source['source'], o.native.source_plan(self.previous, previous=True))
            self.assertNotIn('webservices-huly.service', source['source']['scopes']['rootless-apps']['units'])
        finally:
            snap.close()

    def test_retired_clean_source_with_no_previous_claim(self):
        self.old_reseal('retired-clean'); self.run_verify()

    def test_retired_selected_candidate_is_not_old_restart_authority(self):
        self.selected('preparing'); self.run_verify()
        self.selected('units-selected'); self.run_verify()

    def test_retired_active_source_without_previous_claim_refused(self):
        self.old_reseal('active'); self.reject()

    def test_retired_failed_unretired_source_refused(self):
        self.old_reseal('failed'); self.reject()

    def test_retired_foreign_same_root_current_refused(self):
        link = self.install / 'current'; link.unlink(); link.symlink_to(self.install / 'releases/foreign')
        self.reject()

    def test_retired_current_outside_same_root_refused(self):
        link = self.install / 'current'; link.unlink(); link.symlink_to(self.base / 'foreign')
        self.reject()

    def test_retired_source_public_or_acl_refused(self):
        self.previous.chmod(0o755); self.reject()
        self.previous.chmod(0o700); self.acls[self.key(self.previous)] = (b'invalid', b''); self.reject()

    def test_retired_source_missing_complete_pins_refused(self):
        value = self.old_reseal(); value['inputs'].pop('site/global.settings/webservices.sops.json')
        self.put(self.previous / 'installation-receipt.json', p.encoded(value)); self.reject()

    def test_retired_source_provenance_drift_refused(self):
        self.put(self.previous / 'source-provenance.json', b'{}\n'); self.reject()

    def test_retired_same_site_scope_identity_mismatch_refused(self):
        self.old_document('site/manifest.json', lambda value: value.update(site='foreign.invalid')); self.reject()

    def test_retired_same_scope_mismatch_refused(self):
        self.old_document('podman-domains.json', lambda value: value['storageScope'].update(dataClass='production')); self.reject()

    def test_retired_uid_roots_marker_mismatch_refused(self):
        self.old_document('podman-domains.json', lambda value: value['domains'][0].update(uid=999)); self.reject()

    def test_retired_subrange_declaration_mismatch_refused(self):
        self.old_document('podman-domains.json', lambda value: value['domains'][0].update(subuidStart=123456)); self.reject()

    def test_retired_source_quadlet_acl_refused(self):
        self.acls[self.key(self.previous / 'quadlet/rootful/webservices-old-edge.container')] = (b'invalid', b''); self.reject()

    def test_retired_source_quadlet_symlink_refused(self):
        path = self.previous / 'quadlet/rootful/webservices-old-edge.container'
        body = path.read_bytes(); path.unlink(); self.put(self.base / 'old-source-alias', body)
        path.symlink_to(self.base / 'old-source-alias'); self.reject()

    def test_retired_source_inode_aba_between_sweeps_refused(self):
        original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1:
                path = self.previous / 'quadlet/rootful/webservices-old-edge.container'
                body = path.read_bytes(); path.rename(self.previous / 'retained-old-source')
                self.put(path, body)
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject()

    def test_retired_current_inode_aba_between_sweeps_refused(self):
        original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1:
                link = self.install / 'current'; link.rename(self.install / 'retained-old-pointer')
                link.symlink_to('releases/previous')
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject()

    def test_retired_source_mount_alias_refused(self):
        original = p.child_open
        def opened(fd, name, flags):
            if self.fd_paths[fd] == self.install / 'releases' and name == 'previous':
                raise OSError(18, 'synthetic stop-only release mount alias')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=opened): self.reject()

    def test_retired_source_missing_receipt_refused(self):
        (self.previous / 'installation-receipt.json').unlink(); self.reject()

    def test_retired_source_receipt_inode_aba_between_sweeps_refused(self):
        original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1:
                path = self.previous / 'installation-receipt.json'; body = path.read_bytes()
                path.rename(self.previous / 'retained-old-receipt'); self.put(path, body)
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject()

    def test_retired_source_plan_bytes_drift_second_sweep_refused(self):
        original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1:
                path = self.previous / 'quadlet/rootful/webservices-old-edge.container'
                path.write_bytes(path.read_bytes().replace(b'ContainerName=old-edge', b'ContainerName=foreign'))
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject()

    def test_retired_all_old_actor_captures_none_are_valid(self):
        # Root remains a retired source while a clean actor provision records
        # no old actor pointer. This is still a coherent captured-old set.
        for row in self.rows:
            path = Path(row['stateRoot']) / 'current'; path.unlink()
            proof = self.intent['domainRuntimeProjections'][row['name']]
            proof['projectionCustody']['current'] = None
            proof['custodySha256'] = p.sha(p.encoded(proof['projectionCustody']))
            handoff = proof['environmentStoreHandoff']
            handoff['custodySha256'] = proof['custodySha256']
            handoff['sourceProjectionSha256'] = p.sha(p.encoded({k: val for k, val in proof.items() if k != 'environmentStoreHandoff'}))
        self.sync(); self.run_verify()

    def test_retired_mixed_old_new_actor_pointer_refused(self):
        link = self.state / 'current'; link.unlink(); link.symlink_to(self.slot); self.reject()

    def bind_retired(self):
        return v.bind_retired_current(self.install, self.release, self.intent)

    def test_retired_bind_before_any_projection_is_source_only(self):
        self.intent.pop('domainRuntimeProjections'); self.intent.pop('projectionCustody'); self.sync()
        # Source-only API must not assert graph/runtime/env at all.
        with patch.object(v.Snapshot, 'graph', side_effect=AssertionError('no graph authority')), \
             patch.object(v.Snapshot, 'runtime_tree', side_effect=AssertionError('no runtime authority')), \
             patch.object(v.Snapshot, 'environment', side_effect=AssertionError('no environment authority')):
            result = self.bind_retired()
        self.assertEqual(result['release'], str(self.previous))
        self.assertEqual(result['candidateInputs'], self.intent['inputs'])
        self.assertEqual(result['source']['receipt']['sha256'], p.sha((self.previous / 'installation-receipt.json').read_bytes()))
        self.assertEqual(result['current']['target'], 'releases/previous')
        for field in ('projectionAuthorized', 'environmentAuthorized', 'readinessAuthorized', 'activationAuthorized', 'resetAuthorized'):
            self.assertFalse(result[field])
        self.reject()  # Full verifier still requires every domain proof.

    def test_retired_bind_equality_survives_legitimate_candidate_journal_writes(self):
        self.intent.pop('domainRuntimeProjections'); self.intent.pop('projectionCustody'); self.sync()
        first = self.bind_retired()
        self.intent['projectionCustody'] = {'synthetic': 'next-domain-root-custody'}
        self.intent['domainRuntimeProjections'] = {'platform': {'synthetic': 'preparing-projection-record'}}
        self.sync()
        second = self.bind_retired()
        self.assertEqual(first, second)
        self.assertNotIn(str(self.install / '.install-intent.json'), second['custody'])
        self.assertNotIn(str(self.release / 'installation-receipt.json'), second['custody'])

    def test_retired_bind_revalidates_exact_candidate_records(self):
        self.put(self.release / 'installation-receipt.json', b'{}\n')
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_revalidates_candidate_input_bytes(self):
        self.put(self.release / 'bundle.json', b'{"synthetic-drift":1}\n')
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_absent_current_refused(self):
        (self.install / 'current').unlink()
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_candidate_current_refused(self):
        self.selected('preparing')
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_active_source_without_claim_refused(self):
        self.old_reseal('active')
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_nonpreparing_or_active_previous_claim_refused(self):
        self.intent['phase'] = 'units-selected'; self.sync()
        with self.assertRaises(ValueError): self.bind_retired()
        self.intent['phase'] = 'preparing'; self.intent['previousRelease'] = str(self.previous); self.sync()
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_old_inode_replacement_changes_returned_custody(self):
        first = self.bind_retired()
        path = self.previous / 'quadlet/rootful/webservices-old-edge.container'; body = path.read_bytes()
        path.rename(self.previous / 'retained-original'); self.put(path, body)
        second = self.bind_retired()
        self.assertNotEqual(first, second)
        self.assertEqual(first['source'], second['source'])  # Same bytes, different pinned inode.

    def test_retired_bind_subrange_revalidated(self):
        self.old_document('podman-domains.json', lambda value: value['domains'][0].update(subuidStart=123456))
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_nonroot_current_owner_refused(self):
        self.set_owner(self.install / 'current', self.row['uid'], self.accounts[self.row['user']].pw_gid)
        with self.assertRaises(ValueError): self.bind_retired()

    def test_retired_bind_requires_existing_fd9(self):
        with patch.object(o, 'lock_held', side_effect=ValueError('synthetic lease absent')):
            with self.assertRaises(ValueError): self.bind_retired()

    def test_verifier_has_no_mutating_file_operations(self):
        opened = os.open
        def readonly(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            return opened(path, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=readonly), \
             patch.object(os, 'mkdir', side_effect=AssertionError('no mkdir')), \
             patch.object(os, 'fchmod', side_effect=AssertionError('no chmod')), \
             patch.object(os, 'unlink', side_effect=AssertionError('no unlink')):
            self.run_verify()

    def test_root_cas_changes_during_source_read(self):
        original = v.Snapshot.regular; changed = False
        def regular(snapshot, parent, name, *args, **kwargs):
            nonlocal changed
            result = original(snapshot, parent, name, *args, **kwargs)
            if name == 'public.json' and not changed:
                changed = True
                self.intent['steps'].append('synthetic-CAS-drift'); self.sync()
            return result
        with patch.object(v.Snapshot, 'regular', regular): self.reject()
        self.assertTrue(changed)

    def test_running_exact_uid_mount_boundary_allowed_below_alias_refused(self):
        self.restore(); original = p.child_open
        def no_crossing(fd, name, flags):
            if self.fd_paths[fd] == self.runtime_base:
                raise OSError(18, 'synthetic separate user tmpfs boundary')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=no_crossing):
            self.run_verify(True)
        def alias(fd, name, flags):
            if name == 'webservices' and self.fd_paths[fd].is_relative_to(self.runtime_base):
                raise OSError(18, 'synthetic selected bind alias')
            return original(fd, name, flags)
        with patch.object(p, 'child_open', side_effect=alias): self.reject(True)

    def test_running_runtime_parent_default_acl_refused(self):
        store = self.restore(); self.acls[self.key(store.parent)] = (b'', b'invalid'); self.reject(True)

    def test_running_runtime_mount_changes_between_sweeps(self):
        self.restore(); original = v.Snapshot.sweep; changed = False
        def mount(fd):
            path = self.fd_paths.get(fd)
            return 92 if changed and path is not None and path.is_relative_to(self.runtime_base) else 91
        def sweep(snapshot):
            nonlocal changed
            result = original(snapshot); changed = True
            return result
        with patch.object(p, 'mount_id', side_effect=mount), patch.object(v.Snapshot, 'sweep', sweep):
            self.reject(True)

    def test_source_failure_second_complete_sample_not_admitted(self):
        original = v.Snapshot.sweep; count = 0
        def sweep(snapshot):
            nonlocal count
            result = original(snapshot); count += 1
            if count == 1: self.target.write_bytes(b'{"failed-sample":true}\n')
            return result
        with patch.object(v.Snapshot, 'sweep', sweep): self.reject()
        self.assertTrue(self.target.exists())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', type=int, choices=(1, 2, 3, 4, 5, 6),
                        help='1..5: bounded normal fifth; 6: expensive real pre-producer empty-domain flow only')
    args = parser.parse_args()
    own_names = [name for name in Projections.__dict__ if name.startswith('test_')]
    if args.group is not None:
        real = 'test_retired_real_preproducer_empty_domain_flow'
        if args.group == 6:
            own_names = [real]
        else:
            own_names = [name for name in own_names if name != real]
            own_names = [name for index, name in enumerate(own_names) if index % 5 == args.group - 1]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Projections(name) for name in own_names))
    raise SystemExit(not result.wasSuccessful())
